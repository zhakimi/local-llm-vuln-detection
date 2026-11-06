"""Matching predictions to ground truth, and computing metrics.

Matching rules (documented in benchmarks/README.md):

* A prediction belongs to the case file it was produced for.
* **Strict match**: same file, prediction category == ground-truth category,
  and the predicted line lies within ``[start_line - TOL, end_line + TOL]``
  (TOL = 2 lines).
* **Location match** (reported separately): same file and line window, any
  category.
* Each ground-truth vulnerability is matched by at most one prediction
  (greedy, closest line first). Further predictions that would match an
  already-matched vulnerability are **duplicates**: they are counted but are
  neither TP nor FP.
* Every other prediction is a **false positive**, including predictions with
  no line number, predictions on secure files, and wrong-category predictions
  at the right location (strict mode).
* Vulnerability-level TN is undefined (there is no finite set of "non
  vulnerabilities"), so TN and the false-positive rate are computed at the
  **file level** only: a file is predicted vulnerable if it has >= 1 prediction.

Matcher changelog: v1.0.1 added CWE-319 to insecure_config (Semgrep labels disabled
TLS verification as CWE-319). Applied identically to every system.

Category of a prediction: derived from its CWE via CATEGORY_CWES; if the CWE
is missing/unknown, from the title via the scanner's keyword table; else
"other" (which never strictly matches).
"""

from __future__ import annotations

import math
import re
import statistics
from typing import Any, Iterable, Optional

LINE_TOLERANCE = 2

CATEGORY_CWES: dict[str, set[int]] = {
    "sql_injection": {89, 564, 943},
    "command_injection": {77, 78, 88},
    "xss": {79, 80, 83, 87},
    "path_traversal": {22, 23, 35, 36, 73},
    "insecure_deserialization": {502},
    "hardcoded_credentials": {259, 321, 547, 798},
    "weak_crypto": {261, 326, 327, 328, 330, 331, 335, 338, 759, 760, 780, 916},
    "code_injection": {94, 95, 96, 917, 1336},
    "auth": {287, 290, 306, 345, 347, 384, 602, 862, 863, 1390},
    "insecure_config": {16, 215, 295, 319, 489, 614, 668, 693, 732, 942, 1004},
    "memory_safety": {119, 120, 121, 122, 125, 131, 134, 190, 242, 676, 787},
}
CATEGORIES = sorted(CATEGORY_CWES)
_CWE_TO_CATEGORY = {cwe: cat for cat, cwes in CATEGORY_CWES.items() for cwe in cwes}


def cwe_number(cwe: Any) -> Optional[int]:
    m = re.search(r"(\d+)", str(cwe or ""))
    return int(m.group(1)) if m else None


def category_of(cwe: Any, title: str = "") -> str:
    n = cwe_number(cwe)
    if n in _CWE_TO_CATEGORY:
        return _CWE_TO_CATEGORY[n]
    if title:
        from scanner.analyzer import canonical_cwe

        n2 = cwe_number(canonical_cwe(title, ""))
        if n2 in _CWE_TO_CATEGORY:
            return _CWE_TO_CATEGORY[n2]
    return "other"


def _in_window(line: Optional[int], gt: dict, tol: int) -> bool:
    return line is not None and gt["start_line"] - tol <= line <= gt["end_line"] + tol


def _distance(line: int, gt: dict) -> int:
    if gt["start_line"] <= line <= gt["end_line"]:
        return 0
    return min(abs(line - gt["start_line"]), abs(line - gt["end_line"]))


def match_file(preds: list[dict], gts: list[dict], strict: bool = True, tol: int = LINE_TOLERANCE) -> dict:
    """Match one file's predictions (each has 'line' and 'category')."""
    matched: dict[str, dict] = {}
    outcome = []
    for p in sorted(preds, key=lambda p: (p.get("line") is None, p.get("line") or 0)):
        cands = [g for g in gts if _in_window(p.get("line"), g, tol) and (not strict or p["category"] == g["category"])]
        free = [g for g in cands if g["vuln_id"] not in matched]
        if free:
            g = min(free, key=lambda g: _distance(p["line"], g))
            matched[g["vuln_id"]] = p
            outcome.append({**p, "result": "tp", "vuln_id": g["vuln_id"]})
        elif cands:
            outcome.append({**p, "result": "duplicate", "vuln_id": cands[0]["vuln_id"]})
        else:
            loc = any(_in_window(p.get("line"), g, tol) for g in gts)
            reason = "no_line" if p.get("line") is None else ("wrong_category" if loc else "no_ground_truth_here")
            outcome.append({**p, "result": "fp", "reason": reason})
    return {
        "tp": len(matched),
        "fp": sum(1 for o in outcome if o["result"] == "fp"),
        "fn": len(gts) - len(matched),
        "duplicates": sum(1 for o in outcome if o["result"] == "duplicate"),
        "matched_vulns": sorted(matched),
        "missed_vulns": sorted(g["vuln_id"] for g in gts if g["vuln_id"] not in matched),
        "predictions": outcome,
    }


def ratio(a: float, b: float) -> Optional[float]:
    return a / b if b else None


def prf(tp: int, fp: int, fn: int) -> dict:
    p, r = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and (p + r) else (0.0 if p is not None and r is not None else None)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def evaluate(cases: list[dict], predictions_by_case: dict[str, list[dict]], tol: int = LINE_TOLERANCE) -> dict:
    """Score one system run. ``predictions_by_case``: case_id -> [{'line', 'cwe', 'title', ...}]."""
    per_case = {}
    agg = {"strict": [0, 0, 0, 0], "location": [0, 0, 0, 0]}  # tp fp fn dup
    file_counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    by_cat: dict[str, list[int]] = {c: [0, 0] for c in CATEGORIES}  # [matched, total]
    by_lang: dict[str, list[int]] = {}
    fp_on_secure = 0
    for case in cases:
        cid = case["case_id"]
        preds = [{**p, "category": p.get("category") or category_of(p.get("cwe"), p.get("title", ""))}
                 for p in predictions_by_case.get(cid, [])]
        gts = case["vulnerabilities"]
        res = {mode: match_file(preds, gts, strict=(mode == "strict"), tol=tol) for mode in ("strict", "location")}
        for mode, r in res.items():
            a = agg[mode]
            a[0] += r["tp"]
            a[1] += r["fp"]
            a[2] += r["fn"]
            a[3] += r["duplicates"]
        flagged = bool(preds)
        vulnerable = case["ground_truth"] == "vulnerable"
        key = ("tp" if flagged else "fn") if vulnerable else ("fp" if flagged else "tn")
        file_counts[key] += 1
        if not vulnerable:
            fp_on_secure += len(preds)
        for g in gts:
            by_cat[g["category"]][1] += 1
            if g["vuln_id"] in res["strict"]["matched_vulns"]:
                by_cat[g["category"]][0] += 1
        lang = by_lang.setdefault(case["language"], [0, 0])
        lang[0] += res["strict"]["tp"]
        lang[1] += len(gts)
        per_case[cid] = {"file_result": key, "strict": res["strict"], "location": {k: v for k, v in res["location"].items() if k != "predictions"}}

    fc = file_counts
    file_level = {
        **fc,
        "precision": ratio(fc["tp"], fc["tp"] + fc["fp"]),
        "recall": ratio(fc["tp"], fc["tp"] + fc["fn"]),
        "false_positive_rate": ratio(fc["fp"], fc["fp"] + fc["tn"]),
        "accuracy": ratio(fc["tp"] + fc["tn"], sum(fc.values())),
    }
    p, r = file_level["precision"], file_level["recall"]
    file_level["f1"] = 2 * p * r / (p + r) if p and r else 0.0
    out = {
        "vulnerability_level": {
            mode: {**prf(*agg[mode][:3]), "duplicates": agg[mode][3]} for mode in ("strict", "location")
        },
        "file_level": file_level,
        "findings_on_secure_files": fp_on_secure,
        "recall_by_category": {c: {"detected": m, "total": t, "recall": ratio(m, t)} for c, (m, t) in by_cat.items() if t},
        "recall_by_language": {lg: {"detected": m, "total": t, "recall": ratio(m, t)} for lg, (m, t) in sorted(by_lang.items())},
        "per_case": per_case,
    }
    return out


def summarize(values: Iterable[Optional[float]]) -> dict:
    vals = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    if not vals:
        return {"mean": None, "std": None, "min": None, "max": None, "n": 0}
    return {
        "mean": statistics.fmean(vals),
        "std": statistics.stdev(vals) if len(vals) > 1 else 0.0,
        "min": min(vals),
        "max": max(vals),
        "n": len(vals),
    }


def improvement_pct(ai_tp: float, base_tp: float) -> Optional[float]:
    """((AI TP - baseline TP) / baseline TP) * 100; None if baseline TP is 0."""
    return (ai_tp - base_tp) / base_tp * 100 if base_tp else None
