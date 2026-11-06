"""Benchmark integrity and scoring logic (offline)."""

from __future__ import annotations

import csv
import hashlib

import pytest

from benchmarks import BENCH_DIR, load_manifest
from benchmarks.baselines import run_heuristic
from benchmarks.manual_review import export, parse_worksheet
from benchmarks.matching import CATEGORIES, category_of, evaluate, improvement_pct, match_file

MANIFEST = load_manifest()
CASES = MANIFEST["cases"]


def test_manifest_size_and_balance():
    assert 30 <= len(CASES) <= 80
    assert {c["language"] for c in CASES} == {"python", "javascript", "typescript", "java", "c"}
    assert sum(c["ground_truth"] == "secure" for c in CASES) >= 10
    assert MANIFEST["synthetic"] is True and all(c["origin"] == "synthetic" for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["case_id"] for c in CASES])
def test_case_integrity(case):
    path = BENCH_DIR / case["file"]
    text = path.read_text()
    assert hashlib.sha256(text.encode()).hexdigest() == case["sha256"], "case file changed without rebuilding manifest"
    lines = text.splitlines()
    if case["ground_truth"] == "secure":
        assert not case["vulnerabilities"] and case["secure_rationale"]
    else:
        assert case["vulnerabilities"]
    for v in case["vulnerabilities"]:
        assert v["category"] in CATEGORIES
        assert category_of(v["cwe"]) == v["category"], f"{v['cwe']} not in category {v['category']}"
        assert v["anchor"] in lines[v["start_line"] - 1]
        assert 1 <= v["start_line"] <= v["end_line"] <= len(lines)
        assert v["explanation"] and v["reference"].startswith("https://")


def test_case_files_do_not_leak_labels():
    leaky = ("vulnerab", "insecure", "cwe-", "owasp", "exploit", "secure version", "bm-0")
    for c in CASES:
        if "prompt_injection" in c["tags"]:
            continue  # their comments deliberately make (false) claims to the reviewer
        text = (BENCH_DIR / c["file"]).read_text().lower()
        assert not any(word in text for word in leaky), c["file"]


def _gt(vid, cat, start, end=None):
    return {"vuln_id": vid, "category": cat, "start_line": start, "end_line": end or start}


class TestMatching:
    def test_strict_tp_duplicate_and_fp(self):
        gts = [_gt("V1", "sql_injection", 10)]
        preds = [
            {"line": 11, "category": "sql_injection"},  # TP (within tolerance)
            {"line": 10, "category": "sql_injection"},  # duplicate
            {"line": 10, "category": "xss"},            # wrong category -> FP
            {"line": None, "category": "sql_injection"},  # no line -> FP
        ]
        r = match_file(preds, gts)
        assert (r["tp"], r["fp"], r["fn"], r["duplicates"]) == (1, 2, 0, 1)
        reasons = sorted(p.get("reason", "") for p in r["predictions"] if p["result"] == "fp")
        assert reasons == ["no_line", "wrong_category"]

    def test_location_mode_ignores_category(self):
        r = match_file([{"line": 10, "category": "xss"}], [_gt("V1", "sql_injection", 10)], strict=False)
        assert r["tp"] == 1

    def test_out_of_window_is_fp_and_fn(self):
        r = match_file([{"line": 20, "category": "sql_injection"}], [_gt("V1", "sql_injection", 10, 11)])
        assert (r["tp"], r["fp"], r["fn"]) == (0, 1, 1)

    def test_two_vulns_in_one_file(self):
        gts = [_gt("V1", "weak_crypto", 5), _gt("V2", "weak_crypto", 9)]
        r = match_file([{"line": 9, "category": "weak_crypto"}, {"line": 5, "category": "weak_crypto"}], gts)
        assert r["tp"] == 2 and r["fp"] == 0

    def test_file_level_counts(self):
        cases = [
            {"case_id": "A", "language": "python", "ground_truth": "vulnerable", "vulnerabilities": [_gt("A-V1", "xss", 3)]},
            {"case_id": "B", "language": "python", "ground_truth": "secure", "vulnerabilities": []},
            {"case_id": "C", "language": "python", "ground_truth": "secure", "vulnerabilities": []},
        ]
        m = evaluate(cases, {"A": [{"line": 3, "cwe": "CWE-79"}], "B": [{"line": 1, "cwe": "CWE-89"}]})
        assert m["file_level"]["tp"] == 1 and m["file_level"]["fp"] == 1 and m["file_level"]["tn"] == 1
        assert m["file_level"]["false_positive_rate"] == 0.5
        assert m["vulnerability_level"]["strict"]["precision"] == 0.5

    def test_category_from_title_when_cwe_missing(self):
        assert category_of("", "OS command injection") == "command_injection"
        assert category_of("CWE-20", "") == "other"

    def test_improvement_formula(self):
        assert improvement_pct(13, 10) == pytest.approx(30.0)
        assert improvement_pct(5, 0) is None


def test_heuristic_baseline_runs_offline():
    r = run_heuristic(CASES, BENCH_DIR)
    m = evaluate(CASES, r["predictions"])
    assert m["vulnerability_level"]["strict"]["tp"] > 0


def test_manual_review_export_is_blinded_and_scores(tmp_path):
    out = tmp_path / "packet"
    export(out)
    files = sorted(p.name for p in (out / "files").iterdir())
    assert len(files) == len(CASES)
    assert not (out / "manifest.json").exists()
    rows = list(csv.DictReader(open(out / "worksheet.csv")))
    assert set(rows[0]) == {"file", "reviewed", "vulnerabilities", "notes"} and all(not r["vulnerabilities"] for r in rows)
    # a reviewer marks one real vulnerability and one bogus one
    first = next(c for c in CASES if c["vulnerabilities"])
    v = first["vulnerabilities"][0]
    name = first["file"].split("/")[-1]
    for r in rows:
        r["reviewed"] = "yes"
        if r["file"] == name:
            r["vulnerabilities"] = f"{v['start_line']}:{v['category']}; 1:xss"
    with open(out / "worksheet.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "reviewed", "vulnerabilities", "notes"])
        w.writeheader()
        w.writerows(rows)
    preds, problems, reviewed = parse_worksheet(out / "worksheet.csv")
    assert not problems and reviewed == len(CASES)
    m = evaluate(CASES, preds)
    assert m["vulnerability_level"]["strict"]["tp"] == 1


def test_manual_export_refuses_inside_repo():
    with pytest.raises(SystemExit):
        export(BENCH_DIR / "results" / "packet")
