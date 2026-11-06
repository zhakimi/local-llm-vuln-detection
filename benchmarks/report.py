"""Render benchmark_report.md and 30_percent_validation.md from benchmark_results.json.

    python -m benchmarks.report            # re-render from existing results
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from . import RESULTS_DIR, load_manifest
from .matching import CATEGORIES, improvement_pct

MANUAL_RESULTS = RESULTS_DIR / "manual_review_results.json"


def f3(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def ms(s: dict, fmt=f3, as_int=False) -> str:
    """mean ± std (min–max) for a summarize() dict."""
    if not s or s.get("mean") is None:
        return "n/a"
    if as_int:
        base = f"{s['mean']:.1f} ± {s['std']:.1f}"
        rng = f"{s['min']:.0f}–{s['max']:.0f}"
    else:
        base = f"{fmt(s['mean'])} ± {s['std']:.3f}"
        rng = f"{fmt(s['min'])}–{fmt(s['max'])}"
    return f"{base} ({rng})" if s.get("n", 0) > 1 else base


def _static_row(m: dict) -> dict:
    v, fl = m["vulnerability_level"], m["file_level"]
    return {
        "tp": str(v["strict"]["tp"]), "fp": str(v["strict"]["fp"]), "fn": str(v["strict"]["fn"]),
        "precision": f3(v["strict"]["precision"]), "recall": f3(v["strict"]["recall"]), "f1": f3(v["strict"]["f1"]),
        "dup": str(v["strict"]["duplicates"]), "loc_recall": f3(v["location"]["recall"]),
        "file_precision": f3(fl["precision"]), "file_recall": f3(fl["recall"]), "file_f1": f3(fl["f1"]),
        "file_fpr": f3(fl["false_positive_rate"]), "secure_findings": str(m["findings_on_secure_files"]),
    }


def _llm_row(s: dict) -> dict:
    return {
        "tp": ms(s["vuln_strict_tp"], as_int=True), "fp": ms(s["vuln_strict_fp"], as_int=True),
        "fn": ms(s["vuln_strict_fn"], as_int=True), "precision": ms(s["vuln_strict_precision"]),
        "recall": ms(s["vuln_strict_recall"]), "f1": ms(s["vuln_strict_f1"]),
        "dup": ms(s["vuln_strict_duplicates"], as_int=True), "loc_recall": ms(s["vuln_location_recall"]),
        "file_precision": ms(s["file_precision"]), "file_recall": ms(s["file_recall"]), "file_f1": ms(s["file_f1"]),
        "file_fpr": ms(s["file_fpr"]), "secure_findings": ms(s["findings_on_secure_files"], as_int=True),
    }


ROWS = [
    ("tp", "True positives (vuln-level, strict)"),
    ("fp", "False positives (vuln-level, strict)"),
    ("fn", "False negatives (vuln-level, strict)"),
    ("precision", "Precision (strict)"),
    ("recall", "Recall (strict)"),
    ("f1", "F1 (strict)"),
    ("dup", "Duplicate findings (not counted as FP)"),
    ("loc_recall", "Recall, location-only (any category)"),
    ("file_precision", "File-level precision"),
    ("file_recall", "File-level recall"),
    ("file_f1", "File-level F1"),
    ("file_fpr", "File-level false-positive rate"),
    ("secure_findings", "Findings reported on secure files"),
]


def load_manual() -> Optional[dict]:
    if MANUAL_RESULTS.exists():
        return json.loads(MANUAL_RESULTS.read_text())
    return None


def _cases(res: dict) -> list[dict]:
    ids = set(res.get("case_ids") or [])
    return [c for c in load_manifest()["cases"] if not ids or c["case_id"] in ids]


def render_report(res: dict) -> str:
    env, st, ds = res["environment"], res["settings"], res["dataset"]
    model = env["model"]
    systems = res["systems"]
    out: list[str] = []
    w = out.append
    w("# Benchmark Report — amd-vuln-scanner\n")
    if res.get("partial"):
        w("> **PARTIAL RUN (--limit).** Not a valid benchmark result.\n")
    w("> All test cases are **synthetic** programs written for this benchmark (see `benchmarks/README.md`). "
      "They are not real-world vulnerability discoveries. Results describe performance on this small, "
      "self-authored dataset only and should not be generalized.\n")
    w(f"Generated from `benchmarks/results/benchmark_results.json` · started {res['started_at']} · "
      f"finished {res.get('finished_at', 'n/a')} · scanner v{res['tool_version']} · benchmark v{res['benchmark_version']}\n")

    w("## Environment\n")
    w("| | |\n|---|---|")
    w(f"| CPU | {env['cpu']} |")
    w(f"| GPU | {'; '.join(env['gpu']) or 'n/a'} |")
    w(f"| NPU | {'; '.join(env['npu']) or 'n/a'} (present, **not used** by Ollama) |")
    w(f"| Memory | {env['memory_gib']} GiB (unified, shared CPU/GPU) |")
    w(f"| OS / kernel | {env['os']} / {env['kernel']} |")
    w(f"| Python | {env['python']} |")
    w(f"| Ollama | {model.get('ollama_version')} (backends installed: {', '.join(env['ollama_backends_installed'])}) |")
    w(f"| Model | `{model.get('name')}` — {model.get('parameter_size')} params, {model.get('quantization')}, {model.get('format')}, "
      f"trained context {model.get('trained_context_length')} |")
    w(f"| Model digest | `{model.get('digest')}` |")
    w(f"| Inference settings | temperature={st['temperature']}, num_ctx={st['num_ctx']}, num_predict={st['num_predict']}, "
      f"seed={st['seed']}, format=json; {st['other_sampling_params']} |")
    ps = next((r.get("ollama_ps_after_run") for s in systems.values() for r in s.get("runs", []) if r.get("ollama_ps_after_run")), "")
    if ps:
        w(f"| `ollama ps` after a run | `{' '.join(ps.splitlines()[-1].split())}` |")
    w(f"| Inference endpoint | `{model.get('host')}/api/generate` (loopback: {model.get('host_is_loopback')}) |\n")
    w("Ollama reported the model as **100% GPU** (Radeon iGPU). Which bundled backend (ROCm or Vulkan) "
      "Ollama selected could not be determined without root access to the server logs.\n")

    w("## Dataset\n")
    w(f"{ds['cases']} files ({ds['vulnerable_files']} vulnerable, {ds['secure_files']} secure controls), "
      f"{ds['labeled_vulnerabilities']} labeled vulnerabilities, {ds['prompt_injection_cases']} prompt-injection cases. "
      "Languages: Python, JavaScript, TypeScript, Java, C.\n")

    w("## Method\n")
    w(f"- **Strict match:** same file, same category (derived from CWE), predicted line within ±{st['line_tolerance']} lines "
      "of the labeled region. Each labeled vulnerability is matched at most once; extra matches are *duplicates* "
      "(not TP, not FP). Everything else is a false positive (including unlabeled issues; see the FP breakdown).")
    w("- **Location-only match:** same as strict but any category. Shows how often the system pointed at the right "
      "code even when it named the wrong weakness.")
    w("- **File-level:** a file counts as flagged if it has ≥1 finding. TN and FPR exist only at this level.")
    w(f"- **LLM configurations** were run {st['runs_per_config']}× each with no fixed seed, so sampling varies between runs; "
      "tables show mean ± sample std (min–max).")
    w("- **Pre-validation** = everything the scanner reports (this is what the CLI saves). **Post-validation** = "
      f"findings the same model's second pass disputed with confidence ≥ {st['dispute_confidence_threshold']} are removed.")
    w("- Baselines: **Semgrep OSS** with the registry ruleset `p/default` (fixed in advance, not tuned), and the scanner's "
      "own **hotspot regexes** used standalone (ablation; same author as the benchmark, so likely optimistic).\n")

    cols = []
    if systems.get("semgrep", {}).get("available"):
        cols.append((f"Semgrep `{systems['semgrep']['config']}`", _static_row(systems["semgrep"]["metrics"])))
    if systems.get("heuristic", {}).get("available"):
        cols.append(("Regex hotspots only", _static_row(systems["heuristic"]["metrics"])))
    for key, label in (("llm_full", "LLM full"), ("llm_only", "LLM only (no hotspots)")):
        if key in systems:
            cols.append((f"{label} — pre-validation", _llm_row(systems[key]["summary_pre_validation"])))
            cols.append((f"{label} — post-validation", _llm_row(systems[key]["summary_post_validation"])))

    w("## Results\n")
    w("| Metric | " + " | ".join(c[0] for c in cols) + " |")
    w("|---|" + "---|" * len(cols))
    for key, label in ROWS:
        w(f"| {label} | " + " | ".join(c[1][key] for c in cols) + " |")
    trow = []
    for name, _ in cols:
        if name.startswith("Semgrep"):
            trow.append(f"{systems['semgrep']['seconds']:.1f} s")
        elif name.startswith("Regex"):
            trow.append(f"{systems['heuristic']['seconds']:.3f} s")
        else:
            key = "llm_full" if name.startswith("LLM full") else "llm_only"
            t = systems[key]["timing"]
            trow.append(f"{ms(t['wall_seconds'], fmt=lambda x: f'{x:.0f}')} s total; {ms(t['avg_seconds_per_file'], fmt=lambda x: f'{x:.1f}')} s/file")
    w("| Execution time | " + " | ".join(trow) + " |\n")
    w("Semgrep time includes downloading the rule pack. LLM time is wall-clock for all files including "
      "validation; GPU inference time is in the JSON.\n")

    # per-run detail
    for key in ("llm_full", "llm_only"):
        if key not in systems:
            continue
        w(f"### Per-run detail: {key}\n")
        w("| Run | TP | FP | FN | Precision | Recall | F1 | Post-val TP | Post-val FP | Wall time (s) | Valid / schema-invalid / salvaged / unparseable / timeouts |")
        w("|---|---|---|---|---|---|---|---|---|---|---|")
        for r in systems[key]["runs"]:
            pre = r["metrics_pre_validation"]["vulnerability_level"]["strict"]
            post = r["metrics_post_validation"]["vulnerability_level"]["strict"]
            rs = r["response_stats"]
            w(f"| {r['run']} | {pre['tp']} | {pre['fp']} | {pre['fn']} | {f3(pre['precision'])} | {f3(pre['recall'])} | {f3(pre['f1'])} | "
              f"{post['tp']} | {post['fp']} | {r['wall_seconds']:.0f} | {rs['valid']} / {rs['schema_invalid']} / {rs['salvaged']} / "
              f"{rs['unparseable']} / {rs['timeouts']} |")
        w("")

    # recall by category
    w("## Recall by category (strict)\n")
    hdr = ["Category", "Labeled"]
    getters = []
    if systems.get("semgrep", {}).get("available"):
        hdr.append("Semgrep")
        getters.append(lambda c: _cat(systems["semgrep"]["metrics"], c))
    if systems.get("heuristic", {}).get("available"):
        hdr.append("Regex")
        getters.append(lambda c: _cat(systems["heuristic"]["metrics"], c))
    for key in ("llm_full", "llm_only"):
        if key in systems:
            hdr.append(f"{key} (mean over runs)")
            getters.append(lambda c, k=key: _cat_mean(systems[k]["runs"], c))
    w("| " + " | ".join(hdr) + " |")
    w("|" + "---|" * len(hdr))
    totals = Counter(v["category"] for case in _cases(res) for v in case["vulnerabilities"])
    for c in CATEGORIES:
        if totals.get(c):
            w(f"| {c} | {totals[c]} | " + " | ".join(g(c) for g in getters) + " |")
    w("")

    # validation effect
    if "llm_full" in systems:
        w("## Does second-pass validation help? (Phase 5)\n")
        w("The validator is the **same model** re-reading its own high/critical findings, so agreement is not independent "
          "confirmation. Counts are summed over runs of `llm_full`.\n")
        agg = Counter()
        for r in systems["llm_full"]["runs"]:
            agg.update(r["validation_effect"])
        pre_s, post_s = systems["llm_full"]["summary_pre_validation"], systems["llm_full"]["summary_post_validation"]
        w("| | Value |\n|---|---|")
        w(f"| Validated findings that were true positives | {agg['tp_validated']} |")
        w(f"| … of which disputed (→ validation-induced false negatives) | {agg['tp_disputed']} |")
        w(f"| Validated findings that were false positives | {agg['fp_validated']} |")
        w(f"| … of which disputed (→ false positives removed) | {agg['fp_disputed']} |")
        w(f"| Precision pre → post (mean) | {f3(pre_s['vuln_strict_precision']['mean'])} → {f3(post_s['vuln_strict_precision']['mean'])} |")
        w(f"| Recall pre → post (mean) | {f3(pre_s['vuln_strict_recall']['mean'])} → {f3(post_s['vuln_strict_recall']['mean'])} |")
        w(f"| F1 pre → post (mean) | {f3(pre_s['vuln_strict_f1']['mean'])} → {f3(post_s['vuln_strict_f1']['mean'])} |\n")
        w(_validation_verdict(agg, pre_s, post_s) + "\n")

    # prompt injection
    inj = [c for c in _cases(res) if "prompt_injection" in c["tags"]]
    if inj and "llm_full" in systems:
        w("## Prompt-injection cases\n")
        w("Files containing comments that instruct an AI reviewer to report nothing (vulnerable files) or to report a "
          "fake vulnerability (secure bait file).\n")
        w("| Case | Truth | Semgrep | " + " | ".join(f"{k} runs detecting / with findings" for k in ("llm_full", "llm_only") if k in systems) + " |")
        w("|---|---|---|" + "---|" * sum(k in systems for k in ("llm_full", "llm_only")))
        for c in inj:
            sg = systems.get("semgrep", {}).get("metrics", {}).get("per_case", {}).get(c["case_id"], {})
            sg_txt = (f"{sg['strict']['tp']}/{len(c['vulnerabilities'])} TP" if c["vulnerabilities"] else f"{sg['strict']['fp']} FP") if sg else "n/a"
            cells = []
            for k in ("llm_full", "llm_only"):
                if k not in systems:
                    continue
                runs = systems[k]["runs"]
                if c["vulnerabilities"]:
                    hit = sum(r["metrics_pre_validation"]["per_case"][c["case_id"]]["strict"]["tp"] > 0 for r in runs)
                    cells.append(f"{hit}/{len(runs)} detected")
                else:
                    fl = sum(bool(r["predictions"][c["case_id"]]) for r in runs)
                    cells.append(f"{fl}/{len(runs)} flagged (FP)")
            w(f"| {c['case_id']} | {c['ground_truth']} | {sg_txt} | " + " | ".join(cells) + " |")
        w("")

    # FP breakdown
    w("## What were the false positives?\n")
    w("Top CWEs among strict false positives (LLM counts summed over runs). Some are arguably real but unlabeled weaknesses "
      "(e.g. missing CSRF protection, cookie flags); they are still counted as FPs because labels were fixed before results.\n")
    for name in ("semgrep", "heuristic", "llm_full", "llm_only"):
        s = systems.get(name)
        if not s or (name in ("semgrep", "heuristic") and not s.get("available")):
            continue
        metrics_list = [s["metrics"]] if "metrics" in s else [r["metrics_pre_validation"] for r in s["runs"]]
        cnt: Counter = Counter()
        for m in metrics_list:
            for pc in m["per_case"].values():
                for p in pc["strict"]["predictions"]:
                    if p["result"] == "fp":
                        cnt[f"{p.get('cwe') or '?'} ({p.get('reason')})"] += 1
        w(f"- **{name}:** " + ", ".join(f"{k} ×{v}" for k, v in cnt.most_common(8)))
    w("")

    w("## Limitations\n")
    w("- Small (58 files), synthetic and self-authored: the same AI-assisted process wrote the scanner prompts, the regex "
      "hotspots and the benchmark, which risks favourable bias toward the scanner. The cases are short, single-file and "
      "much easier than real code.")
    w("- No OWASP Benchmark / Juliet cases are included (see benchmarks/README.md), so there is no comparison to "
      "published results.")
    w("- Unlabeled-but-real issues count as false positives for every system.")
    w("- Category mapping from CWE is a judgement call; location-only metrics are reported to show its effect.")
    w("- One model (llama3.2 3B Q4_K_M), one machine; larger models would likely behave differently.")
    w("- Manual review has not been performed (see `30_percent_validation.md`).")
    return "\n".join(out) + "\n"


def _cat(metrics: dict, c: str) -> str:
    v = metrics["recall_by_category"].get(c)
    return f"{v['detected']}/{v['total']}" if v else "-"


def _cat_mean(runs: list[dict], c: str) -> str:
    vals = [r["metrics_pre_validation"]["recall_by_category"].get(c, {}).get("detected", 0) for r in runs]
    tot = runs[0]["metrics_pre_validation"]["recall_by_category"].get(c, {}).get("total", 0)
    return f"{sum(vals) / len(vals):.1f}/{tot}"


def _validation_verdict(agg: Counter, pre: dict, post: dict) -> str:
    dp = (post["vuln_strict_precision"]["mean"] or 0) - (pre["vuln_strict_precision"]["mean"] or 0)
    dr = (post["vuln_strict_recall"]["mean"] or 0) - (pre["vuln_strict_recall"]["mean"] or 0)
    parts = [f"Validation changed mean precision by {dp:+.3f} and mean recall by {dr:+.3f}."]
    if agg["fp_disputed"] == 0 and agg["tp_disputed"] == 0:
        parts.append("It disputed nothing, so it had no measurable filtering effect on this benchmark.")
    else:
        parts.append(f"It removed {agg['fp_disputed']} false positive(s) at the cost of {agg['tp_disputed']} true positive(s).")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 30% claim validation
# ---------------------------------------------------------------------------


def render_30(res: dict, manual: Optional[dict]) -> str:
    systems = res["systems"]
    out: list[str] = []
    w = out.append
    w("# Does the AI scanner detect ≥30% more vulnerabilities? — validation of a résumé claim\n")
    w("**Claim under test:** *\"the scanner caught roughly 30% more issues than manual review alone on the same codebases.\"*\n")
    w("**Formula:** Improvement (%) = ((AI true positives − baseline true positives) / baseline true positives) × 100, "
      "using **strict vulnerability-level true positives** on the same labeled benchmark "
      f"({res['dataset']['labeled_vulnerabilities']} vulnerabilities in {res['dataset']['cases']} synthetic files).\n")
    w("**AI system:** the default scanner configuration (`llm_full`: whole-file + hotspot passes + validation), "
      f"{res['settings']['runs_per_config']} runs, local `{res['environment']['model'].get('name')}` on the Radeon iGPU. "
      "The pre-validation output (what the CLI reports) is the primary number; post-validation is shown too.\n")

    full = systems.get("llm_full")
    if not full:
        w("_No llm_full results available._")
        return "\n".join(out)
    pre, post = full["summary_pre_validation"], full["summary_post_validation"]
    ai_tp = pre["vuln_strict_tp"]
    run_tps = [r["metrics_pre_validation"]["vulnerability_level"]["strict"]["tp"] for r in full["runs"]]

    w("## Comparison\n")
    w("| Metric | Static analysis (Semgrep `p/default`) | Manual review | AI scanner (pre-validation) | AI scanner (post-validation) |")
    w("|---|---|---|---|---|")
    sg = systems.get("semgrep", {})
    sgm = sg.get("metrics", {}).get("vulnerability_level", {}).get("strict") if sg.get("available") else None
    mm = manual["metrics"]["vulnerability_level"]["strict"] if manual else None

    def cell_static(m, k, fmt=f3):
        return "n/a" if m is None else (str(m[k]) if k in ("tp", "fp", "fn") else fmt(m[k]))

    for k, label in (("tp", "True positives"), ("fp", "False positives"), ("fn", "False negatives"),
                     ("precision", "Precision"), ("recall", "Recall"), ("f1", "F1")):
        sk = f"vuln_strict_{k}"
        is_int = k in ("tp", "fp", "fn")
        w(f"| {label} | {cell_static(sgm, k)} | {cell_static(mm, k) if mm else '**pending**'} | "
          f"{ms(pre[sk], as_int=is_int)} | {ms(post[sk], as_int=is_int)} |")
    man_time = f"{manual['review_minutes']:.0f} min" if manual and manual.get("review_minutes") else ("n/a" if manual else "**pending**")
    t = full["timing"]["wall_seconds"]
    w(f"| Review / execution time | {sg.get('seconds', 0):.1f} s | {man_time} | {t['mean']:.0f} s (mean) | same run |\n")

    w("## Improvement\n")
    w("| Comparison | AI TP (mean) | Baseline TP | Improvement | Per-run range | ≥30%? |")
    w("|---|---|---|---|---|---|")
    verdicts = []

    def row(name, base_tp):
        imp = improvement_pct(ai_tp["mean"], base_tp)
        rng = [improvement_pct(x, base_tp) for x in run_tps]
        ok = imp is not None and imp >= 30
        verdicts.append((name, imp, ok, rng))
        rtxt = f"{min(rng):+.1f}% to {max(rng):+.1f}%" if None not in rng else "n/a"
        w(f"| AI vs {name} | {ai_tp['mean']:.1f} | {base_tp} | {'n/a' if imp is None else f'{imp:+.1f}%'} | {rtxt} | "
          f"{'**yes**' if ok else '**no**'} |")

    if sgm:
        row("static analysis (Semgrep)", sgm["tp"])
    if mm:
        row("manual review", mm["tp"])
    else:
        w("| AI vs manual review | — | pending | **not measurable yet** | — | **unknown** |")
    hm = systems.get("heuristic", {}).get("metrics", {}).get("vulnerability_level", {}).get("strict")
    w("")
    if hm:
        imp_h = improvement_pct(ai_tp["mean"], hm["tp"])
        w(f"Ablation (not a traditional tool): the scanner's own regex hotspots alone found {hm['tp']} TP; "
          f"AI vs regex-only = {'n/a' if imp_h is None else f'{imp_h:+.1f}%'}.\n")

    w("## Verdict\n")
    for name, imp, ok, _ in verdicts:
        if imp is None:
            w(f"- **vs {name}:** improvement undefined (baseline found 0).")
        elif ok:
            w(f"- **vs {name}:** the AI scanner found {imp:+.1f}% more correctly located and categorized vulnerabilities "
              "on this benchmark — **at least 30%: yes** (on this synthetic dataset only).")
        else:
            w(f"- **vs {name}:** measured improvement {imp:+.1f}% — **at least 30%: no.**")
    if not mm:
        w("- **vs manual review:** **not yet tested.** The résumé claim compares against *manual review*, which has not "
          "been performed. Semgrep is a static-analysis tool, not manual review, so the Semgrep comparison cannot "
          "be cited as evidence for the manual-review claim.")
    only = systems.get("llm_only")
    if only and sgm:
        o_tp = only["summary_pre_validation"]["vuln_strict_tp"]["mean"]
        w(f"- **Caveat:** the +{improvement_pct(ai_tp['mean'], sgm['tp']):.1f}% depends on the scanner's regex hotspot hints. "
          f"The LLM alone (no hints) found {o_tp:.1f} TP = {improvement_pct(o_tp, sgm['tp']):+.1f}% vs Semgrep, below 30%. "
          f"The AI scanner also raised more false positives ({pre['vuln_strict_fp']['mean']:.1f} vs {sgm['fp']}) and flagged "
          f"{pre['file_fp']['mean']:.1f} of {res['dataset']['secure_files']} secure files.")
    w("")
    w("**What the original claim can and cannot say:** the claim refers to \"the same codebases\" and \"manual review\". "
      "Neither the original codebases nor a recorded manual review exist in this repository, so the original wording is "
      "not supported by evidence here. Only claims backed by the numbers above should be used.\n")

    w("## Manual-review protocol (to complete the comparison)\n")
    w("1. Export a blinded packet **outside the repo** (it contains only the code files, renamed copies are not needed — "
      "names are already opaque):\n\n   ```bash\n   python -m benchmarks.manual_review export --out ~/manual-review-packet\n   ```\n")
    w("2. Before reviewing, do **not** open `benchmarks/manifest.json`, `benchmarks/build_cases.py`, `benchmarks/results/`, "
      "the README benchmark section, or any scanner output for `benchmarks/cases`.")
    w("3. Review each file in the packet, fill in `worksheet.csv` (one row per file; list `line:category` pairs) and record "
      "start/end times in `timing.csv`. No tools other than a text editor; no AI assistance.")
    w("4. Score it with the same matcher:\n\n   ```bash\n   python -m benchmarks.manual_review score ~/manual-review-packet\n"
      "   python -m benchmarks.report\n   ```\n")
    w("This file is then regenerated with the manual column filled in. Results are only as good as the blinding: if the "
      "reviewer has seen labels or AI findings, say so when reporting.\n")

    below = [v for v in verdicts if v[1] is not None and not v[2]]
    if below:
        w("## Evidence-based improvement options\n")
        cats = full["runs"][0]["metrics_pre_validation"]["recall_by_category"]
        weak = sorted(((c, sum(r["metrics_pre_validation"]["recall_by_category"].get(c, {}).get("recall") or 0
                                for r in full["runs"]) / len(full["runs"])) for c in cats), key=lambda x: x[1])[:3]
        w("- Weakest categories for the AI scanner (mean strict recall): " + ", ".join(f"{c} {r:.2f}" for c, r in weak) + ".")
        w("- Try a larger code model (e.g. `qwen2.5-coder:7b`/`14b`/`32b`, which fit in this machine's unified memory) "
          "and re-run the benchmark unchanged.")
        w("- Use Ollama structured outputs (`format` = JSON schema) to cut schema-invalid responses.")
        w("- Combine Semgrep with the LLM (LLM triage of Semgrep findings) and measure that as a separate system.")
        w("- Do **not** change labels, drop cases or tune prompts on this benchmark and then report it as held-out; "
          "add a fresh held-out set for any tuning.")
    return "\n".join(out) + "\n"


def render_all(results_path: Path = RESULTS_DIR / "benchmark_results.json") -> list[Path]:
    res = json.loads(results_path.read_text())
    manual = load_manual()
    p1 = results_path.parent / "benchmark_report.md"
    p1.write_text(render_report(res))
    p2 = results_path.parent / "30_percent_validation.md"
    p2.write_text(render_30(res, manual))
    return [p1, p2]




# ---------------------------------------------------------------------------
# README sections (python -m benchmarks.report --readme)
# ---------------------------------------------------------------------------


def _mean(s: dict) -> Optional[float]:
    return s.get("mean") if s else None


def readme_sections(res: dict, manual: Optional[dict]) -> dict[str, str]:
    sy = res["systems"]
    sg = sy.get("semgrep", {})
    sgm = sg.get("metrics") if sg.get("available") else None
    hm = sy.get("heuristic", {}).get("metrics")
    full, only = sy.get("llm_full"), sy.get("llm_only")
    n_runs = res["settings"]["runs_per_config"]

    def static(m, key):
        v, fl = m["vulnerability_level"]["strict"], m["file_level"]
        return {"tp": f"{v['tp']}", "fp": f"{v['fp']}", "p": f3(v["precision"]), "r": f3(v["recall"]),
                "f1": f3(v["f1"]), "fpr": f3(fl["false_positive_rate"]), "loc": f3(m["vulnerability_level"]["location"]["recall"])}[key]

    def llm(s, key):
        m = {"tp": "vuln_strict_tp", "fp": "vuln_strict_fp", "p": "vuln_strict_precision", "r": "vuln_strict_recall",
             "f1": "vuln_strict_f1", "fpr": "file_fpr", "loc": "vuln_location_recall"}[key]
        x = s[m]
        if key in ("tp", "fp"):
            return f"{x['mean']:.1f} ({x['min']:.0f}–{x['max']:.0f})"
        return f"{x['mean']:.3f} (±{x['std']:.3f})"

    cols = []
    if sgm:
        cols.append(("Semgrep `p/default`", lambda k: static(sgm, k), f"{sg['seconds']:.0f} s"))
    if hm:
        cols.append(("Regex hotspots only¹", lambda k: static(hm, k), "<1 s"))
    if full:
        t = full["timing"]
        tt = f"{t['wall_seconds']['mean'] / 60:.1f} min ({t['avg_seconds_per_file']['mean']:.1f} s/file)"
        cols.append(("LLM scanner (default)²", lambda k: llm(full["summary_pre_validation"], k), tt))
        cols.append(("LLM scanner, post-validation³", lambda k: llm(full["summary_post_validation"], k), "same run"))
    if only:
        t = only["timing"]
        cols.append(("LLM only, no regex hints", lambda k: llm(only["summary_pre_validation"], k),
                     f"{t['wall_seconds']['mean'] / 60:.1f} min ({t['avg_seconds_per_file']['mean']:.1f} s/file)"))
    cols.append(("Manual review", (lambda k: static(manual["metrics"], k)) if manual else (lambda k: "pending"),
                 f"{manual['review_minutes']:.0f} min" if manual and manual.get("review_minutes") else "pending"))

    rows = [("tp", "True positives (of 39)"), ("fp", "False positives"), ("p", "Precision"), ("r", "Recall"),
            ("f1", "F1"), ("loc", "Recall, location only"), ("fpr", "File-level false-positive rate")]
    o = [f"Measured on {res['dataset']['cases']} synthetic files / {res['dataset']['labeled_vulnerabilities']} labeled "
         f"vulnerabilities, strict matching, {n_runs} runs per LLM configuration (mean, with min–max or ±std). "
         "Full tables: [`benchmarks/results/benchmark_report.md`](benchmarks/results/benchmark_report.md).\n",
         "| Metric | " + " | ".join(c[0] for c in cols) + " |", "|---|" + "---|" * len(cols)]
    for key, label in rows:
        o.append(f"| {label} | " + " | ".join(c[1](key) for c in cols) + " |")
    o.append("| Execution time (58 files) | " + " | ".join(c[2] for c in cols) + " |\n")
    o.append("¹ The scanner's own regexes used standalone (ablation; written by the same author as the benchmark, so likely optimistic).  ")
    o.append("² Whole-file + hotspot-focused LLM passes; everything the CLI reports.  ")
    o.append("³ Findings the same model's second pass disputed (confidence ≥ 0.7) removed.\n")

    if full and sgm:
        n_runs = len(full["runs"])
        ai = full["summary_pre_validation"]["vuln_strict_tp"]["mean"]
        imp = improvement_pct(ai, sgm["vulnerability_level"]["strict"]["tp"])
        o.append("**Headline numbers:**\n")
        o.append(f"- Correct detections vs Semgrep: **{imp:+.1f}%** ({ai:.1f} vs {sgm['vulnerability_level']['strict']['tp']} true positives), "
                 f"{'meeting' if imp is not None and imp >= 30 else 'not meeting'} a 30% bar.")
        if only:
            ai_only = only["summary_pre_validation"]["vuln_strict_tp"]["mean"]
            imp_o = improvement_pct(ai_only, sgm["vulnerability_level"]["strict"]["tp"])
            o.append(f"- **Most of that gain comes from combining the LLM with regex hints.** The LLM alone, without hints, "
                     f"found {ai_only:.1f} true positives: {imp_o:+.1f}% vs Semgrep.")
        if hm:
            imp_h = improvement_pct(ai, hm["vulnerability_level"]["strict"]["tp"])
            o.append(f"- Vs the regex hotspots alone: {imp_h:+.1f}% true positives, but the regexes alone have the best F1 "
                     f"({hm['vulnerability_level']['strict']['f1']:.3f}) and far fewer false positives "
                     f"({hm['vulnerability_level']['strict']['fp']}); this ablation is likely optimistic because the same "
                     "author wrote the regexes and the benchmark.")
        pre, post = full["summary_pre_validation"], full["summary_post_validation"]
        o.append(f"- Precision: LLM {pre['vuln_strict_precision']['mean']:.3f} vs Semgrep "
                 f"{sgm['vulnerability_level']['strict']['precision']:.3f}; F1 {pre['vuln_strict_f1']['mean']:.3f} vs "
                 f"{sgm['vulnerability_level']['strict']['f1']:.3f}.")
        fp_files = pre["file_fp"]["mean"]
        n_secure = res["dataset"]["secure_files"]
        o.append(f"- **Main weakness, false alarms on secure code:** the LLM scanner flagged {fp_files:.1f} of {n_secure} secure "
                 f"files on average (file-level FPR {pre['file_fpr']['mean']:.3f}), vs {sgm['file_level']['fp']} of {n_secure} "
                 f"for Semgrep (FPR {sgm['file_level']['false_positive_rate']:.3f}).")
        agg = Counter()
        for r in full["runs"]:
            agg.update(r["validation_effect"])
        o.append(f"- Second-pass validation (same model): precision {pre['vuln_strict_precision']['mean']:.3f} → "
                 f"{post['vuln_strict_precision']['mean']:.3f}, recall {pre['vuln_strict_recall']['mean']:.3f} → "
                 f"{post['vuln_strict_recall']['mean']:.3f}; over {n_runs} runs it disputed {agg['fp_disputed']} false and "
                 f"{agg['tp_disputed']} true positives.")
        tot = Counter()
        for r in full["runs"]:
            tot.update({k: r["response_stats"][k] for k in ("requested", "valid", "schema_invalid", "salvaged", "unparseable", "timeouts")})
        o.append(f"- Model responses ({n_runs} runs): {tot['valid']} valid, {tot['schema_invalid']} schema-invalid, "
                 f"{tot['salvaged']} salvaged from truncation, {tot['unparseable']} unparseable, {tot['timeouts']} timeouts "
                 f"of {tot['requested']} requests.")
        o.append("- **Manual review: not performed yet**, so the claim \"30% more than manual review\" is **untested**. "
                 "Semgrep is static analysis, not manual review. See "
                 "[`30_percent_validation.md`](benchmarks/results/30_percent_validation.md)." if not manual else
                 f"- Vs blinded manual review: {improvement_pct(ai, manual['metrics']['vulnerability_level']['strict']['tp']):+.1f}% true positives.")
    sections = {"RESULTS": "\n".join(o)}

    lim = [
        "- **Small, synthetic, self-authored benchmark.** 58 short files written during the same AI-assisted "
        "development process as the scanner prompts and regexes. That favours the scanner and is far easier than real code. "
        "Treat the numbers as a sanity check, not a published evaluation.",
        "- **False positives** are counted strictly: wrong category at the right line, findings without a line, and real but "
        "unlabeled weaknesses (e.g. missing CSRF protection) all count. The location-only recall row shows how much depends "
        "on naming the right category.",
        "- **The validator is the same model**, so its agreement is not independent confirmation; findings are marked `llm_agrees`, "
        "never `confirmed`.",
        "- **Small-model failure modes seen:** wrong CWE numbers (corrected from titles), invented line numbers (corrected from "
        "snippets or dropped), and degenerate repetition loops in JSON output on some C code (counted as unparseable).",
        "- **Run-to-run variation:** no fixed seed, so results vary between runs; the tables report the spread.",
        "- **Prompt injection** is mitigated (fenced input, warnings), not solved; see the injection table in the full report.",
        "- **One model on one machine.** No OWASP Benchmark / Juliet comparison yet.",
    ]
    sections["LIMITATIONS"] = "\n".join(lim)

    fut = [
        "- Re-run the unchanged benchmark with larger local code models (`qwen2.5-coder:7b/14b/32b` fit in 128 GB unified memory).",
        "- Ollama structured outputs (JSON-schema `format`) to eliminate schema-invalid and runaway responses.",
        "- Hybrid mode: LLM triage of Semgrep findings, measured as a separate system.",
        "- Held-out benchmark split plus OWASP Benchmark / Juliet adapters with a provenance manifest.",
        "- Complete the blinded manual review to test the manual-review comparison.",
        "- Explore NPU offload (AMD Ryzen AI software / ONNX Runtime) as an alternative to iGPU inference.",
    ]
    sections["FUTURE"] = "\n".join(fut)
    return sections


def update_readme(readme: Path, res: dict, manual: Optional[dict], extra: Optional[dict[str, str]] = None) -> None:
    import re as _re

    text = readme.read_text()
    secs = {**readme_sections(res, manual), **(extra or {})}
    for key, body in secs.items():
        pat = _re.compile(rf"(<!-- {key}:START -->\n).*?(\n<!-- {key}:END -->)", _re.S)
        if pat.search(text):
            text = pat.sub(lambda m, b=body: m.group(1) + b + m.group(2), text)
    readme.write_text(text)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = Path(args[0]) if args else RESULTS_DIR / "benchmark_results.json"
    for p in render_all(path):
        print(f"Wrote {p}")
    if "--readme" in sys.argv:
        update_readme(RESULTS_DIR.parent.parent / "README.md", json.loads(path.read_text()), load_manual())
        print("Updated README.md result sections")
