# Does the AI scanner detect ≥30% more vulnerabilities? — validation of a résumé claim

**Claim under test:** *"the scanner caught roughly 30% more issues than manual review alone on the same codebases."*

**Formula:** Improvement (%) = ((AI true positives − baseline true positives) / baseline true positives) × 100, using **strict vulnerability-level true positives** on the same labeled benchmark (39 vulnerabilities in 58 synthetic files).

**AI system:** the default scanner configuration (`llm_full`: whole-file + hotspot passes + validation), 3 runs, local `llama3.2` on the Radeon iGPU. The pre-validation output (what the CLI reports) is the primary number; post-validation is shown too.

## Comparison

| Metric | Static analysis (Semgrep `p/default`) | Manual review | AI scanner (pre-validation) | AI scanner (post-validation) |
|---|---|---|---|---|
| True positives | 24 | **pending** | 33.0 ± 0.0 (33–33) | 32.7 ± 0.6 (32–33) |
| False positives | 31 | **pending** | 38.0 ± 1.0 (37–39) | 36.3 ± 1.2 (35–37) |
| False negatives | 15 | **pending** | 6.0 ± 0.0 (6–6) | 6.3 ± 0.6 (6–7) |
| Precision | 0.436 | **pending** | 0.465 ± 0.007 (0.458–0.471) | 0.473 ± 0.011 (0.464–0.485) |
| Recall | 0.615 | **pending** | 0.846 ± 0.000 (0.846–0.846) | 0.838 ± 0.015 (0.821–0.846) |
| F1 | 0.511 | **pending** | 0.600 ± 0.005 (0.595–0.606) | 0.605 ± 0.012 (0.593–0.617) |
| Review / execution time | 1.9 s | **pending** | 419 s (mean) | same run |

## Improvement

| Comparison | AI TP (mean) | Baseline TP | Improvement | Per-run range | ≥30%? |
|---|---|---|---|---|---|
| AI vs static analysis (Semgrep) | 33.0 | 24 | +37.5% | +37.5% to +37.5% | **yes** |
| AI vs manual review | — | pending | **not measurable yet** | — | **unknown** |

Ablation (not a traditional tool): the scanner's own regex hotspots alone found 31 TP; AI vs regex-only = +6.5%.

## Verdict

- **vs static analysis (Semgrep):** the AI scanner found +37.5% more correctly located and categorized vulnerabilities on this benchmark — **at least 30%: yes** (on this synthetic dataset only).
- **vs manual review:** **not yet tested.** The résumé claim compares against *manual review*, which has not been performed. Semgrep is a static-analysis tool, not manual review, so the Semgrep comparison cannot be cited as evidence for the manual-review claim.
- **Caveat:** the +37.5% depends on the scanner's regex hotspot hints. The LLM alone (no hints) found 26.0 TP = +8.3% vs Semgrep, below 30%. The AI scanner also raised more false positives (38.0 vs 31) and flagged 22.0 of 23 secure files.

**What the original claim can and cannot say:** the claim refers to "the same codebases" and "manual review". Neither the original codebases nor a recorded manual review exist in this repository, so the original wording is not supported by evidence here. Only claims backed by the numbers above should be used.

## Manual-review protocol (to complete the comparison)

1. Export a blinded packet **outside the repo** (it contains only the code files, renamed copies are not needed — names are already opaque):

   ```bash
   python -m benchmarks.manual_review export --out ~/manual-review-packet
   ```

2. Before reviewing, do **not** open `benchmarks/manifest.json`, `benchmarks/build_cases.py`, `benchmarks/results/`, the README benchmark section, or any scanner output for `benchmarks/cases`.
3. Review each file in the packet, fill in `worksheet.csv` (one row per file; list `line:category` pairs) and record start/end times in `timing.csv`. No tools other than a text editor; no AI assistance.
4. Score it with the same matcher:

   ```bash
   python -m benchmarks.manual_review score ~/manual-review-packet
   python -m benchmarks.report
   ```

This file is then regenerated with the manual column filled in. Results are only as good as the blinding: if the reviewer has seen labels or AI findings, say so when reporting.

