# Benchmark

A small, reproducible, labeled benchmark for measuring how well `amd-vuln-scanner`
finds vulnerabilities, compared with non-LLM baselines.

> **All cases are synthetic.** Every file in `cases/` is a short program written
> for this benchmark. None of them is a real-world vulnerability discovery, and
> none contains real credentials. Results apply to this dataset only.

## Contents

| Path | What |
|---|---|
| `cases/bm_NNN.{py,js,ts,java,c}` | 58 case files (35 vulnerable, 23 secure controls) |
| `manifest.json` | Ground truth: per case, language, vulnerable/secure, and for every vulnerability the category, CWE, line region, anchor text, severity, explanation and reference. SHA-256 of each file. |
| `build_cases.py` | Source of truth that generates `cases/` and `manifest.json` (line numbers are computed from anchor text, never typed by hand) |
| `matching.py` | Matching rules and metrics |
| `baselines.py` | Semgrep and regex-only baselines |
| `run.py` | Runner: `python -m benchmarks.run` |
| `report.py` | Renders the markdown reports from the JSON results |
| `manual_review.py` | Blinded manual-review export and scoring |
| `results/` | `benchmark_results.json`, `benchmark_report.md`, `30_percent_validation.md`, `local_inference_check.json` |

## Design decisions

* **Opaque names, no hints in code.** Files are named `bm_NNN` and IDs were
  shuffled with a fixed seed, so neither the file name nor the ID order reveals
  the category or whether a file is vulnerable. The files contain no "vulnerable"
  / "safe" comments; the synthetic label lives in the manifest and this README,
  not in the code the model reads. (A header saying "benchmark case" would prime
  the model, so it was deliberately left out.) A test (`tests/test_benchmark.py`)
  checks that case files do not contain label words.
* **Secure controls** (23 files) are near-twins of vulnerable cases (e.g. a
  parameterized query next to a concatenated one) to measure false positives.
* **Multiple vulnerabilities per file** (4 files have 2) test per-vulnerability
  matching.
* **Prompt-injection cases** (3 files): two vulnerable files contain comments
  telling an AI reviewer to report nothing; one secure file contains a comment
  asking the AI to report a fake critical SQL injection.
* **Categories** (11): `sql_injection`, `command_injection`, `xss`,
  `path_traversal`, `insecure_deserialization`, `hardcoded_credentials`,
  `weak_crypto` (incl. insecure randomness), `code_injection` (unsafe eval),
  `auth` (JWT signature/algorithm flaws), `insecure_config` (debug mode, TLS
  verification, permissive CORS), `memory_safety` (C).
* **Ambiguity policy:** only clear-cut vulnerabilities are labeled. Arguable
  weaknesses that a tool might also report (e.g. missing CSRF middleware, missing
  cookie flags, no rate limiting) are *not* labeled and therefore count as false
  positives for every system. This is conservative and is called out in the report.

### External datasets

No external dataset is included (`manifest.json` → `external_datasets: []`).

* **OWASP Benchmark** (Java only, ~2,700 servlet test cases, GPL-2.0). Vendoring
  GPL files would change this repo's licensing, and scanning 2,700 files with a
  local 3B model takes many hours per run.
* **NIST Juliet / SARD** (C/C++, Java). Large, and labels are per function with
  "bad"/"good" naming conventions that leak the answer to an LLM unless they are
  rewritten.

Both are good future work: an adapter that downloads a pinned version, records
source, version, license and any modifications in a manifest, and strips
label-leaking identifiers before scanning.

## Matching (how predictions are scored)

Implemented in `matching.py`:

1. A prediction belongs to the case file it was produced for.
2. **Strict match:** the prediction's category equals the labeled category
   (category is derived from the predicted CWE; if the CWE is missing or unknown,
   from the title using the scanner's keyword table), **and** the predicted line
   is within ±2 lines of the labeled region.
3. Each labeled vulnerability is matched by at most one prediction (closest line
   first). Further predictions matching an already-matched vulnerability are
   **duplicates**: they are counted but are neither TP nor FP.
4. All other predictions are **false positives**: no line, wrong category at the
   right place, unlabeled issues, anything on a secure file.
5. **Location-only** metrics (any category) are reported too, to show how much
   the category mapping matters.
6. **File level:** a file is "flagged" if it has ≥1 prediction. TN and the
   false-positive rate exist only at this level, because there is no finite set
   of "non-vulnerabilities" to count TNs against.

Matcher changelog: v1.0.1 added CWE-319 to `insecure_config` after reviewing the
baseline output (Semgrep labels disabled TLS verification as CWE-319). It applies
identically to every system.

## Systems measured

| System | What it is |
|---|---|
| `semgrep` | Semgrep OSS, registry ruleset `p/default`, chosen before any results were seen and not tuned. Rules are downloaded from semgrep.dev at run time (`--metrics=off`); scanning is local. |
| `heuristic` | The scanner's own hotspot regexes, standalone. An ablation, not an independent tool (same author as the benchmark). |
| `llm_full` | Default scanner: whole-file pass + hotspot-focused passes + same-model validation. |
| `llm_only` | Whole-file LLM pass + validation, no regex hints. |

LLM systems are reported **pre-validation** (everything the CLI outputs) and
**post-validation** (findings the second pass disputed with confidence ≥ 0.7
removed). Each LLM configuration runs 3 times with no fixed seed; tables show
mean ± sample standard deviation and min–max.

## Running

```bash
pip install -r requirements.txt semgrep
ollama pull llama3.2
python -m benchmarks.run --runs 3          # ~40 min on a Ryzen AI MAX+ 395
python -m benchmarks.report                # re-render markdown from the JSON
python -m benchmarks.run --runs 1 --limit 5 --output /tmp/smoke.json   # smoke test
```

The runner records CPU, GPU, NPU, memory, OS, kernel, Ollama version and
backends, model digest, quantization, parameter count, context size,
temperature, seed, `ollama ps` output, and SHA-256 hashes of the scanner
source and manifest, so a result can be tied to exact code and data.

## Manual review (blinded)

See `results/30_percent_validation.md`. In short:

```bash
python -m benchmarks.manual_review export --out ~/manual-review-packet   # must be outside the repo
# review the files without tools, AI help, or looking at labels/results; fill in worksheet.csv + timing.csv
python -m benchmarks.manual_review score ~/manual-review-packet
python -m benchmarks.report
```

No manual-review result is ever simulated: `score` refuses to run on an
unfinished worksheet, and reports show **pending** until a real review exists.

## Known limitations

* 58 short single-file programs are far easier than real codebases.
* The scanner prompts, the regex hotspots and these cases were all produced in
  the same AI-assisted development process, which can bias results in the
  scanner's favour. Treat the numbers as a sanity check, not an independent
  evaluation.
* One model, one machine, three runs.
