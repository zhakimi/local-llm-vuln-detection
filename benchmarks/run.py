"""Benchmark runner:  python -m benchmarks.run [--runs 3]

Scans every labeled case with the local Ollama scanner (several configurations,
several runs each), runs the non-LLM baselines, scores everything with
benchmarks.matching, and writes:

  benchmarks/results/benchmark_results.json   (machine-readable, per-run detail)
  benchmarks/results/benchmark_report.md      (rendered by benchmarks.report)
  benchmarks/results/30_percent_validation.md (rendered by benchmarks.report)
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner import __version__
from scanner.analyzer import (
    DEFAULT_MODEL,
    DEFAULT_NUM_CTX,
    DEFAULT_NUM_PREDICT,
    DEFAULT_TEMPERATURE,
    DISPUTE_CONFIDENCE,
    Analyzer,
    OllamaClient,
    OllamaError,
)

from . import BENCH_DIR, RESULTS_DIR, load_manifest
from .baselines import run_heuristic, run_semgrep
from .matching import LINE_TOLERANCE, evaluate, summarize

CONFIGS = {
    "llm_full": {"hotspots": True, "validate": True,
                 "description": "Default scanner: whole-file pass + hotspot-focused passes + second-pass validation"},
    "llm_only": {"hotspots": False, "validate": True,
                 "description": "Whole-file LLM pass + validation, no regex hotspot hints (pure-LLM ablation)"},
}


def _sh(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def capture_environment(client: OllamaClient) -> dict:
    cpu = next((ln.split(":", 1)[1].strip() for ln in _sh(["lscpu"]).splitlines() if ln.startswith("Model name")), platform.processor())
    mem_kb = next((int(ln.split()[1]) for ln in Path("/proc/meminfo").read_text().splitlines() if ln.startswith("MemTotal")), 0) \
        if Path("/proc/meminfo").exists() else 0
    gpu = [ln.split(": ", 1)[-1] for ln in _sh(["lspci"]).splitlines() if any(k in ln for k in ("VGA", "Display", "3D"))]
    npu = [ln.split(": ", 1)[-1] for ln in _sh(["lspci"]).splitlines() if "Neural Processing" in ln]
    os_name = next((ln.split("=", 1)[1].strip('"') for ln in Path("/etc/os-release").read_text().splitlines()
                    if ln.startswith("PRETTY_NAME=")), platform.platform()) if Path("/etc/os-release").exists() else platform.platform()
    backends = sorted(p.name for p in Path("/usr/local/lib/ollama").iterdir() if p.is_dir()) if Path("/usr/local/lib/ollama").is_dir() else []
    return {
        "cpu": cpu,
        "memory_gib": round(mem_kb / 1024 / 1024, 1),
        "gpu": gpu,
        "npu": npu,
        "os": os_name,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "ollama_backends_installed": backends,
        "model": client.model_info(),
    }


def _ollama_ps() -> str:
    return _sh(["ollama", "ps"])


def run_llm(cases: list[dict], config: str, run_index: int, args: argparse.Namespace) -> dict:
    cfg = CONFIGS[config]
    client = OllamaClient(model=args.model, temperature=args.temperature, num_ctx=args.num_ctx,
                          seed=args.seed, timeout=args.timeout)
    client.ensure_ready()
    analyzer = Analyzer(client, validate=cfg["validate"], hotspots=cfg["hotspots"])
    preds_pre: dict[str, list[dict]] = {}
    preds_post: dict[str, list[dict]] = {}
    raw: dict[str, list[dict]] = {}
    file_seconds: dict[str, float] = {}
    started = time.perf_counter()
    for i, case in enumerate(cases, 1):
        path = BENCH_DIR / case["file"]
        t0 = time.perf_counter()
        try:
            findings = analyzer.scan_code_file(path)
        except OllamaError as exc:
            if "not running" in str(exc):
                raise
            analyzer.errors.append(f"{case['case_id']}: {exc}")
            findings = []
        file_seconds[case["case_id"]] = round(time.perf_counter() - t0, 3)
        slim = [{
            "line": f.get("line"), "cwe": f.get("cwe"), "title": f.get("title"), "severity": f.get("severity"),
            "status": f.get("status"), "detected_by": f.get("detected_by_all") or [f.get("detected_by")],
            "validation_confidence": (f.get("validation") or {}).get("confidence"),
        } for f in findings]
        raw[case["case_id"]] = slim
        preds_pre[case["case_id"]] = slim
        preds_post[case["case_id"]] = [p for p in slim if p["status"] != "disputed"]
        print(f"  [{config} run {run_index}] {i:>2}/{len(cases)} {case['file']:<18} {len(slim)} finding(s) "
              f"{file_seconds[case['case_id']]:.1f}s", flush=True)
    total = time.perf_counter() - started
    ps = _ollama_ps()
    return {
        "config": config,
        "run": run_index,
        "wall_seconds": round(total, 2),
        "inference_seconds": round(client.stats.inference_seconds, 2),
        "avg_seconds_per_file": round(total / len(cases), 3),
        "file_seconds": file_seconds,
        "client_stats": vars(client.stats),
        "response_stats": analyzer.stats.to_dict(),
        "errors": analyzer.errors[:50],
        "warnings": analyzer.warnings,
        "ollama_ps_after_run": ps,
        "predictions": raw,
        "metrics_pre_validation": evaluate(cases, preds_pre),
        "metrics_post_validation": evaluate(cases, preds_post),
        "validation_effect": validation_effect(cases, preds_pre),
    }


def validation_effect(cases: list[dict], preds: dict[str, list[dict]]) -> dict:
    """How did the same-model second pass treat true vs false positives?"""
    pre = evaluate(cases, preds)
    counts = {"tp_validated": 0, "tp_disputed": 0, "fp_validated": 0, "fp_disputed": 0,
              "tp_needs_review": 0, "fp_needs_review": 0}
    for pc in pre["per_case"].values():
        for p in pc["strict"]["predictions"]:
            if p.get("status") in (None, "unvalidated"):
                continue
            kind = "tp" if p["result"] == "tp" else ("fp" if p["result"] == "fp" else None)
            if not kind:
                continue
            counts[f"{kind}_validated"] += 1
            if p["status"] == "disputed":
                counts[f"{kind}_disputed"] += 1
            elif p["status"] == "needs_review":
                counts[f"{kind}_needs_review"] += 1
    return counts


def metric_summary(runs: list[dict], key: str) -> dict:
    def pick(path: list[str]):
        out = []
        for r in runs:
            v: Any = r[key]
            for p in path:
                v = v.get(p) if isinstance(v, dict) else None
            out.append(v)
        return summarize(out)

    fields = {
        "vuln_strict_tp": ["vulnerability_level", "strict", "tp"],
        "vuln_strict_fp": ["vulnerability_level", "strict", "fp"],
        "vuln_strict_fn": ["vulnerability_level", "strict", "fn"],
        "vuln_strict_precision": ["vulnerability_level", "strict", "precision"],
        "vuln_strict_recall": ["vulnerability_level", "strict", "recall"],
        "vuln_strict_f1": ["vulnerability_level", "strict", "f1"],
        "vuln_strict_duplicates": ["vulnerability_level", "strict", "duplicates"],
        "vuln_location_tp": ["vulnerability_level", "location", "tp"],
        "vuln_location_recall": ["vulnerability_level", "location", "recall"],
        "vuln_location_precision": ["vulnerability_level", "location", "precision"],
        "file_tp": ["file_level", "tp"],
        "file_fp": ["file_level", "fp"],
        "file_tn": ["file_level", "tn"],
        "file_fn": ["file_level", "fn"],
        "file_precision": ["file_level", "precision"],
        "file_recall": ["file_level", "recall"],
        "file_f1": ["file_level", "f1"],
        "file_fpr": ["file_level", "false_positive_rate"],
        "findings_on_secure_files": ["findings_on_secure_files"],
    }
    return {name: pick(path) for name, path in fields.items()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=3, help="Runs per LLM configuration (default 3)")
    ap.add_argument("--configs", default="llm_full,llm_only", help="Comma-separated LLM configs")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    ap.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX)
    ap.add_argument("--seed", type=int, default=None, help="Fixed seed (default: none, so runs vary)")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--limit", type=int, help="Only the first N cases (smoke test; not a valid benchmark)")
    ap.add_argument("--no-semgrep", action="store_true")
    ap.add_argument("--output", default=str(RESULTS_DIR / "benchmark_results.json"))
    ap.add_argument("--resume", action="store_true", help="Reuse completed runs from an interrupted invocation")
    args = ap.parse_args(argv)

    manifest = load_manifest()
    cases = manifest["cases"][: args.limit] if args.limit else manifest["cases"]
    client = OllamaClient(model=args.model, temperature=args.temperature, num_ctx=args.num_ctx, seed=args.seed)
    try:
        client.ensure_ready()
    except OllamaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    env = capture_environment(client)
    print(f"Benchmark: {len(cases)} cases, model {client.model} ({env['model'].get('quantization')}, "
          f"digest {str(env['model'].get('digest'))[:12]}), {args.runs} run(s) per config", flush=True)

    results: dict[str, Any] = {
        "tool_version": __version__,
        "benchmark_version": manifest["version"],
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "partial": bool(args.limit),
        "environment": env,
        "settings": {
            "temperature": args.temperature, "num_ctx": args.num_ctx, "num_predict": DEFAULT_NUM_PREDICT,
            "seed": args.seed, "format": "json", "dispute_confidence_threshold": DISPUTE_CONFIDENCE,
            "line_tolerance": LINE_TOLERANCE, "runs_per_config": args.runs,
            "other_sampling_params": "Ollama/model defaults (not overridden)",
        },
        "dataset": {
            "cases": len(cases),
            "vulnerable_files": sum(c["ground_truth"] == "vulnerable" for c in cases),
            "secure_files": sum(c["ground_truth"] == "secure" for c in cases),
            "labeled_vulnerabilities": sum(len(c["vulnerabilities"]) for c in cases),
            "prompt_injection_cases": sum("prompt_injection" in c["tags"] for c in cases),
        },
        "case_ids": [c["case_id"] for c in cases],
        "scanner_source_sha256": {
            f.name: __import__("hashlib").sha256(f.read_bytes()).hexdigest()
            for f in sorted((BENCH_DIR.parent / "scanner").glob("*.py"))
        },
        "manifest_sha256": __import__("hashlib").sha256((BENCH_DIR / "manifest.json").read_bytes()).hexdigest(),
        "systems": {},
    }

    for name, fn in (("semgrep", run_semgrep), ("heuristic", run_heuristic)):
        if name == "semgrep" and args.no_semgrep:
            continue
        print(f"Baseline: {name}", flush=True)
        b = fn(cases, BENCH_DIR)
        if b.get("available"):
            b["metrics"] = evaluate(cases, b["predictions"])
        results["systems"][name] = b

    # --resume: reuse completed runs from a previous, interrupted invocation, but
    # only if code, data and settings are identical (otherwise runs aren't comparable).
    previous: dict = {}
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        old = json.loads(out_path.read_text())
        same = all(old.get(k) == results[k] for k in ("scanner_source_sha256", "manifest_sha256", "settings", "case_ids"))
        if same:
            previous = {k: v.get("runs", []) for k, v in old.get("systems", {}).items() if "runs" in v}
            results["started_at"] = old.get("started_at", results["started_at"])
            results["resumed"] = True
            print(f"Resuming: {({k: len(v) for k, v in previous.items()})} completed run(s) reused", flush=True)
        else:
            print("Not resuming: code, data or settings differ from the saved results", flush=True)

    def save() -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path.with_suffix(".tmp.json")
        tmp.write_text(json.dumps(results, indent=2, default=str) + "\n")
        tmp.replace(out_path)  # atomic: a killed process never leaves a truncated file

    for config in [c.strip() for c in args.configs.split(",") if c.strip()]:
        runs = list(previous.get(config, []))[: args.runs]
        for i in range(len(runs) + 1, args.runs + 1):
            print(f"LLM config {config}: run {i}/{args.runs}", flush=True)
            runs.append(run_llm(cases, config, i, args))
            results["systems"][config] = {
                "description": CONFIGS[config]["description"],
                "runs": runs,
                "summary_pre_validation": metric_summary(runs, "metrics_pre_validation"),
                "summary_post_validation": metric_summary(runs, "metrics_post_validation"),
                "timing": {
                    "wall_seconds": summarize([r["wall_seconds"] for r in runs]),
                    "avg_seconds_per_file": summarize([r["avg_seconds_per_file"] for r in runs]),
                    "inference_seconds": summarize([r["inference_seconds"] for r in runs]),
                },
            }
            save()  # persist after every run
        if config not in results["systems"]:  # all runs were reused
            results["systems"][config] = {
                "description": CONFIGS[config]["description"], "runs": runs,
                "summary_pre_validation": metric_summary(runs, "metrics_pre_validation"),
                "summary_post_validation": metric_summary(runs, "metrics_post_validation"),
                "timing": {k: summarize([r[k] for r in runs]) for k in ("wall_seconds", "avg_seconds_per_file", "inference_seconds")},
            }
            save()

    results["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save()
    print(f"Wrote {args.output}")

    from .report import render_all

    for p in render_all(Path(args.output)):
        print(f"Wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
