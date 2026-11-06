"""Non-LLM baselines.

* ``semgrep``: Semgrep OSS with the registry ruleset ``p/default`` (rules are
  downloaded from semgrep.dev at run time; scanning itself is local, and
  ``--metrics=off`` disables telemetry). The ruleset was fixed before any
  results were seen and is not tuned to this benchmark.
* ``heuristic``: the scanner's own hotspot regexes used standalone (one
  prediction per matching line and pattern). This is an ablation showing what
  the LLM adds on top of its own hints. Caveat: the regexes and the benchmark
  were written by the same author, so this baseline may be optimistic.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from scanner.analyzer import CODE_HOTSPOTS, HOTSPOT_CWE, find_hotspots

from .matching import category_of

SEMGREP_CONFIG = "p/default"


def semgrep_binary() -> Optional[str]:
    venv = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "semgrep"
    return str(venv) if venv.exists() else shutil.which("semgrep")


def run_semgrep(cases: list[dict], bench_dir: Path, config: str = SEMGREP_CONFIG) -> dict:
    exe = semgrep_binary()
    if not exe:
        return {"available": False, "error": "semgrep not installed (pip install semgrep)"}
    version = subprocess.run([exe, "--version"], capture_output=True, text=True).stdout.strip()
    files = [str(bench_dir / c["file"]) for c in cases]
    started = time.perf_counter()
    proc = subprocess.run(
        [exe, "scan", "--config", config, "--json", "--metrics=off", "--disable-version-check",
         "--quiet", "--no-git-ignore", *files],
        capture_output=True, text=True,
    )
    elapsed = time.perf_counter() - started
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"available": False, "error": f"semgrep failed (exit {proc.returncode}): {proc.stderr[-500:]}"}

    by_path = {str((bench_dir / c["file"]).resolve()): c["case_id"] for c in cases}
    preds: dict[str, list[dict]] = {c["case_id"]: [] for c in cases}
    for r in data.get("results", []):
        cid = by_path.get(str(Path(r["path"]).resolve()))
        if not cid:
            continue
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe") or []
        cwes = [cwes] if isinstance(cwes, str) else cwes
        cats = [category_of(c) for c in cwes]
        cat = next((c for c in cats if c != "other"), "other")
        preds[cid].append({
            "line": r["start"]["line"],
            "cwe": cwes[0].split(":")[0] if cwes else "",
            "category": cat,
            "title": r.get("check_id", ""),
            "severity": r.get("extra", {}).get("severity", "").lower(),
        })
    return {
        "available": True,
        "tool": "semgrep",
        "version": version,
        "config": config,
        "seconds": elapsed,
        "errors": [e.get("message", "")[:200] for e in data.get("errors", [])][:20],
        "predictions": preds,
    }


def run_heuristic(cases: list[dict], bench_dir: Path) -> dict:
    started = time.perf_counter()
    preds: dict[str, list[dict]] = {}
    for c in cases:
        lines = (bench_dir / c["file"]).read_text(encoding="utf-8").splitlines()
        out = []
        for line, names in find_hotspots(lines, CODE_HOTSPOTS).items():
            for name in names:
                cwe = HOTSPOT_CWE[name]
                out.append({"line": line, "cwe": cwe, "category": category_of(cwe), "title": name})
        preds[c["case_id"]] = out
    return {"available": True, "tool": "heuristic-regex", "seconds": time.perf_counter() - started, "predictions": preds}
