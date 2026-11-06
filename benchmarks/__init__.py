"""Reproducible benchmark for amd-vuln-scanner (synthetic, labeled cases)."""

import json
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BENCH_DIR / "results"


def load_manifest() -> dict:
    return json.loads((BENCH_DIR / "manifest.json").read_text(encoding="utf-8"))
