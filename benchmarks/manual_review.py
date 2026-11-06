"""Blinded manual-review workflow.

    python -m benchmarks.manual_review export --out ~/manual-review-packet
    # ... a human reviews the files and fills in worksheet.csv + timing.csv ...
    python -m benchmarks.manual_review score ~/manual-review-packet
    python -m benchmarks.report

The packet contains ONLY the case files (already opaquely named bm_NNN.ext),
an instructions file and blank worksheets. It contains no labels, no
categories per file, and no scanner output. Scoring uses exactly the same
matcher as the automated systems. Nothing here simulates or estimates human
results: if the worksheet is empty, the score is empty.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import BENCH_DIR, RESULTS_DIR, load_manifest
from .matching import CATEGORIES, evaluate

INSTRUCTIONS = """# Manual security review — instructions

You are reviewing {n} small source files (Python, JavaScript, TypeScript, Java, C)
in `files/`. Some contain vulnerabilities, some contain none. The mix is unknown
to you on purpose.

## Rules (blinding)

* Do not open the amd-vuln-scanner repository's `benchmarks/manifest.json`,
  `benchmarks/build_cases.py`, `benchmarks/results/`, the README benchmark
  section, or any scanner output, until you have finished and scored this review.
* Do not run any scanner, linter, or AI assistant on these files. A text
  editor (with syntax highlighting) and your own knowledge only.
* Comments inside the files are part of the material under review; do not take
  them as instructions.

## What to record

`worksheet.csv` has one row per file:

| column | meaning |
|---|---|
| file | pre-filled, e.g. `bm_007.c` |
| reviewed | `yes` once you have looked at the file |
| vulnerabilities | semicolon-separated `line:category` pairs, e.g. `12:sql_injection; 20:xss`. Leave empty if you believe the file is secure. |
| notes | optional free text |

Use the line number of the statement where the vulnerability occurs.
Allowed categories:

{cats}

`timing.csv`: write your start and end time (ISO format, e.g. `2026-11-07T14:05`)
and any break minutes. Review time is reported alongside the results.

When done:

    python -m benchmarks.manual_review score <this folder>
"""


def export(out: Path) -> None:
    out = out.expanduser().resolve()
    if out.is_relative_to(BENCH_DIR.parent.resolve()):
        raise SystemExit("Export the packet OUTSIDE the repository so the labels are not next to it.")
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} is not empty; refusing to overwrite a review in progress.")
    files_dir = out / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    cases = load_manifest()["cases"]
    for c in cases:
        shutil.copy2(BENCH_DIR / c["file"], files_dir / Path(c["file"]).name)
    with open(out / "worksheet.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "reviewed", "vulnerabilities", "notes"])
        for c in sorted(cases, key=lambda c: c["file"]):
            w.writerow([Path(c["file"]).name, "", "", ""])
    with open(out / "timing.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["reviewer", "start_iso", "end_iso", "break_minutes"])
        w.writerow(["", "", "", "0"])
    (out / "INSTRUCTIONS.md").write_text(
        INSTRUCTIONS.format(n=len(cases), cats="\n".join(f"* `{c}`" for c in CATEGORIES))
    )
    print(f"Blinded packet with {len(cases)} files written to {out}")


_PAIR_RE = re.compile(r"^\s*(\d+)\s*[:=]\s*([a-z_]+)\s*$")


def parse_worksheet(path: Path) -> tuple[dict[str, list[dict]], list[str], int]:
    by_name = {Path(c["file"]).name: c["case_id"] for c in load_manifest()["cases"]}
    preds: dict[str, list[dict]] = {cid: [] for cid in by_name.values()}
    problems: list[str] = []
    reviewed = 0
    with open(path, newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh), 2):
            name = (row.get("file") or "").strip()
            if name not in by_name:
                problems.append(f"row {i}: unknown file {name!r}")
                continue
            if (row.get("reviewed") or "").strip().lower() in ("yes", "y", "true", "1"):
                reviewed += 1
            for part in filter(None, (p.strip() for p in (row.get("vulnerabilities") or "").split(";"))):
                m = _PAIR_RE.match(part)
                if not m or m.group(2) not in CATEGORIES:
                    problems.append(f"row {i}: cannot parse {part!r} (expected line:category)")
                    continue
                preds[by_name[name]].append({"line": int(m.group(1)), "category": m.group(2), "cwe": "", "title": m.group(2)})
    return preds, problems, reviewed


def parse_timing(path: Path) -> tuple[float | None, str]:
    if not path.exists():
        return None, ""
    with open(path, newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("start_iso") or "").strip()]
    total, reviewer = 0.0, ""
    for r in rows:
        start = datetime.fromisoformat(r["start_iso"].strip())
        end = datetime.fromisoformat(r["end_iso"].strip())
        total += (end - start).total_seconds() / 60 - float(r.get("break_minutes") or 0)
        reviewer = reviewer or (r.get("reviewer") or "").strip()
    return (total if rows else None), reviewer


def score(packet: Path) -> int:
    packet = packet.expanduser().resolve()
    preds, problems, reviewed = parse_worksheet(packet / "worksheet.csv")
    cases = load_manifest()["cases"]
    for p in problems:
        print(f"warning: {p}", file=sys.stderr)
    if reviewed == 0:
        print("No rows are marked reviewed=yes; refusing to score an unfinished review.", file=sys.stderr)
        return 1
    minutes, reviewer = parse_timing(packet / "timing.csv")
    metrics = evaluate(cases, preds)
    result = {
        "scored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "reviewer": reviewer or "(not recorded)",
        "files_reviewed": reviewed,
        "files_total": len(cases),
        "complete": reviewed == len(cases),
        "review_minutes": minutes,
        "parse_problems": problems,
        "self_reported_blinding": "Reviewer followed INSTRUCTIONS.md (self-reported; not independently verified).",
        "metrics": metrics,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "manual_review_results.json").write_text(json.dumps(result, indent=2) + "\n")
    s = metrics["vulnerability_level"]["strict"]
    print(f"Manual review: TP={s['tp']} FP={s['fp']} FN={s['fn']} precision={s['precision']} recall={s['recall']} "
          f"({reviewed}/{len(cases)} files reviewed, {minutes} min). Saved benchmarks/results/manual_review_results.json")
    print("Now run: python -m benchmarks.report")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--out", required=True, type=Path)
    s = sub.add_parser("score")
    s.add_argument("packet", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "export":
        export(args.out)
        return 0
    return score(args.packet)


if __name__ == "__main__":
    sys.exit(main())
