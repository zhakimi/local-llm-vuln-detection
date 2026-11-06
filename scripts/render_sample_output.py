"""Run the real CLI on sample_targets and save its terminal output.

Writes docs/sample_scan.svg (a rendered screenshot of the actual run) and
docs/sample_scan.txt, then inserts an excerpt into README.md between the
SAMPLE_OUTPUT markers. Requires a running local Ollama server.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402

from scanner import cli  # noqa: E402


def main() -> int:
    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    rec = Console(record=True, width=118, force_terminal=True, color_system="truecolor")
    cli.console = rec
    out = ROOT / "reports" / "sample_findings.json"
    code = cli.main(["scan", str(ROOT / "sample_targets"), "-o", str(out)])
    text = rec.export_text(clear=False)
    rec.save_svg(str(docs / "sample_scan.svg"), title="python -m scanner scan ./sample_targets")
    svg = docs / "sample_scan.svg"
    svg.write_text(svg.read_text().replace(str(ROOT) + "/", ""))  # no absolute home paths in published files
    # Make paths relative for the published copy
    text = text.replace(str(ROOT) + "/", "")
    (docs / "sample_scan.txt").write_text(text)

    lines = text.splitlines()
    # keep the header, the first table rows and the summary
    head = lines[:28]
    tail = [ln for ln in lines if "Summary" in ln or "CRITICAL:" in ln or "Completed" in ln or "Saved" in ln]
    excerpt = "\n".join(head + ["  …"] + tail)
    readme = ROOT / "README.md"
    body = (
        "Real output of `python -m scanner scan ./sample_targets` (llama3.2 on the Radeon 8060S). Full run: "
        "[`docs/sample_scan.txt`](docs/sample_scan.txt); rendered screenshot:\n\n"
        "![scan screenshot](docs/sample_scan.svg)\n\n```text\n" + excerpt + "\n```"
    )
    t = readme.read_text()
    t = re.sub(r"(<!-- SAMPLE_OUTPUT:START -->\n).*?(\n<!-- SAMPLE_OUTPUT:END -->)",
               lambda m: m.group(1) + body + m.group(2), t, flags=re.S)
    readme.write_text(t)
    print(f"exit={code}; wrote docs/sample_scan.svg, docs/sample_scan.txt; updated README")
    return 0


if __name__ == "__main__":
    sys.exit(main())
