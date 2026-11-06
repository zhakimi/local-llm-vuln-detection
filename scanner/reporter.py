"""Output: findings.json persistence, rich terminal tables and markdown reports."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from .analyzer import SEVERITIES, SEVERITY_RANK
from .schemas import schema_errors

SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
}
STATUS_STYLES = {
    "llm_agrees": "green",
    "confirmed": "green",  # legacy files written before v0.2
    "disputed": "magenta",
    "needs_review": "yellow",
    "unvalidated": "dim",
    "validation_failed": "dim red",
}
SEVERITY_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


# ---------------------------------------------------------------------------
# JSON persistence
# ---------------------------------------------------------------------------


def build_results(
    target: str,
    kind: str,
    model: str,
    findings: list[dict],
    files_scanned: int,
    errors: list[str],
    inference: Optional[dict] = None,
    response_stats: Optional[dict] = None,
    warnings: Optional[list[dict]] = None,
    skipped: Optional[list[dict]] = None,
) -> dict:
    return {
        "tool": "amd-vuln-scanner",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": model,
        "inference": inference or {},
        "scan_type": kind,
        "target": target,
        "files_scanned": files_scanned,
        "summary": severity_counts(findings),
        "findings": findings,
        "warnings": warnings or [],
        "skipped_files": skipped or [],
        "response_stats": response_stats or {},
        "errors": errors,
    }


def save_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load_findings(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):  # bare list of findings
        data = {"findings": data}
    problems = schema_errors("findings_file", data)
    if problems:
        raise ValueError(f"{path} is not a valid findings.json file: " + "; ".join(problems[:3]))
    return data


def merge_results(existing: dict, new: dict) -> dict:
    seen = {f.get("id") for f in existing.get("findings", [])}
    existing["findings"].extend(f for f in new["findings"] if f.get("id") not in seen)
    existing["findings"].sort(key=lambda f: SEVERITY_RANK.get(f.get("severity"), 9))
    existing["summary"] = severity_counts(existing["findings"])
    existing["generated_at"] = new["generated_at"]
    existing["files_scanned"] = existing.get("files_scanned", 0) + new.get("files_scanned", 0)
    existing["target"] = f"{existing.get('target')}, {new.get('target')}"
    existing["scan_type"] = "mixed" if existing.get("scan_type") != new.get("scan_type") else new["scan_type"]
    existing.setdefault("errors", []).extend(new.get("errors", []))
    existing.setdefault("warnings", []).extend(new.get("warnings", []))
    existing.setdefault("skipped_files", []).extend(new.get("skipped_files", []))
    return existing


def severity_counts(findings: list[dict]) -> dict[str, int]:
    c = Counter(f.get("severity", "info") for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------


def sev_markup(sev: str) -> str:
    return f"[{SEVERITY_STYLES.get(sev, '')}] {sev.upper()} [/]"


def print_findings(console: Console, findings: list[dict], title: str = "Findings") -> None:
    if not findings:
        console.print(Panel("[green]No findings.[/]", title=title))
        return
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Location", no_wrap=True)
    table.add_column("CWE", no_wrap=True)
    table.add_column("Issue", ratio=3)
    table.add_column("Status", no_wrap=True)
    for f in findings:
        loc = f"{f.get('file')}:{f.get('line') or '?'}"
        issue = f"[bold]{f.get('title')}[/]"
        if f.get("snippet"):
            issue += f"\n[dim]{_escape(f['snippet'].splitlines()[0][:110])}[/]"
        if f.get("source_ip"):
            issue += f"\n[dim]source: {f['source_ip']} ×{f.get('count', 1)}[/]"
        status = f.get("status", "unvalidated")
        table.add_row(sev_markup(f["severity"]), f.get("id", ""), loc, f.get("cwe") or "-",
                      issue, f"[{STATUS_STYLES.get(status, '')}]{status}[/]")
    console.print(table)


def print_summary(console: Console, findings: list[dict]) -> None:
    counts = severity_counts(findings)
    parts = [f"[{SEVERITY_STYLES[s]}] {s.upper()}: {n} [/]" for s, n in counts.items()]
    console.print(Panel("  ".join(parts), title=f"Summary — {len(findings)} finding(s)"))


def print_tests(console: Console, finding: dict, tests: list[dict]) -> None:
    console.rule(f"{sev_markup(finding['severity'])} {finding['title']}  [dim]{finding.get('file')}:{finding.get('line')}[/]")
    if not tests:
        console.print("[dim]  no test cases generated[/]")
        return
    for t in tests:
        console.print(f"  [bold cyan]{t['name']}[/] [dim]({t['type']})[/] {t['description']}")
        if t["payload"]:
            console.print(f"    [yellow]payload:[/] {_escape(t['payload'][:300])}")
        if t["expected_secure_behavior"]:
            console.print(f"    [green]expected:[/] {t['expected_secure_behavior']}")
        if t["code"]:
            lexer = "python" if "pytest" in t.get("framework", "") else (
                "javascript" if "Jest" in t.get("framework", "") else (
                    "java" if "JUnit" in t.get("framework", "") else (
                        "c" if t.get("framework", "").startswith("C") else "bash")))
            console.print(Syntax(t["code"], lexer, theme="monokai", line_numbers=False, word_wrap=True))


def _escape(s: str) -> str:
    return s.replace("[", r"\[")


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _md(s: Any) -> str:
    return str(s or "").replace("|", r"\|").replace("\n", " ").strip()


def build_markdown_report(data: dict, tests: Optional[dict] = None) -> str:
    findings = sorted(data.get("findings", []), key=lambda f: SEVERITY_RANK.get(f.get("severity"), 9))
    counts = severity_counts(findings)
    tests_by_id = {t["finding_id"]: t["test_cases"] for t in (tests or {}).get("results", [])}
    total = len(findings)
    confirmed = sum(1 for f in findings if f.get("status") in ("llm_agrees", "confirmed"))
    disputed = sum(1 for f in findings if f.get("status") == "disputed")

    out: list[str] = []
    w = out.append
    w("# Security Scan Report\n")
    inf = data.get("inference") or {}
    if inf.get("host_is_loopback"):
        w(f"> Generated by **amd-vuln-scanner**. Analysis ran on a local Ollama server (`{inf.get('host')}`, "
          "loopback only), so the scanner did not send the scanned code or logs off this machine.\n")
    else:
        w("> Generated by **amd-vuln-scanner** via Ollama. The inference host was not recorded as loopback; "
          "do not assume the analysis stayed on-device.\n")
    w("| | |\n|---|---|")
    w(f"| **Target** | `{_md(data.get('target'))}` |")
    w(f"| **Scan type** | {_md(data.get('scan_type'))} |")
    w(f"| **Model** | `{_md(data.get('model'))}` |")
    w(f"| **Generated** | {_md(data.get('generated_at'))} |")
    w(f"| **Files scanned** | {data.get('files_scanned', '-')} |")
    if inf.get("digest"):
        w(f"| **Model digest** | `{_md(inf.get('digest'))[:19]}…` ({_md(inf.get('quantization'))}, {_md(inf.get('parameter_size'))}) |")
    w(f"| **Total findings** | {total} ({confirmed} agreed / {disputed} disputed by a second pass of the same model; "
      "not independent confirmation) |\n")
    if data.get("warnings"):
        w("## Warnings\n")
        w("Possible prompt-injection text was found in the scanned material. Treat results for these files with extra care.\n")
        for wn in data["warnings"][:50]:
            w(f"- `{_md(wn.get('file'))}:{wn.get('line')}` — {_md(wn.get('text'))[:160]}")
        w("")

    w("## Severity Summary\n")
    w("| Severity | Count |\n|---|---|")
    for s in SEVERITIES:
        w(f"| {SEVERITY_EMOJI[s]} {s.capitalize()} | {counts[s]} |")
    w("")

    w("## Findings\n")
    if not findings:
        w("_No findings._\n")
    else:
        w("| # | ID | Severity | Issue | CWE | Location | Status |")
        w("|---|---|---|---|---|---|---|")
        for i, f in enumerate(findings, 1):
            w(f"| {i} | `{f.get('id', '')}` | {SEVERITY_EMOJI.get(f['severity'], '')} {f['severity'].upper()} | "
              f"{_md(f.get('title'))} | {_md(f.get('cwe')) or '-'} | `{_md(f.get('file'))}:{f.get('line') or '?'}` | "
              f"{_md(f.get('status'))} |")
        w("")

    w("## Details & Remediation\n")
    for i, f in enumerate(findings, 1):
        w(f"### {i}. {_md(f.get('title'))} — {f['severity'].upper()}\n")
        meta = [f"**ID:** `{f.get('id')}`", f"**Location:** `{f.get('file')}:{f.get('line') or '?'}`"]
        if f.get("cwe"):
            num = f["cwe"].split("-")[-1]
            meta.append(f"**CWE:** [{f['cwe']}](https://cwe.mitre.org/data/definitions/{num}.html)")
        if f.get("source_ip"):
            meta.append(f"**Source:** `{f['source_ip']}` (×{f.get('count', 1)})")
        meta.append(f"**Status:** {f.get('status')}")
        w(" · ".join(meta) + "\n")
        if f.get("snippet"):
            lang = "" if f.get("source") == "log" else Path(str(f.get("file"))).suffix.lstrip(".")
            w(f"```{lang}\n{f['snippet']}\n```\n")
        if f.get("description"):
            w(f"**Description.** {f['description']}\n")
        v = f.get("validation")
        if v:
            w(f"**Second pass (same model).** {'Agrees' if v.get('is_vulnerability') else 'Disagrees'} "
              f"with confidence {v.get('confidence')}. {v.get('reasoning', '')}\n")
        w(f"**Remediation.** {f.get('remediation') or '_No remediation suggested — review manually._'}\n")
        for t in tests_by_id.get(f.get("id"), []):
            w(f"<details><summary>Test: <code>{_md(t['name'])}</code> ({_md(t['type'])})</summary>\n")
            if t.get("description"):
                w(f"{t['description']}\n")
            if t.get("payload"):
                w(f"**Payload:** `{_md(t['payload'])}`\n")
            if t.get("expected_secure_behavior"):
                w(f"**Expected secure behavior:** {t['expected_secure_behavior']}\n")
            if t.get("code"):
                w(f"```\n{t['code']}\n```\n")
            w("</details>\n")
        w("- [ ] Manually verified\n")

    w("---\n")
    w("_LLM output can contain false positives and miss real issues. Every finding "
      "should be manually verified before acting on it._\n")
    return "\n".join(out)


def build_tests_markdown(tests: dict) -> str:
    out = ["# Generated Security Test Cases\n",
           f"_Model: `{tests.get('model')}` · Generated {tests.get('generated_at')} · "
           "For authorized testing of your own systems only._\n"]
    for r in tests.get("results", []):
        f = r["finding"]
        out.append(f"## {f['title']} — {f['severity'].upper()} (`{f.get('file')}:{f.get('line')}`)\n")
        for t in r["test_cases"]:
            out.append(f"### `{t['name']}` ({t['type']})\n")
            if t["description"]:
                out.append(t["description"] + "\n")
            if t["payload"]:
                out.append(f"**Payload:** `{_md(t['payload'])}`\n")
            if t["expected_secure_behavior"]:
                out.append(f"**Expected secure behavior:** {t['expected_secure_behavior']}\n")
            if t["code"]:
                out.append(f"```\n{t['code']}\n```\n")
    return "\n".join(out)
