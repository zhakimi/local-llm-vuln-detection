"""Command-line interface: scan, scan-logs, gen-tests, report."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import __version__, reporter
from .analyzer import (
    CODE_EXTENSIONS,
    DEFAULT_HOST,
    DEFAULT_MODEL,
    DEFAULT_NUM_CTX,
    DEFAULT_TEMPERATURE,
    SEVERITIES,
    SEVERITY_RANK,
    Analyzer,
    OllamaClient,
    OllamaError,
    discover_files,
)
from .logging_utils import configure_logging, get_logger, log_event
from .safety import DEFAULT_MAX_FILE_BYTES, FileLimits, RemoteHostError

console = Console()
err_console = Console(stderr=True)
log = get_logger("cli")

DEFAULT_FINDINGS = Path("reports/findings.json")
DEFAULT_LOG_FINDINGS = Path("reports/log_findings.json")


def _progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def _client(args: argparse.Namespace) -> OllamaClient:
    client = OllamaClient(
        host=args.host, model=args.model, timeout=args.timeout, temperature=args.temperature,
        num_ctx=args.num_ctx, seed=args.seed, allow_remote=args.allow_remote_host,
    )
    client.ensure_ready()
    where = "local loopback server — the scanner does not send scan data off this machine" if client.is_local \
        else "[bold red]REMOTE host — scan data WILL leave this machine[/]"
    console.print(f"[dim]Using model [bold]{client.model}[/bold] at {client.host} ({where}).[/]")
    return client


def _limits(args: argparse.Namespace) -> FileLimits:
    return FileLimits(max_bytes=args.max_file_size, follow_symlinks=args.follow_symlinks)


def _exit_code(findings: list[dict], fail_on: Optional[str]) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK[f["severity"]] <= threshold for f in findings) else 0


def _save_results(results: dict, output: Path, merge: bool) -> None:
    if merge and output.exists():
        results = reporter.merge_results(reporter.load_findings(output), results)
    reporter.save_json(output, results)
    console.print(f"[green]✔[/] Saved {len(results['findings'])} finding(s) to [bold]{output}[/]")


def _print_diagnostics(analyzer: Analyzer, verbose: bool) -> None:
    s = analyzer.stats
    if s.unparseable or s.timeouts:
        err_console.print(f"[yellow]⚠ {s.unparseable} unparseable and {s.timeouts} timed-out model response(s).[/]")
    for sk in analyzer.skipped:
        err_console.print(f"[yellow]⚠ skipped {sk['file']}: {sk['reason']}[/]")
    for w in analyzer.warnings:
        err_console.print(f"[yellow]⚠ possible prompt-injection text in {w['file']}:{w['line']}[/] [dim]{w['text'][:100]}[/]")
    if verbose:
        for e in analyzer.errors:
            err_console.print(f"[dim]{e}[/]")
        err_console.print(f"[dim]model responses: {json.dumps({k: v for k, v in s.to_dict().items() if k != 'by_kind'})}[/]")


def _run_scan(args: argparse.Namespace, kind: str, files: list[Path], target: Path) -> int:
    client = _client(args)
    if kind == "code":
        console.print(f"Scanning [bold]{len(files)}[/] file(s) in [bold]{target}[/] …")
    started = time.time()
    findings: list[dict] = []
    with _progress() as progress:
        task = progress.add_task("starting", total=len(files))
        analyzer = Analyzer(client, validate=not args.no_validate, hotspots=not args.no_hotspots,
                            limits=_limits(args), progress=lambda m: progress.update(task, description=m))
        for path in files:
            try:
                file_findings = analyzer.scan_code_file(path) if kind == "code" else analyzer.scan_log_file(path)
            except OllamaError as exc:
                if "not running" in str(exc):
                    raise
                err_console.print(f"[red]✖ {path}: {exc}[/]")
                file_findings = []
            findings.extend(file_findings)
            progress.console.print(f"  [dim]•[/] {path}  →  {len(file_findings)} finding(s)")
            progress.advance(task)

    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["file"], f.get("line") or 0))
    title = f"Code findings — {target}" if kind == "code" else f"Log anomalies — {target}"
    reporter.print_findings(console, findings, title=title)
    reporter.print_summary(console, findings)
    elapsed = time.time() - started
    console.print(f"[dim]Completed in {elapsed:.1f}s[/]")
    _print_diagnostics(analyzer, args.verbose)

    results = reporter.build_results(
        str(target), kind, client.model, findings, len(files), analyzer.errors,
        inference=client.model_info(), response_stats=analyzer.stats.to_dict(),
        warnings=analyzer.warnings, skipped=analyzer.skipped,
    )
    results["elapsed_seconds"] = round(elapsed, 2)
    _save_results(results, Path(args.output), args.merge)
    log_event(log, logging.INFO, "scan.done", kind=kind, files=len(files), findings=len(findings),
              seconds=round(elapsed, 2))
    return _exit_code(findings, args.fail_on)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        err_console.print(f"[red]Path not found:[/] {target}")
        return 2
    exts = [e.strip() for e in args.ext.split(",")] if args.ext else list(CODE_EXTENSIONS)
    files = discover_files(target, exts, follow_symlinks=args.follow_symlinks)
    if args.max_files:
        files = files[: args.max_files]
    if not files:
        console.print(f"[yellow]No files with extensions {', '.join(exts)} found under {target}[/]")
        return 0
    return _run_scan(args, "code", files, target)


def cmd_scan_logs(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        err_console.print(f"[red]Path not found:[/] {target}")
        return 2
    files = discover_files(target, [".log", ".txt"], follow_symlinks=args.follow_symlinks) if target.is_dir() else [target]
    if not files:
        console.print(f"[yellow]No .log files found under {target}[/]")
        return 0
    return _run_scan(args, "log", files, target)


def cmd_gen_tests(args: argparse.Namespace) -> int:
    data = reporter.load_findings(Path(args.findings))
    threshold = SEVERITY_RANK[args.min_severity]
    selected = [f for f in data["findings"]
                if SEVERITY_RANK.get(f.get("severity"), 9) <= threshold
                and (args.include_disputed or f.get("status") != "disputed")]
    if args.limit:
        selected = selected[: args.limit]
    if not selected:
        console.print("[yellow]No findings match the selected severity / status filters.[/]")
        return 0

    client = _client(args)
    analyzer = Analyzer(client, limits=_limits(args))
    results = []
    with _progress() as progress:
        task = progress.add_task("generating", total=len(selected))
        for f in selected:
            progress.update(task, description=f"tests: {f['title'][:50]}")
            try:
                cases = analyzer.generate_tests(f)
            except OllamaError as exc:
                if "not running" in str(exc):
                    raise
                err_console.print(f"[red]✖ {f['title']}: {exc}[/]")
                cases = []
            results.append({"finding_id": f.get("id"), "finding": f, "test_cases": cases})
            progress.advance(task)

    for r in results:
        reporter.print_tests(console, r["finding"], r["test_cases"])
    _print_diagnostics(analyzer, args.verbose)

    out = Path(args.output) if args.output else Path(args.findings).with_name("test_cases.json")
    payload = {
        "tool": "amd-vuln-scanner",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": client.model,
        "notice": "Candidate tests generated by a local LLM. They were NOT executed. Review before running, "
                  "and only run them against isolated, non-networked test instances.",
        "source_findings": str(args.findings),
        "results": results,
    }
    reporter.save_json(out, payload)
    md = out.with_suffix(".md")
    md.write_text(reporter.build_tests_markdown(payload), encoding="utf-8")
    total = sum(len(r["test_cases"]) for r in results)
    console.print(f"[green]✔[/] Generated {total} candidate test case(s) for {len(results)} finding(s) → "
                  f"[bold]{out}[/] and [bold]{md}[/] (not executed)")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    findings_path = Path(args.findings)
    data = reporter.load_findings(findings_path)
    tests = None
    tests_path = Path(args.tests) if args.tests else findings_path.with_name("test_cases.json")
    if tests_path.exists():
        tests = json.loads(tests_path.read_text(encoding="utf-8"))
        console.print(f"[dim]Including test cases from {tests_path}[/]")

    out = Path(args.output) if args.output else findings_path.with_name("report.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(reporter.build_markdown_report(data, tests), encoding="utf-8")

    reporter.print_summary(console, data["findings"])
    console.print(f"[green]✔[/] Report written to [bold]{out}[/]")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("model / inference")
    g.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL}, env AMD_SCANNER_MODEL)")
    g.add_argument("--host", default=DEFAULT_HOST, help=f"Ollama URL (default: {DEFAULT_HOST}, env OLLAMA_HOST)")
    g.add_argument("--allow-remote-host", action="store_true",
                   help="Allow a non-loopback Ollama host (scan data would leave this machine)")
    g.add_argument("--timeout", type=int, default=300, help="Per-request timeout in seconds (default: 300)")
    g.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE, help=f"Sampling temperature (default: {DEFAULT_TEMPERATURE})")
    g.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX, help=f"Context window in tokens (default: {DEFAULT_NUM_CTX})")
    g.add_argument("--seed", type=int, help="Fixed sampling seed for more repeatable output")
    f = common.add_argument_group("files")
    f.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_BYTES,
                   help=f"Skip files larger than N bytes (default: {DEFAULT_MAX_FILE_BYTES}, env AMD_SCANNER_MAX_FILE_BYTES)")
    f.add_argument("--follow-symlinks", action="store_true", help="Follow symlinked files and directories (off by default)")
    o = common.add_argument_group("output / logging")
    o.add_argument("-v", "--verbose", action="store_true", help="Show model-response diagnostics")
    o.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Structured log level (stderr)")
    o.add_argument("--log-json", action="store_true", help="Emit logs as JSON lines")
    o.add_argument("--log-file", help="Write logs to this file instead of stderr")

    parser = argparse.ArgumentParser(
        prog="amd-vuln-scanner",
        description="Local-LLM vulnerability scanner for source code and logs (Ollama).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_opts = argparse.ArgumentParser(add_help=False)
    scan_opts.add_argument("--no-validate", action="store_true", help="Skip second-pass validation of high/critical findings")
    scan_opts.add_argument("--no-hotspots", action="store_true", help="Skip heuristic-guided focused passes (faster, lower recall)")
    scan_opts.add_argument("--merge", action="store_true", help="Merge into an existing output file instead of overwriting")
    scan_opts.add_argument("--fail-on", choices=SEVERITIES, help="Exit 1 if any finding at or above this severity (for CI)")

    p = sub.add_parser("scan", parents=[common, scan_opts], help="Scan source code (.py .js .ts .c .java)")
    p.add_argument("path", help="File or directory to scan")
    p.add_argument("-o", "--output", default=str(DEFAULT_FINDINGS), help=f"Findings JSON path (default: {DEFAULT_FINDINGS})")
    p.add_argument("--ext", help="Comma-separated extensions to include, e.g. .py,.js")
    p.add_argument("--max-files", type=int, help="Scan at most N files")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("scan-logs", parents=[common, scan_opts], help="Detect attacks and anomalies in log files")
    p.add_argument("path", help="Log file or directory of .log files")
    p.add_argument("-o", "--output", default=str(DEFAULT_LOG_FINDINGS), help=f"Findings JSON path (default: {DEFAULT_LOG_FINDINGS})")
    p.set_defaults(func=cmd_scan_logs)

    p = sub.add_parser("gen-tests", parents=[common], help="Generate candidate test cases / attack inputs for findings (never executed)")
    p.add_argument("findings", help="Path to findings.json")
    p.add_argument("-o", "--output", help="Output JSON path (default: test_cases.json next to findings)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="Only findings at or above this severity (default: low)")
    p.add_argument("--include-disputed", action="store_true", help="Also generate tests for findings disputed by validation")
    p.add_argument("--limit", type=int, help="Generate tests for at most N findings")
    p.set_defaults(func=cmd_gen_tests)

    p = sub.add_parser("report", help="Generate a markdown report from findings.json")
    p.add_argument("findings", help="Path to findings.json")
    p.add_argument("-o", "--output", help="Output markdown path (default: report.md next to findings)")
    p.add_argument("--tests", help="test_cases.json to embed (default: auto-detect next to findings)")
    p.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--log-json", action="store_true")
    p.add_argument("--log-file")
    p.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_json, args.log_file)
    try:
        return args.func(args)
    except RemoteHostError as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        return 2
    except OllamaError as exc:
        err_console.print(f"[bold red]Ollama error:[/] {exc}")
        return 3
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
