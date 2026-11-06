"""Verify, at runtime, where the scanner sends data.

Runs a real scan of one sample file in-process with two monitors attached:

1. A ``sys.addaudithook`` hook that records every ``socket.connect`` /
   ``socket.getaddrinfo`` the Python process performs (all libraries included).
2. A wrapper around ``requests.Session.request`` that records every HTTP
   method + URL the scanner calls.

It then asserts that every connection went to a loopback address and that
inference used Ollama's ``/api/generate`` endpoint.

Usage:  python scripts/verify_local_inference.py [path-to-file]
Writes: benchmarks/results/local_inference_check.json

Scope: this checks the scanner process only. It cannot see what the Ollama
server itself does, or what other software on the machine (for example an
AI coding assistant used during development) sends elsewhere.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import requests  # noqa: E402

from scanner.analyzer import Analyzer, OllamaClient  # noqa: E402

connects: list[tuple[str, int]] = []
lookups: list[str] = []
http_calls: list[tuple[str, str]] = []


def _audit(event: str, args: tuple) -> None:
    if event == "socket.connect":
        addr = args[1]
        if isinstance(addr, tuple) and len(addr) >= 2:
            connects.append((str(addr[0]), int(addr[1])))
    elif event == "socket.getaddrinfo":
        lookups.append(str(args[0]))


_orig_request = requests.Session.request


def _recording_request(self, method, url, *a, **kw):
    http_calls.append((method.upper(), url))
    return _orig_request(self, method, url, *a, **kw)


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "sample_targets" / "vulnerable_app.py"
    sys.addaudithook(_audit)
    requests.Session.request = _recording_request  # type: ignore[method-assign]

    client = OllamaClient()
    client.ensure_ready()
    analyzer = Analyzer(client, validate=True, hotspots=True)
    findings = analyzer.scan_code_file(target)
    info = client.model_info()

    def loopback(host: str) -> bool:
        try:
            return ipaddress.ip_address(host.split("%")[0]).is_loopback
        except ValueError:
            return False

    endpoints = Counter(f"{m} {u.split('11434', 1)[-1]}" for m, u in http_calls)
    non_loopback = sorted({f"{h}:{p}" for h, p in connects if not loopback(h)})
    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(target.relative_to(ROOT)),
        "findings": len(findings),
        "socket_connects": sorted({f"{h}:{p}" for h, p in connects}),
        "dns_lookups": sorted(set(lookups)),
        "non_loopback_connects": non_loopback,
        "http_endpoints": dict(endpoints),
        "generate_calls": endpoints.get("POST /api/generate", 0),
        "client_stats": vars(client.stats),
        "model": {k: info.get(k) for k in ("name", "digest", "quantization", "parameter_size", "ollama_version", "options")},
        "passed": not non_loopback and endpoints.get("POST /api/generate", 0) > 0,
        "scope_note": __doc__.split("Scope:")[1].strip(),
    }
    out = ROOT / "benchmarks" / "results" / "local_inference_check.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
