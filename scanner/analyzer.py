"""Analysis engine: Ollama API client, chunking, JSON extraction, scanning,
deduplication and second-pass validation.

All inference goes to an Ollama server's ``/api/generate`` endpoint. By default
the server must be on a loopback address (see :mod:`scanner.safety`), so scan
material is not sent off the machine by the scanner.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import requests

from . import prompts
from .logging_utils import get_logger, log_event
from .safety import (
    FileLimits,
    detect_prompt_injection,
    new_nonce,
    prompt_safe_name,
    require_local_host,
    safe_read_text,
    wrap_untrusted,
)
from .schemas import schema_errors

log = get_logger("analyzer")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip("/")
    if not re.match(r"^https?://", host):
        host = "http://" + host
    return host.replace("://0.0.0.0", "://localhost")


DEFAULT_HOST = _normalize_host(os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
DEFAULT_MODEL = os.environ.get("AMD_SCANNER_MODEL", "llama3.2")
DEFAULT_TEMPERATURE = 0.1
DEFAULT_NUM_CTX = 8192
DEFAULT_NUM_PREDICT = 2048

CHUNK_SIZE = 6000
CHUNK_OVERLAP = 500

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CODE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".c": "C",
    ".java": "Java",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "reports", ".tox", ".mypy_cache", ".pytest_cache",
}

DISPUTE_CONFIDENCE = 0.7
MAX_HOTSPOT_REGIONS = 40
MAX_LOG_LINES_PER_HOTSPOT = 40


# ---------------------------------------------------------------------------
# Heuristic hotspots: cheap regexes that tell the LLM *where* to look. In the
# scanner they never produce findings on their own; every finding is decided
# by the model. (benchmarks/ also evaluates them standalone as an ablation.)
# ---------------------------------------------------------------------------

_I = re.IGNORECASE
CODE_HOTSPOTS: list[tuple[str, re.Pattern]] = [
    ("SQL built from strings", re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\"\s*\+|'\s*\+|\+\s*\w|\{\w|%s|\.format\()", _I)),
    ("SQL execution", re.compile(r"\.(execute|executemany|query|raw)\s*\(\s*(f[\"']|[\"'].*\+|\w+\s*\))")),
    ("dynamic code execution", re.compile(r"\b(eval|exec)\s*\(|new\s+Function\s*\(|vm\.runIn")),
    ("insecure deserialization", re.compile(r"pickle\.loads?\(|yaml\.load\((?!.*SafeLoader)|marshal\.loads|ObjectInputStream|unserialize\(")),
    ("OS command execution", re.compile(r"shell\s*=\s*True|os\.(system|popen)\(|\bexec(Sync)?\s*\(\s*[`\"'\w]|Runtime\.getRuntime\(\)\.exec|\bsystem\s*\(")),
    ("hardcoded secret", re.compile(r"(secret|passw(or)?d|pwd|api[_-]?key|token|private[_-]?key)\w*\s*[:=]\s*[\"'][^\"']{4,}[\"']", _I)),
    ("weak cryptography", re.compile(r"\b(md5|sha1)\b|DES\b|/ECB/|MODE_ECB", _I)),
    ("insecure randomness", re.compile(r"\brandom\.(randint|random|choice)\(|Math\.random\(")),
    ("path / file access", re.compile(r"send_file\(|open\(.*(request|filename|path)|os\.path\.join\(.*\b(file|name|path)|readFileSync\(|path\.join\(.*req\.")),
    ("HTML output of user input", re.compile(r"res\.(send|end|write)\(.*(\$\{|\+\s*\w)|innerHTML|render_template_string|document\.write|Markup\(")),
    ("JWT / auth handling", re.compile(r"jwt\.(decode|verify)\(|[\"']none[\"']|verify\s*=\s*False", _I)),
    ("insecure configuration", re.compile(r"debug\s*=\s*True|Allow-Origin[\"']?\s*,\s*[\"']\*|rejectUnauthorized\s*:\s*false|host\s*=\s*[\"']0\.0\.0\.0", _I)),
    ("unsafe C memory function", re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(|scanf\s*\(\s*\"%s")),
]

# CWE implied by each code hotspot (used only by the heuristic-only baseline).
HOTSPOT_CWE = {
    "SQL built from strings": "CWE-89",
    "SQL execution": "CWE-89",
    "dynamic code execution": "CWE-95",
    "insecure deserialization": "CWE-502",
    "OS command execution": "CWE-78",
    "hardcoded secret": "CWE-798",
    "weak cryptography": "CWE-327",
    "insecure randomness": "CWE-338",
    "path / file access": "CWE-22",
    "HTML output of user input": "CWE-79",
    "JWT / auth handling": "CWE-347",
    "insecure configuration": "CWE-16",
    "unsafe C memory function": "CWE-120",
}

LOG_HOTSPOTS: list[tuple[str, re.Pattern]] = [
    ("authentication failures / brute force", re.compile(r"Failed password|Invalid user|authentication failure|Too many authentication|\"POST /login[^\"]*\" 401", _I)),
    ("successful login after failures", re.compile(r"Accepted (password|publickey)|\"POST /login[^\"]*\" 200", _I)),
    ("path traversal / sensitive file probing", re.compile(r"\.\./|\.\.%2f|%2e%2e|/etc/(passwd|shadow)|win\.ini|/\.env|/\.git/|id_rsa|/proc/self", _I)),
    ("SQL injection", re.compile(r"union(\s|%20|\+)+select|%27(%20|\s)*(or|and|union|;|--)|'\s*or\s|sleep\(|drop(\s|%20)+table|OperationalError", _I)),
    ("cross-site scripting", re.compile(r"<script|%3cscript|onerror=|javascript:|document\.cookie", _I)),
    ("command injection / web shell", re.compile(r"%3B\w|%7C|;\s*cat\b|\|\s*(sh|bash)|wget|popen|__import__|cmd=|shell\.php", _I)),
    ("scanner / recon tooling", re.compile(r"sqlmap|nikto|nmap|dirbuster|gobuster|masscan|wpscan|phpmyadmin|wp-admin", _I)),
    ("privilege escalation / persistence", re.compile(r"sudo|useradd|usermod|UID=0|crontab|CRON\[", _I)),
    ("misconfiguration", re.compile(r"Debugger is active|debug=True|\[warn\]|\[error\]", _I)),
]
AUTH_FAILURE_HOTSPOT = LOG_HOTSPOTS[0][0]
AUTH_SUCCESS_HOTSPOT = LOG_HOTSPOTS[1][0]

_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s|\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b|\bclient: (\d{1,3}(?:\.\d{1,3}){3})")


def source_of(log_line: str) -> str:
    m = _IP_RE.search(log_line)
    return next((g for g in m.groups() if g), "local") if m else "local"


def group_log_hotspots(lines: list[str]) -> list[tuple[str, str, list[int]]]:
    """Group flagged log lines by (attack type, source IP).

    Small models summarize a mixed batch as one finding, so each prompt gets
    one attack type from one source. Successful logins are only flagged when
    the same source also failed to authenticate, and those failures are
    included as context.
    """
    groups: dict[tuple[str, str], list[int]] = {}
    for n, line in enumerate(lines, 1):
        src = source_of(line)
        for name, rx in LOG_HOTSPOTS:
            if rx.search(line):
                groups.setdefault((name, src), []).append(n)

    out = []
    for (name, src), nums in groups.items():
        if name == AUTH_SUCCESS_HOTSPOT:
            failures = groups.get((AUTH_FAILURE_HOTSPOT, src))
            if not failures or src == "local":
                continue
            nums = sorted(set(nums) | set(failures))
        out.append((name, src, nums[:MAX_LOG_LINES_PER_HOTSPOT]))
    return out


def find_hotspots(lines: list[str], patterns: list[tuple[str, re.Pattern]]) -> dict[int, list[str]]:
    """Return {line_number: [hint, ...]} for lines matching any pattern."""
    hits: dict[int, list[str]] = {}
    for i, line in enumerate(lines, 1):
        for name, rx in patterns:
            if rx.search(line):
                hits.setdefault(i, []).append(name)
    return hits


def group_regions(line_numbers: Iterable[int], gap: int = 4) -> list[list[int]]:
    """Group nearby hotspot lines so that each region is one focused prompt."""
    regions: list[list[int]] = []
    for n in sorted(line_numbers):
        if regions and n - regions[-1][-1] <= gap:
            regions[-1].append(n)
        else:
            regions.append([n])
    return regions


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------


class OllamaError(RuntimeError):
    """Raised when the local Ollama server is unreachable or misbehaves."""


class OllamaTimeout(OllamaError):
    """A single generation took too long; the scan continues without it."""


NOT_RUNNING = "Ollama is not running. Run setup.sh first."


@dataclass
class ClientStats:
    http_requests: int = 0
    generations: int = 0
    http_retries: int = 0
    timeouts: int = 0
    inference_seconds: float = 0.0


class OllamaClient:
    """Minimal client for Ollama's ``/api/generate`` and model metadata APIs."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        model: str = DEFAULT_MODEL,
        timeout: int = 300,
        temperature: float = DEFAULT_TEMPERATURE,
        num_ctx: int = DEFAULT_NUM_CTX,
        num_predict: int = DEFAULT_NUM_PREDICT,
        seed: Optional[int] = None,
        allow_remote: bool = False,
        retry_backoff: float = 3.0,
    ) -> None:
        self.host = _normalize_host(host)
        self.is_local = require_local_host(self.host, allow_remote)
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.seed = seed
        self.retry_backoff = retry_backoff
        self.session = requests.Session()
        self.session.trust_env = False  # never route local inference through HTTP(S)_PROXY
        self.stats = ClientStats()

    @property
    def options(self) -> dict[str, Any]:
        opts: dict[str, Any] = {
            "temperature": self.temperature,
            "num_ctx": self.num_ctx,
            "num_predict": self.num_predict,  # stops runaway JSON-mode generations
        }
        if self.seed is not None:
            opts["seed"] = self.seed
        return opts

    def list_models(self) -> list[dict]:
        try:
            r = self.session.get(f"{self.host}/api/tags", timeout=10)
            r.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaError(
                f"{NOT_RUNNING} (no response from {self.host}; if Ollama is installed, start it with `ollama serve`)"
            ) from exc
        return r.json().get("models", [])

    def ensure_ready(self) -> None:
        names = [m.get("name", "") for m in self.list_models()]
        wanted = {self.model, f"{self.model}:latest"}
        if not wanted.intersection(names):
            available = ", ".join(names) or "none"
            raise OllamaError(
                f"Model '{self.model}' is not installed (available: {available}). "
                f"Run: ollama pull {self.model}"
            )

    def model_info(self) -> dict[str, Any]:
        """Digest, quantization, size and server version, for reproducibility records."""
        info: dict[str, Any] = {"name": self.model, "host": self.host, "host_is_loopback": self.is_local}
        try:
            for m in self.list_models():
                if m.get("name") in (self.model, f"{self.model}:latest"):
                    info.update(digest=m.get("digest"), size_bytes=m.get("size"))
            r = self.session.post(f"{self.host}/api/show", json={"model": self.model}, timeout=10)
            r.raise_for_status()
            d = r.json()
            details = d.get("details", {})
            info.update(
                family=details.get("family"),
                parameter_size=details.get("parameter_size"),
                quantization=details.get("quantization_level"),
                format=details.get("format"),
                trained_context_length=next(
                    (v for k, v in d.get("model_info", {}).items() if k.endswith(".context_length")), None
                ),
            )
            v = self.session.get(f"{self.host}/api/version", timeout=10)
            info["ollama_version"] = v.json().get("version") if v.ok else None
        except (requests.RequestException, ValueError) as exc:
            info["error"] = str(exc)
        info["options"] = self.options
        return info

    def generate(self, prompt: str, system: Optional[str] = None, json_mode: bool = True) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": self.options,
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"
        attempts = 3  # retries cover transient 5xx while Ollama (re)loads the model
        for attempt in range(attempts):
            started = time.perf_counter()
            self.stats.http_requests += 1
            try:
                r = self.session.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout)
                r.raise_for_status()
                body = r.json()
                elapsed = time.perf_counter() - started
                self.stats.generations += 1
                self.stats.inference_seconds += elapsed
                text = body.get("response", "")
                log_event(log, logging.DEBUG, "ollama.generate", endpoint="/api/generate", model=self.model,
                          status=r.status_code, attempt=attempt + 1, seconds=round(elapsed, 3),
                          prompt_chars=len(prompt), response_chars=len(text),
                          eval_count=body.get("eval_count"), prompt_eval_count=body.get("prompt_eval_count"))
                return text
            except requests.Timeout as exc:
                self.stats.timeouts += 1
                log_event(log, logging.WARNING, "ollama.timeout", timeout=self.timeout)
                raise OllamaTimeout(f"generation exceeded {self.timeout}s") from exc
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                log_event(log, logging.WARNING, "ollama.http_error", status=status, attempt=attempt + 1)
                if attempt < attempts - 1 and status is not None and status >= 500:
                    self.stats.http_retries += 1
                    time.sleep(self.retry_backoff * (attempt + 1))
                    continue
                raise OllamaError(f"Ollama request failed: {exc}") from exc
            except requests.ConnectionError as exc:
                log_event(log, logging.WARNING, "ollama.connection_error", attempt=attempt + 1)
                if attempt < attempts - 1:
                    self.stats.http_retries += 1
                    time.sleep(self.retry_backoff * (attempt + 1))
                    continue
                raise OllamaError(NOT_RUNNING) from exc
            except (requests.RequestException, ValueError) as exc:
                raise OllamaError(f"Ollama request failed: {exc}") from exc
        raise OllamaError(f"Ollama request failed after {attempts} attempts")


# ---------------------------------------------------------------------------
# Robust JSON extraction
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


def extract_json(text: str) -> Optional[Any]:
    """Pull a JSON object out of an LLM response.

    Strategy: strip markdown fences, then take everything from the first ``{``
    to the last ``}``. If that fails to parse, retry after removing trailing
    commas, then try to salvage complete items from a truncated array.
    Returns ``None`` when no JSON object can be recovered.
    """
    if not text:
        return None
    text = text.strip()
    fence = _FENCE_RE.search(text)
    if fence:
        text = fence.group(1).strip()

    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    candidate = text[start : end + 1]
    for attempt in (candidate, _TRAILING_COMMA_RE.sub(r"\1", candidate)):
        try:
            return json.loads(attempt)
        except json.JSONDecodeError:
            continue
    return _salvage_objects(text[start:])


def _salvage_objects(text: str) -> Optional[dict]:
    """Recover the complete items from a truncated response such as
    ``{"findings": [{...}, {...}, {"title": "cut of``."""
    m = re.match(r'\{\s*"(\w+)"\s*:\s*\[', text)
    if not m:
        return None
    decoder = json.JSONDecoder()
    items, pos = [], m.end()
    while True:
        while pos < len(text) and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(text) or text[pos] != "{":
            break
        try:
            obj, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        items.append(obj)
    return {m.group(1): items, "_truncated": True} if items else None


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


@dataclass
class Chunk:
    text: str
    start_line: int  # 1-based line number of the first line in this chunk
    index: int
    total: int = 1

    @property
    def label(self) -> str:
        return f"chunk {self.index + 1}/{self.total}, starting at line {self.start_line}"


def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[Chunk]:
    """Split text into ~``size``-char chunks with ``overlap`` chars of overlap.

    Boundaries are snapped to line breaks where possible so that line numbers
    stay meaningful and no line is cut in half.
    """
    if overlap >= size:
        raise ValueError("overlap must be smaller than size")
    if len(text) <= size:
        return [Chunk(text, 1, 0, 1)]

    chunks: list[Chunk] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + size, n)
        if end < n:
            nl = text.rfind("\n", start, end)
            if nl > start + size // 2:
                end = nl + 1
        chunks.append(Chunk(text[start:end], text.count("\n", 0, start) + 1, len(chunks)))
        if end >= n:
            break
        next_start = end - overlap
        nl = text.find("\n", next_start, end)
        next_start = nl + 1 if nl != -1 else next_start
        start = max(next_start, start + 1)  # always make progress

    for c in chunks:
        c.total = len(chunks)
    return chunks


def number_lines(text: str, start_line: int = 1) -> str:
    lines = text.splitlines()
    width = len(str(start_line + len(lines)))
    return "\n".join(f"{start_line + i:>{width}} | {line}" for i, line in enumerate(lines))


def context_around(lines: list[str], line: int, radius: int = 20) -> str:
    if not lines:
        return ""
    line = min(max(line, 1), len(lines))
    lo = max(1, line - radius)
    hi = min(len(lines), line + radius)
    return number_lines("\n".join(lines[lo - 1 : hi]), lo)


# ---------------------------------------------------------------------------
# Finding normalization / dedup
# ---------------------------------------------------------------------------


def normalize_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    aliases = {
        "crit": "critical", "severe": "high", "important": "high",
        "moderate": "medium", "med": "medium", "minor": "low",
        "informational": "info", "information": "info", "none": "info",
    }
    s = aliases.get(s, s)
    return s if s in SEVERITY_RANK else "medium"


# Title keyword -> canonical CWE. Small models often attach a wrong CWE number
# to a correct title (e.g. "Command Injection" / CWE-89), so the title wins.
# Order matters: more specific concepts come first (a "deserialization leading
# to code execution" is CWE-502, a "hardcoded JWT secret" is CWE-798).
CWE_BY_KEYWORD: list[tuple[re.Pattern, str]] = [
    (re.compile(r"web ?shell", re.I), "CWE-434"),
    (re.compile(r"deserializ|pickle|yaml\.load|unmarshal", re.I), "CWE-502"),
    (re.compile(r"hard[- ]?coded|embedded (secret|credential|password|key)|secret|credential|password in|api key", re.I), "CWE-798"),
    (re.compile(r"sql", re.I), "CWE-89"),
    (re.compile(r"xss|cross[- ]site scripting", re.I), "CWE-79"),
    (re.compile(r"path traversal|directory traversal|\blfi\b|file inclusion", re.I), "CWE-22"),
    (re.compile(r"command|shell|os exec|\bexec\b", re.I), "CWE-78"),
    (re.compile(r"eval|code (execution|injection)|dynamic code|new function", re.I), "CWE-95"),
    (re.compile(r"format string", re.I), "CWE-134"),
    (re.compile(r"buffer overflow|out[- ]of[- ]bounds|strcpy|gets\(|sprintf", re.I), "CWE-120"),
    (re.compile(r"md5|sha-?1|weak (hash|crypt|cipher)|broken crypt|password hash|\bdes\b|\becb\b", re.I), "CWE-327"),
    (re.compile(r"random|predictable token", re.I), "CWE-338"),
    (re.compile(r"jwt|token (verification|validation|decod)|signature", re.I), "CWE-347"),
    (re.compile(r"cors|cross[- ]origin|allow-origin", re.I), "CWE-942"),
    (re.compile(r"certificate|tls|ssl", re.I), "CWE-295"),
    (re.compile(r"debug", re.I), "CWE-489"),
    (re.compile(r"misconfig|configuration", re.I), "CWE-16"),
    (re.compile(r"privilege escalation|persistence|new (root|admin) user", re.I), "CWE-269"),
    (re.compile(r"scan(ner|ning)|recon", re.I), "CWE-200"),
    (re.compile(r"brute[- ]?force|credential stuffing|failed login|authentication failure", re.I), "CWE-307"),
]


def canonical_cwe(title: str, cwe: str) -> str:
    for rx, canonical in CWE_BY_KEYWORD:
        if rx.search(title):
            return canonical
    return cwe


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    m = re.search(r"\d+", str(value or ""))
    return int(m.group()) if m else None


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip().lower()


def _strip_line_prefix(snippet: str) -> str:
    """Remove '<n> | ' / '>> <n> | ' prefixes the model sometimes copies from the prompt."""
    return "\n".join(re.sub(r"^\s*(>>)?\s*\d+\s*\|\s?", "", ln) for ln in str(snippet or "").splitlines())


def locate_snippet(lines: list[str], snippet: str, hint: Optional[int]) -> Optional[int]:
    """Find the real line number of a snippet, preferring matches near ``hint``.

    Line numbers outside the file are discarded rather than reported.
    """
    if hint is not None and not (1 <= hint <= len(lines)):
        hint = None
    probe = next((ln.strip() for ln in snippet.splitlines() if ln.strip()), "")
    if len(probe) < 4:
        return hint
    matches = [i + 1 for i, ln in enumerate(lines) if probe in ln]
    if not matches:
        return hint
    if hint is None:
        return matches[0]
    return min(matches, key=lambda m: abs(m - hint))


def finding_id(f: dict) -> str:
    key = f"{f.get('file')}|{_norm(f.get('title'))}|{_norm(f.get('snippet'))}"
    return "F-" + hashlib.sha1(key.encode()).hexdigest()[:8]


def _merge_into(best: dict[tuple, dict], key: tuple, f: dict) -> None:
    cur = best.get(key)
    if cur is None:
        best[key] = f
        return
    keep, drop = (f, cur) if SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[cur["severity"]] else (cur, f)
    for fld in ("description", "remediation", "cwe"):
        if len(str(drop.get(fld) or "")) > len(str(keep.get(fld) or "")):
            keep[fld] = drop[fld]
    if "count" in keep or "count" in drop:
        keep["count"] = max(keep.get("count") or 1, drop.get("count") or 1)
    sources = set(keep.get("detected_by_all") or [keep.get("detected_by")]) | set(
        drop.get("detected_by_all") or [drop.get("detected_by")]
    )
    keep["detected_by_all"] = sorted(s for s in sources if s)
    best[key] = keep


def dedupe_findings(findings: Iterable[dict]) -> list[dict]:
    """Deduplicate findings, keeping the most severe copy.

    Pass 1: same file + normalized title + normalized snippet.
    Pass 2: same file + line + CWE (the same issue reported by the whole-file
    pass and a focused pass under slightly different titles); for logs, same
    source IP + CWE (one finding per attack type per attacker).
    """
    best: dict[tuple, dict] = {}
    for f in findings:
        _merge_into(best, (f.get("file"), _norm(f.get("title")), _norm(f.get("snippet"))), f)

    second: dict[tuple, dict] = {}
    for f in best.values():
        if f.get("source") == "log" and f.get("source_ip") and f.get("cwe"):
            key: tuple = (f.get("file"), "log", f["source_ip"], f["cwe"].upper())
        elif f.get("line") and f.get("cwe"):
            key = (f.get("file"), f["line"], f["cwe"].upper())
        else:
            key = (f.get("file"), _norm(f.get("title")), _norm(f.get("snippet")))
        _merge_into(second, key, f)

    return sorted(
        second.values(),
        key=lambda f: (SEVERITY_RANK[f["severity"]], str(f.get("file")), f.get("line") or 0),
    )


def display_path(path: Path) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:  # different drive on Windows
        return str(path)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

ProgressFn = Callable[[str], None]


@dataclass
class ResponseStats:
    """Classification of every model response the analyzer asked for."""

    requested: int = 0          # ask_json calls
    valid: int = 0              # parsed and schema-valid
    schema_invalid: int = 0     # parsed JSON object but violated the schema (still coerced)
    salvaged: int = 0           # truncated output, complete items recovered
    unparseable: int = 0        # no JSON object even after one retry
    json_retries: int = 0       # re-asks after unparseable output
    timeouts: int = 0
    by_kind: dict[str, dict[str, int]] = field(default_factory=dict)

    def bump(self, kind: str, outcome: str) -> None:
        setattr(self, outcome, getattr(self, outcome) + 1)
        k = self.by_kind.setdefault(kind, {})
        k[outcome] = k.get(outcome, 0) + 1

    def to_dict(self) -> dict:
        return asdict(self)


class Analyzer:
    def __init__(
        self,
        client: OllamaClient,
        validate: bool = True,
        hotspots: bool = True,
        progress: Optional[ProgressFn] = None,
        limits: Optional[FileLimits] = None,
    ):
        self.client = client
        self.validate = validate
        self.hotspots = hotspots
        self.limits = limits or FileLimits()
        self.progress = progress or (lambda msg: None)
        self.errors: list[str] = []
        self.warnings: list[dict] = []
        self.skipped: list[dict] = []
        self.stats = ResponseStats()

    # -- LLM plumbing -------------------------------------------------------

    def ask_json(self, prompt: str, kind: str = "findings") -> dict:
        """Query the model and return a parsed JSON object (retrying once on unparseable output)."""
        self.stats.requested += 1
        text = ""
        for attempt in range(2):
            if attempt:
                self.stats.json_retries += 1
            try:
                text = self.client.generate(
                    prompt if attempt == 0 else prompt + prompts.RETRY_SUFFIX,
                    system=prompts.SYSTEM_PROMPT,
                )
            except OllamaTimeout as exc:
                self.errors.append(f"Timeout: {exc}")
                self.stats.bump(kind, "timeouts")
                return {}
            data = extract_json(text)
            if isinstance(data, dict):
                if data.pop("_truncated", False):
                    self.stats.bump(kind, "salvaged")
                elif schema_errors(kind, data):
                    self.stats.bump(kind, "schema_invalid")
                else:
                    self.stats.bump(kind, "valid")
                return data
        self.stats.bump(kind, "unparseable")
        self.errors.append(f"Unparseable model output ({len(text)} chars)")
        log_event(log, logging.WARNING, "llm.unparseable", kind=kind, response_chars=len(text))
        return {}

    # -- scanning -----------------------------------------------------------

    def _scan_text(self, path: Path, text: str, kind: str, language: str) -> list[dict]:
        started = time.perf_counter()
        lines = text.splitlines()
        for w in detect_prompt_injection(lines):
            self.warnings.append({**w, "file": display_path(path)})
        template = prompts.CODE_SCAN if kind == "code" else prompts.LOG_SCAN
        chunks = chunk_text(text)
        raw_findings: list[dict] = []
        safe_name = prompt_safe_name(path.name)

        for chunk in chunks:
            self.progress(f"{display_path(path)} [{chunk.index + 1}/{chunk.total}]")
            prompt = template.substitute(
                language=language,
                filename=safe_name,
                chunk_info=chunk.label,
                code=wrap_untrusted(number_lines(chunk.text, chunk.start_line), new_nonce()),
            )
            raw_findings += self._collect(self.ask_json(prompt), path, kind, lines, "llm-file")

        if self.hotspots:
            raw_findings += (self._focused_code(path, lines, language) if kind == "code"
                             else self._focused_logs(path, lines))

        findings = dedupe_findings(raw_findings)
        if self.validate:
            for f in findings:
                if f["severity"] in ("critical", "high"):
                    self.progress(f"validating: {f['title'][:50]}")
                    self.validate_finding(f, lines, kind)
        for f in findings:
            f["id"] = finding_id(f)
        log_event(log, logging.INFO, "scan.file", path=display_path(path), kind=kind, chunks=len(chunks),
                  findings=len(findings), seconds=round(time.perf_counter() - started, 3))
        return findings

    def _collect(self, data: dict, path: Path, kind: str, lines: list[str], detected_by: str) -> list[dict]:
        items = data.get("findings", [])
        if isinstance(items, dict):
            items = [items]
        out = []
        for raw in items if isinstance(items, list) else []:
            f = self._coerce(raw, path, kind, lines)
            if f:
                f["detected_by"] = detected_by
                out.append(f)
        return out

    def _focused_code(self, path: Path, lines: list[str], language: str) -> list[dict]:
        hits = find_hotspots(lines, CODE_HOTSPOTS)
        regions = group_regions(hits)[:MAX_HOTSPOT_REGIONS]
        out: list[dict] = []
        for i, region in enumerate(regions, 1):
            self.progress(f"{display_path(path)} hotspot {i}/{len(regions)}")
            lo, hi = max(1, region[0] - 6), min(len(lines), region[-1] + 6)
            marked = set(region)
            width = len(str(hi))
            excerpt = "\n".join(
                f"{'>>' if n in marked else '  '} {n:>{width}} | {lines[n - 1]}" for n in range(lo, hi + 1)
            )
            hints = "; ".join(f"line {n}: {', '.join(hits[n])}" for n in region)
            prompt = prompts.FOCUSED_CODE_SCAN.substitute(
                language=language, filename=prompt_safe_name(path.name), hints=hints,
                code=wrap_untrusted(excerpt, new_nonce()),
            )
            out += self._collect(self.ask_json(prompt), path, "code", lines, "llm-hotspot")
        return out

    def _focused_logs(self, path: Path, lines: list[str]) -> list[dict]:
        out: list[dict] = []
        groups = group_log_hotspots(lines)
        for i, (name, src, nums) in enumerate(groups, 1):
            self.progress(f"{display_path(path)} hotspot {i}/{len(groups)}: {name} ({src})")
            width = len(str(nums[-1]))
            excerpt = "\n".join(f"{n:>{width}} | {lines[n - 1]}" for n in nums)
            prompt = prompts.FOCUSED_LOG_SCAN.substitute(
                filename=prompt_safe_name(path.name), hints=name, source=src,
                code=wrap_untrusted(excerpt, new_nonce()),
            )
            found = self._collect(self.ask_json(prompt), path, "log", lines, "llm-hotspot")
            for f in found:
                # every line in this group came from `src`, so it is authoritative
                f["source_ip"] = "" if src == "local" else src
            out += found
        return out

    def _coerce(self, raw: Any, path: Path, kind: str, lines: list[str]) -> Optional[dict]:
        if not isinstance(raw, dict):
            return None
        title = str(raw.get("title") or raw.get("name") or raw.get("type") or "").strip()
        if not title:
            return None
        snippet = _strip_line_prefix(raw.get("snippet") or raw.get("evidence") or raw.get("code") or "").strip()
        line = locate_snippet(lines, snippet, _to_int(raw.get("line")))
        cwe = str(raw.get("cwe") or "").strip().upper()
        if re.fullmatch(r"\d+", cwe):
            cwe = f"CWE-{cwe}"
        cwe = canonical_cwe(title, cwe)
        f: dict[str, Any] = {
            "id": "",
            "source": kind,
            "file": display_path(path),
            "title": title[:200],
            "severity": normalize_severity(raw.get("severity")),
            "cwe": cwe,
            "line": line,
            "snippet": snippet[:500],
            "description": str(raw.get("description") or "").strip()[:2000],
            "remediation": str(raw.get("remediation") or raw.get("recommendation") or raw.get("fix") or "").strip()[:2000],
            "status": "unvalidated",
            "manual_review": "pending",
        }
        if kind == "log":
            f["category"] = str(raw.get("category") or "other")
            ip = str(raw.get("source_ip") or "").strip()
            # Discard IPs the model invented (e.g. copied from the prompt's
            # example): the address must actually appear in the log.
            log_line = lines[line - 1] if line and 0 < line <= len(lines) else ""
            if ip and ip not in snippet and ip not in log_line and not any(ip in ln for ln in lines):
                ip = ""
            if not ip and log_line and source_of(log_line) != "local":
                ip = source_of(log_line)
            f["source_ip"] = ip
            f["count"] = _to_int(raw.get("count")) or 1
        return f

    def read(self, path: Path) -> Optional[str]:
        """Safe read; records and skips files that violate the limits."""
        from .safety import UnsafeFileError

        try:
            return safe_read_text(path, self.limits)
        except UnsafeFileError as exc:
            self.skipped.append({"file": display_path(path), "reason": exc.reason})
            log_event(log, logging.WARNING, "file.skipped", path=display_path(path), reason=exc.reason)
            return None

    def scan_code_file(self, path: Path) -> list[dict]:
        text = self.read(path)
        if not text or not text.strip():
            return []
        language = CODE_EXTENSIONS.get(path.suffix.lower(), "source")
        return self._scan_text(path, text, "code", language)

    def scan_log_file(self, path: Path) -> list[dict]:
        text = self.read(path)
        if not text or not text.strip():
            return []
        return self._scan_text(path, text, "log", "log")

    # -- validation ---------------------------------------------------------

    def validate_finding(self, f: dict, lines: list[str], kind: str) -> dict:
        summary = {k: f.get(k) for k in ("title", "severity", "cwe", "line", "snippet", "description")}
        template = prompts.VALIDATION if kind == "code" else prompts.LOG_VALIDATION
        prompt = template.substitute(
            finding=wrap_untrusted(json.dumps(summary, indent=2), new_nonce()),
            kind="source code" if kind == "code" else "log",
            context=wrap_untrusted(context_around(lines, f.get("line") or 1), new_nonce()),
        )
        data = self.ask_json(prompt, kind="validation")
        if not data:
            f["status"] = "validation_failed"
            return f

        verdict = data.get("is_vulnerability")
        if isinstance(verdict, str):
            verdict = verdict.strip().lower() in ("true", "yes", "1")
        try:
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0.0

        f["validation"] = {
            "is_vulnerability": bool(verdict),
            "confidence": round(confidence, 2),
            "attacker_input": str(data.get("attacker_input") or "")[:300],
            "dangerous_operation": str(data.get("dangerous_operation") or "")[:300],
            "sanitization": str(data.get("sanitization") or "")[:300],
            "suggested_severity": normalize_severity(data.get("severity")) if data.get("severity") else None,
            "reasoning": str(data.get("reasoning") or "").strip()[:1000],
            "validator": "same-model second pass (not independent confirmation)",
        }
        # Only let the validator dismiss a finding when it is confident; a
        # low-confidence "no" from a small model is not evidence of safety.
        # "llm_agrees" means the SAME model agreed on a second look; it is not
        # an independent confirmation.
        if verdict:
            f["status"] = "llm_agrees"
        elif confidence >= DISPUTE_CONFIDENCE:
            f["status"] = "disputed"
        else:
            f["status"] = "needs_review"
        return f

    # -- test generation ----------------------------------------------------

    def generate_tests(self, f: dict) -> list[dict]:
        kind = f.get("source", "code")
        context = ""
        p = Path(f.get("file") or "")
        text = self.read(p) if p.is_file() else None
        if text:
            context = context_around(text.splitlines(), f.get("line") or 1, radius=25)
        language = "log" if kind == "log" else CODE_EXTENSIONS.get(p.suffix.lower(), "Python")
        framework = prompts.TEST_FRAMEWORKS.get(language, "pytest")

        summary = {k: f.get(k) for k in ("title", "severity", "cwe", "file", "line", "snippet", "description", "remediation")}
        prompt = prompts.TEST_GEN.substitute(
            finding=wrap_untrusted(json.dumps(summary, indent=2), new_nonce()),
            context=wrap_untrusted(context or f.get("snippet", ""), new_nonce()),
            framework=framework,
        )
        data = self.ask_json(prompt, kind="tests")
        cases = data.get("test_cases", [])
        if isinstance(cases, dict):
            cases = [cases]
        out = []
        for c in cases if isinstance(cases, list) else []:
            if not isinstance(c, dict):
                continue
            payload = c.get("payload", "")
            if isinstance(payload, (list, dict)):
                payload = json.dumps(payload)
            out.append({
                "name": str(c.get("name") or "unnamed_test"),
                "type": str(c.get("type") or "payload"),
                "description": str(c.get("description") or ""),
                "payload": str(payload or ""),
                "expected_secure_behavior": str(c.get("expected_secure_behavior") or ""),
                "code": str(c.get("code") or ""),
                "framework": framework,
                "status": "candidate - AI-generated, not executed, review before use",
            })
        return out


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def discover_files(target: Path, extensions: Iterable[str], follow_symlinks: bool = False) -> list[Path]:
    exts = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}
    if target.is_file():
        return [target]
    found = []
    for root, dirs, files in os.walk(target, followlinks=follow_symlinks):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            p = Path(root) / name
            if p.suffix.lower() in exts and (follow_symlinks or not p.is_symlink()):
                found.append(p)
    return found
