"""Safety helpers: local-only inference guard, safe file reading, and
prompt-injection hygiene for untrusted scan material."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

DEFAULT_MAX_FILE_BYTES = int(os.environ.get("AMD_SCANNER_MAX_FILE_BYTES", 1_000_000))


# ---------------------------------------------------------------------------
# Local-only inference
# ---------------------------------------------------------------------------


class RemoteHostError(ValueError):
    """The Ollama URL does not point at this machine."""


def is_loopback_host(url: str) -> bool:
    """True if ``url``'s host resolves only to loopback addresses."""
    host = urlparse(url).hostname or ""
    if host in ("localhost", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    addrs = {info[4][0] for info in infos}
    return bool(addrs) and all(ipaddress.ip_address(a.split("%")[0]).is_loopback for a in addrs)


def require_local_host(url: str, allow_remote: bool = False) -> bool:
    """Raise unless ``url`` is loopback (or the caller explicitly opted out).

    Returns whether the host is loopback, so callers can record it.
    """
    local = is_loopback_host(url)
    if not local and not allow_remote:
        raise RemoteHostError(
            f"Refusing to send scan data to non-local Ollama host {url!r}. Code and logs "
            "would leave this machine. Pass --allow-remote-host if that is intended."
        )
    return local


# ---------------------------------------------------------------------------
# Safe file reading
# ---------------------------------------------------------------------------


class UnsafeFileError(OSError):
    def __init__(self, path: Path, reason: str):
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


@dataclass
class FileLimits:
    max_bytes: int = DEFAULT_MAX_FILE_BYTES
    follow_symlinks: bool = False


def safe_read_text(path: Path, limits: Optional[FileLimits] = None) -> str:
    """Read a text file defensively.

    Rejects symlinks (unless allowed), non-regular files, files over the size
    limit and binary files (NUL bytes in the first 8 KiB). Decodes as UTF-8
    with replacement so malformed bytes never crash a scan.
    """
    limits = limits or FileLimits()
    try:
        if path.is_symlink() and not limits.follow_symlinks:
            raise UnsafeFileError(path, "symlink skipped (use --follow-symlinks to allow)")
        st = path.stat()
    except UnsafeFileError:
        raise
    except OSError as exc:
        raise UnsafeFileError(path, f"cannot stat: {exc.strerror or exc}") from exc
    if not path.is_file():
        raise UnsafeFileError(path, "not a regular file")
    if st.st_size > limits.max_bytes:
        raise UnsafeFileError(path, f"{st.st_size} bytes exceeds limit of {limits.max_bytes}")
    try:
        with open(path, "rb") as fh:
            data = fh.read(limits.max_bytes + 1)
    except OSError as exc:
        raise UnsafeFileError(path, f"cannot read: {exc.strerror or exc}") from exc
    if len(data) > limits.max_bytes:  # file grew between stat and read
        raise UnsafeFileError(path, f"exceeds limit of {limits.max_bytes} bytes")
    if b"\x00" in data[:8192]:
        raise UnsafeFileError(path, "binary file skipped")
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Prompt-injection hygiene
# ---------------------------------------------------------------------------

_MARKER = "UNTRUSTED_INPUT"
_MARKER_RE = re.compile(r"<<<\s*/?\s*" + _MARKER, re.IGNORECASE)


def new_nonce() -> str:
    return secrets.token_hex(6)


def wrap_untrusted(text: str, nonce: str) -> str:
    """Fence untrusted material between nonce-tagged markers.

    The nonce is random per prompt, so content cannot forge a closing marker;
    any marker-like text already in the content is defanged as well.
    """
    safe = _MARKER_RE.sub("<<<untrusted-input-text", text)
    return f"<<<{_MARKER} BEGIN {nonce}>>>\n{safe}\n<<<{_MARKER} END {nonce}>>>"


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._\-]+")


def prompt_safe_name(name: str, limit: int = 80) -> str:
    """Filenames are attacker-controlled too; keep them short and inert."""
    return _SAFE_NAME_RE.sub("_", name)[:limit] or "file"


INJECTION_RE = re.compile(
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)"
    r"|disregard\s+(all\s+|any\s+)?(previous|prior|above|your)\s+\w+"
    r"|\b(ai|llm|gpt|assistant|language model|scanner|reviewer|auditor)s?\b[^\n]{0,60}"
    r"\b(report|return|output|respond|mark|classify)\b[^\n]{0,40}\b(no|zero|empty|nothing|safe|secure)\b"
    r"|\bsystem prompt\b"
    r"|\bdo not (report|flag)\b"
    r"|\"findings\"\s*:\s*\[\s*\]",
    re.IGNORECASE,
)


def detect_prompt_injection(lines: list[str]) -> list[dict]:
    """Flag lines that look like instructions aimed at an AI reviewer."""
    out = []
    for n, line in enumerate(lines, 1):
        if INJECTION_RE.search(line):
            out.append({"type": "prompt_injection_suspected", "line": n, "text": line.strip()[:200]})
    return out
