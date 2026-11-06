"""Structured logging. Log records never contain scanned code or prompts:
only metadata (paths, sizes, timings, counts, status codes)."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional

LOGGER_NAME = "amd_vuln_scanner"


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}) or {})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class KeyValueFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, "fields", {}) or {}
        kv = " ".join(f"{k}={v}" for k, v in fields.items())
        return f"{record.levelname.lower():<7} {record.name}: {record.getMessage()} {kv}".rstrip()


def configure_logging(level: str = "WARNING", json_format: bool = False, log_file: Optional[str] = None) -> None:
    root = logging.getLogger(LOGGER_NAME)
    root.handlers.clear()
    root.setLevel(level.upper())
    handler: logging.Handler = logging.FileHandler(log_file, encoding="utf-8") if log_file else logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if json_format else KeyValueFormatter())
    root.addHandler(handler)
    root.propagate = False


def log_event(logger: logging.Logger, level: int, event: str, **fields) -> None:
    logger.log(level, event, extra={"fields": fields})
