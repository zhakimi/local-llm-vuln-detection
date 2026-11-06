"""JSON Schemas for model responses and for findings.json.

Model output is checked against these schemas so the scanner can count valid
vs. invalid responses. Invalid-but-parseable responses are still coerced
leniently (small models often add or rename fields), but they are counted.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

_SEVERITY = {"type": "string", "pattern": "^(?i:critical|high|medium|low|info|informational)$"}
_LINE = {"anyOf": [{"type": "integer", "minimum": 0}, {"type": "string", "pattern": r"^\s*\d+"}, {"type": "null"}]}

FINDING_ITEM = {
    "type": "object",
    "required": ["title", "severity", "line"],
    "properties": {
        "title": {"type": "string", "minLength": 1},
        "severity": _SEVERITY,
        "cwe": {"type": ["string", "integer", "null"]},
        "line": _LINE,
        "snippet": {"type": ["string", "null"]},
        "description": {"type": ["string", "null"]},
        "remediation": {"type": ["string", "null"]},
        "category": {"type": ["string", "null"]},
        "source_ip": {"type": ["string", "null"]},
        "count": {"type": ["integer", "string", "null"]},
    },
}

FINDINGS_RESPONSE = {
    "type": "object",
    "required": ["findings"],
    "properties": {"findings": {"type": "array", "items": FINDING_ITEM}},
}

VALIDATION_RESPONSE = {
    "type": "object",
    "required": ["is_vulnerability", "confidence"],
    "properties": {
        "is_vulnerability": {"type": ["boolean", "string"]},
        "confidence": {"type": ["number", "string"]},
        "severity": {"anyOf": [_SEVERITY, {"type": "null"}]},
        "reasoning": {"type": ["string", "null"]},
    },
}

TESTS_RESPONSE = {
    "type": "object",
    "required": ["test_cases"],
    "properties": {
        "test_cases": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "type"],
                "properties": {"name": {"type": "string"}, "type": {"type": "string"}},
            },
        }
    },
}

FINDINGS_FILE = {
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file", "title", "severity"],
                "properties": {
                    "id": {"type": "string"},
                    "file": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
                    "line": {"type": ["integer", "null"]},
                    "cwe": {"type": "string"},
                    "status": {"type": "string"},
                },
            },
        }
    },
}

_VALIDATORS = {
    "findings": Draft202012Validator(FINDINGS_RESPONSE),
    "validation": Draft202012Validator(VALIDATION_RESPONSE),
    "tests": Draft202012Validator(TESTS_RESPONSE),
    "findings_file": Draft202012Validator(FINDINGS_FILE),
}


def schema_errors(kind: str, data: Any) -> list[str]:
    """Return human-readable schema violations (empty list if valid)."""
    v = _VALIDATORS[kind]
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(v.iter_errors(data), key=lambda e: list(e.absolute_path))
    ][:10]
