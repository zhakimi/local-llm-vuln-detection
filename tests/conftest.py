"""Shared fixtures. No test needs a running Ollama server or network access."""

from __future__ import annotations

import json
import re
from typing import Callable

import pytest

from scanner.analyzer import ClientStats


class FakeClient:
    """Stands in for OllamaClient. ``responder(prompt) -> str`` returns raw model text."""

    def __init__(self, responder: Callable[[str], str]):
        self.responder = responder
        self.prompts: list[str] = []
        self.model = "fake-model"
        self.host = "http://localhost:11434"
        self.is_local = True
        self.stats = ClientStats()

    def generate(self, prompt: str, system=None, json_mode=True) -> str:
        self.prompts.append(prompt)
        self.stats.generations += 1
        return self.responder(prompt)

    def ensure_ready(self) -> None:
        pass

    def model_info(self) -> dict:
        return {"name": self.model, "host": self.host, "host_is_loopback": True, "digest": "sha256:fake"}


def finding(title, line, snippet, severity="high", cwe="CWE-89", **extra):
    return {"title": title, "severity": severity, "cwe": cwe, "line": line, "snippet": snippet,
            "description": "d", "remediation": "r", **extra}


def scripted(findings_by_marker: dict[str, list[dict]], verdict: dict | None = None) -> Callable[[str], str]:
    """Return findings when a marker string occurs in the prompt; answer validation prompts with ``verdict``."""
    verdict = verdict or {"is_vulnerability": True, "confidence": 0.9, "severity": "high", "reasoning": "ok"}

    def respond(prompt: str) -> str:
        if "is_vulnerability" in prompt:
            return json.dumps(verdict)
        if "test_cases" in prompt:
            return json.dumps({"test_cases": [{"name": "t1", "type": "payload", "payload": "' OR 1=1 --"}]})
        for marker, fs in findings_by_marker.items():
            if re.search(marker, prompt):
                return json.dumps({"findings": fs})
        return json.dumps({"findings": []})

    return respond


@pytest.fixture
def make_client():
    return FakeClient
