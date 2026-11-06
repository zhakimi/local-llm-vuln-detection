"""OllamaClient integration tests with the HTTP layer mocked (no server needed)."""

from __future__ import annotations

from unittest import mock

import pytest
import requests

from scanner.analyzer import NOT_RUNNING, OllamaClient, OllamaError, OllamaTimeout
from scanner.safety import RemoteHostError


def _resp(status=200, payload=None):
    r = mock.Mock(spec=requests.Response)
    r.status_code = status
    r.ok = status < 400
    r.json.return_value = payload if payload is not None else {}
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f"{status} error", response=r)
    else:
        r.raise_for_status.return_value = None
    return r


@pytest.fixture
def client():
    c = OllamaClient(host="http://localhost:11434", model="llama3.2", retry_backoff=0, seed=7)
    c.session = mock.Mock()
    return c


def test_generate_posts_to_api_generate_with_json_mode(client):
    client.session.post.return_value = _resp(200, {"response": '{"findings": []}', "eval_count": 5})
    out = client.generate("PROMPT", system="SYS")
    assert out == '{"findings": []}'
    url = client.session.post.call_args.args[0]
    body = client.session.post.call_args.kwargs["json"]
    assert url == "http://localhost:11434/api/generate"
    assert body["format"] == "json" and body["stream"] is False
    assert body["system"] == "SYS" and body["model"] == "llama3.2"
    assert body["options"] == {"temperature": 0.1, "num_ctx": 8192, "num_predict": 2048, "seed": 7}
    assert client.stats.generations == 1


def test_retries_transient_5xx_then_succeeds(client):
    client.session.post.side_effect = [_resp(500), _resp(200, {"response": "{}"})]
    assert client.generate("p") == "{}"
    assert client.session.post.call_count == 2
    assert client.stats.http_retries == 1


def test_gives_up_after_three_5xx(client):
    client.session.post.side_effect = [_resp(500)] * 3
    with pytest.raises(OllamaError, match="Ollama request failed"):
        client.generate("p")


def test_4xx_is_not_retried(client):
    client.session.post.side_effect = [_resp(404)]
    with pytest.raises(OllamaError):
        client.generate("p")
    assert client.session.post.call_count == 1


def test_connection_error_reports_not_running(client):
    client.session.post.side_effect = requests.ConnectionError("refused")
    with pytest.raises(OllamaError, match="Ollama is not running. Run setup.sh first."):
        client.generate("p")


def test_timeout_raises_ollama_timeout(client):
    client.session.post.side_effect = requests.Timeout("slow")
    with pytest.raises(OllamaTimeout):
        client.generate("p")
    assert client.stats.timeouts == 1


def test_list_models_unreachable(client):
    client.session.get.side_effect = requests.ConnectionError("refused")
    with pytest.raises(OllamaError, match=NOT_RUNNING):
        client.ensure_ready()


def test_missing_model_message(client):
    client.session.get.return_value = _resp(200, {"models": [{"name": "mistral:latest"}]})
    with pytest.raises(OllamaError, match="ollama pull llama3.2"):
        client.ensure_ready()


def test_model_info_records_digest_and_quantization(client):
    client.session.get.side_effect = [
        _resp(200, {"models": [{"name": "llama3.2:latest", "digest": "abc", "size": 10}]}),
        _resp(200, {"version": "0.40.15"}),
    ]
    client.session.post.return_value = _resp(200, {
        "details": {"family": "llama", "parameter_size": "3.2B", "quantization_level": "Q4_K_M", "format": "gguf"},
        "model_info": {"llama.context_length": 131072},
    })
    info = client.model_info()
    assert info["digest"] == "abc" and info["quantization"] == "Q4_K_M"
    assert info["trained_context_length"] == 131072 and info["ollama_version"] == "0.40.15"
    assert info["host_is_loopback"] is True


def test_remote_host_is_refused_by_default():
    with pytest.raises(RemoteHostError):
        OllamaClient(host="http://192.0.2.10:11434")
    c = OllamaClient(host="http://192.0.2.10:11434", allow_remote=True)
    assert c.is_local is False


def test_proxy_environment_is_ignored():
    assert OllamaClient().session.trust_env is False
