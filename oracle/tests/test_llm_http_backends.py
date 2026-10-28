import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import pytest


def test_openrouter_unavailable_without_key():
    b = L.OpenRouterBackend("reflex", L.DEFAULT_CONFIG, env={})
    assert b.available() is False


def test_openrouter_raises_when_all_models_fail(monkeypatch):
    b = L.OpenRouterBackend("reflex", L.DEFAULT_CONFIG, env={"OPENROUTER_API_KEY": "k"})
    monkeypatch.setattr(b, "_models", lambda: ["m1:free", "m2:free"])

    def boom(model, system, prompt, timeout):
        raise L.BackendError("429")

    monkeypatch.setattr(b, "_one_call", boom)
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt", timeout=5)


def test_ollama_unavailable_when_down(monkeypatch):
    b = L.OllamaBackend("devstral:24b")
    monkeypatch.setattr(b, "_ping", lambda: False)
    assert b.available() is False


class _FakeStreamResp:
    def __init__(self, lines, ok=True):
        self._lines = lines
        self.ok = ok
        self.status_code = 200 if ok else 500
        self.seen_timeout = None
        self.seen_stream = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_lines(self):
        return iter(self._lines)


def test_ollama_complete_assembles_stream(monkeypatch):
    import json as _json

    b = L.OllamaBackend("m")
    lines = [
        _json.dumps({"response": "Hel", "done": False}).encode(),
        b"",
        _json.dumps({"response": "lo", "done": True}).encode(),
    ]
    fake = _FakeStreamResp(lines)
    captured = {}

    def fake_post(*a, **kw):
        captured.update(kw)
        return fake

    monkeypatch.setattr(L.requests, "post", fake_post)
    assert b.complete("sys", "prompt") == "Hello"
    assert captured["stream"] is True
    assert captured["timeout"] == (10, 600)  # idle watchdog, no total cap
    assert captured["json"]["stream"] is True


def test_ollama_complete_deadline_enforced(monkeypatch):
    import json as _json

    b = L.OllamaBackend("m")
    fake = _FakeStreamResp([_json.dumps({"response": "x"}).encode()])
    monkeypatch.setattr(L.requests, "post", lambda *a, **kw: fake)
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt", timeout=0)


def test_ollama_complete_errors_fail_closed(monkeypatch):
    b = L.OllamaBackend("m")
    monkeypatch.setattr(
        L.requests, "post", lambda *a, **kw: _FakeStreamResp([], ok=False)
    )
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt")
    monkeypatch.setattr(L.requests, "post", lambda *a, **kw: _FakeStreamResp([]))
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt")
