#!/usr/bin/env python3
"""Test that Backend.fits() enforces context bounds and rejects unknown or overflowing windows."""

import pytest
import oracle_llm as ollm


def test_fits_rejects_none_window():
    """An unknown context window (None) must return False (fail-closed, no blind dispatch)."""
    b = ollm.Backend()
    b.context_tokens = None
    assert b.fits(100) is False


def test_fits_accepts_within_window():
    b = ollm.Backend()
    b.context_tokens = 4000
    assert b.fits(1000) is True
    assert b.fits(4000) is True
    assert b.fits(4001) is False


def test_complete_skips_overflowing_backend(monkeypatch):
    """When a prompt exceeds a backend's context_tokens, that backend is skipped."""
    cfg = {
        "routes": {"reflex": ["test_small", "test_large"]},
        "backends": {
            "test_small": {
                "base_url": "https://fake.small/v1",
                "api_key_env": "FAKE_KEY",
                "context_tokens": 100,
            },
            "test_large": {
                "base_url": "https://fake.large/v1",
                "api_key_env": "FAKE_KEY",
                "context_tokens": 10000,
            },
        },
    }
    env = {"FAKE_KEY": "dummy"}

    class DummyBackend(ollm.Backend):
        def __init__(self, name, ctx_tokens):
            self.name = name
            self.context_tokens = ctx_tokens
            self.last_model = f"{name}:m1"

        def available(self):
            return True

        def complete(self, system, prompt, timeout=None):
            return f"answered_by_{self.name}"

    backends = [
        DummyBackend("test_small", 100),
        DummyBackend("test_large", 10000),
    ]

    monkeypatch.setattr(ollm, "load_backend_config", lambda *a, **kw: cfg)
    monkeypatch.setattr(ollm, "build_backends_for", lambda *a, **kw: backends)

    # 500 chars is ~125 tokens (estimate_tokens = chars / 4)
    # This overflows test_small (100 tokens), so it must go to test_large.
    large_prompt = "x" * 500
    res = ollm.complete("system", large_prompt, task_type="reflex", env=env)
    assert res == "answered_by_test_large"


def test_complete_raises_when_all_overflow(monkeypatch):
    """When all available backends overflow, complete() must raise RuntimeError loudly."""
    class DummySmallBackend(ollm.Backend):
        def __init__(self, name):
            self.name = name
            self.context_tokens = 50

        def available(self):
            return True

        def complete(self, system, prompt, timeout=None):
            return "unexpected"

    monkeypatch.setattr(ollm, "build_backends_for", lambda *a, **kw: [DummySmallBackend("tiny")])
    huge_prompt = "x" * 1000
    with pytest.raises(RuntimeError) as exc_info:
        ollm.complete("system", huge_prompt, task_type="reflex", env={})
    assert "context-overflow" in str(exc_info.value)
