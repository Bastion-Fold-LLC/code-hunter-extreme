"""Final-review fix tests.

Covers the security-review findings that touch the router work:
- #5 fail-open/cascade: a backend raising a NON-BackendError must not crash the
  router; it must cascade, and exhaustion must still raise RuntimeError.
- #5b: OpenRouter discovery failure surfaces as BackendError, not a raw OSError.
- #3 parser-differential: a stray line-start 'SEAM N' with no card body must not
  manufacture a phantom finding.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import oracle_hunter as oh
import pytest


class Raiser(L.Backend):
    def __init__(self, name, exc):
        self.name, self.exc = name, exc

    def available(self):
        return True

    def complete(self, system, prompt, timeout=None):
        raise self.exc


def test_router_cascades_past_non_backenderror(monkeypatch):
    class OK(L.Backend):
        name = "ok"

        def available(self):
            return True

        def complete(self, system, prompt, timeout=None):
            return "GOOD"

    order = [Raiser("boom", ValueError("kaboom")), OK()]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    assert L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={}) == "GOOD"


def test_router_all_raise_nonbackenderror_still_raises_runtimeerror(monkeypatch):
    order = [Raiser("a", OSError("net")), Raiser("b", ValueError("x"))]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    with pytest.raises(RuntimeError):
        L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={})


def test_openrouter_discovery_failure_is_backenderror(monkeypatch):
    b = L.OpenRouterBackend("reflex", L.DEFAULT_CONFIG, env={"OPENROUTER_API_KEY": "k"})

    def boom():
        raise OSError("discovery network down")

    monkeypatch.setattr(b, "_models", boom)
    with pytest.raises(L.BackendError):
        b.complete("s", "p", timeout=5)


def test_stray_seam_line_without_body_is_not_a_card():
    # A line-start 'SEAM 1' in prose with no assertions/check must be discarded.
    raw = "Analysis: SEAM 1 would be interesting but nothing was found here.\nClean."
    assert len(oh._parse_seams(raw, target_base="http://x")) == 0
