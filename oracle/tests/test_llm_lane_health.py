"""Lane health contracts: dead lanes must not be re-walked every pass.

The HERE live hunt starved because each pass serially re-tried dead
lanes (exhausted Databricks, TPM-rejecting Groq) until the 420s
collection deadline, then the 180s ladder retry did it again. These
tests pin: per-run circuit breaker, total router/lane time budgets,
and per-lane request-size caps.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_llm as L
import pytest


@pytest.fixture(autouse=True)
def _reset():
    L.reset_round_robin()
    yield
    L.reset_round_robin()


class Fake(L.Backend):
    def __init__(self, name, ok=True, delay=0.0, max_request_tokens=None):
        self.name, self.ok, self.delay = name, ok, delay
        self.context_tokens = 128000
        self.max_request_tokens = max_request_tokens
        self.calls = 0

    def available(self):
        return True

    def complete(self, system, prompt, timeout=None):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if not self.ok:
            raise L.BackendError(f"{self.name} exhausted")
        return "OUT"


def _route(monkeypatch, lanes):
    monkeypatch.setattr(
        L, "build_backends_for", lambda t, c, e, **kw: list(lanes)
    )
    return {"round_robin": False}


def test_failed_lane_skipped_on_next_call_until_reset(monkeypatch):
    dead, ok = Fake("dead", ok=False), Fake("ok")
    cfg = _route(monkeypatch, [dead, ok])
    assert L.complete("p", "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert dead.calls == 1
    # Second call in the same run: dead lane is in cooldown, not re-walked.
    assert L.complete("p", "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert dead.calls == 1
    # Reset re-enables it.
    L.reset_lane_health()
    assert L.complete("p", "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert dead.calls == 2


def test_lane_recovers_after_cooldown_and_success_clears(monkeypatch):
    flaky = Fake("flaky", ok=False)
    # Second (also failing) lane keeps this off the sole-lane exemption
    # while still exhausting the router.
    cfg = _route(monkeypatch, [flaky, Fake("other", ok=False)])
    monkeypatch.setattr(L, "_LANE_COOLDOWN_S", 0.05)
    with pytest.raises(RuntimeError):
        L.complete("p", "s", "reflex", cfg=cfg, env={})
    assert L._lane_is_down("flaky")
    time.sleep(0.07)
    assert not L._lane_is_down("flaky")
    flaky.ok = True
    assert L.complete("p", "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert not L._lane_is_down("flaky")


def test_max_request_tokens_skips_big_prompt_only(monkeypatch):
    capped = Fake("capped", max_request_tokens=10)
    ok = Fake("ok")
    cfg = _route(monkeypatch, [capped, ok])
    big = "x" * 400  # ~100 est tokens > cap 10
    assert L.complete(big, "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert capped.calls == 0
    assert L.complete("tiny", "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert capped.calls == 1


def test_router_total_budget_stops_between_lanes(monkeypatch):
    slow = Fake("slow", ok=False, delay=0.3)
    never = Fake("never")
    cfg = _route(monkeypatch, [slow, never])
    with pytest.raises(RuntimeError, match="timeout-budget-exhausted"):
        L.complete("p", "s", "reflex", timeout=0.05, cfg=cfg, env={})
    assert never.calls == 0


def test_lane_timeout_slice_reserves_later_lanes():
    assert L._lane_timeout_slice(360, 1) == 360
    assert L._lane_timeout_slice(360, 5) == 120
    assert L._lane_timeout_slice(360, 12) == 30
    assert L._lane_timeout_slice(150, 3) == 90
    assert L._lane_timeout_slice(120, 12) == 10
    assert L._lane_timeout_slice(0, 3) == 0


class TimeoutHonoringFake(Fake):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeouts = []

    def complete(self, system, prompt, timeout=None):
        self.calls += 1
        self.timeouts.append(timeout)
        if timeout is not None and self.delay > timeout:
            time.sleep(timeout)
            raise L.BackendError("lane-deadline")
        if self.delay:
            time.sleep(self.delay)
        if not self.ok:
            raise L.BackendError(f"{self.name} exhausted")
        return "OUT"


def test_slow_lane_slice_leaves_budget_for_later_lanes(monkeypatch):
    slow_a = TimeoutHonoringFake("slow-a", ok=True, delay=1.0)
    slow_b = TimeoutHonoringFake("slow-b", ok=True, delay=1.0)
    ok = TimeoutHonoringFake("ok", ok=True, delay=0.0)
    cfg = _route(monkeypatch, [slow_a, slow_b, ok])

    assert L.complete("p", "s", "reflex", timeout=0.34, cfg=cfg, env={}) == "OUT"
    assert [slow_a.calls, slow_b.calls, ok.calls] == [1, 1, 1]
    assert slow_a.timeouts[0] < 0.2
    assert slow_b.timeouts[0] < 0.2


def test_lane_total_deadline_stops_model_loop(monkeypatch):
    cfg = {
        "backends": {
            "fake": {
                "base_url": "https://x.example/v1",
                "api_key_env": "FAKE_KEY",
                "context_tokens": 128000,
                "models": ["m1", "m2", "m3"],
            }
        }
    }
    b = L.OpenAICompatBackend("fake", "reflex", cfg, {"FAKE_KEY": "k"})
    tried = []

    def _slow_fail(model, system, prompt, timeout):
        tried.append(model)
        time.sleep(0.05)
        raise L.BackendError("no")

    monkeypatch.setattr(b, "_one_call", _slow_fail)
    with pytest.raises(L.BackendError, match="lane-deadline"):
        b.complete("s", "p", timeout=0.06)
    assert len(tried) <= 2  # m3 never attempted: budget spent


class Sized(Fake):
    def complete(self, system, prompt, timeout=None):
        self.calls += 1
        if len(prompt or "") > 100:
            raise L.BackendError("HTTP 413: Request too large")
        return "OUT"


def test_size_rejection_never_poisons_lane(monkeypatch):
    sized = Sized("sized")
    ok = Fake("ok")
    cfg = _route(monkeypatch, [sized, ok])
    assert L.complete("x" * 400, "s", "reflex", cfg=cfg, env={}) == "OUT"
    # Small prompt next: the lane must still serve it (size-dependent
    # failures are fits()'s job, not the breaker's).
    assert L.complete("tiny", "s", "poc", cfg=cfg, env={}) == "OUT"
    assert sized.calls == 2


@pytest.mark.parametrize(
    "message",
    [
        "lane-deadline",
        "ollama qwen: exceeded timeout=120s",
        "omnicli: lane deadline already spent (0.0s); not dispatched",
        "omnicli: timed out after 120.0s — run_orchestration worker abandoned (daemon)",
    ],
)
def test_own_deadline_variants_never_trip_breaker(message):
    assert not L._failure_trips_breaker(L.BackendError(message), 120, False)


@pytest.mark.parametrize(
    "message",
    [
        "provider: timeout",
        "groq: upstream timed out after 3 retries",
    ],
)
def test_provider_timeout_wording_still_trips_breaker(message):
    assert L._failure_trips_breaker(L.BackendError(message), 120, False)


def test_starved_slice_never_poisons_lane(monkeypatch):
    slow = Fake("slow", ok=False, delay=0.05)
    ok = Fake("ok")
    cfg = _route(monkeypatch, [slow, ok])
    # Allotted slice (10s total budget, first lane gets <30s fair-shot
    # floor after remaining-time math) — use a tiny total timeout so
    # the slice is far below the floor.
    assert L.complete("p", "s", "reflex", timeout=10, cfg=cfg, env={}) == "OUT"
    assert not L._lane_is_down(L._lane_key(slow))


def test_sole_lane_never_marked_down(monkeypatch):
    only = Fake("only", ok=False)
    cfg = _route(monkeypatch, [only])
    with pytest.raises(RuntimeError):
        L.complete("p", "s", "reflex", cfg=cfg, env={})
    # Marking the only lane down would turn one failure into a
    # guaranteed 600s total outage (--no-cloud local-only hunts).
    assert not L._lane_is_down(L._lane_key(only))
    only.ok = True
    assert L.complete("p", "s", "reflex", cfg=cfg, env={}) == "OUT"


def test_local_light_heavy_do_not_poison_each_other(monkeypatch):
    heavy = Fake("local", ok=False)
    heavy.model = "qwen3-coder:30b-16k"
    light = Fake("local")
    light.model = "qwen2.5-coder:14b-16k"
    filler = Fake("filler")
    cfg = _route(monkeypatch, [heavy, filler])
    assert L.complete("p", "s", "reflex", cfg=cfg, env={}) == "OUT"
    assert L._lane_is_down(L._lane_key(heavy))
    assert not L._lane_is_down(L._lane_key(light))


def test_invalid_request_cap_fails_closed_without_raising():
    for bad in ("8k", 0, -5, object()):
        f = Fake("x")
        f.max_request_tokens = bad
        assert f.fits(10) is False


def test_transient_retry_recovers_under_deadline(monkeypatch):
    cfg = {
        "backends": {
            "fake": {
                "base_url": "https://x.example/v1",
                "api_key_env": "FAKE_KEY",
                "context_tokens": 128000,
                "models": ["m1"],
            }
        }
    }
    b = L.OpenAICompatBackend("fake", "reflex", cfg, {"FAKE_KEY": "k"})
    attempts = {"n": 0}

    def _flaky(model, system, prompt, timeout):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ConnectionError("IncompleteRead(135194 bytes read)")
        return "RECOVERED"

    monkeypatch.setattr(b, "_one_call", _flaky)
    monkeypatch.setattr(L.time, "sleep", lambda s: None)
    assert b.complete("s", "p", timeout=60) == "RECOVERED"
    assert attempts["n"] == 2


def test_groq_config_carries_request_cap():
    cfg = L.load_backend_config()
    b = L.OpenAICompatBackend("groq", "reflex", cfg, {"GROQ_API_KEY": "k"})
    assert b.max_request_tokens == 8000
    assert b.fits(7000)
    assert not b.fits(9000)
    # Mindset prompts (~68k-105k est tokens) must skip Groq fast.
    assert not b.fits(68000)
