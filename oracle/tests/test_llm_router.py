import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import pytest


@pytest.fixture(autouse=True)
def reset_no_cloud():
    """Keep process-wide cloud policy from leaking across test modules."""
    L.set_no_cloud(False)
    L.reset_round_robin()
    yield
    L.set_no_cloud(False)
    L.reset_round_robin()


class Fake(L.Backend):
    def __init__(self, name, ok, out="OUT", avail=True):
        self.name, self.ok, self.out, self._avail = name, ok, out, avail

    def available(self):
        return self._avail

    def complete(self, system, prompt, timeout=None):
        if not self.ok:
            raise L.BackendError(f"{self.name} boom")
        return self.out


def test_round_robin_spreads_across_backends(monkeypatch):
    """Phase 1a GATE: test issues N calls and asserts they land on >=2 distinct backends (not all one lane)."""
    L.reset_round_robin()
    calls = []

    class TrackingFake(Fake):
        def complete(self, system, prompt, timeout=None):
            calls.append(self.name)
            return f"OUT_{self.name}"

    backends = [
        TrackingFake("lane_a", ok=True),
        TrackingFake("lane_b", ok=True),
        TrackingFake("lane_c", ok=True),
    ]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: list(backends))

    results = [L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={}) for _ in range(6)]

    assert len(calls) == 6
    distinct = set(calls)
    assert len(distinct) >= 2, f"Expected calls to spread across >=2 distinct backends, got: {distinct}"
    assert distinct == {"lane_a", "lane_b", "lane_c"}
    assert calls[:3] == ["lane_a", "lane_b", "lane_c"]


def test_returns_first_success(monkeypatch):
    order = [Fake("a", ok=False), Fake("b", ok=True, out="B")]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: list(order))
    assert L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={}) == "B"


def test_skips_unavailable(monkeypatch):
    order = [Fake("a", ok=True, out="A", avail=False), Fake("b", ok=True, out="B")]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    assert L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={}) == "B"


def test_oversized_prompt_skips_lane_that_cannot_hold_it(monkeypatch):
    small = Fake("small", ok=True, out="SMALL")
    small.context_tokens = 10
    big = Fake("big", ok=True, out="BIG")
    order = [small, big]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: list(order))
    out = L.complete("x" * 400, "s", "reflex", cfg=L.DEFAULT_CONFIG, env={})
    assert out == "BIG"


def test_all_lanes_overflow_fails_loud(monkeypatch):
    small = Fake("small", ok=True, out="SMALL")
    small.context_tokens = 10
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: [small])
    with pytest.raises(RuntimeError, match="context-overflow"):
        L.complete("x" * 400, "s", "reflex", cfg=L.DEFAULT_CONFIG, env={})


def test_smallest_viable_lane_limit_ignores_unusable_lanes(monkeypatch):
    tiny = Fake("tiny", ok=True)
    tiny.context_tokens = 800
    unknown = Fake("unknown", ok=True)
    unknown.context_tokens = None
    unavailable = Fake("unavailable", ok=True, avail=False)
    unavailable.context_tokens = 16000
    down = Fake("down", ok=True)
    down.context_tokens = 16000
    local = Fake("local", ok=True)
    local.context_tokens = 16000
    local.max_request_tokens = 12000
    cloud = Fake("cloud", ok=True)
    cloud.context_tokens = 128000
    backends = [tiny, unknown, unavailable, down, local, cloud]
    L._mark_lane_down(L._lane_key(down))
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: list(backends))

    assert L.viable_lane_limits(backends, minimum_tokens=1000) == [
        ("local", 12000),
        ("cloud", 128000),
    ]
    assert (
        L.smallest_viable_lane_limit(
            cfg=L.DEFAULT_CONFIG, env={}, minimum_tokens=1000
        )
        == 12000
    )
    assert (
        L.smallest_viable_lane_limit(
            cfg=L.DEFAULT_CONFIG, env={}, minimum_tokens=200000
        )
        is None
    )


def test_local_backend_carries_configured_context():
    cfg = L.load_backend_config()
    assert cfg["local_context_tokens"] == 16000
    backends = L.build_backends_for("reflex", cfg, env={})
    local = [b for b in backends if isinstance(b, L.OllamaBackend)][0]
    assert local.context_tokens == 16000


def test_cloud_gate_counts_every_configured_lane():
    cfg = L.load_backend_config()
    cfg["routes"] = {"reflex": ["groq", "nvidia", "local"]}
    assert L.cloud_lane_available(cfg, {"GROQ_API_KEY": "x"}) is True
    assert L.cloud_lane_available(cfg, {}) is False


def test_trace_spans_record_attempts_without_prompt_text(monkeypatch, tmp_path):
    import json as _json

    path = tmp_path / "traces.jsonl"
    a = Fake("a", ok=False)
    b = Fake("b", ok=True, out="TRACED")
    order = [a, b]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: list(order))
    env = {"ORACLE_TRACE": "1", "ORACLE_TRACE_FILE": str(path)}
    out = L.complete("SECRET-PROMPT", "SYSTEM", "reflex", cfg=L.DEFAULT_CONFIG, env=env)
    assert out == "TRACED"
    spans = [_json.loads(ln) for ln in path.read_text().splitlines()]
    attempts = [s for s in spans if s["span"] == "backend_attempt"]
    assert [s["status"] for s in attempts] == ["failed", "ok"]
    assert attempts[0]["backend"] == "a" and attempts[1]["backend"] == "b"
    assert attempts[0]["trace_id"] == attempts[1]["trace_id"]
    text = path.read_text()
    assert "SECRET-PROMPT" not in text and "SYSTEM" not in text


def test_trace_off_by_default(monkeypatch, tmp_path):
    path = tmp_path / "traces.jsonl"
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e, **kw: [Fake("a", ok=True)])
    monkeypatch.delenv("ORACLE_TRACE", raising=False)
    monkeypatch.setenv("ORACLE_TRACE_FILE", str(path))
    L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={})
    assert not path.exists()


def test_all_fail_raises(monkeypatch):
    # fail-closed: exhaustion raises, never returns a sentinel/placeholder string
    order = [Fake("a", ok=False), Fake("b", ok=False)]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    with pytest.raises(RuntimeError):
        L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={})


def test_build_backends_maps_names():
    cfg = L.DEFAULT_CONFIG
    backends = L.build_backends_for("reflex", cfg, env={})
    names = [b.name for b in backends]
    assert names == ["openrouter", "nvidia", "local"]
    assert isinstance(backends[0], L.OpenRouterBackend)
    assert isinstance(backends[1], L.NvidiaNimBackend)
    assert isinstance(backends[2], L.OllamaBackend)


def test_build_backends_light_task_uses_light_model():
    cfg = L.DEFAULT_CONFIG
    backends = L.build_backends_for("assess", cfg, env={})
    local = [b for b in backends if isinstance(b, L.OllamaBackend)][0]
    assert local.model == cfg["light_local_model"]


def test_second_vote_packet_fits_budget_top_ranked_first():
    seams = [
        {
            "n": i,
            "mindset": "mitre",
            "severity": "high",
            "assertion_a": "claim " + "a" * 200,
            "assertion_b": "reality " + "b" * 200,
            "check": "curl -i https://h.test/api",
            "expected": "status 200",
            "redteam_verdict": "confirmed",
        }
        for i in range(1, 6)
    ]
    packet, included = L.build_second_vote_packet(seams, "SYS", budget_tokens=300)
    assert included == list(range(len(included)))
    assert 0 < len(included) < 5
    assert L.estimate_tokens("SYS", packet) <= 300
    assert "SEAM 1" in packet


def test_second_vote_packet_empty_when_no_seams():
    assert L.build_second_vote_packet([], "SYS", budget_tokens=16000) == ("", [])


def test_collaboration_runs_scout_adversary_and_private_roles(monkeypatch):
    class NamedFake(Fake):
        def complete(self, system, prompt, timeout=None):
            self.last_model = f"{self.name}-model"
            return super().complete(system, prompt, timeout)

    # Roles are deliberately different families: scout runs on the
    # Databricks generation lane, the adversary on the OmniCLI swarm
    # (independent model families), private review stays local.
    backends = [
        NamedFake("databricks", ok=True, out="SCOUT"),
        NamedFake("omnicli", ok=True, out="ADVERSARY"),
        NamedFake("local", ok=True, out="PRIVATE"),
    ]
    monkeypatch.setattr(L, "build_backends_for", lambda *args, **kwargs: backends)

    result = L.collaborate("EVIDENCE", "SYSTEM", cfg=L.DEFAULT_CONFIG, env={})

    assert result["scout"]["output"] == "SCOUT"
    assert result["adversary"]["output"] == "ADVERSARY"
    assert result["private_reviewer"]["output"] == "PRIVATE"
    assert result["scout"]["model"] == "databricks-model"
    assert result["adversary"]["model"] == "omnicli-model"
    assert result["adversary"]["backend"] == "omnicli"
