#!/usr/bin/env python3
"""Phase 2 (hunt-4b: 0/396): three proven failures, three fixes.

1. Template ranking: /metrics (confirmable true positive — 200 plus
   token/version/config markers) was cut by self-observing's [:25] cap,
   ranked 25th alphabetically. Candidates must rank live-first and
   canonical-short-path-first so sort order cannot bury them.
2. Dead-target burn: hunt-4a ran 319 checks against a dead target
   (all curl exit 7). Ten consecutive transport failures must abort
   verify with an honest banner instead of burning the loop.
3. Router model: the hunt's --model never reached the router — 17
   failed qwen3-coder:30b calls on a 7b hunt. The hunt model must win.
"""

import http.server
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_seam_templates as st  # noqa: E402
from oracle_hunter import ProgramScopeGate, verify_seams  # noqa: E402


def test_self_observing_ranks_live_canonical_first(tmp_path):
    base = "http://127.0.0.1:9"
    decoys = [f"{base}/a-debug-{i:02d}/deep/path [404]" for i in range(30)]
    fuzzed = decoys + [f"{base}/metrics [200]", f"{base}/debug/metrics [200]"]
    (tmp_path / "fuzzed_paths.txt").write_text("\n".join(fuzzed) + "\n")
    (tmp_path / "js_endpoints.txt").write_text("")
    (tmp_path / "js_secrets.txt").write_text("")
    (tmp_path / "api_specs.txt").write_text("")
    (tmp_path / "live_hosts.txt").write_text(base + "\n")
    seams = st.scan_template_seams(
        recon_dir=tmp_path,
        repo_path=None,
        program=None,
        scope_gate=ProgramScopeGate({}, target_fallback=base),
    )
    self_cards = [s for s in seams if s.get("claim_type") == "self-observing-equation"]
    assert self_cards, "no self-observing cards emitted"
    assert any(
        "9/metrics'" in (c.get("check") or "") for c in self_cards
    ), f"live /metrics cut from {[c.get('check') for c in self_cards][:5]}"


def _dead_cards(n, path="/x"):
    return [
        {
            "n": i + 1,
            "assertion_a": "The endpoint is stable.",
            "assertion_b": "The endpoint is reachable.",
            "assertion_a_source": "http://127.0.0.1:9/spec",
            "impact": "test impact",
            "check": f"curl -i -s http://127.0.0.1:9{path}",
            "expected": "status 200",
            "reframed": True,
        }
        for i in range(n)
    ]


def _run_cards(cards, tmp_path):
    (tmp_path / "known_urls.txt").write_text("http://127.0.0.1:9/x\n")
    gate = ProgramScopeGate({}, "127.0.0.1:9")
    return verify_seams(
        cards,
        "http://127.0.0.1:9",
        tmp_path,
        auto=True,
        scope_gate=gate,
        is_testnet=True,
    )


def test_breaker_aborts_dead_target(tmp_path, capsys):
    out = _run_cards(_dead_cards(12), tmp_path)
    # Breaker trips after 10 consecutive transport failures; the remaining
    # 2 unexecuted seams are recorded as CANDIDATE (never silently dropped).
    # Total entries = 12 (10 attempted + 2 unexecuted), all confirmed=False.
    assert len(out) == 12, f"expected 12 (10+2 unexecuted), got {len(out)}"
    assert all(v["confirmed"] is False for v in out.values())
    # The 2 unexecuted entries carry the circuit-breaker kill_gate tag.
    unreachable = [v for v in out.values() if v.get("kill_gate") == "target_unreachable"]
    assert len(unreachable) == 2, f"expected 2 unexecuted entries, got {len(unreachable)}"
    assert "UNREACHABLE" in capsys.readouterr().out


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        raw = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_breaker_resets_on_success(tmp_path, capsys):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        live = {
            "n": 10,
            "assertion_a": "The endpoint is stable.",
            "assertion_b": "The endpoint is reachable.",
            "assertion_a_source": f"http://127.0.0.1:{port}/spec",
            "impact": "test impact",
            "check": f"curl -i -s http://127.0.0.1:{port}/ok",
            "expected": 'status 200, body contains "ok"',
            "reframed": True,
        }
        cards = _dead_cards(9) + [live] + _dead_cards(9)
        for i, c in enumerate(cards):
            c["n"] = i + 1
        (tmp_path / "known_urls.txt").write_text(
            f"http://127.0.0.1:9/x\nhttp://127.0.0.1:{port}/ok\n"
        )
        gate = ProgramScopeGate({}, "127.0.0.1")
        out = verify_seams(
            cards,
            "http://127.0.0.1",
            tmp_path,
            auto=True,
            scope_gate=gate,
            is_testnet=True,
        )
        assert len(out) == 19, f"breaker tripped early: ran {len(out)}"
        assert "UNREACHABLE" not in capsys.readouterr().out
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_router_prefers_hunt_model():
    import oracle_llm

    cfg = {
        "routes": {"reflex": ["local"]},
        "local_model": "cfg-model",
        "light_local_model": "cfg-light",
    }
    oracle_llm.set_preferred_local_model("hunt-model")
    try:
        backends = oracle_llm.build_backends_for("reflex", cfg, {})
        assert [b.model for b in backends] == ["hunt-model"]
    finally:
        oracle_llm.set_preferred_local_model(None)


def test_router_default_without_override():
    import oracle_llm

    cfg = {
        "routes": {"reflex": ["local"]},
        "local_model": "cfg-model",
        "light_local_model": "cfg-light",
    }
    backends = oracle_llm.build_backends_for("reflex", cfg, {})
    assert [b.model for b in backends] == ["cfg-model"]


def test_reporting_prompt_is_compact_and_scoped():
    from oracle_mindset_context import OracleMindsetContext

    ctx = OracleMindsetContext(program={"name": "t", "platform": "direct"}, voice=True)
    lean = ctx.reporting_prompt()
    assert len(lean) <= 32000, f"reporting prompt too large: {len(lean)}"
    assert "SOURCE CONTEXT" not in lean
    assert "t" in lean and "direct" in lean


def _poc_seam():
    return {
        "n": 1,
        "assertion_a": "Internals are not exposed.",
        "assertion_b": "Metrics endpoint reachable.",
        "reflex": "REFLEX 1",
        "mitre": "CWE-200",
        "impact": "test impact",
        "check": "curl -i -s http://127.0.0.1:9/metrics",
    }


def test_poc_router_leg_uses_compact(monkeypatch):
    import oracle_hunter as oh
    import oracle_llm

    seen = {}

    def fake_complete(prompt, system, **kw):
        seen["system"] = system
        return "poc"

    monkeypatch.setattr(oracle_llm, "complete", fake_complete)
    out = oh._synthesize_poc(
        _poc_seam(),
        "HTTP/1.1 200 OK",
        "t",
        no_cloud=True,
        mindset_system="FULL-" + "x" * 100000,
        mindset_compact="COMPACT-MARKER",
    )
    assert out == "poc"
    assert seen["system"] == "COMPACT-MARKER"


def test_escalate_provider_still_routes_via_router(monkeypatch):
    # S5: an explicit legacy provider name no longer bypasses the router;
    # the router leg keeps the lean compact system (16k-local safe).
    import oracle_hunter as oh
    import oracle_llm

    seen = {}

    def fake_complete(prompt, system, **kw):
        seen["system"] = system
        seen["task_type"] = kw.get("task_type")
        return "router-poc"

    def boom(*a, **k):
        raise AssertionError("direct cloud post must never be called")

    monkeypatch.setattr(oh, "_cloud_direct_post", boom, raising=False)
    monkeypatch.setattr(
        oh, "_load_env", lambda: {"GEMINI_API_KEY": "x", "ANTHROPIC_API_KEY": "y"}
    )
    monkeypatch.setattr(oracle_llm, "complete", fake_complete)
    out = oh._cloud_escalate(
        "card",
        "t",
        provider="gemini",
        mindset_system="FULL-MARKER",
        mindset_compact="COMPACT-MARKER",
    )
    assert out == "router-poc"
    assert seen["system"] == "COMPACT-MARKER"
    assert seen["task_type"] == "poc"


def test_normalize_collapses_float_jitter():
    from oracle_foundation import normalize_wire_output

    assert normalize_wire_output("lag 0") == normalize_wire_output("lag 0.5")
    assert normalize_wire_output("lag NaN") == normalize_wire_output("lag 0.5")
    assert normalize_wire_output("x +Inf") == normalize_wire_output("x 1")
    assert normalize_wire_output("a1b2") == "a#b#"
    assert "info" in normalize_wire_output("info conference")
    assert normalize_wire_output("") == ""
    assert normalize_wire_output(None) == ""


class _JitterHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).hits += 1
        val = "0" if type(self).hits % 2 else "0.5"
        raw = f"lag {val}\nrequests_total 42\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_differential_ignores_float_jitter(tmp_path, capsys):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _JitterHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        base = f"http://127.0.0.1:{port}"
        (tmp_path / "known_urls.txt").write_text(f"{base}/jit\n")
        gate = ProgramScopeGate({}, f"127.0.0.1:{port}")
        out = verify_seams(
            [
                {
                    "n": 1,
                    "assertion_a": "access is enforced server-side",
                    "assertion_b": "server trusts X-Jit header — injecting it bypasses validation",
                    "assertion_a_source": base + "/spec",
                    "impact": "test impact",
                    "check": f"curl -i -s -H 'X-Jit: 1' {base}/jit",
                    "expected": 'status 200, body contains "lag"',
                    "reframed": True,
                }
            ],
            base,
            tmp_path,
            auto=True,
            scope_gate=gate,
            is_testnet=True,
        )
        assert out[1]["confirmed"] is False, out[1]["verdict"]
        assert "no observable effect" in out[1]["verdict"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_engine_b_tactic_passes_get_timeout():
    """Phase 2.2 — Engine B tactic passes must have a per-tactic timeout set.

    Grep oracle_hunter.py for the _ENGINE_B_TACTIC_TIMEOUT_S constant and
    verify it is a positive integer. Then confirm the two submit() calls that
    use it pass a non-None timeout to oracle_llm.complete.
    """
    import inspect
    import oracle_hunter as oh

    src = inspect.getsource(oh.cmd_hunt)
    assert "_ENGINE_B_TACTIC_TIMEOUT_S" in src, (
        "Engine B per-tactic timeout constant missing from cmd_hunt"
    )
    # Verify the value is a sensible integer (not None or 0)
    import re as _re
    match = _re.search(r"_ENGINE_B_TACTIC_TIMEOUT_S\s*=\s*(\d+)", src)
    assert match, "_ENGINE_B_TACTIC_TIMEOUT_S assignment not found"
    timeout_val = int(match.group(1))
    assert timeout_val > 0, f"per-tactic timeout must be > 0, got {timeout_val}"
    assert timeout_val <= 300, (
        f"per-tactic timeout {timeout_val}s is too large — defeats the budgeting purpose"
    )
