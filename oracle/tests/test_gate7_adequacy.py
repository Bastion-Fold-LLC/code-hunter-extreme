#!/usr/bin/env python3
"""Gate 7: prediction adequacy (hunt-3: 3/411 confirmed, all vacuous).

Hunt-3 proved the verifier checks prediction-MATCH but never
prediction-ADEQUACY: a bare status-200 prediction confirmed body-content
claims (seam 40), bypass claims with no executed variation (seam 7), and
header-spoof claims with no differential (seam 69). The js miner also
fingerprinted JS property plumbing (this.options.authToken) as a secret.

Rules (web-only; static-analysis cards exempt):
  A  content-claim + status-200 + no body/header discriminator -> REJECT
  S  shipped-secret claim pinned on a bare identifier -> REJECT
     (identifiers match plumbing; require assignment fragment or literal)
  B2 variation-claim whose check executes no variation -> REJECT
  B1 (hunt path) executed header variation must differ from its
     unvaried control, or -> REJECT
  C  (hunt path) spelling-twin claims must differ across twins, or -> REJECT
Plus: post-gate verdicts must be printed (hunt-3 hid Gate-6 flips
behind a stale CONFIRMED line), and direct-cloud calls must fail fast
(hunt-3 burned 120s x 16 addresses per call).
"""

import http.server
import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_deterministic import verify_seam_card  # noqa: E402
from oracle_hunter import ProgramScopeGate, verify_seams  # noqa: E402

BASE = "http://127.0.0.1:9"
BODY_200 = "HTTP/1.1 200 OK\r\n\r\n{}"


def _card(**over):
    base = {
        "n": 1,
        "assertion_a": "The endpoint is safe.",
        "assertion_a_source": BASE + "/spec",
        "assertion_b": "The endpoint is reachable.",
        "check": f"curl -i -s {BASE}/x",
        "expected": "status 200",
    }
    base.update(over)
    return base


# ── Rule A: content claims need a discriminator ───────────────────────────


def test_ruleA_content_claim_status_only_rejects():
    seam = _card(
        assertion_b="The users endpoint leaks SSNs in its response.",
        expected="status 200",
    )
    v = verify_seam_card(seam, [BASE + "/x"], status=200, body=BODY_200)
    assert v["verdict"] == "REJECTED", v["reason"]
    assert "prediction inadequate" in v["reason"]


def test_ruleA_with_marker_confirms():
    seam = _card(
        assertion_b="The users endpoint leaks SSNs in its response.",
        expected='status 200, body contains "123-45-6789"',
    )
    body = BODY_200.format('{"ssn": "123-45-6789"}')
    v = verify_seam_card(seam, [BASE + "/x"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_ruleA_crash_status_exempt():
    seam = _card(
        assertion_b="Fuzzed input produced HTTP 500 — unhandled exception (info leak).",
        expected="status 500",
    )
    body = "HTTP/1.1 500 Internal Server Error\r\n\r\nTraceback (most recent call last)"
    v = verify_seam_card(seam, [BASE + "/x"], status=500, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


# ── Rule S: shipped-secret claims need a shaped marker ────────────────────


def test_ruleS_js_bare_identifier_rejects():
    seam = _card(
        assertion_a="secrets live server-side, never ship to clients",
        assertion_b="shipped JS contains secret-shaped assignment: authToken=<redacted>",
        check=f"curl -i -s {BASE}/main.js",
        expected='status 200, body contains "authToken"',
        impact="API keys/tokens shipped to every visitor — credential exposure.",
    )
    body = BODY_200.format(
        "this.authToken=this.options.authToken,this.authTokenHeader="
    )
    v = verify_seam_card(seam, [BASE + "/main.js"], status=200, body=body)
    assert v["verdict"] == "REJECTED", v["reason"]
    assert "shaped" in v["reason"] or "identifier" in v["reason"]


def test_ruleS_js_quoted_literal_confirms():
    seam = _card(
        assertion_a="secrets live server-side, never ship to clients",
        assertion_b="shipped JS contains secret-shaped assignment: api_key=<redacted>",
        check=f"curl -i -s {BASE}/app.js",
        expected='status 200, body contains "sk-live-abcdef1234567890"',
    )
    body = BODY_200.format('const api_key = "sk-live-abcdef1234567890";')
    v = verify_seam_card(seam, [BASE + "/app.js"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_ruleS_nonjs_key_marker_confirms():
    seam = _card(
        assertion_a="Debug endpoints are disabled in staging.",
        assertion_b="Debug config exposes cloud credentials.",
        check=f"curl -i -s {BASE}/debug/config",
        expected='status 200, body contains "aws_secret"',
    )
    body = BODY_200.format('{"aws_secret": "AKIAEXAMPLE"}')
    v = verify_seam_card(seam, [BASE + "/debug/config"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


# ── Rule B2: variation claims need an executed variation ──────────────────


def test_ruleB2_bypass_plain_check_rejects():
    seam = _card(
        assertion_a="router normalizes '/api/x' to a single route",
        assertion_b="middleware may bind to one spelling only — the other bypasses it",
        check=f"curl -i -s {BASE}/api/x",
        expected="status 200",
    )
    v = verify_seam_card(seam, [BASE + "/api/x"], status=200, body=BODY_200)
    assert v["verdict"] == "REJECTED", v["reason"]
    assert "does not execute" in v["reason"]


def test_ruleB2_variation_executed_passes():
    seam = _card(
        assertion_a="access is enforced by server-side role validation",
        assertion_b="injecting X-Original-Role: admin bypasses validation",
        check=f"curl -i -s -H 'X-Original-Role: admin' {BASE}/metrics",
        expected='status 200, body contains "authorized"',
    )
    body = BODY_200.format('{"status": "authorized"}')
    v = verify_seam_card(seam, [BASE + "/metrics"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_ruleB2_reframe_exempt():
    seam = _card(
        assertion_b="stripped-auth request still reaches the endpoint",
        check=f"curl -i -s {BASE}/x",
        expected='status 200, body contains "ok"',
        reframe_transform="strip-auth",
        reframe_of=0,
    )
    body = BODY_200.format('{"ok": true}')
    v = verify_seam_card(seam, [BASE + "/x"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_ruleB2_spelling_words_are_ruleC_domain():
    seam = _card(
        assertion_b="two spellings live in client code: '/a' vs '/a/' — middleware may bind to one only",
        check=f"curl -i -s {BASE}/a",
        expected='status 200, body contains "items"',
    )
    body = BODY_200.format('{"items": []}')
    v = verify_seam_card(seam, [BASE + "/a"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_ruleB2_omission_frame_exempt():
    seam = _card(
        assertion_a="Endpoint requires admin JWT per security policy.",
        assertion_b="Endpoint returns 200 OK without Authorization header.",
        check=f"curl -i -s {BASE}/v1/users",
        expected='status 200, body contains "records"',
    )
    body = BODY_200.format('{"records": [{"id": 1}]}')
    v = verify_seam_card(seam, [BASE + "/v1/users"], status=200, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_gate7_web3_exempt():
    seam = {
        "n": 101,
        "assertion_a": "State transitions must finalize before external calls",
        "assertion_a_source": "EtherStore.sol",
        "assertion_b": "External call in withdraw() occurs before state write; reentrancy window exposed",
        "check": "slither EtherStore.sol --detect reentrancy-eth",
        "expected": 'detector "reentrancy-eth"',
    }
    body = "INFO:Detectors:\nReentrancy in EtherStore.withdraw (reentrancy-eth)\n"
    v = verify_seam_card(seam, ["EtherStore.sol"], status=0, body=body)
    assert v["verdict"] == "CONFIRMED", v["reason"]


# ── Hunt path: B1/C differentials + post-gate print ────────────────────────


class _Gate7Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        raw = payload.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/grant":
            self._send(200, '{"status": "authorized", "role": "admin"}')
        elif self.path == "/gate":
            if self.headers.get("X-Role") == "admin":
                self._send(200, '{"status": "authorized"}')
            else:
                self._send(403, '{"error": "forbidden"}')
        elif self.path in ("/api/orders", "/api/orders/"):
            self._send(200, '{"id": 1, "items": []}')
        elif self.path == "/a/route":
            self._send(403, '{"error": "forbidden"}')
        elif self.path == "/a/route/":
            self._send(200, '{"secret": "x"}')
        elif self.path == "/x":
            self._send(200, '{"ok": true}')
        else:
            self._send(404, '{"error": "nope"}')


def _serve():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Gate7Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def _run_hunt_cards(cards, tmp_path):
    httpd = _serve()
    try:
        port = httpd.server_address[1]
        base = f"http://127.0.0.1:{port}"
        known = "\n".join(
            f"{base}{p}"
            for p in (
                "/grant",
                "/gate",
                "/api/orders",
                "/api/orders/",
                "/a/route",
                "/a/route/",
                "/x",
            )
        )
        (tmp_path / "known_urls.txt").write_text(known)
        gate = ProgramScopeGate({}, f"127.0.0.1:{port}")
        for c in cards:
            c["check"] = c["check"].replace("BASE", base)
            c["assertion_a_source"] = base + "/spec"
            c.setdefault("impact", "test impact")
            text_b = c.get("assertion_b", "")
            if "BASE" in text_b:
                c["assertion_b"] = text_b.replace("BASE", base)
        return verify_seams(
            cards, base, tmp_path, auto=True, scope_gate=gate, is_testnet=True
        )
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ruleB1_no_effect_rejects(tmp_path):
    out = _run_hunt_cards(
        [
            {
                "n": 1,
                "assertion_a": "access is enforced by server-side role validation",
                "assertion_b": "server trusts X-Role header — injecting admin bypasses validation",
                "check": "curl -i -s -H 'X-Role: admin' BASE/grant",
                "expected": 'status 200, body contains "authorized"',
                "reframed": True,
            }
        ],
        tmp_path,
    )
    assert out[1]["confirmed"] is False, out[1]["verdict"]
    assert "no observable effect" in out[1]["verdict"]


def test_ruleB1_effect_confirms(tmp_path):
    out = _run_hunt_cards(
        [
            {
                "n": 1,
                "assertion_a": "access is enforced by server-side role validation",
                "assertion_b": "server trusts X-Role header — injecting admin bypasses validation",
                "check": "curl -i -s -H 'X-Role: admin' BASE/gate",
                "expected": 'status 200, body contains "authorized"',
                "reframed": True,
            }
        ],
        tmp_path,
    )
    assert out[1]["confirmed"] is True, out[1]["verdict"]


def test_ruleC_twins_identical_rejects(tmp_path):
    out = _run_hunt_cards(
        [
            {
                "n": 1,
                "assertion_a": "router normalizes to a single route",
                "assertion_b": (
                    "two spellings live in client code: 'BASE/api/orders' vs "
                    "'BASE/api/orders/' — middleware may bind to one only"
                ),
                "check": "curl -i -s BASE/api/orders",
                "expected": 'status 200, body contains "items"',
                "reframed": True,
            }
        ],
        tmp_path,
    )
    assert out[1]["confirmed"] is False, out[1]["verdict"]
    assert "twin" in out[1]["verdict"].lower()


def test_ruleC_twins_differ_confirms(tmp_path):
    out = _run_hunt_cards(
        [
            {
                "n": 1,
                "assertion_a": "router normalizes to a single route",
                "assertion_b": (
                    "two spellings live in client code: 'BASE/a/route' vs "
                    "'BASE/a/route/' — middleware may bind to one only"
                ),
                "check": "curl -i -s BASE/a/route/",
                "expected": 'status 200, body contains "secret"',
                "reframed": True,
            }
        ],
        tmp_path,
    )
    assert out[1]["confirmed"] is True, out[1]["verdict"]


def test_postgate_verdict_printed(tmp_path, capsys):
    out = _run_hunt_cards(
        [
            {
                "n": 1,
                "assertion_a": "The endpoint is stable.",
                "assertion_b": "The endpoint is reachable.",
                "check": "curl -i -s BASE/x",
                "expected": "status 200",
                "reframed": True,
            },
            {
                "n": 2,
                "assertion_a": "The endpoint ignores spoofed origin headers.",
                "assertion_b": "X-Forwarded-For header changes the response.",
                "check": "curl -i -s -H 'X-Forwarded-For: 127.0.0.1' BASE/x",
                "expected": "status 200",
                "reframed": True,
                "reframe_transform": "header-spoof",
                "reframe_of": 1,
            },
        ],
        tmp_path,
    )
    assert out[2]["confirmed"] is False, out[2]["verdict"]
    assert "no observable effect" in out[2]["verdict"]
    assert "Post-gate" in capsys.readouterr().out


# ── Miner: plumbing is not a secret ───────────────────────────────────────


def test_miner_ignores_js_plumbing(monkeypatch, tmp_path):
    import oracle_deeprecon

    html = b'<script src="/app.js"></script>'
    javascript = (
        b"this.authToken=this.options.authToken;"
        b"uploader=new Ps({authToken:`Bearer ${localStorage.getItem(`token`)}`});"
    )

    def fake_fetch(url, scope_gate, **_kwargs):
        if url.endswith("/"):
            return html, 200, url
        return javascript, 200, url

    class Allow:
        def is_in_scope(self, url):
            return True, "test"

    monkeypatch.setattr(oracle_deeprecon, "_fetch", fake_fetch)
    oracle_deeprecon.mine_js(["https://example.test/"], Allow(), tmp_path)
    artifact = (tmp_path / "js_secrets.txt").read_text()
    assert "authToken" not in artifact, artifact


# ── Cloud: fail fast, then stay local ─────────────────────────────────────


def test_poc_escalation_uses_router_never_direct(monkeypatch):
    # S5: PoC flows through the multi-lane router (task "poc") first and
    # only — no hardcoded single-provider direct bypass remains.
    import oracle_hunter as oh
    import oracle_llm

    def boom(*a, **k):
        raise AssertionError("direct cloud post must never be called")

    monkeypatch.setattr(oh, "_cloud_direct_post", boom, raising=False)
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: "router-poc")
    assert oh._cloud_escalate("card", "t", provider="gemini") == "router-poc"
    assert oh._cloud_escalate("card", "t", provider="claude") == "router-poc"
