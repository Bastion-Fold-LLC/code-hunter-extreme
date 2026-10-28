#!/usr/bin/env python3
"""P14: self-describing gate replay (pygoat /secret X-Host miss).

Root cause: beautiful-liar probes ONE role header (X-Original-Role). Pygoat
/secret consults X-Host for the value 'admin.localhost:8000' — a blind
battery cannot guess it, but the PAGE STATES ITS OWN RULE:
"Only admin.localhost:8000 can access, Your X-Host is None".

Fix (wire-guided, zero bench literals): harvest_text() extracts
(header, required_value) from self-describing gate messages and
harvest_reframes() replays them verbatim on the rejected parent.
"""
from __future__ import annotations

import http.server
import re
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_harvest as hv  # noqa: E402
import oracle_hunter as oh  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)
from oracle_foundation import build_seam_card  # noqa: E402

# Pygoat-shaped message, generic positions (header + value vary by test).
GATE_MSG = "Only admin.localhost:8000 can access, Your X-Host is None"


def _parent(check: str, n: int = 1):
    return build_seam_card(
        n=n,
        assertion_a="access is enforced by server-side role validation",
        assertion_a_source="fuzzed_paths.txt",
        assertion_b="server trusts a client-controlled header as the role proof",
        check=check,
        expected='status 200, body contains any of "secret","vault-open"',
        impact="auth bypass",
        origin="seam-template",
        mindset="seam",
    )


def test_harvest_extracts_gate_hint():
    out = hv.harvest_text(f"<html><p>{GATE_MSG}</p></html>")
    assert out["gate_hints"] == [("X-Host", "admin.localhost:8000")]


def test_gate_hint_requires_both_halves():
    assert hv.harvest_text("Only admins can access this page")["gate_hints"] == []
    assert hv.harvest_text("Your X-Host is None")["gate_hints"] == []
    assert hv.harvest_text("")["gate_hints"] == []


def test_gate_hint_skips_noop_and_malformed():
    same = "Only None can access, Your X-Host is None"
    assert hv.harvest_text(same)["gate_hints"] == []
    # header name must be header-shaped
    bad_hdr = "Only v can access, Your <b>X</b> is None"
    assert hv.harvest_text(bad_hdr)["gate_hints"] == []
    # value with quotes / shell metachars is rejected (injection-safe)
    evil = "Only a'b can access, Your X-H is None"
    assert hv.harvest_text(evil)["gate_hints"] == []
    evil2 = "Only a;rm can access, Your X-H is None"
    assert hv.harvest_text(evil2)["gate_hints"] == []


def test_reframe_replays_stated_rule():
    corpus = hv._blank()
    corpus["gate_hints"] = [("X-Host", "admin.localhost:8000")]
    parent = _parent("curl -i -s -H 'X-Original-Role: admin' 'http://t/secret'")
    cards = hv.harvest_reframes(parent, corpus, {}, 100)
    gate = [c for c in cards if c.get("reframe_transform") == "harvest-gate"]
    assert len(gate) == 1
    assert "-H 'X-Host: admin.localhost:8000'" in gate[0]["check"]
    assert "X-Original-Role" in gate[0]["check"]


def test_reframe_skips_present_header_and_reframed_parent():
    corpus = hv._blank()
    corpus["gate_hints"] = [("X-Host", "admin.localhost:8000")]
    dup = _parent("curl -i -s -H 'X-Host: x' 'http://t/secret'")
    assert hv.harvest_reframes(dup, corpus, {}, 100) == []
    reframed = _parent("curl -i -s 'http://t/secret'")
    reframed["reframed"] = True
    assert hv.harvest_reframes(reframed, corpus, {}, 100) == []


class _GateStub(http.server.BaseHTTPRequestHandler):
    """Generic self-describing gate (NOT pygoat literals)."""

    def do_GET(self):  # noqa: N802
        if self.headers.get("X-Pass") == "letmein-zone":
            body = b"<html>vault-open: welcome to the vault</html>"
        else:
            body = b"<html>Only letmein-zone can access, " b"Your X-Pass is None</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # noqa: ANN001, ANN202
        pass


class _Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def test_stub_chain_reject_then_replay_confirms():
    srv = _Threaded(("127.0.0.1", 0), _GateStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        parent = _parent(f"curl -i -s -H 'X-Original-Role: admin' '{base}/gate'")
        _, out, err = oh._run_check(parent["check"])
        assert "[BLOCKED]" not in err
        status = extract_status_from_curl_output(out)
        v = verify_seam_card(parent, [base + "/gate"], status=status, body=out)
        assert v["verdict"] == "REJECTED", f"parent must reject: {v['reason']}"
        corpus = hv.merge_harvest(hv.harvest_text(out, source_url=base))
        assert corpus["gate_hints"] == [("X-Pass", "letmein-zone")]
        cards = hv.harvest_reframes(parent, corpus, {}, 100)
        gate = [c for c in cards if c.get("reframe_transform") == "harvest-gate"]
        assert gate, "no harvest-gate replay emitted"
        _, out2, err2 = oh._run_check(gate[0]["check"])
        assert "[BLOCKED]" not in err2
        status2 = extract_status_from_curl_output(out2)
        m = re.search(r"https?://[^\s'\"]+", gate[0]["check"])
        assert m, "replay check lost its URL"
        url2 = m.group(0)
        v2 = verify_seam_card(gate[0], [url2], status=status2, body=out2)
        assert v2["verdict"] == "CONFIRMED", f"replay must confirm: {v2['reason']}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_gate_replay_runs_on_live_pygoat_shape():
    """Pygoat literals end-to-end at the harvest layer (no bench needed).

    Feeds the REAL /secret wire bodies (captured live) through harvest +
    verify to prove the literals replay — the live-bench assertion itself
    belongs to the P14 bench-recall mapping test.
    """
    denied = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<html>Only admin.localhost:8000 can access, Your X-Host is None</html>"
    )
    granted = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<html><h2>Success. You have the secret key S3CR37K3Y</h2></html>"
    )
    corpus = hv.merge_harvest(hv.harvest_text(denied))
    assert corpus["gate_hints"] == [("X-Host", "admin.localhost:8000")]
    parent = _parent("curl -i -s -H 'X-Original-Role: admin' 'http://t/secret'")
    gate = [
        c
        for c in hv.harvest_reframes(parent, corpus, {}, 100)
        if c.get("reframe_transform") == "harvest-gate"
    ][0]
    v = verify_seam_card(gate, ["http://t/secret"], status=200, body=granted)
    assert v["verdict"] == "CONFIRMED", f"pygoat-shaped replay: {v['reason']}"
