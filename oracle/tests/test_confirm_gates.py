#!/usr/bin/env python3
"""Round 4: Gate 6a variation differential, 6b SPA control, generic stoplist.

Proves the hunt-2 precision fixes: vacuous header-spoof and SPA-fallback
confirmations are rejected, genuine differentials and real endpoints confirm.
"""

import http.server
import sys
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE / "tests"))

import bad_code_app  # noqa: E402
import pytest  # noqa: E402
from oracle_deterministic import verify_seam_card  # noqa: E402
from oracle_foundation import build_spa_control  # noqa: E402
from oracle_hunter import ProgramScopeGate, verify_seams  # noqa: E402

SHELL = (
    "<!doctype html><html><head><title>dashboard</title></head>"
    '<body><div id="app" data-state="ok">loading</div></body></html>'
)


class _ComboHandler(http.server.BaseHTTPRequestHandler):
    """SPA fallback (unknown -> shell 200), real JSON API, header ignorer."""

    def do_GET(self):
        if self.path == "/api/real":
            body = b'{"dashboard": "ok", "widgets": 3}'
        elif self.path == "/locked":
            body = b'{"locked": true, "role": "none"}'
        else:
            body = SHELL.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def combo():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ComboHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def vuln():
    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), bad_code_app.VulnerableHandler
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _gate(port):
    return ProgramScopeGate({}, f"127.0.0.1:{port}")


def test_6a_honored_variation_confirms(vuln, tmp_path):
    base = f"http://127.0.0.1:{vuln}"
    (tmp_path / "known_urls.txt").write_text(f"{base}/api/v1/admin/metrics\n")
    seams = [
        {
            "n": 1,
            "assertion_a": "Admin metrics require verified admin session.",
            "assertion_b": "Metrics endpoint leaks without auth.",
            "assertion_a_source": f"{base}/api/v1/admin/metrics",
            "check": f"curl -i -s {base}/api/v1/admin/metrics",
            "expected": 'status 200, body contains "role_effective"',
            "impact": "x",
            "origin": "t",
        },
        {
            "n": 2,
            "assertion_a": "Admin metrics require verified admin session.",
            "assertion_b": "Premise fails under header-spoof: role header grants metrics.",
            "assertion_a_source": f"{base}/api/v1/admin/metrics",
            "check": f"curl -i -s -H 'X-Original-Role: admin' {base}/api/v1/admin/metrics",
            "expected": 'status 200, body contains "role_effective"',
            "impact": "x",
            "origin": "t",
            "reframed": True,
            "reframe_of": 1,
            "reframe_transform": "header-spoof",
        },
    ]
    out = verify_seams(seams, "diff", tmp_path, auto=True, scope_gate=_gate(vuln))
    assert out[1]["confirmed"] is False
    assert out[2]["confirmed"] is True, out[2]["verdict"]


def test_6a_ignored_variation_rejected(combo, tmp_path):
    base = f"http://127.0.0.1:{combo}"
    (tmp_path / "known_urls.txt").write_text(f"{base}/locked\n")
    parent = {
        "n": 1,
        "assertion_a": "Locked endpoint needs a session.",
        "assertion_b": "Locked endpoint leaks.",
        "assertion_a_source": f"{base}/locked",
        "check": f"curl -i -s {base}/locked",
        "expected": 'status 200, body contains "locked"',
        "impact": "x",
        "origin": "t",
    }
    child = dict(
        parent,
        n=2,
        assertion_b="Premise fails under header-spoof: role header unlocks.",
        check=f"curl -i -s -H 'X-Role: admin' {base}/locked",
        reframed=True,
        reframe_of=1,
        reframe_transform="header-spoof",
    )
    seams = [parent, child]
    out = verify_seams(seams, "diff", tmp_path, auto=True, scope_gate=_gate(combo))
    assert out[2]["confirmed"] is False
    assert "no observable effect" in out[2]["verdict"]


def test_6a_missing_baseline_rejected(combo, tmp_path):
    base = f"http://127.0.0.1:{combo}"
    (tmp_path / "known_urls.txt").write_text(f"{base}/api/real\n")
    seams = [
        {
            "n": 9,
            "assertion_a": "A.",
            "assertion_b": "Premise fails under header-spoof: B.",
            "assertion_a_source": base,
            "check": f"curl -i -s -H 'X-Role: admin' {base}/api/real",
            "expected": 'status 200, body contains "widgets"',
            "impact": "x",
            "origin": "t",
            "reframed": True,
            "reframe_of": 999,
            "reframe_transform": "header-spoof",
        }
    ]
    out = verify_seams(seams, "diff", tmp_path, auto=True, scope_gate=_gate(combo))
    assert out[9]["confirmed"] is False
    assert "no recorded baseline" in out[9]["verdict"]


def test_6b_spa_fallback_rejected_real_api_confirmed(combo, tmp_path):
    base = f"http://127.0.0.1:{combo}"
    (tmp_path / "known_urls.txt").write_text(f"{base}/old-stuff\n{base}/api/real\n")
    mk = lambda n, path: {
        "n": n,
        "assertion_a": "Only live routes respond.",
        "assertion_b": f"Route {path} serves content.",
        "assertion_a_source": base,
        "check": f"curl -i -s {base}{path}",
        "expected": 'status 200, body contains "dashboard"',
        "impact": "x",
        "origin": "t",
    }
    out = verify_seams(
        [mk(1, "/old-stuff"), mk(2, "/api/real")],
        "spa",
        tmp_path,
        auto=True,
        scope_gate=_gate(combo),
    )
    assert out[1]["confirmed"] is False
    assert "SPA fallback" in out[1]["verdict"]
    assert out[2]["confirmed"] is True, out[2]["verdict"]


def test_verify_entries_carry_funnel_keys(combo, tmp_path):
    """Funnel instrumentation: every verify_seams entry records its
    deterministic verdict + killing gate (None when not applicable)."""
    base = f"http://127.0.0.1:{combo}"
    (tmp_path / "known_urls.txt").write_text(f"{base}/old-stuff\n{base}/api/real\n")
    mk = lambda n, path: {
        "n": n,
        "assertion_a": "Only live routes respond.",
        "assertion_b": f"Route {path} serves content.",
        "assertion_a_source": base,
        "check": f"curl -i -s {base}{path}",
        "expected": 'status 200, body contains "dashboard"',
        "impact": "x",
        "origin": "t",
    }
    out = verify_seams(
        [mk(1, "/old-stuff"), mk(2, "/api/real")],
        "spa",
        tmp_path,
        auto=True,
        scope_gate=_gate(combo),
    )
    for n, v in out.items():
        assert "det_verdict" in v, n
        assert "kill_gate" in v, n
    assert out[1]["det_verdict"] == "CONFIRMED"
    assert out[1]["kill_gate"] == "6b_spa"
    assert out[2]["det_verdict"] == "CONFIRMED"
    assert out[2]["kill_gate"] is None


def test_stoplist_rejects_generic_only_markers(combo):
    base = f"http://127.0.0.1:{combo}"
    seam = {
        "n": 1,
        "assertion_a": "A.",
        "assertion_b": "B.",
        "assertion_a_source": base,
        "check": f"curl -i -s {base}/api/real",
        "expected": 'status 200, body contains any of "id","data","result"',
        "origin": "t",
    }
    v = verify_seam_card(
        seam,
        [f"{base}/api/real"],
        scope_gate=_gate(combo),
        status=200,
        body='HTTP/1.1 200 OK\n\n{"id": 1, "data": {"result": []}}',
    )
    assert v["verdict"] == "REJECTED"
    assert "not discriminating" in v["reason"]


def test_stoplist_allows_specific_marker(combo):
    base = f"http://127.0.0.1:{combo}"
    seam = {
        "n": 1,
        "assertion_a": "A.",
        "assertion_b": "B.",
        "assertion_a_source": base,
        "check": f"curl -i -s {base}/api/real",
        "expected": 'status 200, body contains any of "data","widgets"',
        "origin": "t",
    }
    v = verify_seam_card(
        seam,
        [f"{base}/api/real"],
        scope_gate=_gate(combo),
        status=200,
        body='HTTP/1.1 200 OK\n\n{"data": 1, "widgets": 3}',
    )
    assert v["verdict"] == "CONFIRMED", v["reason"]


def test_build_spa_control_shapes():
    c = build_spa_control("curl -i -s 'http://h:3000/.env'")
    assert c is not None and c.startswith(
        "curl -i -s 'http://h:3000/__oracle_spa_probe_"
    )
    assert c.endswith(".env'")
    assert build_spa_control("curl -i -s 'http://h:3000/a'").endswith("'")
    assert "| " not in (build_spa_control("curl x") or "")
    assert build_spa_control("slither .") is None
    # Randomness: two probes differ.
    assert build_spa_control("curl http://h/") != build_spa_control("curl http://h/")
