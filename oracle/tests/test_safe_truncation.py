#!/usr/bin/env python3
"""Break-it-locally: safe `| head -N` truncation pipes run; hostile pipes drop."""

import http.server
import threading

import pytest

from oracle_foundation import (
    SHELL_METACHARS,
    strip_safe_truncation,
    validate_card_shape,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("curl -i -s http://h/ | head -30", "curl -i -s http://h/"),
        ("curl -s http://h/ | tail -5", "curl -s http://h/"),
        ("curl -s http://h/ | head -n 30", "curl -s http://h/"),
        ("curl -s http://h/", "curl -s http://h/"),
        # Hostile / compound forms survive the strip → dropped downstream.
        ("curl -s http://h/ | grep foo", "curl -s http://h/ | grep foo"),
        ("curl -s http://h/ | head -30 | tail -5", "curl -s http://h/ | head -30"),
        ("curl -s http://h/; rm -rf /", "curl -s http://h/; rm -rf /"),
        ("curl -s http://h/ | head", "curl -s http://h/ | head"),
    ],
)
def test_strip_table(raw, expected):
    assert strip_safe_truncation(raw) == expected


def _card(check):
    return {
        "n": 1,
        "assertion_a": "headers are set",
        "assertion_b": "headers are missing",
        "check": check,
        "expected": "status 200",
    }


def test_stripped_card_passes_shape_and_raw_still_drops():
    piped = "curl -i -s http://127.0.0.1:9/ | head -30"
    assert validate_card_shape(_card(piped)) is not None  # guard intact pre-strip
    assert validate_card_shape(_card(strip_safe_truncation(piped))) is None
    assert any(m in "curl x | grep y" for m in SHELL_METACHARS)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/debug/config":
            body = "debug_mode=true\naws_secret=AKIAEXAMPLE\n" + "\n".join(
                f"line{i}" for i in range(10)
            )
        else:
            body = "\n".join(f"line{i}" for i in range(10))
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_run_check_executes_piped_and_returns_full_output(server):
    from oracle_hunter import _run_check

    rc, out, err = _run_check(f"curl -s http://127.0.0.1:{server}/lines | head -5")
    assert rc == 0, err
    assert "[BLOCKED]" not in err
    for i in range(10):  # full output, not truncated to 5
        assert f"line{i}" in out


def test_verify_seams_accepts_piped_check(server, tmp_path):
    from oracle_hunter import ProgramScopeGate, verify_seams

    gate = ProgramScopeGate({}, f"127.0.0.1:{server}")
    seams = [
        {
            "n": 1,
            "assertion_a": "debug endpoints are disabled",
            "assertion_b": "debug config leaks secrets",
            "check": f"curl -s http://127.0.0.1:{server}/debug/config | head -20",
            "expected": "status 200",
            "impact": "credential exposure",
            "origin": "test",
        }
    ]
    out = verify_seams(seams, "piped_testbed", tmp_path, auto=True, scope_gate=gate)
    verdict = out[1]["verdict"]
    assert "Op1" not in verdict and "MALFORMED" not in verdict
    assert out[1]["output"], "piped check must execute and return output"
