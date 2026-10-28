#!/usr/bin/env python3
"""Break-it-locally: hand-written cards for known bad_code_app flaws.

Decomposes the battery: reflex quality (LLM-dependent) is measured by the
ground-truth runner; THIS file proves the verify path (gates + wire match)
confirms real flaws and rejects clean endpoints, deterministically.
"""

import copy
import http.server
import sys
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE / "tests"))

import bad_code_app  # noqa: E402

from oracle_hunter import ProgramScopeGate, verify_seams  # noqa: E402


def _serve():
    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), bad_code_app.VulnerableHandler
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def test_known_flaws_confirm_and_clean_rejects(tmp_path):
    httpd = _serve()
    # Flaw 7 POSTs mutate the shared ORDERS global — snapshot/restore so
    # later tests (e.g. test_known_bugs refund math) see fresh state.
    orders_snapshot = copy.deepcopy(bad_code_app.ORDERS)
    try:
        port = httpd.server_address[1]
        base = f"http://127.0.0.1:{port}"
        (tmp_path / "known_urls.txt").write_text(
            "\n".join(
                [
                    f"{base}/debug/config",
                    f"{base}/api/v1/admin/metrics",
                    f"{base}/api/v1/users",
                    f"{base}/api/v1/orders/ord_101/apply_discount",
                    f"{base}/health",
                ]
            )
        )
        gate = ProgramScopeGate({}, f"127.0.0.1:{port}")
        seams = [
            {
                "n": 1,
                "assertion_a": "Debug endpoints are disabled in staging.",
                "assertion_b": "Debug config exposes cloud credentials.",
                "assertion_a_source": f"{base}/debug/config (testbed route)",
                "check": f"curl -i -s {base}/debug/config",
                "expected": 'status 200, body contains "aws_secret"',
                "impact": "credential exposure",
                "origin": "flaw-battery",
            },
            {
                "n": 2,
                "assertion_a": "Admin metrics require verified admin session.",
                "assertion_b": "Untrusted role header grants admin metrics.",
                "assertion_a_source": f"{base}/api/v1/admin/metrics (testbed route)",
                "check": (
                    f"curl -i -s -H 'X-Original-Role: admin' "
                    f"{base}/api/v1/admin/metrics"
                ),
                "expected": 'status 200, body contains "authorized"',
                "impact": "access control bypass",
                "origin": "flaw-battery",
            },
            {
                "n": 3,
                "assertion_a": "User APIs never return SSNs.",
                "assertion_b": "Stale v1 users endpoint leaks SSNs.",
                "assertion_a_source": f"{base}/api/v1/users (testbed route)",
                "check": f"curl -i -s {base}/api/v1/users",
                "expected": 'status 200, body contains "123-45-6789"',
                "impact": "PII exposure",
                "origin": "flaw-battery",
            },
            {
                "n": 4,
                "assertion_a": "Paid orders reject further discounts.",
                "assertion_b": "Discount applies to an already-paid order.",
                "assertion_a_source": (
                    f"{base}/api/v1/orders/ord_101/apply_discount (testbed route)"
                ),
                "check": (
                    f"curl -i -s -X POST -H 'Content-Type: application/json' "
                    f"-d '{{\"amount\": 30.0}}' "
                    f"{base}/api/v1/orders/ord_101/apply_discount"
                ),
                "expected": 'status 200, body contains "discount_applied"',
                "impact": "state invariant violation",
                "origin": "flaw-battery",
            },
            {
                "n": 5,
                "assertion_a": "Health endpoint exposes no secrets.",
                "assertion_b": "Health endpoint leaks credentials.",
                "assertion_a_source": f"{base}/health (testbed route)",
                "check": f"curl -i -s {base}/health",
                "expected": 'status 200, body contains "aws_secret"',
                "impact": "none — negative control",
                "origin": "flaw-battery",
            },
        ]
        out = verify_seams(
            seams, "flaw_battery", tmp_path, auto=True, scope_gate=gate, is_testnet=True
        )
        for n in (1, 2, 3, 4):
            assert out[n]["confirmed"] is True, f"seam {n}: {out[n]['verdict']}"
        assert out[5]["confirmed"] is False, "clean endpoint must not confirm"
    finally:
        bad_code_app.ORDERS.clear()
        bad_code_app.ORDERS.update(orders_snapshot)
        httpd.shutdown()
        httpd.server_close()
