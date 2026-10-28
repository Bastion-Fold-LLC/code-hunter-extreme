"""Gate 5b: a denial/absence status supports A, never confirms B.

Mirror-parity with _assess_response rules 3-4 (oracle_hunter.py).
R3 Seam 5 replay: B claimed unauthenticated access while expecting
403 + Forbidden — and CONFIRMED. Must now REJECT.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_deterministic import _grounded, verify_seam_card  # noqa: E402

URL = "http://localhost:32768/server-status"
BODY_403 = (
    "HTTP/1.1 403 Forbidden\r\n"
    "Server: Apache/2.4.67 (Debian)\r\n"
    "\r\n"
    "<html><head><title>403 Forbidden</title></head>"
    "<body><h1>Forbidden</h1>"
    "<p>You don't have permission to access this resource.</p>"
    "</body></html>"
)
BODY_404 = (
    "HTTP/1.1 404 Not Found\r\n"
    "\r\n"
    "<html><head><title>404 Not Found</title></head>"
    "<body><h1>Not Found</h1></body></html>"
)
BODY_200 = "HTTP/1.1 200 OK\r\n" "\r\n" '{"orders": [{"id": 1, "total": 99}]}'


def _card(**over):
    base = {
        "n": 5,
        "assertion_a": "The server-status page requires authentication.",
        "assertion_a_source": "http://localhost:32768/raw.html",
        "assertion_b": "The server-status page is accessible "
        "without authentication.",
        "check": "curl -i -s http://localhost:32768/server-status",
        "expected": 'status 403, body contains "Forbidden"',
    }
    base.update(over)
    return base


def test_r3_seam5_replay_rejected():
    res = verify_seam_card(_card(), [URL], status=403, body=BODY_403)
    assert res["verdict"] == "REJECTED"
    assert "supports A, not B" in res["reason"]


def test_denial_markers_all_reject():
    for marker, status, body, pinned in [
        (
            "401 unauthorized",
            401,
            "HTTP/1.1 401 Unauthorized\r\n\r\nDenied",
            "Denied",
        ),
        ("403 forbidden", 403, BODY_403, "Forbidden"),
        (
            "access denied",
            403,
            "HTTP/1.1 403\r\n\r\nAccess Denied",
            "Access Denied",
        ),
        (
            "error 530",
            530,
            "HTTP/2 530\r\n\r\nError 530: Origin DNS error",
            "Error 530",
        ),
    ]:
        seam = _card(expected=f'status {status}, body contains "{pinned}"')
        res = verify_seam_card(seam, [URL], status=status, body=body)
        assert res["verdict"] == "REJECTED", marker
        assert "barrier holds" in res["reason"], marker


def test_absent_endpoint_rejects_unless_asserted():
    seam = _card(expected='status 404, body contains "Not Found"')
    res = verify_seam_card(seam, [URL], status=404, body=BODY_404)
    assert res["verdict"] == "REJECTED"
    assert "nothing to access" in res["reason"]

    explicit = _card(
        assertion_a="The debug route existed before removal.",
        assertion_b="The debug route returns 404 after removal.",
        expected="status 404",
    )
    res = verify_seam_card(explicit, [URL], status=404, body=BODY_404)
    assert res["verdict"] == "CONFIRMED"


def test_granted_access_still_confirms():
    seam = _card(
        check="curl -i -s http://localhost:32768/orders",
        expected='status 200, body contains "orders"',
    )
    res = verify_seam_card(
        seam, ["http://localhost:32768/orders"], status=200, body=BODY_200
    )
    assert res["verdict"] == "CONFIRMED"


def test_parity_with_assess_response():
    import oracle_hunter as oh

    cases = [
        ("curl -i -s " + URL, BODY_403, 403),
        ("curl -i -s " + URL, BODY_404, 404),
    ]
    for check, body, status in cases:
        seam = _card(check=check, expected=f"status {status}")
        strict = oh._assess_response(check, body, "", seam)
        assert "FALSE_POSITIVE" in strict
        det = verify_seam_card(seam, [URL], status=status, body=body)
        assert det["verdict"] == "REJECTED"


def test_grounding_root_query_against_bare_host():
    # Template probes mint root URLs with payload query strings; a bare
    # host recon entry must ground them (query is the probe, not provenance).
    assert _grounded(
        "http://127.0.0.1:8765?id=%27%20OR%20%271%27%3D%271",
        ["http://127.0.0.1:8765"],
    )


def test_grounding_subpath_and_sibling_prefix():
    recon = ["http://127.0.0.1:8080/vulnerabilities/sqli/"]
    assert _grounded(
        "http://127.0.0.1:8080/vulnerabilities/sqli/?id=%27&Submit=Submit", recon
    )
    assert not _grounded("http://127.0.0.1:8080/vulnerabilities/sqli2/", recon)


def test_grounding_lookalike_host_never_grounds():
    assert not _grounded(
        "http://api.example.com.evil.com/x", ["api.example.com"]
    )
    assert not _grounded("http://127.0.0.1:8765/", ["http://127.0.0.2:8765"])
