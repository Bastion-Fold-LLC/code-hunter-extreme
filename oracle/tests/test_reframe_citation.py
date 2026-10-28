"""Reframe authors must emit Assertion-A citations (Gate 4).

R3: 21 of 26 rejections died on "no cited program source" — harvest
and Op2 follow-ups never carried one. Children inherit the parent's
citation, else cite the parent's check URL (the observed wire
location). A sourced reframe with matching wire must reach CONFIRMED.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_deterministic import verify_seam_card  # noqa: E402
from oracle_foundation import reframe_a_source, reframe_rejected  # noqa: E402
from oracle_harvest import harvest_reframes  # noqa: E402

ORDERS = "http://localhost:32768/orders"
BODY_200 = 'HTTP/1.1 200 OK\r\n\r\n{"orders": [{"id": 1}]}'


def _parent(**over):
    base = {
        "n": 3,
        "assertion_a": "The orders page requires authentication.",
        "assertion_b": "The orders page is accessible without auth.",
        "check": "curl -i -s http://localhost:32768/orders",
        "expected": 'status 200, body contains "orders"',
        "impact": "Order data leak.",
    }
    base.update(over)
    return base


def _corpus():
    return {"creds": [("test", "test")], "ids": [], "tokens": [], "links": []}


def test_source_helper_prefers_parent_citation():
    assert reframe_a_source(_parent(assertion_a_source="http://h/a")) == ("http://h/a")
    assert reframe_a_source(_parent()) == ORDERS
    assert reframe_a_source({"check": "not a url"}) == ""


def test_harvest_basic_inherits_citation():
    kids = harvest_reframes(
        _parent(assertion_a_source="http://h/spec"), _corpus(), {}, 22
    )
    assert kids
    assert all(k["assertion_a_source"] == "http://h/spec" for k in kids)


def test_harvest_basic_falls_back_to_check_url():
    kids = harvest_reframes(_parent(), _corpus(), {}, 22)
    assert kids
    assert all(k["assertion_a_source"] == ORDERS for k in kids)


def test_op2_reframes_carry_citation():
    kids = reframe_rejected(_parent(), 30)
    assert kids
    assert all(k["assertion_a_source"] == ORDERS for k in kids)
    kids2 = reframe_rejected(_parent(assertion_a_source="http://h/s"), 30)
    assert kids2
    assert all(k["assertion_a_source"] == "http://h/s" for k in kids2)


def test_sourced_reframe_reaches_confirmed():
    (kid,) = harvest_reframes(_parent(), _corpus(), {}, 22)
    res = verify_seam_card(kid, [ORDERS], status=200, body=BODY_200)
    assert res["verdict"] == "CONFIRMED", res["reason"]
