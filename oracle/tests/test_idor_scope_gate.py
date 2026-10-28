#!/usr/bin/env python3
"""IDOR scope-gate tests (C1+C2): evil/prose/recon/token containment."""
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

from oracle_auth_session import (  # noqa: E402
    ACCOUNT_B_AUTH_PLACEHOLDER,
    DualAccountHarness,
    substitute_probe_placeholders,
)


def _harness(**kw):
    kw.setdefault("target_domain", "victim.com")
    kw.setdefault("platform", "hackerone")
    kw.setdefault("researcher_username", "r")
    return DualAccountHarness(**kw)


class _Gate:
    def __init__(self, allowed):
        self.allowed = set(allowed)

    def is_in_scope(self, url):
        from urllib.parse import urlsplit
        host = urlsplit(url).netloc.lower().split("@")[-1].split(":")[0]
        return (host in self.allowed, "test-gate")


def test_prose_url_never_becomes_probe():
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK"
    seams = [{
        "check": "curl -s 'https://victim.com/api/orders/ord_12345'",
        "assertion_a": "a",
        "assertion_b": "see https://evil.com/api/orders/ord_99999",
    }]
    gate = _Gate({"victim.com"})
    probes = [p for p in h.build_idor_probes(
        seams, scope_gate=gate,
        recon_hosts=["https://victim.com/"]) if p.get("check")]
    assert len(probes) == 1
    assert "victim.com" in probes[0]["check"]
    assert all("evil.com" not in p["check"] for p in probes)


def test_out_of_scope_dropped_with_marker():
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK"
    gate = _Gate({"victim.com"})
    seams = [
        {"check": "curl -s 'https://victim.com/api/orders/ord_11111'", "assertion_a": "a", "assertion_b": "b"},
        {"check": "curl -s 'https://evil.com/api/orders/ord_22222'", "assertion_a": "a", "assertion_b": "b"},
    ]
    out = h.build_idor_probes(seams, scope_gate=gate, recon_hosts=["https://victim.com/"])
    live = [p for p in out if p.get("check")]
    assert len(live) == 1 and "victim.com" in live[0]["check"]
    markers = [p for p in out if p.get("_dropped")]
    assert markers and markers[0]["_dropped"]["scope"] >= 1


def test_recon_unverified_host_dropped():
    h = _harness(target_domain="ghost.com")
    h.account_b.token = "Bearer LIVE_ATK"
    seams = [{"check": "curl -s 'https://ghost.com/api/orders/ord_33333'", "assertion_a": "a", "assertion_b": "b"}]
    out = h.build_idor_probes(seams, recon_hosts=["https://victim.com/"])
    assert [p for p in out if p.get("check")] == []


def test_no_live_token_in_storage_and_fail_closed():
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK_123"
    seams = [{"check": "curl -s 'https://victim.com/api/orders/ord_44444'", "assertion_a": "a", "assertion_b": "b"}]
    out = h.build_idor_probes(
        seams, scope_gate=_Gate({"victim.com"}), recon_hosts=["https://victim.com/"])
    live = [p for p in out if p.get("check")]
    assert live
    assert all("LIVE_ATK_123" not in p["check"] for p in live)
    assert all(ACCOUNT_B_AUTH_PLACEHOLDER in p["check"] for p in live)
    resolved, secrets = substitute_probe_placeholders(live[0]["check"], h, as_account="b")
    assert "LIVE_ATK_123" in resolved and secrets
    # no secret → fail closed
    h2 = _harness()
    resolved2, secrets2 = substitute_probe_placeholders(live[0]["check"], h2, as_account="b")
    assert secrets2 == [] and ACCOUNT_B_AUTH_PLACEHOLDER in resolved2
