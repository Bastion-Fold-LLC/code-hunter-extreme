"""S4: one scope judge — bridge and execution gate must agree.

Three matchers (Scan4Me check, bridge verify_in_scope, hunter
ProgramScopeGate) historically diverged on apex and eligibility.
The gate is the load-bearing control; the bridge delegates to it.
These vectors pin identical verdicts from both entry points.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_scan4me as bridge
from oracle_hunter import ProgramScopeGate


def _prog(*entries, name="Parity"):
    return {"name": name, "structured_scopes": list(entries)}


def _e(ident, **kw):
    base = {"asset_identifier": ident}
    base.update(kw)
    return base


CASES = [
    # (program, host, expected)
    (_prog(_e("*.acme.com", is_wildcard=1)), "api.acme.com", True),
    (_prog(_e("*.acme.com", is_wildcard=1)), "acme.com", False),  # apex: strict
    (_prog(_e("*.acme.com", is_wildcard=1)), "evilacme.com", False),
    (_prog(_e("*.acme.com", is_wildcard=1)), "acme.com.evil.org", False),
    (_prog(_e("acme.com")), "acme.com", True),
    (_prog(_e("acme.com")), "api.acme.com", False),
    (_prog(_e("*.com", is_wildcard=1)), "anything.com", False),
    (_prog(_e("*.example.co.uk", is_wildcard=1)), "app.example.co.uk", True),
    (_prog(_e("*.acme.com", is_wildcard=1, eligible_for_bounty=False)),
     "api.acme.com", False),
    (_prog(_e("*.acme.com", is_wildcard=1, eligible_for_submission=False)),
     "api.acme.com", False),
    (_prog(_e("10.0.0.0/8", asset_type="CIDR")), "10.1.2.3", True),
    (_prog(_e("10.0.0.0/8", asset_type="CIDR")), "11.0.0.1", False),
]


def test_bridge_and_gate_agree():
    for prog, host, expected in CASES:
        bridge_ok = bridge.verify_in_scope(host, prog)[0]
        gate_ok = ProgramScopeGate(dict(prog), "").is_in_scope(host)[0]
        assert bridge_ok == expected, f"bridge {host} {prog} -> {bridge_ok}"
        assert gate_ok == expected, f"gate {host} {prog} -> {gate_ok}"
        assert bridge_ok == gate_ok, f"divergence on {host} {prog}"


def test_ipv6_cidr_bare_and_bracketed():
    prog = _prog(_e("2001:db8::/32", asset_type="CIDR"))
    for host in ("2001:db8::1", "[2001:db8::1]", "https://[2001:db8::1]:8443/x"):
        assert ProgramScopeGate(dict(prog), "").is_host_in_scope(host)[0], host
        assert ProgramScopeGate(dict(prog), "").is_in_scope(host)[0], host
        assert bridge.verify_in_scope(host, prog)[0], host
    assert not ProgramScopeGate(dict(prog), "").is_host_in_scope("2001:db9::1")[0]


def test_glued_wildcard_single_label():
    prog = _prog(_e("*-cdn.acme.com", is_wildcard=1))
    assert ProgramScopeGate(dict(prog), "").is_host_in_scope("foo-cdn.acme.com")[0]
    assert bridge.verify_in_scope("foo-cdn.acme.com", prog)[0]
    # multi-label prefix stays out (stricter than Scan4Me endswith, fail-closed)
    assert not ProgramScopeGate(dict(prog), "").is_host_in_scope("a.b-cdn.acme.com")[0]
    assert not ProgramScopeGate(dict(prog), "").is_host_in_scope("-cdn.acme.com")[0]
    assert not ProgramScopeGate(dict(prog), "").is_host_in_scope("foocdn.acme.com")[0]


def test_bridge_whitespace_padded_domain_delegates_like_gate():
    prog = _prog(_e("acme.com"))
    gate_ok = ProgramScopeGate(dict(prog), "").is_host_in_scope("  acme.com  ")[0]
    assert bridge.verify_in_scope("  acme.com  ", prog)[0] == gate_ok
