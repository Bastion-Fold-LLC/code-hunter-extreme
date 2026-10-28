#!/usr/bin/env python3
"""Adversarial probes: scope-gate evasion attempts must fail closed."""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

from oracle_hunter import ProgramScopeGate


def _gate():
    return ProgramScopeGate(
        {
            "name": "Bank",
            "scope": "*.bank.com",
            "out_of_scope": "secret.bank.com",
        },
        "bank.com",
    )


def _verdict(url):
    ok, reason = _gate().is_in_scope(url)
    return ok


def test_legit_variants_allowed():
    assert _verdict("https://api.bank.com/v1")
    assert _verdict("HTTP://API.BANK.COM/UPPER")
    assert _verdict("https://api.bank.com:8443/port")


def test_lookalikes_blocked():
    assert not _verdict("https://api-bank.com/phish")
    assert not _verdict("https://bank.com.evil.com/phish")
    assert not _verdict("https://evil.com")


def test_explicit_oos_and_children_blocked():
    assert not _verdict("https://secret.bank.com/admin")
    assert not _verdict("https://deep.secret.bank.com/x")


def test_userinfo_trick_blocked_or_neutered():
    # http://evil.com@api.bank.com/ — host parses as api.bank.com with
    # userinfo evil.com. Either reject outright (fail closed) or treat host
    # as api.bank.com (in scope, userinfo ignored by HTTP clients anyway).
    # What must NEVER happen: treating evil.com as the target host.
    ok, reason = _gate().is_in_scope("http://evil.com@api.bank.com/")
    if ok:
        assert "evil.com" not in reason or "api.bank.com" in reason


def test_trailing_dot_and_ip_and_scheme_relative():
    # Trailing dot / bare IP / scheme-relative: must not widen scope.
    # Allowed only if the gate normalizes to the same in-scope host.
    for url in (
        "http://api.bank.com./trailing",
        "http://1.2.3.4/literal",
        "//api.bank.com/scheme-relative",
    ):
        ok, reason = _gate().is_in_scope(url)
        if ok:
            assert "bank.com" in reason, f"{url} admitted without bank.com basis"


def test_credentials_and_javascript_rejected():
    assert not _verdict("javascript:alert(1)")
    assert not _verdict("ftp://api.bank.com/file")
    assert not _verdict("")
