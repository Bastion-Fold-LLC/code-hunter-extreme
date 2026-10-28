#!/usr/bin/env python3
"""Phase 1: scan4me_home() resolution + None-payout bridge contract."""

import sqlite3

import pytest

import oracle_scan4me as bridge


def test_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    assert bridge.scan4me_home() == tmp_path
    assert bridge.scan4me_db_path() == tmp_path / "scan4me.db"


def test_default_resolves_to_real_checkout(monkeypatch):
    monkeypatch.delenv("SCAN4ME_HOME", raising=False)
    home = bridge.scan4me_home()
    assert home.name == "Scan4Me"
    if not home.is_dir():
        pytest.skip(f"no Scan4Me sibling checkout at {home}")
    assert home.is_dir()


def test_db_none_when_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    assert bridge._db() is None
    assert bridge.resolve("anything") is None


def test_env_tilde_expanded(monkeypatch):
    monkeypatch.setenv("SCAN4ME_HOME", "~/Scan4Me")
    assert "~" not in str(bridge.scan4me_home())


def _make_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE programs (id INTEGER PRIMARY KEY, name TEXT, handle TEXT,"
        " url TEXT, platform TEXT, max_payout REAL, currency TEXT,"
        " offers_bounties INT, managed_triage INT, safe_harbor TEXT,"
        " program_kind TEXT, first_response_hours REAL, response_efficiency REAL,"
        " validation_days REAL, rewarded_vulnerabilities INT, average_payout REAL)"
    )
    conn.execute(
        "CREATE TABLE assets (id INTEGER PRIMARY KEY, program_id INT,"
        " asset_identifier TEXT, asset_type TEXT, is_wildcard INT)"
    )
    conn.execute(
        "INSERT INTO programs (name, handle, url, platform, max_payout)"
        " VALUES ('Acme', 'acme', 'https://example.com/acme', 'hackerone', NULL)"
    )
    conn.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard)"
        " VALUES (1, '*.acme.com', 'WILDCARD', 1)"
    )
    conn.commit()
    conn.close()


def test_db_roundtrip_via_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    _make_db(tmp_path / "scan4me.db")
    prog = bridge.resolve("acme")
    assert prog is not None
    assert prog["max_payout_usd"] is None  # unknown stays None, not 0
    assert prog["max_payout"] is None
    ok, rule = bridge.verify_in_scope("api.acme.com", prog)
    assert ok and rule == "*.acme.com"


def test_bridge_rejects_apex_end_to_end(monkeypatch, tmp_path):
    """P7: '*.acme.com' must NOT cover the apex 'acme.com' through the
    resolve() -> verify_in_scope() bridge path (fail-closed, scope_match parity)."""
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    _make_db(tmp_path / "scan4me.db")
    prog = bridge.resolve("acme")
    assert prog is not None

    # Apex rejected (the P7 gap: previously allowed)
    ok, _ = bridge.verify_in_scope("acme.com", prog)
    assert not ok

    # Proper subdomains still accepted
    ok, rule = bridge.verify_in_scope("api.acme.com", prog)
    assert ok and rule == "*.acme.com"
    ok, _ = bridge.verify_in_scope("deep.sub.acme.com", prog)
    assert ok

    # Lookalike suffix rejected
    ok, _ = bridge.verify_in_scope("evilexample.com", prog)
    assert not ok
    ok, _ = bridge.verify_in_scope("evilacme.com", prog)
    assert not ok

    # Empty / degenerate inputs rejected
    ok, _ = bridge.verify_in_scope("", prog)
    assert not ok


def test_canon_asset_type_covers_legacy_and_canonical():
    assert bridge.canon_asset_type("URL") == "URL"
    assert bridge.canon_asset_type("url") == "URL"
    assert bridge.canon_asset_type("website") == "URL"
    assert bridge.canon_asset_type("WILDCARD") == "WILDCARD"
    assert bridge.canon_asset_type("wildcard") == "WILDCARD"
    assert bridge.canon_asset_type("iprange") == "CIDR"
    assert bridge.canon_asset_type("IP_ADDRESS") == "CIDR"
    assert bridge.canon_asset_type("cidr") == "CIDR"
    assert bridge.canon_asset_type("android_app") == "GOOGLE_PLAY_APP_ID"
    assert bridge.canon_asset_type("ios_app") == "APPLE_STORE_APP_ID"
    assert bridge.canon_asset_type("SmartContract") == "SMART_CONTRACT"
    assert bridge.canon_asset_type("smart_contract") == "SMART_CONTRACT"
    assert bridge.canon_asset_type("bogus-type") == "OTHER"
    assert bridge.canon_asset_type(None) == "OTHER"


def test_verify_in_scope_rejects_public_suffix_wildcards():
    # A hostile or corrupt *.com row must never authorize the whole TLD,
    # even if it bypasses Scan4Me ingest (defense in depth at match time).
    for rule in ("*.com", "*.co.uk", "*.io"):
        prog = {
            "structured_scopes": [
                {"asset_identifier": rule, "is_wildcard": 1}
            ]
        }
        assert bridge.verify_in_scope("anything.com", prog)[0] is False, rule
        assert bridge.verify_in_scope("anything.co.uk", prog)[0] is False, rule
    ok_prog = {
        "structured_scopes": [
            {"asset_identifier": "*.example.co.uk", "is_wildcard": 1}
        ]
    }
    assert bridge.verify_in_scope("app.example.co.uk", ok_prog)[0] is True
    assert bridge.verify_in_scope("app.other.co.uk", ok_prog)[0] is False


def test_verify_in_scope_strips_scheme_prefixed_rules():
    prog = {
        "structured_scopes": [
            {
                "asset_identifier": "http://*.innov8.work",
                "is_wildcard": 1,
            },
            {
                "asset_identifier": "https://sub.x.com/login",
                "is_wildcard": 0,
            },
        ]
    }
    ok, _ = bridge.verify_in_scope("a.innov8.work", prog)
    assert ok
    ok, _ = bridge.verify_in_scope("innov8.work", prog)
    assert not ok
    ok, _ = bridge.verify_in_scope("sub.x.com", prog)
    assert ok


def _make_db_with_contest(path):
    _make_db(path)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE contests (id INTEGER PRIMARY KEY, platform TEXT, name TEXT,"
        " handle TEXT, url TEXT, offers_bounties INT, max_payout REAL,"
        " currency TEXT, status TEXT, starts_at TEXT, ends_at TEXT, description TEXT)"
    )
    conn.execute(
        "INSERT INTO contests (platform, name, handle, url, offers_bounties,"
        " max_payout, currency, status) VALUES ('Sherlock', 'Optimism',"
        " 'sherlock-38', 'https://audits.sherlock.xyz/contests/38', 1, 700000.0,"
        " 'USDC', 'active')"
    )
    conn.commit()
    conn.close()


def test_fetch_contests_and_resolve_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    _make_db_with_contest(tmp_path / "scan4me.db")
    contests = bridge.fetch_contests()
    assert len(contests) == 1
    assert contests[0]["name"] == "Optimism"
    assert contests[0]["program_kind"] == "web3"
    assert contests[0]["structured_scopes"] == []
    assert contests[0]["_source"] == "scan4me-contest"
    assert contests[0]["max_payout_usd"] == 700000.0
    prog = bridge.resolve("optimism")
    assert prog is not None and prog["_source"] == "scan4me-contest"
    # Programs still win over contests.
    assert bridge.resolve("acme")["_source"] == "scan4me"


def test_verify_in_scope_excludes_oos_cidr_and_ineligible():
    """Parity with fixed Scan4Me: out-of-scope hosts/IP-ranges disqualify a
    target, and submission-ineligible assets are not usable in-scope targets."""
    import oracle_scan4me as bridge

    prog = {
        "structured_scopes": [
            {"asset_identifier": "*.acme.com", "is_wildcard": True,
             "eligible_for_submission": True},
            {"asset_identifier": "10.1.2.3", "is_wildcard": False,
             "eligible_for_submission": True},
            {"asset_identifier": "legacy.example.org", "is_wildcard": False,
             "eligible_for_submission": False},
            {"asset_identifier": "live.example.org", "is_wildcard": False,
             "eligible_for_submission": True},
        ],
        "out_of_scope": ["admin.acme.com", "10.0.0.0/8"],
    }
    # in-scope
    assert bridge.verify_in_scope("api.acme.com", prog)[0] is True
    assert bridge.verify_in_scope("live.example.org", prog)[0] is True
    # excluded by out-of-scope host
    assert bridge.verify_in_scope("admin.acme.com", prog)[0] is False
    # excluded by out-of-scope CIDR (string match alone would miss this)
    assert bridge.verify_in_scope("10.1.2.3", prog)[0] is False
    assert bridge.verify_in_scope("10.1.2.3:8080", prog)[0] is False
    assert bridge.verify_in_scope("http://10.1.2.3/path", prog)[0] is False
    # submission-ineligible asset is not a usable target
    assert bridge.verify_in_scope("legacy.example.org", prog)[0] is False
    # unrelated host
    assert bridge.verify_in_scope("evil.com", prog)[0] is False


def test_scan4me_home_has_no_absolute_fallback():
    import inspect

    src = inspect.getsource(bridge.scan4me_home)
    assert "/home/" not in src
    assert "phantomcore" not in src


def test_bridge_db_is_read_only(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    _make_db(tmp_path / "scan4me.db")
    conn = bridge._db()
    assert conn is not None
    with pytest.raises(Exception):
        conn.execute("INSERT INTO programs (name) VALUES ('x')")
        conn.commit()
