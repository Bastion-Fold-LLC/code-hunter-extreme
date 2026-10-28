#!/usr/bin/env python3
"""P11: prescan / scan verify-pass / -N deep-dive intake sweep.

All network I/O is faked (probe_fn / fetch_fn / resolve_fn injection) or
disabled (no_cloud) — this file never touches the network.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_intake as intake
import oracle_scan4me as _bridge


def _import_scan4me():
    """Import the REAL Scan4Me producer module, or skip when the sibling
    checkout is absent (clean CI runner). Never hardcode a username."""
    home = _bridge.scan4me_home()
    if not (home / "scan4me.py").is_file():
        pytest.skip(f"Scan4Me checkout not available at {home}")
    if str(home) not in sys.path:
        sys.path.insert(0, str(home))
    try:
        import scan4me as s4m
    except ModuleNotFoundError as exc:
        if exc.name in (None, "scan4me") and "scan4me" in str(exc):
            pytest.skip("scan4me module not importable in this environment")
        raise

    return s4m


# ── fixtures ────────────────────────────────────────────────────────────────


def _scope(ident, atype="url", wildcard=False):
    return {
        "asset_identifier": ident,
        "asset_type": atype,
        "is_wildcard": wildcard,
        "eligible_for_submission": True,
    }


def make_prog(
    name="Acme",
    handle="acme",
    payout=10000,
    rules="RULES v1: be nice.",
    score=50.0,
    scopes=None,
):
    return {
        "name": name,
        "handle": handle,
        "platform": "hackerone",
        "url": f"https://hackerone.com/{handle}",
        "website": f"https://{handle}.com",
        "score": score,
        "max_payout_usd": payout,
        "currency": "USD",
        "safe_harbor": "Standard",
        "managed_triage": True,
        "program_kind": "web2",
        "first_response_hours": 12,
        "response_efficiency": 95,
        "structured_scopes": (
            scopes if scopes is not None else [_scope("app.acme.com")]
        ),
        "rules_text": rules,
    }


def snap_of(prog):
    return intake._snapshot_program(prog)


def probe_live(host, timeout=8.0):
    return {"host": host, "resolves": True, "live": True, "status": 200, "error": ""}


def probe_dead(host, timeout=8.0):
    return {
        "host": host,
        "resolves": False,
        "live": False,
        "status": None,
        "error": "dns: NXDOMAIN",
    }


def probe_must_not_run(host, timeout=8.0):
    raise AssertionError("probe ran on the offline path")


# ── prescan ─────────────────────────────────────────────────────────────────


def test_prescan_writes_untrusted_report(tmp_path):
    progs = [make_prog(), make_prog("Beta", "beta", payout=5000, score=80.0)]
    report = intake.run_prescan(
        fetch_fn=lambda: progs, limit=50, out_dir=tmp_path, stamp="t1"
    )
    path = Path(report["_report_path"])
    assert path.exists()
    on_disk = json.loads(path.read_text())
    assert on_disk["_schema"] == intake.PRESCAN_SCHEMA
    assert on_disk["trusted"] is False
    assert on_disk["count"] == 2
    assert all(p["trusted"] is False for p in on_disk["programs"])
    assert on_disk["programs"][0]["rules_hash"]
    assert on_disk["programs"][0]["scope_count"] == 1


def test_prescan_empty_fail_closed(tmp_path):
    report = intake.run_prescan(fetch_fn=lambda: [], out_dir=tmp_path, stamp="t2")
    assert report["count"] == 0
    assert report["programs"] == []
    assert Path(report["_report_path"]).exists()


def test_source_code_asset_is_not_probed_even_when_listed_in_scope():
    # Matomo lists plugins.matomo.org as SOURCE_CODE in scope and also in
    # out_of_scope. Source code is not a DNS probe target; the host conflict
    # must never turn into a live probe or a false in-scope finding.
    prog = {
        "structured_scopes": [
            {
                "asset_identifier": "plugins.matomo.org",
                "asset_type": "SOURCE_CODE",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "out_of_scope": ["plugins.matomo.org"],
    }
    hosts, skipped = intake.derive_probe_hosts(prog)
    assert hosts == []
    assert any(
        "plugins.matomo.org" in s and "non-DNS" in s and "source_code" in s
        for s in skipped
    )


def test_prescan_sync_refused_offline(tmp_path):
    with pytest.raises(ValueError, match="no-cloud"):
        intake.run_prescan(
            fetch_fn=lambda: [], sync=True, no_cloud=True, out_dir=tmp_path
        )


# ── verify pass: three checks ───────────────────────────────────────────────


def test_verify_all_pass_verified():
    prog = make_prog()
    verdict = intake.verify_program(snap_of(prog), dict(prog), probe_fn=probe_live)
    assert verdict["verdict"] == "verified"
    assert verdict["failed_checks"] == []
    assert all(c["pass"] for c in verdict["checks"].values())


def test_stale_scope_unverified():
    prog = make_prog()
    verdict = intake.verify_program(snap_of(prog), dict(prog), probe_fn=probe_dead)
    assert verdict["verdict"] == "unverified"
    assert "scope_live" in verdict["failed_checks"]
    assert "stale" in verdict["checks"]["scope_live"]["reason"]


def test_mismatched_payout_unverified():
    prog = make_prog(payout=10000)
    fresh = make_prog(payout=5000)
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["verdict"] == "unverified"
    assert verdict["failed_checks"] == ["payouts_match"]
    assert "mismatch" in verdict["checks"]["payouts_match"]["reason"]


def test_payout_float_dust_matches():
    # #24: conversion dust / str-float round-trips are not payout changes.
    prog = make_prog(payout=10000)
    fresh = make_prog(payout=10000.0000001)
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["checks"]["payouts_match"]["status"] == "match"
    assert "payouts_match" not in verdict["failed_checks"]


def test_payout_subdollar_rounding_matches():
    prog = make_prog(payout=10000)
    fresh = make_prog(payout=9999.60)
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["checks"]["payouts_match"]["status"] == "match"


def test_payout_string_float_mix_matches():
    prog = make_prog(payout="10000")
    fresh = make_prog(payout=10000.0)
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["checks"]["payouts_match"]["status"] == "match"


def test_payout_real_change_still_blocks():
    # #24: tolerance is dust-only — a 1% move still mismatches, with the
    # delta in the reason.
    prog = make_prog(payout=10000)
    fresh = make_prog(payout=9900)
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    leg = verdict["checks"]["payouts_match"]
    assert leg["status"] == "mismatch"
    assert "payouts_match" in verdict["failed_checks"]
    assert "100.00" in leg["reason"]


def test_payout_currency_change_still_blocks():
    prog = make_prog(payout=10000)
    fresh = make_prog(payout=10000)
    fresh["currency"] = "EUR"
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["checks"]["payouts_match"]["status"] == "mismatch"


def test_unknown_payout_does_not_block():
    # Tri-state leg: unknown payouts (e.g. all of HackerOne) are explicit
    # and non-blocking — only a proven mismatch blocks verification.
    prog = make_prog(payout=10000)
    fresh = make_prog(payout=None)
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["verdict"] == "verified"
    assert verdict["checks"]["payouts_match"]["status"] == "unknown"
    assert "payouts_match" not in verdict["failed_checks"]


def test_changed_rules_unverified():
    prog = make_prog(rules="RULES v1")
    fresh = make_prog(rules="RULES v2: no more bugs.")
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["verdict"] == "unverified"
    assert verdict["failed_checks"] == ["rules_unchanged"]
    assert "changed" in verdict["checks"]["rules_unchanged"]["reason"]


def test_missing_rules_advisory_unknown():
    # Advisory leg: no feed carries rules text, so unknown is explicit and
    # non-blocking — only a proven change (both sides known, hashes differ)
    # or a vanished program fails it. Rules text is never faked.
    prog = make_prog(rules="")
    prog.pop("rules_text")
    fresh = make_prog(rules="")
    fresh.pop("rules_text")
    verdict = intake.verify_program(snap_of(prog), fresh, probe_fn=probe_live)
    assert verdict["verdict"] == "verified"
    assert verdict["checks"]["rules_unchanged"]["status"] == "unknown"
    assert verdict["checks"]["rules_unchanged"]["advisory"] is True
    assert "unavailable" in verdict["checks"]["rules_unchanged"]["reason"]


def test_missing_fresh_program_unverified():
    verdict = intake.verify_program(snap_of(make_prog()), None, probe_fn=probe_live)
    assert verdict["verdict"] == "unverified"
    assert set(verdict["failed_checks"]) == {
        "scope_live",
        "payouts_match",
        "rules_unchanged",
    }


# ── apex exclusion (P7) ─────────────────────────────────────────────────────


def test_wildcard_only_scope_never_verifies():
    prog = make_prog(scopes=[_scope("*.acme.com", "wildcard", True)])
    hosts, skipped = intake.derive_probe_hosts(prog)
    assert hosts == []
    assert any("P7" in s for s in skipped)
    verdict = intake.verify_program(snap_of(prog), dict(prog), probe_fn=probe_live)
    assert verdict["verdict"] == "unverified"
    assert "scope_live" in verdict["failed_checks"]


def test_apex_rejected_under_wildcard_parity():
    import oracle_scan4me as bridge

    prog = make_prog(scopes=[_scope("*.acme.com", "wildcard", True)])
    ok, _ = bridge.verify_in_scope("acme.com", prog)
    assert not ok  # P7 parity: apex never covered by the wildcard
    ok2, _ = bridge.verify_in_scope("api.acme.com", prog)
    assert ok2


def test_wildcard_only_gets_policy_status_in_report():
    # #14: declared policy, distinct from stale/empty scope. The status
    # rides the scope_live leg into the scan report verdict.
    prog = make_prog(scopes=[_scope("*.acme.com", "wildcard", True)])
    verdict = intake.verify_program(snap_of(prog), dict(prog), probe_fn=probe_live)
    leg = verdict["checks"]["scope_live"]
    assert leg["pass"] is False
    assert leg["status"] == "wildcard_only_unverifiable"
    assert "policy" in leg["reason"] and "P7" in leg["reason"]
    assert verdict["verdict"] == "unverified"


def test_empty_scope_gets_distinct_status():
    prog = make_prog(scopes=[])
    verdict = intake.verify_program(snap_of(prog), dict(prog), probe_fn=probe_live)
    leg = verdict["checks"]["scope_live"]
    assert leg["pass"] is False
    assert leg["status"] == "no_probe_hosts"


def test_explicit_apex_asset_is_probed_on_own_merit():
    prog = make_prog(
        scopes=[
            _scope("*.acme.com", "wildcard", True),
            _scope("acme.com", "url", False),
        ]
    )
    hosts, _ = intake.derive_probe_hosts(prog)
    assert hosts == ["acme.com"]
    verdict = intake.verify_program(snap_of(prog), dict(prog), probe_fn=probe_live)
    assert verdict["checks"]["scope_live"]["pass"] is True


# ── -N deep-dive selection ──────────────────────────────────────────────────


def _scan_report(*verdicts):
    return {"_schema": intake.SCAN_SCHEMA, "verdicts": list(verdicts)}


def _verdict(name, score, ok=True, failed=()):
    return {
        "name": name,
        "handle": name.lower(),
        "platform": "hackerone",
        "url": f"https://hackerone.com/{name.lower()}",
        "score": score,
        "max_payout_usd": 1000,
        "currency": "USD",
        "verdict": "verified" if ok else "unverified",
        "failed_checks": list(failed),
        "checks": {},
    }


def test_top_n_selects_top_verified_by_score():
    progs = [snap_of(make_prog("Low", "low", score=10.0))]
    scan = _scan_report(
        _verdict("Low", 10.0), _verdict("High", 90.0), _verdict("Mid", 50.0)
    )
    sel = intake.select_deep_dive(scan, prescan_programs=progs, top_n=2)
    assert [r["name"] for r in sel["ranked_verified"]] == ["High", "Mid"]
    assert [r["rank"] for r in sel["ranked_verified"]] == [1, 2]
    assert sel["excluded_named"] == []


def test_named_sites_override_count():
    scan = _scan_report(
        _verdict("High", 90.0), _verdict("Mid", 50.0), _verdict("Low", 10.0)
    )
    sel = intake.select_deep_dive(scan, top_n=1, sites=["low", "mid"])
    # count ignored: both named sites returned despite top_n=1
    assert [r["name"] for r in sel["ranked_verified"]] == ["Low", "Mid"]


def test_named_unverified_site_excluded():
    scan = _scan_report(
        _verdict("Good", 90.0),
        _verdict("Bad", 99.0, ok=False, failed=["payouts_match"]),
    )
    sel = intake.select_deep_dive(scan, sites=["bad"])
    assert sel["ranked_verified"] == []
    assert len(sel["excluded_named"]) == 1
    assert "unverified" in sel["excluded_named"][0]["reason"]


def test_unverified_never_proceeds():
    scan = _scan_report(
        _verdict("Good", 10.0),
        _verdict("Bad", 99.0, ok=False, failed=["scope_live"]),
        {"name": "NoVerdict", "handle": "noverdict", "score": 100.0},
    )
    sel = intake.select_deep_dive(scan, top_n=10)
    assert [r["name"] for r in sel["ranked_verified"]] == ["Good"]
    sel2 = intake.select_deep_dive(scan, sites=["bad", "noverdict", "good"])
    assert [r["name"] for r in sel2["ranked_verified"]] == ["Good"]


def test_top_n_negative_raises():
    with pytest.raises(ValueError, match="top-n"):
        intake.select_deep_dive(_scan_report(_verdict("A", 1.0)), top_n=-1)


def test_deep_dive_carries_assets_company_resources():
    scan = _scan_report(_verdict("Acme", 70.0))
    sel = intake.select_deep_dive(
        scan, prescan_programs=[snap_of(make_prog(score=70.0))], top_n=1
    )
    dd = sel["ranked_verified"][0]["deep_dive"]
    assert dd["assets"] and dd["assets"][0]["asset_identifier"] == "app.acme.com"
    assert dd["company"]["website"] == "https://acme.com"
    assert dd["resources"]["program_url"].endswith("/acme")
    assert dd["sources"] == ["scan4me:programs+assets"]


# ── offline path + handoff ──────────────────────────────────────────────────


def test_offline_scan_skips_probes(tmp_path):
    prog = make_prog()
    prescan = {
        "_schema": intake.PRESCAN_SCHEMA,
        "programs": [snap_of(prog)],
        "_report_path": "x",
    }
    report = intake.run_scan(
        prescan,
        resolve_fn=lambda _k: dict(prog),
        probe_fn=probe_must_not_run,
        no_cloud=True,
        out_dir=tmp_path,
        stamp="off1",
    )
    chk = report["verdicts"][0]["checks"]["scope_live"]
    assert chk["pass"] is False
    assert "offline" in chk["reason"]
    assert Path(report["_report_path"]).exists()


def test_run_scan_end_to_end(tmp_path):
    good, stale = make_prog("Good", "good"), make_prog("Stale", "stale")
    prescan = {
        "_schema": intake.PRESCAN_SCHEMA,
        "programs": [snap_of(good), snap_of(stale)],
        "_report_path": "x",
    }

    def resolve(key):
        return {"good": dict(good), "stale": dict(stale)}[key]

    report = intake.run_scan(
        prescan, resolve_fn=resolve, probe_fn=probe_live, out_dir=tmp_path, stamp="e2e"
    )
    assert report["verified_count"] == 2  # both live here; staleness is per-probe

    report2 = intake.run_scan(
        prescan,
        resolve_fn=resolve,
        probe_fn=probe_dead,
        out_dir=tmp_path,
        stamp="e2e2",
    )
    assert report2["verified_count"] == 0
    assert report2["count"] == 2


def test_handoff_schema_and_fail_closed_empty(tmp_path):
    sel = {"ranked_verified": [], "excluded_named": [{"site": "x", "reason": "y"}]}
    payload = intake.write_handoff(
        sel,
        scan_report_path="s.json",
        prescan_report_path="p.json",
        top_n=3,
        out_dir=tmp_path,
        stamp="h1",
    )
    on_disk = json.loads(Path(payload["_report_path"]).read_text())
    assert on_disk["_schema"] == intake.HANDOFF_SCHEMA
    assert on_disk["ranked_verified"] == []
    assert on_disk["selector"] == {"top_n": 3, "sites": None}
    assert on_disk["scan_report"] == "s.json"
    assert "unverified" in on_disk["note"]


def test_handoff_only_verified(tmp_path):
    scan = _scan_report(_verdict("Good", 10.0), _verdict("Bad", 99.0, ok=False))
    sel = intake.select_deep_dive(scan)
    payload = intake.write_handoff(sel, out_dir=tmp_path, stamp="h2")
    names = [r["name"] for r in payload["ranked_verified"]]
    assert names == ["Good"]
    assert all(r["verdict"] == "verified" for r in payload["ranked_verified"])


# ── hunter CLI wiring ───────────────────────────────────────────────────────


# ── P11-findings (a): fresh deep-dive assets ─────────────────────────────────


def test_deep_dive_reresolves_fresh_assets_not_snapshot():
    """Aged prescan: snapshot scopes must NOT feed deep-dive (MODERATE)."""
    aged_snap = snap_of(make_prog(scopes=[_scope("old-retired.acme.com")], score=70.0))
    fresh_prog = make_prog(
        scopes=[_scope("new.acme.com"), _scope("api.acme.com")], score=70.0
    )
    scan = _scan_report(_verdict("Acme", 70.0))
    sel = intake.select_deep_dive(
        scan,
        prescan_programs=[aged_snap],
        top_n=1,
        resolve_fn=lambda _k: dict(fresh_prog),
    )
    assert len(sel["ranked_verified"]) == 1
    dd = sel["ranked_verified"][0]["deep_dive"]
    idents = [a["asset_identifier"] for a in dd["assets"]]
    assert idents == ["new.acme.com", "api.acme.com"]
    assert "old-retired.acme.com" not in idents
    assert "deep-dive:fresh-resolve" in dd["sources"]


def test_deep_dive_missing_fresh_excluded_fail_closed():
    """Vanished-at-dive-time program: excluded, never snapshot-fed."""
    scan = _scan_report(_verdict("Acme", 70.0), _verdict("Beta", 60.0))
    snaps = [snap_of(make_prog("Acme", "acme")), snap_of(make_prog("Beta", "beta"))]

    def resolve(key):
        return dict(make_prog("Acme", "acme")) if key == "acme" else None

    sel = intake.select_deep_dive(
        scan, prescan_programs=snaps, top_n=5, resolve_fn=resolve
    )
    assert [r["name"] for r in sel["ranked_verified"]] == ["Acme"]
    assert [r["rank"] for r in sel["ranked_verified"]] == [1]
    stale = [e for e in sel["excluded_named"] if e.get("program") == "Beta"]
    assert len(stale) == 1
    assert "deep-dive-stale" in stale[0]["reason"]


def test_deep_dive_resolve_error_excluded_fail_closed():
    """Resolver exception at dive time: excluded, like run_scan does."""

    def boom(_key):
        raise RuntimeError("db locked")

    scan = _scan_report(_verdict("Acme", 70.0))
    sel = intake.select_deep_dive(
        scan,
        prescan_programs=[snap_of(make_prog())],
        top_n=1,
        resolve_fn=boom,
    )
    assert sel["ranked_verified"] == []
    assert any("deep-dive-stale" in e["reason"] for e in sel["excluded_named"])


def test_deep_dive_legacy_snapshot_path_without_resolver():
    """No resolve_fn: snapshot path preserved (sources unflagged)."""
    scan = _scan_report(_verdict("Acme", 70.0))
    sel = intake.select_deep_dive(
        scan, prescan_programs=[snap_of(make_prog(score=70.0))], top_n=1
    )
    dd = sel["ranked_verified"][0]["deep_dive"]
    assert dd["assets"][0]["asset_identifier"] == "app.acme.com"
    assert dd["sources"] == ["scan4me:programs+assets"]


# ── P11-findings (b): precise --sites matching ───────────────────────────────


def test_matches_site_exact_name_handle():
    prog = make_prog()
    assert intake._matches_site(prog, "acme") is True
    assert intake._matches_site(prog, "Acme") is True  # case-insensitive
    assert intake._matches_site(prog, "  ACME  ") is True


def test_matches_site_no_substring_false_positives():
    prog = make_prog()
    for site in ("acm", "cme", "cm", "acme2", "my-acme", ""):
        assert intake._matches_site(prog, site) is False, site


def test_matches_site_domain_boundary():
    prog = make_prog()  # website https://acme.com
    assert intake._matches_site(prog, "acme.com") is True
    assert intake._matches_site(prog, "app.acme.com") is True  # subdomain
    assert intake._matches_site(prog, "https://acme.com/some/path") is True
    for site in ("notacme.com", "acme.com.evil.com", "evil-acme.com", "cme.com"):
        assert intake._matches_site(prog, site) is False, site


def test_named_substring_site_no_longer_matches():
    scan = _scan_report(_verdict("Acme", 70.0))
    sel = intake.select_deep_dive(scan, sites=["acm"])
    assert sel["ranked_verified"] == []
    assert sel["excluded_named"][0]["reason"] == "no verified program matches"
    sel2 = intake.select_deep_dive(scan, sites=["acme"])
    assert [r["name"] for r in sel2["ranked_verified"]] == ["Acme"]


# ── P11-findings (d): unified handle round-trip ──────────────────────────────


def _seed_scan4me_db(path):
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE programs (
            id INTEGER PRIMARY KEY, name TEXT, handle TEXT, url TEXT,
            website TEXT, platform TEXT, max_payout REAL, currency TEXT,
            offers_bounties INTEGER, managed_triage INTEGER, safe_harbor TEXT,
            program_kind TEXT, first_response_hours REAL,
            response_efficiency REAL, validation_days REAL,
            rewarded_vulnerabilities INTEGER, average_payout REAL)"""
    )
    conn.execute(
        """CREATE TABLE assets (
            id INTEGER PRIMARY KEY, program_id INTEGER,
            asset_identifier TEXT, asset_type TEXT, is_wildcard INTEGER)"""
    )
    # DB handle differs from the URL slug on purpose (the skew case).
    conn.execute(
        "INSERT INTO programs (id, name, handle, url, website, platform,"
        " max_payout, currency, offers_bounties, managed_triage, safe_harbor,"
        " program_kind) VALUES (1, 'Acme Corp', 'acme-corp',"
        " 'https://hackerone.com/acme', 'https://acme.com', 'HackerOne',"
        " 10000, 'USD', 1, 1, 'Standard', 'web2')"
    )
    conn.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type,"
        " is_wildcard) VALUES (1, 'app.acme.com', 'URL', 0)"
    )
    conn.commit()
    conn.close()


def test_resolve_url_slug_round_trips_to_db_handle(tmp_path, monkeypatch):
    """fetch's slug handle must resolve even when the DB handle differs."""
    import oracle_scan4me as bridge

    _seed_scan4me_db(tmp_path / "scan4me.db")
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    assert bridge.handle_from_url("https://hackerone.com/acme/") == "acme"
    by_slug = bridge.resolve("acme")
    assert by_slug is not None
    assert by_slug["handle"] == "acme-corp"
    assert by_slug["name"] == "Acme Corp"
    by_handle = bridge.resolve("acme-corp")
    assert by_handle is not None
    assert by_handle["handle"] == "acme-corp"


def test_fetch_programs_diversifies_ranked_platforms():
    """A telemetry-rich platform must not monopolize Oracle's prescan.

    Scan4Me's score remains the within-platform ordering; Oracle's
    shortlist interleaves the best program from each represented
    platform before taking second-ranked programs.
    """
    import oracle_scan4me as bridge

    ranked = [
        {"name": f"H{i}", "platform": "HackerOne", "score": 100 - i}
        for i in range(6)
    ] + [
        {"name": "B0", "platform": "Bugcrowd", "score": 70},
        {"name": "B1", "platform": "Bugcrowd", "score": 69},
        {"name": "I0", "platform": "Intigriti", "score": 66},
        {"name": "P0", "platform": "PDPrograms", "score": 65},
        {"name": "Y0", "platform": "YesWeHack", "score": 59},
    ]

    selected = bridge._diversify_ranked_by_platform(ranked, limit=8)

    assert [p["name"] for p in selected] == [
        "H0",
        "B0",
        "I0",
        "P0",
        "Y0",
        "H1",
        "B1",
        "H2",
    ]
    assert [p["_platform_rank"] for p in selected] == [1, 1, 1, 1, 1, 2, 2, 3]
    assert [p["_selection_rank"] for p in selected] == list(range(1, 9))
    assert ranked[0].get("_selection_rank") is None  # inputs are copied


def test_fetch_programs_uses_db_handle(tmp_path, monkeypatch):
    """fetch_programs emits the DB handle (what resolve matches exactly)."""
    import sys
    import types

    import oracle_scan4me as bridge

    _seed_scan4me_db(tmp_path / "scan4me.db")
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    fake = types.ModuleType("scan4me")
    fake.load_config = lambda: {}
    fake.evaluate_targets = lambda _cfg: [
        {
            "id": 1,
            "name": "Acme Corp",
            "url": "https://hackerone.com/acme",
            "website": "https://acme.com",
            "platform": "HackerOne",
            "max_payout": 10000,
            "currency": "USD",
            "managed": True,
            "safe_harbor": "Standard",
            "program_kind": "web2",
            "first_resp": 12,
            "efficiency": 95,
            "validation_days": None,
            "rewarded_vulnerabilities": None,
            "average_payout": None,
            "score": 70.0,
            "speed_score": 50.0,
            "fresh_score": 50.0,
            "surface_score": 25.0,
            "payout_score": 70.0,
            "surface_tier": "narrow",
        }
    ]
    monkeypatch.setitem(sys.modules, "scan4me", fake)
    progs = bridge.fetch_programs(limit=5)
    assert len(progs) == 1
    assert progs[0]["handle"] == "acme-corp"
    # Full round-trip: the fetched handle resolves back to the same program.
    back = bridge.resolve(progs[0]["handle"])
    assert back is not None
    assert back["name"] == "Acme Corp"


# ── hunter CLI wiring ───────────────────────────────────────────────────────


def test_hunter_cli_wiring(monkeypatch):
    import oracle_hunter as oh

    seen = {}

    def fake_prescan(args):
        seen["prescan"] = {
            "limit": getattr(args, "limit", None),
            "cloud": getattr(args, "cloud", "unset"),
        }

    def fake_scan(args):
        seen["scan"] = {
            "top_n": getattr(args, "top_n", "unset"),
            "sites": getattr(args, "sites", "unset"),
        }

    monkeypatch.setattr(oh, "cmd_prescan", fake_prescan)
    monkeypatch.setattr(oh, "cmd_scan", fake_scan)

    monkeypatch.setattr(sys, "argv", ["oracle-hunter", "--prescan"])
    oh.main()
    # global alias carries no options (use the prescan subcommand for flags)
    assert seen["prescan"] == {"limit": None, "cloud": "unset"}

    monkeypatch.setattr(
        sys, "argv", ["oracle-hunter", "prescan", "--limit", "5", "--no-cloud"]
    )
    oh.main()
    assert seen["prescan"] == {"limit": 5, "cloud": False}

    monkeypatch.setattr(sys, "argv", ["oracle-hunter", "scan", "-N", "3"])
    oh.main()
    assert seen["scan"] == {"top_n": 3, "sites": None}

    monkeypatch.setattr(
        sys, "argv", ["oracle-hunter", "scan", "--sites", "a,b", "--top-n", "1"]
    )
    oh.main()
    assert seen["scan"] == {"top_n": 1, "sites": "a,b"}


# ── #5/#9 provenance stamps ─────────────────────────────────────────────────


def _tmp_scan4me_db(tmp_path, monkeypatch, sha="deadbeef"):
    import sqlite3
    import time

    s4m = _import_scan4me()

    home = tmp_path / "s4m"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("SCAN4ME_HOME", str(home))
    db = home / "scan4me.db"
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    s4m.init_db(conn)
    s4m.migrate_db(conn)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('upstream_sha', ?)", (sha,)
    )
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('last_sync_ts', ?)",
        (str(int(time.time())),),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(s4m, "DB_PATH", db)
    return s4m


def test_reports_carry_feed_provenance(tmp_path, monkeypatch):
    _tmp_scan4me_db(tmp_path, monkeypatch)
    out = tmp_path / "r"
    prescan = intake.run_prescan(fetch_fn=lambda: [], out_dir=out)
    assert prescan["feed_provenance"]["upstream_sha"] == "deadbeef"
    assert prescan["feed_provenance"]["stale"] is False
    scan = intake.run_scan(prescan, resolve_fn=lambda k: None, out_dir=out)
    assert scan["feed_provenance"]["upstream_sha"] == "deadbeef"
    hand = intake.write_handoff({"ranked_verified": []}, out_dir=out)
    assert hand["feed_provenance"]["upstream_sha"] == "deadbeef"
    assert "feed_trust" in hand


def _prov(source="public-file", *, age=1.0, stale=False, refresh_ok=True):
    return {
        "refresh_ok": refresh_ok,
        "age_hours": age,
        "stale": stale,
        "platforms": {
            "hackerone": {
                "count": 10,
                "source": source,
                "status": "ok",
            }
        },
    }


def test_feed_trust_rejects_public_rows_and_missing_auth():
    trust = intake.feed_trust_block(_prov())
    assert trust["ok"] is False
    assert any("public-file" in i for i in trust["issues"])
    assert any("authenticated" in i for i in trust["issues"])


def test_feed_trust_accepts_fresh_authenticated_feed():
    trust = intake.feed_trust_block(_prov("authenticated"))
    assert trust["ok"] is True
    assert trust["issues"] == []
    assert trust["authenticated_platforms"] == ["hackerone"]


def test_feed_trust_rejects_public_listing_sources():
    prov = _prov("authenticated")
    prov["platforms"]["immunefi"] = {
        "count": 5, "source": "live-board", "status": "ok",
    }
    prov["platforms"]["pd_programs"] = {
        "count": 3, "source": "pd-repo", "status": "ok",
    }
    trust = intake.feed_trust_block(prov)
    assert trust["ok"] is False
    assert set(trust["public_platforms"]) == {"immunefi", "pd_programs"}
    assert any("live-board" in i for i in trust["issues"])


def test_feed_trust_rejects_unknown_and_unlabeled_sources():
    for source in ("some-future-source", None):
        trust = intake.feed_trust_block(_prov(source))
        assert trust["ok"] is False, source
        assert trust["public_platforms"] == ["hackerone"]


def test_feed_trust_rejects_stale_or_failed_refresh():
    stale = intake.feed_trust_block(_prov("authenticated", age=200.0, stale=True))
    assert stale["ok"] is False
    assert any("stale" in i for i in stale["issues"])
    failed = intake.feed_trust_block(
        _prov("authenticated", refresh_ok=False)
    )
    assert failed["ok"] is False
    assert any("refresh" in i for i in failed["issues"])


def test_run_prescan_writes_report_then_rejects_untrusted_feed(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(intake, "feed_provenance_block", lambda: _prov())
    monkeypatch.setattr(
        _bridge, "fetch_programs", lambda limit: [make_prog()]
    )
    with pytest.raises(intake.FeedTrustError) as exc:
        intake.run_prescan(out_dir=tmp_path, stamp="untrusted")
    report = exc.value.report
    path = Path(exc.value.report_path)
    assert path.exists()
    assert report["feed_trust"]["ok"] is False
    assert report["feed_trust"]["enforced"] is True
    on_disk = json.loads(path.read_text())
    assert on_disk["feed_trust"]["ok"] is False
    assert on_disk["count"] == 1


def test_run_prescan_explicit_public_override_is_recorded(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(intake, "feed_provenance_block", lambda: _prov())
    monkeypatch.setattr(
        _bridge, "fetch_programs", lambda limit: [make_prog()]
    )
    report = intake.run_prescan(
        out_dir=tmp_path, stamp="override", allow_public_feed=True
    )
    assert report["feed_trust"]["ok"] is True
    assert report["feed_trust"]["overridden"] is True
    assert report["feed_trust"]["warnings"]


def test_run_scan_requires_trusted_prescan_and_current_feed(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(intake, "feed_provenance_block", lambda: _prov("authenticated"))
    untrusted = {
        "programs": [],
        "feed_trust": {"ok": False, "issues": ["public-file rows"]},
    }
    with pytest.raises(intake.FeedTrustError, match="prescan feed"):
        intake.run_scan(
            untrusted,
            out_dir=tmp_path,
            stamp="reject",
            require_trusted_prescan=True,
        )
    trusted = {"programs": [], "feed_trust": {"ok": True, "issues": []}}
    report = intake.run_scan(
        trusted,
        out_dir=tmp_path,
        stamp="accept",
        require_trusted_prescan=True,
    )
    assert report["feed_trust"]["ok"] is True
    # Current provenance is also part of product truth: a trusted old
    # prescan cannot make a now-public feed acceptable.
    monkeypatch.setattr(intake, "feed_provenance_block", lambda: _prov())
    with pytest.raises(intake.FeedTrustError, match="current Scan4Me feed"):
        intake.run_scan(
            trusted,
            out_dir=tmp_path,
            stamp="now-public",
            require_trusted_prescan=True,
        )


def test_provenance_unknowns_when_db_empty(tmp_path, monkeypatch):
    import sqlite3

    s4m = _import_scan4me()

    home = tmp_path / "s4m"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("SCAN4ME_HOME", str(home))
    db = home / "scan4me.db"
    sqlite3.connect(str(db)).close()  # no tables at all
    monkeypatch.setattr(s4m, "DB_PATH", db)
    block = intake.feed_provenance_block()
    # Tolerant read: unknowns reported, never zeros, never an exception.
    assert block.get("upstream_sha", "unknown") == "unknown"
    assert block["row_counts"] == {
        "programs": None,
        "live_assets": None,
        "contests": None,
    }
