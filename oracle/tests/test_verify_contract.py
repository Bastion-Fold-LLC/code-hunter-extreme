#!/usr/bin/env python3
"""Hole #11: bridge → verify contract test (the seam no test covered).

Builds a REAL Scan4Me DB with the producer's own schema (init_db +
migrate_db), resolves a program through the REAL bridge, and runs it
through the REAL intake verify pass. Proves holes #1/#2/#3 fixes:

  - a feed-describable program (no rules text, no payout amount) VERIFIES
    instead of failing legs 2+3 by construction;
  - eligibility flags + out-of-scope identifiers survive producer → bridge;
  - tombstoned assets never reach the consumer;
  - proven mismatches (payout / rules-change) STILL block verification.

No network: liveness is a stub probe_fn (scope_live derivation is real).
"""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_intake as intake
import oracle_scan4me as bridge


def _scan4me_module():
    home = bridge.scan4me_home()
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


@pytest.fixture()
def live_db(monkeypatch, tmp_path):
    """Temp Scan4Me DB with producer-real schema + one H1-style program."""
    s4m = _scan4me_module()  # real checkout, before env redirect
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    db_path = tmp_path / "scan4me.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    s4m.init_db(conn)
    s4m.migrate_db(conn)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO programs (platform, name, handle, url, website,
           offers_bounties, managed_triage, first_response_hours,
           response_efficiency, max_payout, currency, safe_harbor,
           program_kind)
           VALUES ('HackerOne', 'Acme', 'acme',
           'https://hackerone.com/acme', 'https://acme.com',
           1, 1, 12.0, 95.0, 0.0, 'USD', 'Standard', 'web2')"""
    )
    pid = cur.lastrowid
    cur.execute(
        """INSERT INTO assets (program_id, asset_identifier, asset_type,
           is_wildcard, eligible_for_bounty, eligible_for_submission,
           instruction, max_severity, first_seen_timestamp, deleted_timestamp)
           VALUES (?, 'app.acme.com', 'URL', 0, 1, 1, '', 'critical', 100, 0),
                  (?, 'legacy.acme.com', 'URL', 0, 0, 0, 'Do not test',
                   'none', 100, 0),
                  (?, 'dead.acme.com', 'URL', 0, 1, 1, '', '', 100, 999)""",
        (pid, pid, pid),
    )
    cur.execute(
        """INSERT INTO oos_assets (program_id, asset_identifier, asset_type,
           is_wildcard, first_seen_timestamp, deleted_timestamp)
           VALUES (?, 'evil.acme.com', 'URL', 0, 100, 0)""",
        (pid,),
    )
    conn.commit()
    conn.close()
    return db_path


def _probe_live(host, timeout=8.0):
    return {"host": host, "resolves": True, "live": True, "status": 200, "error": ""}


def test_bridge_passes_real_eligibility_and_oos(live_db):
    """#3: no hardcoded eligible=True; OOS list + flags reach the program dict;
    tombstones are filtered."""
    prog = bridge.resolve("acme")
    assert prog is not None
    assert prog["max_payout_usd"] is None  # H1's 0.0 stays unknown, not $0
    assert "rules_text" not in prog and "policy" not in prog  # feeds have none
    assert prog["out_of_scope"] == ["evil.acme.com"]

    by_ident = {s["asset_identifier"]: s for s in prog["structured_scopes"]}
    assert "dead.acme.com" not in by_ident  # tombstoned → invisible
    assert by_ident["app.acme.com"]["eligible_for_bounty"] is True
    assert by_ident["app.acme.com"]["eligible_for_submission"] is True
    assert by_ident["app.acme.com"]["max_severity"] == "critical"
    # The crux: explicit False survives (was hardcoded True).
    assert by_ident["legacy.acme.com"]["eligible_for_bounty"] is False
    assert by_ident["legacy.acme.com"]["eligible_for_submission"] is False
    assert by_ident["legacy.acme.com"]["instruction"] == "Do not test"


def test_feed_describable_program_verifies(live_db):
    """#1+#2: unknown payouts + unknown rules do not block verification."""
    prog = bridge.resolve("acme")
    snap = intake._snapshot_program(prog)
    assert snap["rules_hash"] is None  # unknown, honestly recorded
    assert snap["out_of_scope"] == ["evil.acme.com"]

    fresh = bridge.resolve("acme")  # fresh re-resolve, like run_scan
    verdict = intake.verify_program(snap, fresh, probe_fn=_probe_live)
    assert verdict["verdict"] == "verified"
    assert verdict["failed_checks"] == []
    assert verdict["checks"]["scope_live"]["pass"] is True
    assert verdict["checks"]["payouts_match"]["status"] == "unknown"
    assert verdict["checks"]["rules_unchanged"]["status"] == "unknown"
    assert verdict["checks"]["rules_unchanged"]["advisory"] is True


def test_proven_mismatches_still_block(live_db):
    """Tri-state/advisory legs stay teeth: real mismatch/change still fails."""
    prog = bridge.resolve("acme")

    # Payout mismatch with both sides known.
    pre = dict(prog, max_payout_usd=10000)
    fr = dict(prog, max_payout_usd=5000)
    v = intake.verify_program(intake._snapshot_program(pre), fr, probe_fn=_probe_live)
    assert v["verdict"] == "unverified"
    assert v["checks"]["payouts_match"]["status"] == "mismatch"

    # Rules change with both sides known.
    pre = dict(prog, rules_text="RULES v1")
    fr = dict(prog, rules_text="RULES v2")
    v = intake.verify_program(intake._snapshot_program(pre), fr, probe_fn=_probe_live)
    assert v["verdict"] == "unverified"
    assert v["checks"]["rules_unchanged"]["status"] == "mismatch"


def test_hunter_gate_receives_real_flags(live_db):
    """#3 end-to-end: the scope gate blocks OOS + ineligible, allows eligible."""
    from oracle_hunter import ProgramScopeGate

    prog = bridge.resolve("acme")
    gate = ProgramScopeGate(prog, target_fallback="acme")
    ok, _ = gate.is_in_scope("app.acme.com")
    assert ok is True
    blocked, reason = gate.is_in_scope("evil.acme.com")
    assert blocked is False
    assert "out_of_scope" in reason.lower()
    blocked, reason = gate.is_in_scope("legacy.acme.com")
    assert blocked is False
    assert "out_of_scope" in reason.lower()


def test_old_schema_bridge_stays_tolerant(monkeypatch, tmp_path):
    """Pre-migration DBs (no new columns/tables) still resolve with eligible
    defaults — tolerance until the next Scan4Me sync migrates them."""
    monkeypatch.setenv("SCAN4ME_HOME", str(tmp_path))
    conn = sqlite3.connect(str(tmp_path / "scan4me.db"))
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
        "INSERT INTO programs (name, handle, url, platform)"
        " VALUES ('Acme', 'acme', 'https://example.com/acme', 'hackerone')"
    )
    conn.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard)"
        " VALUES (1, 'app.acme.com', 'URL', 0)"
    )
    conn.commit()
    conn.close()

    prog = bridge.resolve("acme")
    assert prog is not None
    assert prog["out_of_scope"] == []
    scope = prog["structured_scopes"][0]
    assert scope["eligible_for_bounty"] is True
    assert scope["eligible_for_submission"] is True
