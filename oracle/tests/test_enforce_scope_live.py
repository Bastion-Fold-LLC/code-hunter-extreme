"""Oracle enforcement #13: check_scope_live requires live, not just resolves."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_intake as intake


def _prog():
    return {
        "name": "Acme",
        "handle": "acme",
        "platform": "h1",
        "url": "https://h1/acme",
        "max_payout_usd": 1000,
        "currency": "USD",
        "score": 50.0,
        "structured_scopes": [
            {
                "asset_identifier": "api.acme.com",
                "asset_type": "DOMAIN",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "rules_text": "rules",
    }


def probe_resolves_not_live(host, timeout=8.0):
    return {
        "host": host,
        "resolves": True,
        "live": False,
        "status": None,
        "error": "http: connection refused",
    }


def probe_live(host, timeout=8.0):
    return {"host": host, "resolves": True, "live": True, "status": 200, "error": ""}


def test_resolves_but_not_live_fails():
    chk = intake.check_scope_live(_prog(), probe_fn=probe_resolves_not_live)
    assert chk["pass"] is False
    assert "stale scope" in chk["reason"]
    assert chk["resolved_count"] == 1 and chk["live_count"] == 0


def test_live_passes_with_counts():
    chk = intake.check_scope_live(_prog(), probe_fn=probe_live)
    assert chk["pass"] is True
    assert "live" in chk["reason"]
    assert chk["resolved_count"] == 1 and chk["live_count"] == 1


def test_verify_program_rejects_resolves_only_scope():
    prog = _prog()
    verdict = intake.verify_program(
        intake._snapshot_program(prog), dict(prog), probe_fn=probe_resolves_not_live
    )
    assert verdict["verdict"] == "unverified"
    assert "scope_live" in verdict["failed_checks"]
