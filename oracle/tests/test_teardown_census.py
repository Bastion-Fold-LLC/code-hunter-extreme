#!/usr/bin/env python3
"""Teardown census: one terminal stage per candidate, counts must reconcile."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import teardown_census as tc


def _card(**over):
    base = {
        "check": "grep -n 'SELECT' /tmp/x.php",
        "assertion_a": "a",
        "assertion_b": "b",
        "verdict": "CERTAIN",
        "lens": "seam-template",
    }
    base.update(over)
    return base


def test_static_unsolved_card_is_runnable_check_not_teardown():
    """UNSOLVED means no probe ran; it must not be counted as a teardown loss."""
    stage, reason = tc.classify(_card(verdict="UNSOLVED", lens="invisible-seam"))
    assert stage == "runnable-check"
    assert "static" in reason


def test_failed_replay_is_teardown_with_named_attack():
    card = _card(
        poc_teardown={
            "verdict": "FAIL",
            "attacks": [
                {"name": "replay", "result": "FAIL", "detail": "0/3 replays re-confirmed"},
                {"name": "evaluator_sanity", "result": "PASS", "detail": ""},
            ],
            "notes": "Teardown FAILED",
        }
    )
    stage, reason = tc.classify(card)
    assert stage == "teardown"
    assert reason == "replay: 0/3 replays re-confirmed"


def test_passing_teardown_that_wire_rejects_is_wire_verify():
    stage, reason = tc.classify(
        _card(poc_teardown={"verdict": "PASS", "attacks": []}, verify_confirmed="False",
              verify_verdict="TEARDOWN-FAILED — nope")
    )
    assert stage == "wire-verify"


def test_only_rejected_redteam_cards_are_redteam():
    assert tc.classify(_card(redteam_verdict="rejected"))[0] == "redteam"
    assert tc.classify(_card(redteam_verdict="confirmed"))[0] == "CONFIRMED"


def test_conflicted_cross_lens_card_is_corroboration():
    assert tc.classify(_card(m3_seam_state="conflicted"))[0] == "corroboration"
    assert tc.classify(_card(m3_seam_conflict=True))[0] == "corroboration"


def test_missing_check_is_schema():
    assert tc.classify(_card(check=""))[0] == "schema"


def test_fully_confirmed_card():
    assert tc.classify(
        _card(verdict="CERTAIN", poc_teardown={"verdict": "PASS", "attacks": []},
              verify_confirmed="True")
    )[0] == "CONFIRMED"


def test_census_accounts_for_every_candidate():
    findings = [
        _card(verdict="UNSOLVED", lens="invisible-seam"),
        _card(verdict="UNSOLVED", lens="invisible-seam"),
        _card(poc_teardown={"verdict": "FAIL",
                            "attacks": [{"name": "replay", "result": "FAIL",
                                         "detail": "0/3 replays re-confirmed"}]}),
        _card(verdict="CERTAIN", poc_teardown={"verdict": "PASS", "attacks": []},
              verify_confirmed="True"),
    ]
    result = tc.census(findings)
    assert result["total"] == 4
    assert result["confirmed"] == 1
    accounted = sum(result["stages"].values()) + result["confirmed"]
    assert accounted == 4
    assert result["per_lens"]["invisible-seam"] == {"runnable-check": 2}
    assert result["top_reasons"][0] == ("runnable-check: static conflict, no observable probe", 2)


def test_render_reports_the_accounting_line():
    result = tc.census([_card(verdict="UNSOLVED")])
    text = tc.render(result, Path("/tmp/ws"))
    assert "accounted for: 1/1" in text
    assert "runnable-check" in text
