"""Foundation-3 operators: iPhone shape, frame rewrite, gear-turn."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_corpus import _FOUNDATION_IDS as CORPUS_FOUNDATION_IDS
from oracle_foundation import (
    FOUNDATION_IDS,
    GearTurn,
    build_seam_card,
    grade_strength,
    reframe_rejected,
    validate_card_shape,
    validate_discriminating,
)


def _card(**over):
    base = {
        "n": 1,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without creds",
        "check": "curl -s https://x.test/api",
        "expected": "status 200",
    }
    base.update(over)
    return base


def test_foundation_ids_match_packaged_corpus():
    assert tuple(FOUNDATION_IDS) == tuple(CORPUS_FOUNDATION_IDS)


# Op 1 ── iPhone isolator ──────────────────────────────────────────────


def test_valid_card_passes():
    assert validate_card_shape(_card()) is None


def test_missing_assertion_rejected():
    assert "assertion_a" in validate_card_shape(_card(assertion_a=""))


def test_missing_check_rejected():
    assert "check" in validate_card_shape(_card(check=""))


def test_multiline_check_rejected():
    assert "one command line" in validate_card_shape(_card(check="curl a\ncurl b"))


def test_builder_raises_on_malformed():
    with pytest.raises(ValueError):
        build_seam_card(1, "", "b", "curl x", "status 200")


def test_bare_get_cannot_prove_identity_claim():
    seam = _card(
        assertion_b="The server does not verify the session",
        check="curl -i -s http://x.test/",
        expected="status 200",
    )
    assert "cannot discriminate" in validate_discriminating(seam)


def test_marker_or_variation_satisfies_floor():
    base = {"assertion_b": "The server does not verify the session"}
    assert (
        validate_discriminating(
            _card(**base, check="curl -i -s http://x.test/", expected='status 200, body contains "admin"')
        )
        is None
    )
    assert "cannot discriminate" in validate_discriminating(
        _card(**base, check="curl -s http://x.test/a", expected="status 200")
    )
    assert (
        validate_discriminating(
            _card(**base, check='curl -s http://x.test/a -H "Cookie: none"', expected="status 200")
        )
        is None
    )


def test_non_identity_claim_unaffected():
    seam = _card(
        assertion_b="The backup file is exposed",
        check="curl -i -s http://x.test/.bak",
        expected="status 200",
    )
    assert validate_discriminating(seam) is None


def test_strength_grades():
    assert grade_strength(_card(check="curl -s http://x/a -H 'X: y'")).startswith("strong")
    assert grade_strength(
        _card(assertion_b="backup exposed", check="curl -s http://x/.bak")
    ).startswith("standard")
    assert grade_strength(
        _card(
            assertion_b="session not verified",
            check="curl -s http://x/",
            expected='status 200, body contains "t"',
        )
    ).startswith("weak")


def test_reframe_satisfies_floor_and_grades_strong():
    seam = _card(
        assertion_b="session not verified",
        check="curl -s http://x/",
        expected="status 200",
        reframe_transform="strip-auth",
    )
    assert validate_discriminating(seam) is None
    assert grade_strength(seam).startswith("strong")


def test_identical_assertions_rejected():
    assert "no binary conflict" in validate_card_shape(
        _card(assertion_b=_card()["assertion_a"])
    )
    with pytest.raises(ValueError):
        build_seam_card(1, "same", "same", "curl x", "status 200")


def test_builder_passes_extra_keys():
    card = build_seam_card(2, "a", "b", "curl x", "status 200", origin="t", n2=1)
    assert card["origin"] == "t"


# Op 2 ── frame rewriter ───────────────────────────────────────────────


def test_reframe_emits_bounded_followups():
    seam = _card(
        check='curl -s -X GET "https://x.test/a?id=3" -H "Authorization: Bearer z"'
    )
    cards = reframe_rejected(seam, 100)
    assert 1 <= len(cards) <= 5
    assert all(c["reframed"] and c["reframe_of"] == 1 for c in cards)
    assert [c["n"] for c in cards] == list(range(100, 100 + len(cards)))


def test_reframe_skips_non_curl():
    assert reframe_rejected(_card(check="slither ."), 100) == []


def test_reframe_cookie_mint_escalates_identity_cookie():
    seam = _card(
        check="curl -s 'https://x.test/bac' -H 'Cookie: PHPSESSID=abc; user_id=1'"
    )
    cards = reframe_rejected(seam, 100)
    minted = [c for c in cards if c.get("reframe_transform") == "cookie-mint"]
    assert len(minted) == 1
    assert "user_id=2" in minted[0]["check"]
    assert "user_id=1" not in minted[0]["check"]


def test_reframe_cookie_mint_ignores_cookieless_checks():
    seam = _card(check='curl -s "https://x.test/a?user_id=1"')
    cards = reframe_rejected(seam, 100)
    assert all(c.get("reframe_transform") != "cookie-mint" for c in cards)


def test_reframe_single_generation_only():
    assert reframe_rejected(_card(reframed=True), 100) == []


def test_strip_auth_transform_present():
    seam = _card(check='curl -s https://x.test/a -H "Authorization: Bearer z"')
    kinds = [c["reframe_transform"] for c in reframe_rejected(seam, 50)]
    assert "strip-auth" in kinds
    stripped = [
        c for c in reframe_rejected(seam, 50) if c["reframe_transform"] == "strip-auth"
    ][0]
    assert "Authorization" not in stripped["check"]


def test_param_tamper_escalates_role():
    seam = _card(check="curl -s 'https://x.test/a?role=user'")
    kinds = [c["reframe_transform"] for c in reframe_rejected(seam, 50)]
    assert "param-tamper" in kinds


# Op 3 ── gear-turn escalator ───────────────────────────────────────────


def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        GearTurn().mark("turbo")


def test_zero_confirmed_is_always_failure():
    g = GearTurn()
    assert "SYSTEM FAILURE" in g.summary(0)
    for m in ("instant", "delayed", "breakthrough", "recalled"):
        g.mark(m)
    assert "SYSTEM FAILURE" in g.summary(0)
    assert "all 4 modes" in g.summary(0)


def test_partial_and_complete_summaries():
    g = GearTurn()
    g.mark("instant")
    assert "PARTIAL" in g.summary(2)
    assert "delayed" in g.summary(2)
    for m in ("delayed", "breakthrough", "recalled"):
        g.mark(m)
    assert "COMPLETE" in g.summary(2)


def _funnel_entry(det=None, conf=False, kill=None, inconc=False):
    return {
        "det_verdict": det,
        "confirmed": conf,
        "kill_gate": kill,
        "inconclusive": inconc,
    }


def test_funnel_counts_classify_verify_outcomes():
    """funnel.json aggregation: deterministic vs post-gate vs pre-verify
    deaths counted from entry keys, not log scraping."""
    from oracle_foundation import build_funnel_counts

    confirmed = {
        1: _funnel_entry("CONFIRMED", True, None),
        2: _funnel_entry("REJECTED", False, None),
        3: _funnel_entry("CONFIRMED", False, "6b_spa"),
        4: _funnel_entry(None, False, "scope_gate"),
        5: _funnel_entry("CONFIRMED", False, None, True),
    }
    f = build_funnel_counts(confirmed, mined_wave1=4, followups_queued=1)
    assert f["mined_wave1"] == 4
    assert f["followups_queued"] == 1
    assert f["verify_attempted"] == 5
    assert f["det_confirmed"] == 3
    assert f["det_rejected"] == 1
    assert f["det_other"] == 1
    assert f["preverify_dropped"] == {"scope_gate": 1}
    assert f["postgate_killed"] == {"6b_spa": 1}
    assert f["final_confirmed"] == 1
    assert f["final_inconclusive"] == 1


def test_funnel_counts_tolerate_legacy_entries():
    """Entries without funnel keys (static code-lens verdicts merged
    post-verify) must not crash the aggregation or mislabel."""
    from oracle_foundation import build_funnel_counts

    out = build_funnel_counts({1: {"confirmed": False, "verdict": "x"}}, 1, 0)
    assert out["verify_attempted"] == 1
    assert out["det_other"] == 1
    assert out["preverify_dropped"] == {}
    assert out["postgate_killed"] == {}
