"""R2 mindset-2 completeness: both lenses get bounty context; paradox lens
gets framework + full verbatim corpus (philosophy, impossible problems,
paradoxes, iPhone framing).

Locks the doctrine wiring at the prompt-assembly level (no network, no keys).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext
from oracle_mindsets import require_mindsets, seam_candidate_key, synthesize_seams

_PROGRAM = {
    "name": "acme",
    "platform": "hackerone",
    "url": "https://h1.test/acme",
    "max_payout_usd": 5000,
    "kind": "web2",
    "structured_scopes": [
        {
            "asset_identifier": "https://api.example.test",
            "asset_type": "URL",
            "instruction": "in-scope",
        }
    ],
    "rules": "Do not test production payment flows.",
}


def _paradox_prompt() -> str:
    ctx = OracleMindsetContext(
        program=_PROGRAM, voice=False, ttp_mode="compact", mindset="paradox"
    )
    return ctx.system_prompt()


def _mitre_prompt() -> str:
    ctx = OracleMindsetContext(
        program=_PROGRAM, voice=False, ttp_mode="compact", mindset="mitre"
    )
    return ctx.system_prompt()


def _seam_prompt() -> str:
    ctx = OracleMindsetContext(
        program=_PROGRAM, voice=False, ttp_mode="compact", mindset="seam"
    )
    return ctx.system_prompt()


def test_all_lenses_get_bounty_context():
    for prompt in (_paradox_prompt(), _mitre_prompt(), _seam_prompt()):
        assert "ACTIVE PROGRAM — SCOPE WALL" in prompt
        assert "https://api.example.test" in prompt


def test_synthesis_lens_gets_synthesis_directive_and_compact_ttp():
    prompt = _seam_prompt()
    assert "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS" in prompt
    assert "ORACLE TTP REFERENCE" in prompt


def test_paradox_lens_gets_framework_and_full_corpus():
    prompt = _paradox_prompt()
    # Framework philosophy (ORACLE_FRAMEWORK.md is paradox-profile-only).
    assert "Binary Conflict Isolation" in prompt
    # Verbatim corpus: foundation + every family + the newly registered docs.
    assert "SOURCE CONTEXT (verbatim corpus)" in prompt
    for ident in (
        "iphone-problem",
        "four-modes",
        "mind-that-does-not-wait",
        "beautiful-liar",
        "repulsive-gravity",
        "self-observing-equation",
        "phililo-speech",
        "paradox-impossible-crossover",
    ):
        assert f"[{ident}]" in prompt, f"corpus doc missing from paradox lens: {ident}"
    # Compact TTP reference rides along.
    assert "ORACLE TTP REFERENCE" in prompt


def test_mitre_lens_gets_ttp_reference():
    assert "ORACLE TTP REFERENCE" in _mitre_prompt()


# ── P1 Mindset-3 synthesis: consumes both lenses' outputs + red-team ──
# Fixture-only (no network, no models): locks synthesize_seams' contract.

_MITRE_SEAM = {
    "n": 1,
    "check": "curl -i https://app.acme.com/api",
    "severity": "high",
    "mindset": "mitre",
}
_PARADOX_SEAM = {
    "n": 2,
    "check": "curl -i https://app.acme.com/api/",
    "severity": "high",
    "mindset": "paradox",
}
_FEED_SEAM = {
    "n": 9,
    "file": "vault.py",
    "function": "withdraw",
    "severity": "medium",
    "mindset": "seam",
}


def test_synthesis_unifies_both_lens_outputs_ranked():
    out = synthesize_seams(
        {
            "mitre": [dict(_MITRE_SEAM)],
            "paradox": [dict(_PARADOX_SEAM)],
            "seam": [dict(_FEED_SEAM)],
        }
    )
    assert len(out) == 3  # unified, nothing dropped
    assert [s["synthesis_rank"] for s in out] == [1, 2, 3]
    # Corroborated pair (agreement 2) outranks the lone feed seam.
    assert all(s["agreement"] == 2 for s in out[:2])
    assert out[2]["mindset"] == "seam" and out[2]["agreement"] == 1
    assert set(out[0]["corroborated_by"]) == {"mitre", "paradox"}
    assert out[0]["synthesis_sources"] == ["mitre", "paradox"]
    assert all(s["redteam_verdict"] == "unreviewed" for s in out)


def test_synthesis_applies_redteam_verdicts_without_dropping():
    lone = dict(_FEED_SEAM)
    verdicts = {seam_candidate_key(lone): "confirmed"}
    out = synthesize_seams(
        {
            "mitre": [dict(_MITRE_SEAM)],
            "paradox": [dict(_PARADOX_SEAM)],
            "seam": [lone],
        },
        redteam_verdicts=verdicts,
    )
    assert len(out) == 3  # rejected/confirmed never drop — verifier decides
    assert out[0]["mindset"] == "seam"  # confirmed outranks unreviewed pair
    assert out[0]["redteam_verdict"] == "confirmed"

    # Per-candidate verdicts: rejecting the MITRE card must NOT drag its
    # same-subject paradox twin down (separate S3 gates).
    verdicts = {seam_candidate_key(_MITRE_SEAM): "rejected"}
    out = synthesize_seams(
        {
            "mitre": [dict(_MITRE_SEAM)],
            "paradox": [dict(_PARADOX_SEAM)],
            "seam": [dict(_FEED_SEAM)],
        },
        redteam_verdicts=verdicts,
    )
    assert len(out) == 3
    assert out[-1]["mindset"] == "mitre"
    assert out[-1]["redteam_verdict"] == "rejected"
    paradox_out = [s for s in out if s["mindset"] == "paradox"][0]
    assert paradox_out["redteam_verdict"] == "unreviewed"


def test_synthesis_fail_loud_on_none_lens():
    with pytest.raises(ValueError, match="paradox"):
        synthesize_seams({"mitre": [dict(_MITRE_SEAM)], "paradox": None})


def test_synthesis_fail_loud_on_unknown_verdict():
    with pytest.raises(ValueError, match="unknown red-team verdict"):
        synthesize_seams(
            {"mitre": [dict(_MITRE_SEAM)]},
            redteam_verdicts={seam_candidate_key(_MITRE_SEAM): "maybe"},
        )


def test_synthesis_tolerates_unselected_and_clean_lenses():
    # Missing key = lens not selected; empty list = lens ran clean. Both fine.
    out = synthesize_seams({"seam": [dict(_FEED_SEAM)]})
    assert len(out) == 1
    out = synthesize_seams({"mitre": [], "paradox": [], "seam": [dict(_FEED_SEAM)]})
    assert len(out) == 1


def test_require_mindsets_no_cloud_runs_all_with_local_engine():
    assert require_mindsets(
        ["mitre", "paradox", "seam"], False, True, local_only=True
    ) == [
        "mitre",
        "paradox",
        "seam",
    ]


def test_require_mindsets_no_cloud_fails_loud_without_engine():
    with pytest.raises(RuntimeError, match="paradox"):
        require_mindsets(["mitre", "paradox", "seam"], False, False, local_only=True)


def test_require_mindsets_cloud_mode_stays_graceful():
    # Cloud mode keeps the disclose path: subset returned, caller warns.
    assert require_mindsets(["mitre", "paradox", "seam"], False, False) == ["seam"]
