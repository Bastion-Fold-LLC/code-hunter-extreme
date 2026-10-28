"""Owner-spec locks for the three-mindset Oracle pipeline.

These tests deliberately exercise the universal seam/mindset layer only:
no language-specific extractor is part of the contract being proved.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_corpus import DOCUMENTS
from oracle_mindset_context import (
    OracleMindsetContext,
    _company_name,
    _scope_records,
)
from oracle_mindsets import (
    apply_mindset3_gates,
    redteam_challenge,
    seam_candidate_key,
    second_seam_pass,
    synthesize_seams,
)

_PROGRAM = {
    "name": "acme",
    "platform": "hackerone",
    "url": "https://h1.test/acme",
    "structured_scopes": [
        {
            "asset_identifier": "https://api.example.test",
            "asset_type": "URL",
            "instruction": "in-scope",
        }
    ],
    "rules": "Stay inside the listed assets.",
}


def _seam(**over):
    base = {
        "n": 1,
        "mindset": "mitre",
        "assertion_a": "Only the owner can read the record",
        "assertion_b": "Another account can read the record",
        "check": "curl -s https://api.example.test/records/2",
        "expected": "status 200",
        "severity": "high",
    }
    base.update(over)
    return base


def test_mindset2_prompt_contains_every_registered_corpus_document():
    prompt = OracleMindsetContext(
        program=_PROGRAM, voice=False, ttp_mode="compact", mindset="paradox"
    ).system_prompt()

    for document in DOCUMENTS:
        assert f"[{document.identifier}]" in prompt, document.identifier


def test_program_update_rebuilds_bounty_context_for_downloaded_rules():
    ctx = OracleMindsetContext(
        program=dict(_PROGRAM), voice=False, ttp_mode="compact", mindset="mitre"
    )
    assert "DOWNLOADED-RULES-MARKER" not in ctx.system_prompt()

    enriched = dict(_PROGRAM)
    enriched["policy_text"] = "DOWNLOADED-RULES-MARKER: never test payments."
    ctx.update_program(enriched)

    assert "DOWNLOADED-RULES-MARKER" in ctx.system_prompt()


def test_seam_block_carries_check_expected_sources_and_chain_fields():
    ctx = OracleMindsetContext(
        program=_PROGRAM, voice=False, ttp_mode="compact", mindset="seam"
    )
    ctx.inject_pending_seams(
        [
            _seam(
                assertion_a_source="policy.md",
                source_a="src/app.py",
                line_a=10,
                source_b="src/app.py",
                line_b=42,
                check_output="HTTP/1.1 200 OK",
                chain_output_candidates=["record-id"],
                chain_preconditions=["authenticated"],
            )
        ]
    )
    prompt = ctx.system_prompt()

    assert "Assertion A source: policy.md" in prompt
    assert "Behavior source: src/app.py:42" in prompt
    assert "Check: curl -s https://api.example.test/records/2" in prompt
    assert "Expected: status 200" in prompt
    assert "Check output: HTTP/1.1 200 OK" in prompt
    assert "Chain outputs: record-id" in prompt


def test_policy_extraction_does_not_truncate_downloaded_rules():
    from oracle_bulk_download import _extract_section

    text = (
        "Program Rules\n"
        + ("Rule detail. " * 20)
        + "\nXSS\nStored XSS is in scope. RULES-TAIL-MARKER\n"
    )
    out = _extract_section(text, ["Program Rules"])

    assert "XSS" in out
    assert "RULES-TAIL-MARKER" in out


def test_clean_invisible_seam_feed_is_still_injected_into_both_lenses():
    for mindset in ("mitre", "paradox"):
        ctx = OracleMindsetContext(
            program=_PROGRAM, voice=False, ttp_mode="compact", mindset=mindset
        )
        ctx.inject_pending_seams([])
        prompt = ctx.system_prompt()
        assert "PENDING SEAMS" in prompt
        assert "Invisible Seam ran before this lens" in prompt
        assert "no deterministic seam candidates" in prompt


def test_second_seam_pass_marks_corroborated_and_conflicted_subjects():
    mitre = _seam(n=1, mindset="mitre")
    paradox = _seam(n=2, mindset="paradox")
    conflict_a = _seam(
        n=3,
        mindset="mitre",
        check="",
        file="vault.py",
        function="withdraw",
        assertion_b="Anyone can withdraw",
        expected="",
        check_output="ran",
    )
    conflict_b = _seam(
        n=4,
        mindset="paradox",
        check="",
        file="vault.py",
        function="withdraw",
        assertion_b="Only an admin can withdraw",
        expected="",
        check_output="ran",
    )

    out = second_seam_pass([mitre, paradox, conflict_a, conflict_b])

    assert len(out) == 4  # the second seam pass never drops or invents cards
    assert out[0]["m3_seam_state"] == "corroborated"
    assert out[0]["m3_seam_sources"] == ["mitre", "paradox"]
    assert out[2]["m3_seam_state"] == "conflicted"
    assert out[2]["m3_seam_conflict"] is True
    assert out[3]["m3_seam_conflict"] is True


def test_second_seam_pass_groups_code_cards_by_source_fields():
    left = _seam(
        n=1,
        mindset="mitre",
        check="",
        expected="",
        source_a="src/vault.py",
        line_a=12,
        source_b="src/vault.py",
        line_b=42,
        subject="withdraw",
        assertion_b="Anyone can withdraw",
    )
    right = _seam(
        n=2,
        mindset="paradox",
        check="",
        expected="",
        source_a="src/vault.py",
        line_a=12,
        source_b="src/vault.py",
        line_b=42,
        subject="withdraw",
        assertion_b="Only an admin can withdraw",
    )

    out = second_seam_pass([left, right])

    assert [s["m3_seam_state"] for s in out] == ["conflicted", "conflicted"]
    assert out[0]["m3_seam_subject"].endswith(":withdraw:42")


def test_mindset3_gates_rechallenge_cards_after_second_seam_pass():
    left = _seam(
        n=1,
        mindset="mitre",
        check="forge test Withdraw",
        file="vault.py",
        function="withdraw",
        assertion_b="Anyone can withdraw",
        expected="",
        check_output="ran",
    )
    right = _seam(
        n=2,
        mindset="paradox",
        check="forge test Withdraw",
        file="vault.py",
        function="withdraw",
        assertion_b="Only an admin can withdraw",
        expected="",
        check_output="ran",
    )
    # Each card looks statically confirmable in isolation.
    assert set(redteam_challenge([left, right]).values()) == {"confirmed"}

    out, verdicts, counts = apply_mindset3_gates([left, right])

    # Mindset 3 sees the same subject carrying contradictory Assertion B
    # values, so its second red-team pass must not keep the stale isolated
    # confirmations.
    assert [s["m3_seam_state"] for s in out] == ["conflicted", "conflicted"]
    assert set(verdicts.values()) == {"unreviewed"}
    assert counts["mitre"]["unreviewed"] == 1
    assert counts["paradox"]["unreviewed"] == 1
    assert all(s["m3_redteam_verdict"] == "unreviewed" for s in out)


def test_merge_preserves_mindset_twins_for_separate_redteam_gates():
    import oracle_hunter as oh

    mitre = _seam(n=1, mindset="mitre", origin="cloud-mitre")
    paradox = _seam(n=2, mindset="paradox", origin="cloud-paradox")
    synth = _seam(n=3, mindset="seam", origin="cloud-seam-synth")

    out = oh._merge_seams([mitre, paradox, synth], [])

    assert [s["mindset"] for s in out] == ["mitre", "paradox", "seam"]


def test_mindset3_synthesis_carries_second_seam_annotations():
    confirmed_key = seam_candidate_key(_seam(mindset="mitre"))
    out = synthesize_seams(
        {
            "mitre": [_seam(n=1, mindset="mitre")],
            "paradox": [_seam(n=2, mindset="paradox")],
            "seam": [],
        },
        redteam_verdicts={confirmed_key: "confirmed"},
    )

    assert len(out) == 2
    assert all(s["m3_seam_state"] == "corroborated" for s in out)
    assert all(s["m3_seam_sources"] == ["mitre", "paradox"] for s in out)


def test_second_seam_pass_corroborates_different_natural_language_phrasing():
    mitre = _seam(
        n=1,
        mindset="mitre",
        assertion_b="Unauthenticated GET request receives the record payload",
        expected="status 200 OK with record body",
    )
    paradox = _seam(
        n=2,
        mindset="paradox",
        assertion_b="Another account can read the record without ownership check",
        expected="HTTP/1.1 200 and JSON payload",
    )

    out, verdicts, counts = apply_mindset3_gates([mitre, paradox])

    assert [s["m3_seam_state"] for s in out] == ["corroborated", "corroborated"]
    assert all(s["m3_seam_conflict"] is False for s in out)
    assert set(verdicts.values()) == {"confirmed"}
    assert counts["mitre"]["confirmed"] == 1
    assert counts["paradox"]["confirmed"] == 1


def test_mindset1_default_auto_ttp_mode_loads_all_342_ttps():
    prompt = OracleMindsetContext(
        program=_PROGRAM, voice=False, mindset="mitre"
    ).system_prompt()

    assert "All 342 techniques mapped to the 11 reflexes" in prompt
    assert prompt.count("You never said:") == 342


def test_policy_extraction_retains_multi_section_headings_without_truncation(tmp_path):
    from oracle_bulk_download import _extract_policy_from_assets

    page = tmp_path / "program_page.txt"
    page.write_text(
        "Program Rules\n"
        + ("Rule detail line. " * 20)
        + "\nSafe Harbor\n"
        + ("Authorized testing is protected. " * 10)
        + "\nOut of Scope\n"
        + "Do not test third-party mail servers. MULTI_SECTION_TAIL_MARKER\n",
        encoding="utf-8",
    )

    extracted = _extract_policy_from_assets(tmp_path, "hackerone")
    assert "Safe Harbor" in extracted
    assert "MULTI_SECTION_TAIL_MARKER" in extracted


def test_program_brief_retains_long_flat_scope_targets_and_oos_without_truncation():
    prog = {
        "name": "Acme",
        "scope": "S" * 700 + "SCOPE_TAIL_MARKER",
        "targets": "T" * 500 + "TARGET_TAIL_MARKER",
        "out_of_scope": "O" * 500 + "OOS_TAIL_MARKER",
    }
    prompt = OracleMindsetContext(
        program=prog, voice=False, ttp_mode="compact", mindset="mitre"
    ).system_prompt()

    assert "SCOPE_TAIL_MARKER" in prompt
    assert "TARGET_TAIL_MARKER" in prompt
    assert "OOS_TAIL_MARKER" in prompt


def test_all_three_mindsets_get_company_scope_assets_and_urls():
    prog = {
        "name": "Acme Bounty",
        "platform": "bugcrowd",
        "handle": "acme",
        "url": "https://bugcrowd.example/acme",
        "website": "https://acme.example",
        "currency": "EUR",
        "min_payout": 50,
        "max_payout": 2000,
        "max_payout_usd": 2000,
        "offers_bounties": True,
        "safe_harbor": "Full",
        "first_response_hours": 12,
        "validation_days": 7,
        "rewarded_vulnerabilities": 42,
        "average_payout": 250,
        "company": {
            "name": "Acme Inc",
            "website": "https://acme.example",
            "description": "Payments infrastructure for small teams.",
        },
        "structured_scopes": [
            {
                "asset_identifier": "app.acme.example",
                "asset_type": "URL",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "max_severity": "critical",
                "instruction": "Primary application.",
            },
            {
                "asset_identifier": "*.api.acme.example",
                "asset_type": "WILDCARD",
                "is_wildcard": True,
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "asset_identifier": "github.com/acme/widgets",
                "asset_type": "SOURCE_CODE",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "asset_identifier": "com.acme.mobile",
                "asset_type": "GOOGLE_PLAY_APP_ID",
                "eligible_for_submission": True,
                "eligible_for_bounty": False,
                "instruction": "Token-compromise reports only.",
            },
            {
                "asset_identifier": "123456789",
                "asset_type": "APPLE_STORE_APP_ID",
                "eligible_for_submission": True,
                "eligible_for_bounty": False,
            },
            {
                "asset_identifier": "plugins.acme.example",
                "asset_type": "SOURCE_CODE",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "instruction": "SOURCE_NOTE_MARKER",
            },
            {
                "asset_identifier": "plugins.acme.example",
                "asset_type": "URL",
                "eligible_for_submission": False,
                "eligible_for_bounty": False,
                "instruction": "LIVE_URL_NOTE_MARKER",
            },
        ],
        "scope": ["edge.acme.example"],
        "targets": [
            {"asset_identifier": "status.acme.example", "asset_type": "URL"}
        ],
        "out_of_scope": [
            "payments.acme.example",
            {"asset_identifier": "admin.acme.example", "asset_type": "URL"},
        ],
    }

    expected = (
        "Acme Inc",
        "https://acme.example",
        "https://bugcrowd.example/acme",
        "Payments infrastructure for small teams.",
        "50–2,000 EUR",
        "First Response: 12h",
        "Validation: 7d",
        "Rewarded Vulnerabilities: 42",
        "app.acme.example",
        "https://app.acme.example",
        "*.api.acme.example",
        "https://github.com/acme/widgets",
        "com.acme.mobile",
        "https://play.google.com/store/apps/details?id=com.acme.mobile",
        "123456789",
        "https://apps.apple.com/app/id123456789",
        "Submission-only / no bounty:",
        "plugins.acme.example [SOURCE_CODE]",
        "plugins.acme.example [URL]",
        "SOURCE_NOTE_MARKER",
        "LIVE_URL_NOTE_MARKER",
        "edge.acme.example",
        "https://edge.acme.example",
        "status.acme.example",
        "payments.acme.example",
        "admin.acme.example",
        "OUT OF SCOPE (never probe these):",
    )

    for mindset in ("paradox", "mitre", "seam"):
        ctx = OracleMindsetContext(
            program=prog, voice=False, ttp_mode="compact", mindset=mindset
        )
        brief = ctx._program_brief()
        reporting = ctx.reporting_prompt()
        for marker in expected:
            assert marker in brief, f"{mindset} brief missing {marker!r}"
            assert marker in reporting, f"{mindset} reporting missing {marker!r}"


def test_update_program_syncs_legacy_program_alias():
    ctx = OracleMindsetContext(
        program=dict(_PROGRAM), voice=False, ttp_mode="compact", mindset="mitre"
    )
    enriched = dict(_PROGRAM)
    enriched["website"] = "https://acme.example"
    ctx.update_program(enriched)

    assert ctx._program is enriched
    assert "https://acme.example" in ctx._program_brief()


def test_scope_records_name_only_single_record_dicts():
    direct = _scope_records({"name": "named.acme.example"})
    nested = _scope_records({"assets": {"name": "nested.acme.example"}})

    assert direct[0]["asset_identifier"] == "named.acme.example"
    assert nested[0]["asset_identifier"] == "nested.acme.example"


def test_company_name_reads_nested_string_company():
    for wrapper in ("deep_dive", "raw", "resources"):
        prog = {
            "name": "Acme Bounty",
            wrapper: {"company": "Acme Inc"},
        }
        assert _company_name(prog) == "Acme Inc", wrapper

