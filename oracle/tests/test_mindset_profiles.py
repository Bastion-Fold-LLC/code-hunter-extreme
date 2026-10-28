import pytest
from oracle_mindset_context import OracleMindsetContext

PROG = {"name": "Acme", "scope": "app.acme.com", "rules_text": "no DoS"}


def test_mitre_profile_has_ttp_omits_corpus():
    p = OracleMindsetContext(program=PROG, mindset="mitre").system_prompt()
    assert "TTP REFERENCE" in p          # MITRE block present
    assert "ORACLE TTP" in p
    assert "SOURCE CONTEXT" not in p     # corpus section omitted


def test_paradox_profile_has_corpus_omits_full_ttp():
    p = OracleMindsetContext(program=PROG, mindset="paradox").system_prompt()
    assert "SOURCE CONTEXT" in p         # corpus section present
    # compact TTP only: no more T-codes than the mitre profile's full block
    mitre = OracleMindsetContext(program=PROG, mindset="mitre").system_prompt()
    assert p.count("T10") <= mitre.count("T10")


def test_both_profiles_carry_program_brief():
    for m in ("mitre", "paradox"):
        p = OracleMindsetContext(program=PROG, mindset=m).system_prompt()
        assert "app.acme.com" in p        # scope wall present in both


def test_invalid_mindset_raises():
    with pytest.raises(ValueError):
        OracleMindsetContext(program=PROG, mindset="bogus")


def test_seam_mindset_accepted_for_synthesis():
    # "seam" is a valid synthesis profile (Mindset 3 path constructs it);
    # only unknown values raise.
    ctx = OracleMindsetContext(program=PROG, mindset="seam")
    assert ctx.mindset == "seam"


def test_full_ttp_mode_gives_every_mindset_full_mitre():
    counts = {}
    for m in ("mitre", "paradox", "seam"):
        p = OracleMindsetContext(
            program=PROG, mindset=m, ttp_mode="full"
        ).system_prompt()
        counts[m] = p.count("You never said:")
    assert counts["mitre"] > 300
    assert counts["paradox"] == counts["mitre"]
    assert counts["seam"] == counts["mitre"]


def test_unknown_tactic_fails_loud():
    ctx = OracleMindsetContext(program=PROG, mindset="mitre", ttp_mode="tactic")
    with pytest.raises(ValueError, match="tactic"):
        ctx.tactic_prompt("NO SUCH TACTIC")


def test_paradox_prompt_larger_and_size_queryable():
    paradox = OracleMindsetContext(program=PROG, mindset="paradox")
    assert paradox.prompt_size() == len(paradox.system_prompt())
    assert paradox.prompt_size() > 12_000   # corpus cap is lifted, not the old 12K


def test_effective_mindsets_no_cloud_keeps_all_on_local():
    """P1: paradox runs on Engine B locally too. A --no-cloud hunt with a
    live local engine reports all three — never a silent paradox drop."""
    from oracle_mindsets import effective_mindsets

    assert effective_mindsets(["mitre", "paradox", "seam"], False, True) == [
        "mitre",
        "paradox",
        "seam",
    ]


def test_effective_mindsets_cloud_keeps_all():
    from oracle_mindsets import effective_mindsets

    assert effective_mindsets(["mitre", "paradox", "seam"], True, False) == [
        "mitre",
        "paradox",
        "seam",
    ]


def test_effective_mindsets_no_engine_leaves_seam_only():
    """Neither cloud nor ollama: LLM lenses dead, deterministic seam lens
    (templates/code) still runs."""
    from oracle_mindsets import effective_mindsets

    assert effective_mindsets(["mitre", "paradox", "seam"], False, False) == ["seam"]


def test_full_rules_tail_reaches_every_mindset():
    prog = {
        "name": "Acme",
        "scope": "app.acme.com",
        "rules_text": "R" * 2000 + "RULES-TAIL-MARKER",
    }
    for m in ("mitre", "paradox", "seam"):
        p = OracleMindsetContext(program=prog, mindset=m).system_prompt()
        assert "RULES-TAIL-MARKER" in p, m


def test_full_scope_note_and_company_profile_reach_brief():
    prog = {
        "name": "Acme",
        "tagline": "T" * 900 + "COMPANY-TAIL-MARKER",
        "structured_scopes": [
            {
                "asset_identifier": "app.acme.com",
                "asset_type": "URL",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "instruction": "N" * 500 + "NOTE-TAIL-MARKER",
            }
        ],
    }
    p = OracleMindsetContext(program=prog, mindset="mitre").system_prompt()
    assert "NOTE-TAIL-MARKER" in p
    assert "COMPANY-TAIL-MARKER" in p


def test_effective_mindsets_honors_request_subset():
    from oracle_mindsets import effective_mindsets

    assert effective_mindsets(["paradox"], True, True) == ["paradox"]
    assert effective_mindsets(["paradox"], False, True) == ["paradox"]
    assert effective_mindsets(["paradox"], False, False) == []
    assert effective_mindsets(["mitre"], False, True) == ["mitre"]
    assert effective_mindsets(["seam"], False, False) == ["seam"]
