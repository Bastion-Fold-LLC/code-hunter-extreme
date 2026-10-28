import pytest
import oracle_mindsets as om


def test_all_expands_to_three():
    assert om.resolve_mindsets("all", {}) == ["mitre", "paradox", "seam"]


def test_single_value():
    assert om.resolve_mindsets("paradox", {}) == ["paradox"]
    assert om.resolve_mindsets("mitre", {}) == ["mitre"]
    assert om.resolve_mindsets("seam", {}) == ["seam"]
    # redteam expands to all three since red teaming is embedded across all mindsets
    assert om.resolve_mindsets("redteam", {}) == ["mitre", "paradox", "seam"]


def test_cli_overrides_config():
    assert om.resolve_mindsets("mitre", {"hunt": {"mindset": "all"}}) == ["mitre"]


def test_config_used_when_no_cli():
    assert om.resolve_mindsets(None, {"hunt": {"mindset": "seam"}}) == ["seam"]


def test_default_all_when_nothing_set():
    assert om.resolve_mindsets(None, {}) == ["mitre", "paradox", "seam"]


def test_invalid_raises():
    with pytest.raises(ValueError):
        om.resolve_mindsets("banana", {})


def test_cross_compare_empty_returns_empty():
    assert om.cross_compare({"mitre": [], "paradox": [], "seam": []}) == []


def test_cross_compare_two_way_agreement():
    a = {"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}
    b = {"n": 1, "check": "curl -i https://app.acme.com/api/", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    assert len(out) == 2                       # both kept — agreement never drops a seam
    assert all(s["agreement"] == 2 for s in out)
    assert all(set(s["corroborated_by"]) == {"mitre", "paradox"} for s in out)


def test_cross_compare_lone_wolf_retained():
    a = {"n": 1, "check": "curl -i https://app.acme.com/x", "mindset": "mitre"}
    out = om.cross_compare({"mitre": [a], "paradox": []})
    assert len(out) == 1 and out[0]["agreement"] == 1


def test_cross_compare_code_seam_matches_on_file_function():
    a = {"n": 1, "file": "Vault.sol", "function": "withdraw", "mindset": "seam"}
    b = {"n": 2, "file": "Vault.sol", "function": "withdraw",
         "assertion_a_source": "Vault.sol", "mindset": "paradox"}
    out = om.cross_compare({"seam": [a], "paradox": [b]})
    assert len(out) == 2 and all(s["agreement"] == 2 for s in out)


def test_cross_compare_distinct_urls_stay_separate():
    a = {"n": 1, "check": "curl -i https://app.acme.com/a", "mindset": "mitre"}
    b = {"n": 2, "check": "curl -i https://app.acme.com/b", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    assert len(out) == 2


def test_cross_compare_same_url_different_bugs_inflates_agreement():
    # Known, accepted property: subject identity is URL + probe, so two
    # cards running the SAME probe at one URL corroborate. Documented so
    # it is not a surprise.
    a = {"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}
    b = {"n": 2, "check": "curl -i https://app.acme.com/api", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    # both findings survive (agreement never drops a seam); both are flagged
    # corroborated because they share subject + probe — accepted rank-only noise
    assert len(out) == 2 and all(s["agreement"] == 2 for s in out)


def test_subject_key_splits_same_url_different_probes():
    # #12: distinct probes at one URL get distinct verdict slots.
    get = {"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}
    post = {
        "n": 2,
        "check": "curl -i -X POST https://app.acme.com/api -d 'role=admin'",
        "mindset": "paradox",
    }
    assert om.seam_subject_key(get) != om.seam_subject_key(post)
    out = om.cross_compare({"mitre": [get], "paradox": [post]})
    assert len(out) == 2 and all(s["agreement"] == 1 for s in out)


def test_subject_key_probe_shape_ignores_url_trivia():
    # Trailing slash / URL case do not split a probe: same shape, same slot.
    a = {"n": 1, "check": "curl -i https://app.acme.com/api"}
    b = {"n": 2, "check": "curl -i https://APP.acme.com/api/"}
    assert om.seam_subject_key(a) == om.seam_subject_key(b)


def test_sort_confirmed_orders_by_agreement_then_severity():
    rows = [
        {"seam": {"n": 1, "agreement": 1, "severity": "high"}},
        {"seam": {"n": 2, "agreement": 3, "severity": "low"}},
        {"seam": {"n": 3, "agreement": 2, "severity": "high"}},
        {"seam": {"n": 4, "agreement": 2, "severity": "critical"}},
    ]
    order = [r["seam"]["n"] for r in om.sort_confirmed(rows)]
    assert order == [2, 4, 3, 1]
    messy = [
        {"seam": {"n": 5, "agreement": None, "severity": " high"}},
        {"seam": {"n": 6, "agreement": 1, "severity": "CRITICAL "}},
    ]
    assert [r["seam"]["n"] for r in om.sort_confirmed(messy)] == [6, 5]


def test_cross_compare_query_params_distinguish_endpoints():
    a = {"n": 1, "check": "curl -i 'https://app.acme.com/api?user=admin'", "mindset": "mitre"}
    b = {"n": 2, "check": "curl -i 'https://app.acme.com/api?q=search'", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    assert len(out) == 2
    assert all(s["agreement"] == 1 for s in out)


def test_cross_compare_does_not_mutate_inputs():
    orig_a = {"n": 1, "check": "curl -i https://app.acme.com/api"}
    seams = [orig_a]
    om.cross_compare({"mitre": seams})
    assert "mindset" not in orig_a


def test_mindset_of_origin_maps_seam_and_synth():
    assert om.mindset_of_origin("cloud-seam-synth") == "seam"
    assert om.mindset_of_origin("local-seam-synth") == "seam"
    assert om.mindset_of_origin("cloud-redteam") == "seam"


def test_all_mindsets_contain_redteam_directives_and_company_info():
    from oracle_mindset_context import OracleMindsetContext
    prog = {
        "name": "TargetCorp",
        "company": "Target Corporation",
        "platform": "hackerone",
        "handle": "targetcorp",
        "tagline": "Enterprise Cloud Solutions",
        "rules": "No denial of service. Report immediately.",
        "structured_scopes": [
            {"asset_identifier": "api.targetcorp.com", "asset_type": "DOMAIN",
             "eligible_for_bounty": True, "eligible_for_submission": True}
        ]
    }
    for m in ("mitre", "paradox", "seam"):
        ctx = OracleMindsetContext(program=prog, mindset=m)
        prompt = ctx.system_prompt()
        # Verify scope wall & company context
        assert "TargetCorp" in prompt
        assert "Target Corporation" in prompt
        assert "api.targetcorp.com" in prompt
        assert "No denial of service" in prompt
        # Verify red-team offensive posture is embedded in every mindset
        assert "RED-TEAM" in prompt

    # Specific directives
    assert "MITRE ATT&CK OFFENSIVE RED-TEAM" in OracleMindsetContext(program=prog, mindset="mitre").system_prompt()
    assert "PARADOX & PHILOSOPHY ADVERSARIAL RED-TEAM" in OracleMindsetContext(program=prog, mindset="paradox").system_prompt()
    seam_prompt = OracleMindsetContext(program=prog, mindset="seam").system_prompt()
    assert "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS" in seam_prompt
    assert "CLAIM" in seam_prompt and "PROOF" in seam_prompt and "REPRO" in seam_prompt


def test_seam_block_renders_every_injected_seam_and_verdict():
    from oracle_mindset_context import OracleMindsetContext

    seams = [
        {
            "n": i,
            "classification": "test",
            "reflex": "r",
            "mitre": "T0000",
            "assertion_a": "claim",
            "assertion_b": "reality",
            "impact": "low",
            "redteam_verdict": "confirmed" if i == 30 else "unreviewed",
        }
        for i in range(1, 31)
    ]
    ctx = OracleMindsetContext(
        program={"name": "Acme", "scope": "app.acme.com"}, mindset="seam"
    )
    ctx.inject_pending_seams(seams)
    prompt = ctx.system_prompt()
    assert "**SEAM 30" in prompt  # no top-25 cut downstream either
    assert "Pre-synthesis red-team verdict: confirmed" in prompt


def test_dead_generator_stays_cut():
    # #16: generate_seam_candidates had zero production callers — it is cut,
    # not wired. This locks the cut: re-adding it must be a deliberate,
    # caller-backed decision, not an accidental resurrection.
    assert not hasattr(om, "generate_seam_candidates")


