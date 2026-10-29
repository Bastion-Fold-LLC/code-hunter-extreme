"""Stages 4-6 mindset firing contracts (local fit, refusals, ledgers)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
from oracle_mindset_context import OracleMindsetContext


_PROG = {
    "name": "Acme",
    "platform": "TestPlat",
    "url": "https://platform.example/acme",
    "website": "https://acme.example",
    "structured_scopes": [{"asset_identifier": "app.acme.example"}],
}


def test_feed_manifest_mitre_complete_with_truncation_named():
    ctx = OracleMindsetContext(program=dict(_PROG), mindset="mitre")
    manifest = ctx.feed_manifest()
    assert manifest["schema"] == "oracle.feed-manifest/v1"
    assert manifest["mindset"] == "mitre"
    feeds = manifest["feeds"]
    for required in (
        "bounty_info",
        "in_scope_assets",
        "company_info",
        "mitre",
        "invisible_seam",
        "red_teaming",
    ):
        assert feeds[required]["present"] is True, required
    assert feeds["mitre"]["items"] == 342
    assert feeds["mitre"]["desc_truncated"] > 0  # loss named, not hidden
    assert manifest["complete"] is True


def test_feed_manifest_paradox_corpus_categories():
    ctx = OracleMindsetContext(program=dict(_PROG), mindset="paradox")
    feeds = ctx.feed_manifest()["feeds"]
    assert feeds["philosophies"]["items"] >= 15
    assert feeds["impossible_problems"]["items"] == 5
    assert feeds["paradoxes"]["items"] == 3
    assert feeds["iphone_framing"]["present"] is True
    assert feeds["framework"]["present"] is True


def test_feed_manifest_seam_requires_injected_results():
    ctx = OracleMindsetContext(program=dict(_PROG), mindset="seam")
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["m1_m2_results"]["present"] is False
    assert manifest["complete"] is False
    ctx.inject_pending_seams([])
    manifest = ctx.feed_manifest()
    # An injected-but-empty results feed is delivered-empty, not present:
    # M3 has nothing to synthesize from, and the manifest must say so.
    assert manifest["feeds"]["m1_m2_results"]["present"] is False
    assert manifest["feeds"]["m1_m2_results"]["items"] == 0
    assert manifest["complete"] is False
    ctx.inject_pending_seams([{"assertion_a": "A", "assertion_b": "B"}])
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["m1_m2_results"]["present"] is True
    assert manifest["complete"] is True


def test_feed_manifest_submission_ineligible_asset_is_not_in_scope():
    # The brief buckets by eligibility: a submission-ineligible asset
    # renders OUT OF SCOPE and triggers SCOPE NOT LOADED when alone.
    for flag in (False, "false"):
        ctx = OracleMindsetContext(
            program={
                "name": "Acme",
                "url": "https://platform.example/acme",
                "website": "https://acme.example",
                "structured_scopes": [{
                    "asset_identifier": "api.acme.example",
                    "eligible_for_submission": flag,
                }],
            },
            mindset="mitre",
        )
        manifest = ctx.feed_manifest()
        assert manifest["feeds"]["in_scope_assets"]["present"] is False, flag
        assert manifest["feeds"]["in_scope_assets"]["items"] == 0
        assert manifest["complete"] is False
        assert manifest["feeds"]["out_of_scope_assets"]["items"] == 1
    # Submission-eligible but not bounty-eligible still renders IN SCOPE
    # (Submission-only sub-list) in the brief.
    ctx = OracleMindsetContext(
        program={
            "name": "Acme",
            "url": "https://platform.example/acme",
            "website": "https://acme.example",
            "structured_scopes": [{
                "asset_identifier": "api.acme.example",
                "eligible_for_bounty": False,
            }],
        },
        mindset="mitre",
    )
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["in_scope_assets"]["present"] is True
    assert manifest["feeds"]["in_scope_assets"]["items"] == 1


def test_feed_manifest_empty_ident_scope_is_absent():
    for scopes in ([{}], [{"asset_identifier": ""}], [{"asset_identifier": "   "}]):
        ctx = OracleMindsetContext(
            program={
                "name": "Acme",
                "url": "https://platform.example/acme",
                "website": "https://acme.example",
                "structured_scopes": scopes,
            },
            mindset="mitre",
        )
        manifest = ctx.feed_manifest()
        assert manifest["feeds"]["in_scope_assets"]["present"] is False, scopes
        assert manifest["feeds"]["in_scope_assets"]["items"] == 0
        assert manifest["complete"] is False


def test_feed_manifest_string_scopes_do_not_crash_and_count_assets():
    ctx = OracleMindsetContext(
        program={
            "name": "Acme",
            "url": "https://platform.example/acme",
            "website": "https://acme.example",
            "structured_scopes": "api.acme.example\nweb.acme.example",
        },
        mindset="mitre",
    )
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["in_scope_assets"]["present"] is True
    assert manifest["feeds"]["in_scope_assets"]["items"] == 2


def test_feed_manifest_whitespace_and_nonstr_fields_are_absent():
    ctx = OracleMindsetContext(
        program={
            "name": "Acme",
            "website": "   ",
            "policy": {"text": "hi"},
            "structured_scopes": [{"asset_identifier": "api.acme.example"}],
        },
        mindset="mitre",
    )
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["company_info"]["present"] is False
    assert manifest["feeds"]["bounty_info"]["present"] is False
    assert manifest["complete"] is False


def test_count_served_200_lines_strict_status_token():
    lines = [
        "https://a.test [200] [1234]",
        "https://b.test [403] [200]",  # status is 403; 200 is a later field
        "https://c.test/p[200] [403]",  # [200] inside the URL path
        "https://d.test [200]",
        "https://e.test",
    ]
    assert oh.count_served_200_lines(lines) == 2
    # Host filter: only injected hosts count.
    assert oh.count_served_200_lines(lines, hosts=["https://a.test"]) == 1
    assert oh.count_served_200_lines(lines, hosts=[]) == 0


def test_complete_lens_outcomes_fills_withheld_slices():
    recorded = {"cloud-paradox-1": "clean"}
    submitted = [
        {"origin": "cloud-paradox-1"},
        {"origin": "cloud-paradox-2", "outcome": "empty"},  # cage-withheld
        {"origin": "cloud-mitre-1"},  # nothing recorded anywhere
    ]
    completed = oh.complete_lens_outcomes(recorded, submitted)
    assert completed["cloud-paradox-1"] == "clean"
    assert completed["cloud-paradox-2"] == "empty"
    assert completed["cloud-mitre-1"] == "error"
    # And the ledger can no longer qualified-clean over the withheld slice.
    from oracle_mindsets import mindset_yield_ledger, yield_unserved

    receipts = {
        "paradox": {"endpoints_served_200": 9, "session_regime": True}
    }
    ledger = mindset_yield_ledger(
        ["paradox"], [], completed, regime_receipts=receipts
    )
    assert yield_unserved(ledger) == ["paradox"]


def test_feed_manifest_name_only_program_is_incomplete():
    ctx = OracleMindsetContext(program={"name": "Acme"}, mindset="mitre")
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["in_scope_assets"]["present"] is False
    assert manifest["feeds"]["in_scope_assets"]["items"] == 0
    assert manifest["complete"] is False
    assert "downloaded_material" in manifest["feeds"]
    assert "out_of_scope_assets" in manifest["feeds"]


def test_m3_exact_copy_with_seam_stamp_is_kept():
    known = [_src_seam()]
    synth = _src_seam()
    synth["mindset"] = "seam"
    synth["origin"] = "cloud-seam-synth"
    kept, dropped = oh.corroborate_synth_seams([synth], known, allow_new=False)
    assert kept == [synth]
    assert dropped == []


def test_feed_manifest_empty_program_is_incomplete():
    ctx = OracleMindsetContext(program={}, mindset="mitre")
    manifest = ctx.feed_manifest()
    assert manifest["feeds"]["bounty_info"]["present"] is False
    assert manifest["complete"] is False


def test_refusal_is_a_distinct_failed_outcome():
    assert (
        oh.lens_outcome("I can't help with that request.", []) == "refusal"
    )
    assert oh.pass_failed("refusal") is True
    # Ordinary prose stays empty; explicit clean stays clean.
    assert oh.lens_outcome("some analysis without cards", []) == "empty"
    assert oh.lens_outcome("TARGET CLEAN", []) == "clean"


def test_local_lens_systems_slice_to_fit_local_window():
    ctx = OracleMindsetContext(
        program={"name": "Acme", "platform": "TestPlat"},
        ttp_mode="compact",
        mindset="paradox",
    )
    task = "Find seams. " * 20
    systems = oh._local_lens_systems(ctx, task, 16000)
    assert len(systems) > 1  # full paradox prompt cannot fit 16k unsliced
    for system in systems:
        assert oh.estimate_tokens(system, task) <= 16000


def test_mitre_coverage_ledger_per_code_dispositions():
    records = [
        {"code": "T1001", "tactic": "INITIAL ACCESS"},
        {"code": "T1002", "tactic": "INITIAL ACCESS"},
        {"code": "T2001", "tactic": "PERSISTENCE"},
        {"code": "T3001", "tactic": "EXFILTRATION"},
    ]
    futures = [
        {"origin": "local-tactic:INITIAL ACCESS", "system": "... T1001 T1002 ..."},
        {"origin": "cloud-mitre-1", "system": "... T2001 ..."},
    ]
    outcomes = {
        "local-tactic:INITIAL ACCESS": "clean",
        "cloud-mitre-1": "seams",
    }
    seams = [{"mitre": "T2001", "mindset": "mitre"}]
    ledger = oh.mitre_coverage_ledger(records, futures, outcomes, seams)
    by = {e["code"]: e["disposition"] for e in ledger["entries"]}
    assert by["T1001"] == "served-clean"
    assert by["T1002"] == "served-clean"
    assert by["T2001"] == "minted"
    assert by["T3001"] == "not-served"
    assert ledger["total"] == 4
    assert ledger["complete"] is False


def test_slice_coverage_ledger_requires_every_pass():
    futures = [
        {"origin": "cloud-paradox-1"},
        {"origin": "cloud-paradox-2"},
        {"origin": "local-paradox-1"},
        {"origin": "cloud-mitre-1"},
    ]
    outcomes = {
        "cloud-paradox-1": "clean",
        "cloud-paradox-2": "error",
        "local-paradox-1": "refusal",
        "cloud-mitre-1": "clean",
    }
    ledger = oh.slice_coverage_ledger(futures, outcomes, "paradox")
    assert ledger["complete"] is False
    assert ledger["passes"]["cloud-paradox-2"] == "error"
    assert ledger["passes"]["local-paradox-1"] == "refusal"
    assert "cloud-mitre-1" not in ledger["passes"]


def _src_seam(a="docs claim X", b="code does Y", check="grep"):
    return {
        "assertion_a": a,
        "assertion_b": b,
        "check": check,
        "assertion_a_source": "src/app.py",
        "assertion_b_source": "docs/readme.md",
        "origin": "cloud-paradox",
        "mindset": "paradox",
    }


def test_m3_corroboration_is_content_bound_not_subject_only():
    known = [_src_seam()]
    exact = _src_seam()
    invented_b = _src_seam(b="code does Z (invented)")
    contentless = {"assertion_a_source": "src/app.py"}
    kept, dropped = oh.corroborate_synth_seams(
        [exact, invented_b, contentless], known, allow_new=False
    )
    assert kept == [exact]
    assert invented_b in dropped and contentless in dropped


def test_m3_production_card_shape_restatement_kept():
    """Round-2 verifier: production synth cards come from _parse_seams and
    carry no file/function/source/check_output fields, so the old exact
    candidate-key dropped faithful restatements of code seams."""
    known = [{
        "assertion_a": "export requires admin role",
        "assertion_b": "export handler never checks the role",
        "expected": "non-admin export succeeds",
        "check": "grep -n export repo/app/export.py",
        "check_output": "88: def export(req): ...",
        "file": "repo/app/export.py",
        "function": "export",
        "line_b": "88",
        "mindset": "mitre",
        "origin": "cloud-mitre",
    }]
    parsed_shape = {
        "n": 7,
        "mindset": "seam",
        "assertion_a": "export requires admin role",
        "assertion_b": "export handler never checks the role",
        "expected": "non-admin export succeeds",
        "check": "grep -n export repo/app/export.py",
    }
    rewritten_b = dict(parsed_shape, assertion_b="export leaks all tenants")
    kept, dropped = oh.corroborate_synth_seams(
        [parsed_shape, rewritten_b], known, allow_new=False
    )
    assert kept == [parsed_shape]
    assert dropped == [rewritten_b]


def test_m3_url_probe_restatement_is_synthesis_not_invention():
    """Gauntlet contract: on an identical probe-bound URL subject the
    synthesis pass may restate/compound assertion prose (wire still
    verifies the probe); a new probe is invention and drops."""
    known = [{
        "assertion_a": "admin metrics needs admin token",
        "assertion_b": "role header is trusted",
        "expected": "status 200",
        "check": "curl -s -H 'X-Role: admin' 'http://h.test/admin'",
        "mindset": "mitre",
    }]
    restated = {
        "assertion_a": "Gateway enforces administrator identity",
        "assertion_b": "The endpoint trusts the unverified role header",
        "expected": "status 200",
        "check": "curl -s -H 'X-Role: admin' 'http://h.test/admin'",
        "mindset": "seam",
    }
    new_probe = dict(restated, check="curl -s 'http://h.test/other'")
    kept, dropped = oh.corroborate_synth_seams(
        [restated, new_probe], known, allow_new=False
    )
    assert kept == [restated]
    assert dropped == [new_probe]


def test_yield_ledger_malformed_inputs_fail_closed_not_crash():
    from oracle_mindsets import mindset_yield_ledger, yield_unserved

    # Non-dict receipt value (verifier probe crashed with AttributeError).
    ledger = mindset_yield_ledger(
        ["paradox"], [], {"paradox": "clean"},
        regime_receipts={"paradox": "notadict"},
    )
    assert yield_unserved(ledger) == ["paradox"]
    # Unknown outcome tokens poison like an error slice, even with minting.
    seams = [{"mindset": "paradox", "assertion_a": "A", "assertion_b": "B"}]
    ledger = mindset_yield_ledger(
        ["paradox"],
        seams,
        {"cloud-paradox-1": "seams", "cloud-paradox-2": "error: timeout"},
        regime_receipts={},
    )
    assert ledger[0]["cause"] == "unserved"
    assert ledger[0]["minted"] == 1


def test_regime_receipt_forged_types_do_not_qualify_clean():
    from oracle_mindsets import mindset_yield_ledger, yield_unserved

    for receipt in (
        {"session_regime": "false", "endpoints_served_200": 8},
        {"session_regime": True, "endpoints_served_200": "8"},
        {"session_regime": True, "endpoints_served_200": True},
        {"session_regime": 1, "endpoints_served_200": 999},
    ):
        ledger = mindset_yield_ledger(
            ["paradox"], [], {"paradox": "clean"},
            regime_receipts={"paradox": receipt},
        )
        assert yield_unserved(ledger) == ["paradox"], receipt


def test_build_regime_receipts_requires_auth_and_observed_200():
    from oracle_mindsets import build_regime_receipts

    r = build_regime_receipts(["mitre"], auth_configured=True, served_200=5)
    assert r["mitre"] == {"endpoints_served_200": 5, "session_regime": True}
    # Credentials configured but recon served no observed 200: no regime.
    r = build_regime_receipts(["mitre"], auth_configured=True, served_200=0)
    assert r["mitre"]["session_regime"] is False
    # 200s served anonymously: counted, but not a session regime.
    r = build_regime_receipts(["mitre"], auth_configured=False, served_200=5)
    assert r["mitre"] == {"endpoints_served_200": 5, "session_regime": False}
    # Non-int counts fail closed to zero.
    r = build_regime_receipts(["mitre"], auth_configured=True, served_200="5")
    assert r["mitre"] == {"endpoints_served_200": 0, "session_regime": False}


def test_count_served_200_lines():
    lines = [
        "https://a.test [200] [1234]",
        "https://b.test [403]",
        "https://c.test [200]",
        "https://d.test",
    ]
    assert oh.count_served_200_lines(lines) == 2
    assert oh.count_served_200_lines([]) == 0


def test_correlate_seams_over_budget_returns_counted_skip(monkeypatch):
    import oracle_llm

    def _boom(*a, **k):
        raise AssertionError("backend must not be called when over budget")

    monkeypatch.setattr(oracle_llm, "complete", _boom)
    seams = [
        {"seam": {"n": i, "assertion_a": "A" * 200_000,
                  "assertion_b": "B", "impact": "x"}, "output": "e"}
        for i in range(3)
    ]
    result = oh._correlate_seams(seams, "https://app.example/", no_cloud=True)
    assert result is not None
    assert not result.get("summary")
    assert result["total"] == 3
    assert result["count"] == 0
    assert result["omitted"] == 3


def test_correlate_seams_backend_failure_preserves_omission_counts(monkeypatch):
    import oracle_llm

    def _fail(*a, **k):
        raise RuntimeError("all backends down")

    monkeypatch.setattr(oracle_llm, "complete", _fail)
    seams = [
        {"seam": {"n": i, "assertion_a": "A " * 40,
                  "assertion_b": "B " * 40, "impact": "x"}, "output": "e " * 60}
        for i in range(300)
    ]
    result = oh._correlate_seams(seams, "https://app.example/", no_cloud=True)
    assert result is not None
    assert not result.get("summary")
    assert result["omitted"] > 0
    assert result["count"] + result["omitted"] == result["total"] == 300


def test_correlate_seams_respects_local_budget(monkeypatch):
    import oracle_llm

    captured = {}

    def fake_complete(prompt, system, task_type=None, no_cloud=False, **kw):
        captured["prompt"] = prompt
        captured["system"] = system
        return "compound analysis"

    monkeypatch.setattr(oracle_llm, "complete", fake_complete)
    seams = [
        {
            "seam": {
                "n": i,
                "assertion_a": "A " * 40,
                "assertion_b": "B " * 40,
                "impact": "impact",
            },
            "output": "evidence " * 60,
        }
        for i in range(300)
    ]
    result = oh._correlate_seams(seams, "https://app.example/", no_cloud=True)
    assert result is not None
    assert oh.estimate_tokens(captured["system"], captured["prompt"]) <= 16000
    assert result.get("omitted", 0) > 0


def test_tactic_prompt_slices_cover_tactic_exactly_once():
    ctx = OracleMindsetContext(
        program={"name": "Acme", "platform": "TestPlat"},
        mindset="mitre",
    )
    tactics = ctx.all_tactics()
    assert tactics
    tactic = max(tactics, key=lambda t: len(ctx.tactic_prompt(t)))
    slices = ctx.tactic_prompt_slices(tactic, 30000)
    assert len(slices) >= 1
    assert all(len(s) <= 30000 for s in slices)
    # Every TTP code of the tactic appears (count-complete within tactic).
    records = [
        r
        for r in ctx._load_ttps()
        if str(r.get("tactic") or "").upper() == tactic.upper()
    ]
    joined = "\n".join(slices)
    for rec in records:
        assert str(rec.get("code")) in joined
