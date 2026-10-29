from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_programs
import oracle_scan


def _program(name, **overrides):
    now = datetime.now(timezone.utc)
    base = {
        "platform": "example",
        "name": name,
        "kind": "web2",
        "max_payout_usd": 1_000,
        "fast_triage": True,
        "reports_count": 10,
        "launched_at": (now - timedelta(days=5)).isoformat(),
        "structured_scopes": [{
            "asset_identifier": f"https://{name}.example.test",
            "first_seen": (now - timedelta(days=5)).isoformat(),
        }],
    }
    base.update(overrides)
    return base


def test_explicit_fast_money_gates_do_not_admit_unknown_metadata():
    matching = _program("matching")
    unknown_payout = _program("unknown-payout", max_payout_usd=None)
    unknown_triage = _program("unknown-triage", fast_triage=None)
    stale_program = _program(
        "stale-program",
        launched_at=(datetime.now(timezone.utc) - timedelta(days=180)).isoformat(),
    )

    selected = oracle_programs.filter_programs(
        [matching, unknown_payout, unknown_triage, stale_program],
        min_payout=500,
        fast_triage=True,
        new_programs_only=True,
        new_program_days=30,
        recently_added_assets=True,
    )

    assert [program["name"] for program in selected] == ["matching"]


def test_fresh_asset_gate_ignores_program_recency_without_asset_evidence():
    recent_program_but_old_asset = _program(
        "recent-program-old-asset",
        structured_scopes=[{
            "asset_identifier": "https://old.example.test",
            "first_seen": (datetime.now(timezone.utc) - timedelta(days=180)).isoformat(),
        }],
    )
    fresh_asset = _program("fresh-asset")

    selected = oracle_programs.filter_programs(
        [recent_program_but_old_asset, fresh_asset],
        recently_added_assets=True,
    )

    assert [program["name"] for program in selected] == ["fresh-asset"]


def test_scan_uses_triage_score_as_the_authoritative_ranker(monkeypatch):
    programs = [_program("first"), _program("second")]
    cfg = oracle_scan._default_config()
    cfg["filter"]["min_payout_usd"] = 0
    cfg["filter"]["pick_per_platform"] = None
    cfg["filter"]["top_n"] = 2

    monkeypatch.setattr(oracle_programs, "_load_cache", lambda: programs)
    expected = [dict(programs[1], score=99), dict(programs[0], score=1)]
    calls = {}

    import oracle_triage
    monkeypatch.setattr(
        oracle_triage,
        "score_programs",
        lambda values, programs_dir, triage_cfg: calls.setdefault(
            "values", values
        ) and expected,
    )

    assert [p["name"] for p in oracle_scan.scan_platforms(cfg)] == ["second", "first"]
    assert calls["values"] == programs


def test_unknown_triage_metadata_does_not_pass_a_strict_fast_triage_gate():
    unknown_triage = _program("unknown-triage", fast_triage=None)

    selected = oracle_programs.filter_programs(
        [unknown_triage],
        fast_triage=True,
    )

    assert selected == []


def test_unknown_payout_does_not_pass_a_strict_maximum_payout_gate():
    matching = _program("matching", max_payout_usd=500)
    unknown = _program("unknown", max_payout_usd=None)
    over_cap = _program("over-cap", max_payout_usd=1_000)

    selected = oracle_programs.filter_programs(
        [matching, unknown, over_cap],
        max_payout=750,
    )

    assert [program["name"] for program in selected] == ["matching"]


def test_platform_record_normalization_rejects_bad_identity_and_marks_scope_unfetched():
    normalized = oracle_programs.normalize_program_record(
        {
            "name": "Example",
            "url": "https://example.test/program",
            "raw": {"source": "fixture"},
        },
        "hackerone",
    )

    assert normalized["platform"] == "hackerone"
    assert normalized["kind"] == "web2"
    assert normalized["reports_count"] is None
    assert normalized["structured_scopes"] == []
    assert normalized["scope_status"] == "not-fetched"
    assert normalized["intake_status"] == "discovered"
    assert oracle_programs.normalize_program_record(
        {"name": "Missing URL"}, "hackerone"
    ) is None


def test_include_variable_retains_unparsed_bounties_when_min_payout_set():
    fixed_payout = _program("fixed", max_payout_usd=1000)
    unparsed_bounty = _program("variable-tier", max_payout_usd=None, offers_bounties=True)
    unpaid = _program("vdp-only", max_payout_usd=None, offers_bounties=False)

    # Without include_variable: drops unparsed
    res_default = oracle_programs.filter_programs(
        [fixed_payout, unparsed_bounty, unpaid],
        min_payout=500,
        include_variable=False,
    )
    assert [p["name"] for p in res_default] == ["fixed"]

    # With include_variable: preserves programs that offer bounties
    res_variable = oracle_programs.filter_programs(
        [fixed_payout, unparsed_bounty, unpaid],
        min_payout=500,
        include_variable=True,
    )
    assert set(p["name"] for p in res_variable) == {"fixed", "variable-tier"}


def test_program_score_clamps_report_penalty_for_enterprise():
    # Enterprise program with $50k payout and 400 reports vs startup with $3k and 0 reports
    enterprise = _program("enterprise", max_payout_usd=50_000, reports_count=400, fast_triage=False, launched_at="")
    startup = _program("startup", max_payout_usd=3_000, reports_count=0, fast_triage=False, launched_at="")

    ent_score = oracle_programs._program_score(enterprise)
    stu_score = oracle_programs._program_score(startup)

    # 50,000 / sqrt(100+1) ~ 4975 > 3000
    assert ent_score > stu_score
    assert ent_score > 4900


def test_unknown_reports_assumes_saturation_not_freshness():
    """LOGIC_AUDIT burial fix: a thin scraper (reports unknown) must not get
    the denominator-1 free pass that used to outrank observed data."""
    now = datetime.now(timezone.utc).isoformat()
    verified = _program(
        "verified",
        max_payout_usd=3_000,
        reports_count=5,
        fast_triage=True,
        launched_at=now,
    )
    thin = _program(
        "thin",
        max_payout_usd=3_000,
        reports_count=None,
        fast_triage=None,
        launched_at="",
    )

    verified_score = oracle_programs._program_score(verified)
    thin_score = oracle_programs._program_score(thin)

    # thin: 3000 / sqrt(100+1) ~ 298.5 (clamp, no bonuses)
    assert thin_score < 300
    assert verified_score > thin_score


def test_unknown_payout_scores_floor_zero():
    ranked = oracle_programs.filter_programs(
        [
            _program("known", max_payout_usd=500),
            _program("unknown", max_payout_usd=None),
        ]
    )
    assert [p["name"] for p in ranked] == ["known", "unknown"]
    assert ranked[1]["score"] == 0.0


def test_observed_zero_reports_keeps_freshness_reward():
    """Observed 0 reports is real freshness signal — only *unknown* (None)
    is treated as saturated."""
    fresh = _program("fresh", max_payout_usd=1_000, reports_count=0)
    unknown = _program("unknown", max_payout_usd=1_000, reports_count=None)
    assert oracle_programs._program_score(fresh) > oracle_programs._program_score(unknown)


def test_managed_triage_passes_fast_triage_gate():
    """Programs from platforms that indicate managed triage satisfy fast_triage filter."""
    h1_managed = _program("h1", fast_triage=True)
    bc_managed = _program("bc", fast_triage=None, managed_triage=True)
    unmanaged = _program("unmanaged", fast_triage=False, managed_triage=False)

    selected = oracle_programs.filter_programs(
        [h1_managed, bc_managed, unmanaged],
        fast_triage=True,
    )
    names = [p["name"] for p in selected]
    assert "h1" in names
    assert "bc" in names
    assert "unmanaged" not in names


def test_program_kind_passes_web2_and_web3_filter():
    """Programs with program_kind (e.g. from Scan4Me bridge) pass kind filters."""
    p_web2 = _program("w2", kind=None, program_kind="web2")
    p_web3 = _program("w3", kind=None, program_kind="web3")

    sel_w2 = oracle_programs.filter_programs([p_web2, p_web3], web2=True, web3=False)
    assert [p["name"] for p in sel_w2] == ["w2"]

    sel_w3 = oracle_programs.filter_programs([p_web2, p_web3], web2=False, web3=True)
    assert [p["name"] for p in sel_w3] == ["w3"]


def test_oracle_hunt_filter_program_qualifies_with_managed_triage():
    """oracle_hunt_filter.program_qualifies recognizes managed_triage under require_fast_triage."""
    import oracle_hunt_filter

    prog = _program("bc-target", fast_triage=None, managed_triage=True, max_payout_usd=5000)
    hf = {"min_payout_usd": 1000, "require_fast_triage": True}
    ok, reasons = oracle_hunt_filter.program_qualifies(prog, hf)
    assert ok is True
    assert reasons == []


def test_scan4me_bridge_records_carry_fast_triage_and_kind():
    """oracle_scan4me bridge exports fast_triage and kind for downstream Oracle filters.

    Needs a synced Scan4Me DB with paypal's live triage stats; a fresh checkout
    has none, so skip loudly instead of passing vacuously when the program is
    absent.
    """
    import pytest
    import oracle_scan4me

    if oracle_scan4me._db() is None:
        pytest.skip("Scan4Me DB not synced — run `python3 scan4me.py sync`")
    prog = oracle_scan4me.resolve("paypal")
    if not prog:
        pytest.skip("program 'paypal' not present in the synced Scan4Me DB")
    assert prog.get("kind") == "web2"
    assert prog.get("fast_triage") is True

