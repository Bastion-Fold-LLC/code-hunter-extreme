#!/usr/bin/env python3
"""Shared triage profile: Oracle prescan must rank by triage.yaml.

Boss-file contract (owner decision, 2026-10-18):
- triage.yaml weights drive Scan4Me scoring on the Oracle prescan path.
- Payout is a GATE (hunt_filter.min_payout_usd), never a rank weight.
- Prescan is the public/outside-the-wall pass: loose. Unknown telemetry
  never drops a program there; strict gates bite later in Oracle.
- Explicit caller config and Scan4Me standalone config stay untouched:
  the overlay only applies inside the bridge when no config is given,
  and triage_prescan_overlay itself never mutates its inputs.
"""

import copy
from pathlib import Path

import oracle_scan4me as bridge
from oracle_triage import load_config as load_triage

ROOT = Path(__file__).resolve().parent.parent


def _base_cfg():
    """Scan4Me-shaped config with pre-boss-file (payout-heavy) weights."""
    return {
        "platforms": {"hackerone": True, "bugcrowd": True},
        "api_keys": {"hackerone": {"api_token": None}},
        "ranking_weights": {
            "payout_size": 0.35,
            "attack_surface_size": 0.30,
            "freshness_and_low_saturation": 0.20,
            "triage_speed": 0.15,
        },
        "filters": {
            "paid_bounties_only": True,
            "fast_triage": {
                "prefer_managed_triage": False,
                "require_measured_response_time": True,
                "managed_triage_baseline": 70.0,
            },
            "attack_surface_and_scope": {"wildcard_multiplier": 2.5},
            "freshness_and_competition": {
                "new_company_days": 365,
                "new_asset_days": 365,
                "strict_new_companies": True,
                "strict_new_assets": True,
            },
            "payouts": {"min_max_payout_usd": 1000.0},
            "program_kind": {"web2": True, "web3": True},
        },
    }


def _real_triage():
    return load_triage(ROOT / "triage.yaml")


def test_overlay_payout_is_gate_not_rank():
    out = bridge.triage_prescan_overlay(_base_cfg(), _real_triage())
    w = out["ranking_weights"]
    # triage.yaml: payout weight is 0.0 by owner rule.
    assert w["payout_size"] == 0.0
    # Remaining weights keep triage ratios (surface 1.0, fast 0.4,
    # fresh = new_assets 0.3 + recency 0.1 + low_reports 0.1) and sum to 1.
    assert abs(sum(w.values()) - 1.0) < 1e-9
    assert w["attack_surface_size"] > w["freshness_and_low_saturation"]
    assert w["freshness_and_low_saturation"] > w["triage_speed"] > 0
    assert abs(w["attack_surface_size"] - 1.0 / 1.9) < 1e-9
    # The payout GATE value comes from hunt_filter, not Scan4Me's $1000.
    tri = _real_triage()
    assert out["filters"]["payouts"]["min_max_payout_usd"] == float(
        tri["hunt_filter"]["min_payout_usd"] or 0
    )


def test_overlay_windows_and_loose_prescan():
    out = bridge.triage_prescan_overlay(_base_cfg(), _real_triage())
    fresh = out["filters"]["freshness_and_competition"]
    assert fresh["new_asset_days"] == 30  # triage new_asset_full_days
    assert fresh["new_company_days"] == 90  # triage recency_full_days
    # Public pass is loose: walled-garden unknowns must not drop programs.
    assert fresh["strict_new_assets"] is False
    assert fresh["strict_new_companies"] is False
    fast = out["filters"]["fast_triage"]
    assert fast["require_measured_response_time"] is False
    assert fast["prefer_managed_triage"] is True
    # Scan4Me-only knobs survive untouched.
    assert fast["managed_triage_baseline"] == 70.0
    assert out["filters"]["attack_surface_and_scope"]["wildcard_multiplier"] == 2.5
    assert out["platforms"] == {"hackerone": True, "bugcrowd": True}


def test_overlay_kind_mapping_and_no_mutation():
    base = _base_cfg()
    snapshot = copy.deepcopy(base)
    tri = {
        "weights": {"asset_count": 2.0, "fast_triage": 1.0, "new_assets": 1.0,
                    "recency": 0.0, "low_reports": 0.0, "payout": 0.0},
        "new_asset_full_days": 14,
        "recency_full_days": 45,
        "kind": "web2",
        "hunt_filter": {"min_payout_usd": 500},
    }
    out = bridge.triage_prescan_overlay(base, tri)
    assert base == snapshot  # inputs never mutated
    assert out["filters"]["program_kind"] == {"web2": True, "web3": False}
    assert out["filters"]["payouts"]["min_max_payout_usd"] == 500.0
    assert out["filters"]["freshness_and_competition"]["new_asset_days"] == 14
    assert abs(out["ranking_weights"]["attack_surface_size"] - 0.5) < 1e-9


def test_overlay_zero_day_windows_propagate_not_ignored():
    """triage.yaml: 0 disables a signal. Overlay must pass 0 through."""
    tri = {
        "weights": {"asset_count": 1.0},
        "new_asset_full_days": 0,
        "recency_full_days": 0,
        "hunt_filter": {},
    }
    out = bridge.triage_prescan_overlay(_base_cfg(), tri)
    fresh = out["filters"]["freshness_and_competition"]
    assert fresh["new_asset_days"] == 0
    assert fresh["new_company_days"] == 0


def test_overlay_degenerate_triage_keeps_base_weights():
    base = _base_cfg()
    out = bridge.triage_prescan_overlay(base, {"weights": {}, "hunt_filter": {}})
    assert out["ranking_weights"] == base["ranking_weights"]
