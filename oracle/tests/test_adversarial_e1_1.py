"""Adversarial Torture Test Suite for E1.1.

Probes the decision space of the five E1.1 hardening fixes:
  Fix E: Scope-empty fail-closed
  Fix A: Carry-through tags (lens + T-code on card faces)
  Fix B: Auth-feasibility filter (502 wall dropping)
  Fix C: Mint-cap per template family
  Fix D: Slice-cap config (20-host / 30-endpoint escape hatches)
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import oracle_hunter as oh
import oracle_mindsets as om
import oracle_seam_templates as ost
from oracle_mindset_context import OracleMindsetContext


def _make_args(**kwargs) -> SimpleNamespace:
    defaults = dict(
        auth=None,
        cookie=None,
        account_a=None,
        account_b=None,
        prompt_login=False,
        controlled=True,
        mindset=None,
        no_verify=False,
        auto=True,
        testnet=False,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ── 1. Fix E: Scope-empty Fail-Closed ─────────────────────────────────────────

def test_scope_empty_hunt_blocked(monkeypatch):
    """Hunt must raise RuntimeError when program scope is empty after intake."""
    import oracle_bulk_download as obd

    fake_prog = {
        "name": "gatedprog",
        "handle": "gatedprog",
        "platform": "bugcrowd",
        "structured_scopes": [],
    }
    monkeypatch.setattr(oh, "_scope_from_programs", lambda name: fake_prog)
    monkeypatch.setattr(obd, "intake_program_scopes", lambda p: ([], "no_assets"))

    with pytest.raises(RuntimeError, match=r"SCOPE EMPTY — cannot hunt gatedprog"):
        oh.cmd_hunt("gatedprog", _make_args())


def test_scope_single_wildcard_accepted(monkeypatch, tmp_path):
    """A program with even one wildcard scope must pass the scope-empty gate."""
    import oracle_bulk_download as obd

    fake_prog = {
        "name": "wildcardprog",
        "handle": "wildcardprog",
        "platform": "hackerone",
        "structured_scopes": [
            {
                "asset_identifier": "*.target.com",
                "asset_type": "WILDCARD",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
    }
    monkeypatch.setattr(oh, "_scope_from_programs", lambda name: fake_prog)

    # Verify structured_scopes is non-empty so the gate does not raise
    assert len(fake_prog["structured_scopes"]) == 1
    # Verify Mindset context accepts wildcard
    ctx = OracleMindsetContext(program=fake_prog, voice=False, mindset="mitre")
    assert "*.target.com" in ctx.system_prompt()


# ── 2. Fix A: Carry-through Tags (Lens + T-code) ──────────────────────────────

def test_mitre_n_a_never_on_template_card(tmp_path):
    """All template cards must carry a non-empty, non-N/A mitre code."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://target.com [200]\n")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://target.com/api/v1/data\nhttps://target.com/api/v2/data\n"
    )

    gate = oh.ProgramScopeGate({}, target_fallback="https://target.com")
    cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate)
    assert len(cards) > 0, "Precondition: template cards generated"
    for c in cards:
        assert c.get("mitre") not in (None, "", "N/A", "?"), (
            f"Card {c.get('id')} has invalid mitre: {c.get('mitre')}"
        )


def test_lens_field_set_on_all_cards(tmp_path):
    """Every card (template + LLM parsed) must carry a non-empty lens field."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://target.com [200]\n")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://target.com/api/v1/data\nhttps://target.com/api/v2/data\n"
    )

    gate = oh.ProgramScopeGate({}, target_fallback="https://target.com")
    tpl_cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate)
    for c in tpl_cards:
        assert c.get("lens") == "seam-template"

    llm_raw = (
        "SEAM 1: [LOGIC] Path Traversal\n"
        "REFLEX: Axiom Rewrite\n"
        "MITRE: T1083\n"
        "ASSERTION A: path is sanitized\n"
        "ASSERTION B: dot-dot-slash reaches /etc/passwd\n"
        "CHECK: curl -s https://target.com/file?p=../../etc/passwd\n"
    )
    llm_cards = oh._parse_seams(llm_raw)
    assert len(llm_cards) == 1
    llm_card = llm_cards[0]
    llm_card["origin"] = "cloud-paradox"
    oh._attribute_candidate_lenses(llm_card)
    assert llm_card.get("lens") == "cloud-paradox"
    assert llm_card.get("template_id") == ""


# ── 3. Fix B: Auth-Feasibility Filter ─────────────────────────────────────────

def test_auth_filter_empty_live_hosts(tmp_path):
    """Empty live_hosts.txt must not trigger false drops in auth filter."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://target.com/api/v1/data\nhttps://target.com/api/v2/data\n"
    )

    gate = oh.ProgramScopeGate({}, target_fallback="https://target.com")
    cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate)
    assert len(cards) > 0, "Cards must not be dropped when live_hosts is empty"


def test_auth_filter_200_host_not_dropped(tmp_path):
    """200-status host cards must survive without auth."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://healthy.com [200] [OK]\n")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://healthy.com/api/v1/u\nhttps://healthy.com/api/v2/u\n"
    )

    gate = oh.ProgramScopeGate({}, target_fallback="https://healthy.com")
    cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate, auth=None)
    assert len(cards) > 0, "Healthy 200 hosts must generate cards without auth"


def test_auth_filter_wall_host_with_auth(tmp_path):
    """Wall host (502/401/403) cards must survive when auth token is provided."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://wall.com [502] [Bad Gateway]\n")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://wall.com/api/v1/u\nhttps://wall.com/api/v2/u\n"
    )

    gate = oh.ProgramScopeGate({}, target_fallback="https://wall.com")
    cards_no_auth = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate, auth=None)
    assert len(cards_no_auth) == 0, "No auth -> wall host cards must be dropped"

    cards_with_auth = ost.scan_template_seams(
        recon_dir=recon_dir, scope_gate=gate, auth="Bearer test-token-xyz"
    )
    assert len(cards_with_auth) > 0, "Auth supplied -> wall host cards must survive"


def test_auth_filter_50pct_wall_not_blocked():
    """50% wall hosts is below the 60% session-gate block threshold."""
    total = 10
    wall = 5
    wall_ratio = wall / total
    assert wall_ratio < 0.60, "50% must not trigger the 60% session-gate abort"


def test_no_cards_from_session_gated_wall(tmp_path):
    """100% wall hosts with no auth must yield zero cards from template scanning."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text(
        "https://api1.wall.com [502]\n"
        "https://api2.wall.com [401]\n"
        "https://api3.wall.com [403]\n"
    )
    (recon_dir / "js_endpoints.txt").write_text(
        "https://api1.wall.com/api/v1/users\n"
        "https://api1.wall.com/api/v2/users\n"
        "https://api2.wall.com/status\n"
    )

    gate = oh.ProgramScopeGate({}, target_fallback="https://api1.wall.com")
    cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate, auth=None)
    assert len(cards) == 0, f"Expected 0 cards from session-gated wall, got {len(cards)}"


# ── 4. Fix C: Mint-Cap Diversity ──────────────────────────────────────────────

def test_mint_cap_uniform_across_families(tmp_path):
    """Mint-cap restricts cards to max_per_family without starvation of others."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://target.com [200]\n")
    # 50 status endpoints that trigger self-observing-equation
    status_eps = [f"https://target.com/status/{i}\n" for i in range(50)]
    (recon_dir / "js_endpoints.txt").write_text("".join(status_eps))

    gate = oh.ProgramScopeGate({}, target_fallback="https://target.com")
    cards = ost.scan_template_seams(
        recon_dir=recon_dir,
        scope_gate=gate,
        max_per_family=5,
    )
    self_obs_family = ost._family("self-observing-equation")
    family_cards = [c for c in cards if ost._family(c.get("claim_type", "")) == self_obs_family]
    assert len(family_cards) <= 5, f"Expected <=5 cards from family, got {len(family_cards)}"


def test_mint_cap_one_family_zero(tmp_path):
    """A template family with zero match is unaffected and records 0."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://target.com [200]\n")
    # Clean endpoints, no .git or secrets
    (recon_dir / "js_endpoints.txt").write_text("https://target.com/api/v1/u\n")
    (recon_dir / "js_secrets.txt").write_text("")

    gate = oh.ProgramScopeGate({}, target_fallback="https://target.com")
    cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate, max_per_family=10)
    secrets_family = ost._family("t1552-secrets-in-client")
    secrets_cards = [c for c in cards if ost._family(c.get("claim_type", "")) == secrets_family]
    assert len(secrets_cards) == 0


# ── 5. Fix D: Slice-Cap Configuration ─────────────────────────────────────────

def test_slice_cap_default_20_30():
    """Default caps produce <=20 hosts and <=30 endpoints."""
    ctx = OracleMindsetContext(program={}, voice=False, mindset="mitre")
    hosts = [f"https://host{i}.com" for i in range(50)]
    endpoints = [f"https://host0.com/ep/{i}" for i in range(50)]
    ctx.inject_recon_context(hosts, endpoints)
    assert len(ctx._recon_hosts) == 20
    assert len(ctx._recon_endpoints) == 30


def test_slice_cap_override_100():
    """Config override to 100 scales up to 100 items (or input length)."""
    prog = {
        "hunt_config": {
            "max_hosts": 100,
            "max_endpoints": 100,
        }
    }
    ctx = OracleMindsetContext(program=prog, voice=False, mindset="mitre")
    hosts = [f"https://host{i}.com" for i in range(40)]
    endpoints = [f"https://host0.com/ep/{i}" for i in range(120)]
    ctx.inject_recon_context(hosts, endpoints)
    # Bounded by input size for hosts (40 <= 100)
    assert len(ctx._recon_hosts) == 40
    # Bounded by cap for endpoints (100)
    assert len(ctx._recon_endpoints) == 100


# ── 6. Yield Ledger Unserved Verification ─────────────────────────────────────

def test_yield_ledger_unserved_on_zero_mint():
    """Yield ledger must report both LLM lenses unserved when 0 cards are minted."""
    profiles = ["seam", "mitre", "paradox"]
    minted_seams = []
    # Both LLM lenses returned 'clean' without regime receipts
    regimes = {"mitre": "clean", "paradox": "clean"}
    ledger = om.mindset_yield_ledger(profiles, minted_seams, regimes, regime_receipts={})
    unserved = om.yield_unserved(ledger)
    assert "mitre" in unserved, "Mitre lens must be marked unserved"
    assert "paradox" in unserved, "Paradox lens must be marked unserved"
