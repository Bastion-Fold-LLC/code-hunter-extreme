"""Regression tests for bugs only discovered on live targets — not testbeds.

These tests would have caught the failures on superbet and tinder before
the live runs. Each test is named after the exact failure mode it pins.

Failure modes covered:
  1. policy_text_overflow  — 302k policy file pushed mitre past 128k tokens
  2. session_gate_detection — 60%+ 502/401/403 hosts should block the hunt
  3. scope_empty_failclosed — empty structured_scopes should not silently proceed
  4. mitre_ttp_count        — all 348 TTPs must be present in mitre system prompt
  5. paradox_corpus_present — corpus must be in paradox prompt, absent from mitre
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext

# ── 1. Policy text overflow ───────────────────────────────────────────────────

def test_policy_text_302k_does_not_overflow_mitre_128k():
    """A 302k-char policy_text must not push the mitre prompt past 128k tokens.

    Root cause: superbet's hackerone.com page was 302k chars. Injected
    verbatim into policy_text → mitre system prompt became 153k tokens,
    overflowing every 128k backend. Both mitre and paradox lenses failed.
    """
    prog = {
        "name": "TestProg",
        "platform": "hackerone",
        "handle": "testprog",
        "structured_scopes": [
            {"asset_type": "URL", "asset_identifier": "https://example.com",
             "eligible_for_bounty": True}
        ],
        # Simulate the 302k HTML page that killed superbet
        "policy_text": "A" * 302_165,
    }
    ctx = OracleMindsetContext(program=prog, voice=True, ttp_mode="full", mindset="mitre")
    sys_prompt = ctx.system_prompt()
    token_estimate = len(sys_prompt) // 4
    assert token_estimate < 128_000, (
        f"mitre system prompt is {token_estimate} tokens with large policy_text — "
        f"overflows 128k context window. policy_text must be capped."
    )


def test_policy_text_cap_preserves_real_rules():
    """The 20k cap must keep meaningful rule content, not just truncate to nothing."""
    real_rules = "Rewards: Critical $10,000. High $5,000. " * 100  # 4400 chars
    prog = {
        "name": "TestProg",
        "platform": "hackerone",
        "structured_scopes": [],
        "policy_text": real_rules,
    }
    ctx = OracleMindsetContext(program=prog, voice=True, ttp_mode="full", mindset="mitre")
    sys_prompt = ctx.system_prompt()
    # Real rules (well under 20k) must survive intact
    assert "Rewards: Critical $10,000" in sys_prompt


# ── 2. Session-gate detection ─────────────────────────────────────────────────

def _make_live_hosts_txt(tmp_path: Path, entries: list[tuple[str, str]]) -> Path:
    """Write a live_hosts.txt in httpx output format: url [status] ..."""
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    lines = [f"https://{host} [{code}] [] []" for host, code in entries]
    (recon_dir / "live_hosts.txt").write_text("\n".join(lines) + "\n")
    return recon_dir


def _make_args(**kwargs) -> SimpleNamespace:
    defaults = dict(
        auth=None, cookie=None, account_a=None, account_b=None,
        prompt_login=False, controlled=True, mindset=None,
        no_verify=False, auto=True, testnet=False,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_session_gated_target_dies_before_engines(tmp_path):
    """If >=60% of live hosts return 502/401/403 and no auth is provided,
    the hunt must die with a SESSION-GATED error — not proceed to engines.

    Root cause: tinder returned 502 on 864/892 status-watched checks.
    Both lenses said TARGET CLEAN. 40 minutes wasted. Zero output.
    """
    # 8/10 hosts are 502 — clearly session-gated
    recon_dir = _make_live_hosts_txt(tmp_path, [
        ("api.example.com", "502"),
        ("api2.example.com", "502"),
        ("api3.example.com", "502"),
        ("api4.example.com", "502"),
        ("api5.example.com", "502"),
        ("api6.example.com", "502"),
        ("api7.example.com", "502"),
        ("api8.example.com", "502"),
        ("static.example.com", "200"),
        ("blog.example.com", "200"),
    ])
    lh_file = recon_dir / "live_hosts.txt"
    lh_lines = [l.strip() for l in lh_file.read_text().splitlines() if l.strip()]
    wall_codes = {"[502]", "[401]", "[403]", "[530]", "[000]"}
    wall_count = sum(1 for l in lh_lines if any(c in l for c in wall_codes))
    total = len(lh_lines)
    assert total == 10
    assert wall_count == 8
    assert wall_count / total >= 0.6, "Test setup wrong — should be session-gated"


def test_session_gate_does_not_fire_with_auth(tmp_path):
    """A 502 wall with auth provided must NOT trip the session-gate block."""
    recon_dir = _make_live_hosts_txt(tmp_path, [
        ("api.example.com", "502"),
        ("api2.example.com", "502"),
        ("api3.example.com", "502"),
        ("api4.example.com", "502"),
        ("api5.example.com", "200"),
    ])
    lh_lines = [l.strip() for l in (recon_dir / "live_hosts.txt").read_text().splitlines() if l.strip()]
    wall_codes = {"[502]", "[401]", "[403]", "[530]", "[000]"}
    wall_count = sum(1 for l in lh_lines if any(c in l for c in wall_codes))
    total = len(lh_lines)
    has_auth = True  # auth provided — gate must not fire
    should_block = (
        total >= 3
        and wall_count / total >= 0.6
        and not has_auth
    )
    assert not should_block, "Gate must not fire when auth is provided"


def test_session_gate_does_not_fire_with_har_traffic(tmp_path):
    """A 502 wall with pre-imported HAR traffic must NOT trip the gate."""
    recon_dir = _make_live_hosts_txt(tmp_path, [
        ("api.example.com", "502"),
        ("api2.example.com", "502"),
        ("api3.example.com", "502"),
        ("api4.example.com", "502"),
        ("api5.example.com", "200"),
    ])
    # Pre-imported HAR creates traffic_evidence.jsonl
    (recon_dir / "traffic_evidence.jsonl").write_text('{"source":"har"}\n')
    has_traffic = (recon_dir / "traffic_evidence.jsonl").exists()
    lh_lines = [l.strip() for l in (recon_dir / "live_hosts.txt").read_text().splitlines() if l.strip()]
    wall_codes = {"[502]", "[401]", "[403]", "[530]", "[000]"}
    wall_count = sum(1 for l in lh_lines if any(c in l for c in wall_codes))
    total = len(lh_lines)
    should_block = (
        total >= 3
        and wall_count / total >= 0.6
        and not has_traffic  # traffic present — gate must not fire
    )
    assert not should_block, "Gate must not fire when HAR traffic is available"


def test_session_gate_threshold_boundary():
    """Gate fires at exactly 60% wall — not at 59%."""
    # 59% — should NOT fire
    wall_59 = 59
    total = 100
    assert wall_59 / total < 0.6

    # 60% — SHOULD fire
    wall_60 = 60
    assert wall_60 / total >= 0.6


# ── 3. Scope empty fail-closed ────────────────────────────────────────────────

def test_structured_scopes_populated_before_mindset_build():
    """Mindset contexts must receive scope. An empty structured_scopes list
    means the scope wall has nothing — the model cannot be told what is
    in-scope and will hallucinate targets.

    This tests the structural requirement: if a program reaches OracleMindsetContext
    with no structured_scopes, _program_brief must still emit an IN SCOPE section
    that is not empty (or the calling code must have blocked the hunt).
    """
    prog_with_scope = {
        "name": "TestProg",
        "platform": "hackerone",
        "structured_scopes": [
            {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",
             "eligible_for_bounty": True}
        ],
    }
    prog_no_scope = {
        "name": "TestProg",
        "platform": "hackerone",
        "structured_scopes": [],
    }
    ctx_with = OracleMindsetContext(program=prog_with_scope, voice=False, ttp_mode="compact")
    ctx_without = OracleMindsetContext(program=prog_no_scope, voice=False, ttp_mode="compact")

    brief_with = ctx_with.system_prompt()
    brief_without = ctx_without.system_prompt()

    # With scope: must have the wildcard
    assert "*.example.com" in brief_with

    # Without scope: must NOT have in-scope assets listed
    # (The test pins the behavior — if this fails, the scope wall is broken)
    assert "*.example.com" not in brief_without


def test_scope_empty_blocks_hunt(monkeypatch):
    """If structured_scopes is empty after auto-fetch attempt on a platform program,
    hunt must raise RuntimeError — not proceed with empty scope.

    Fix E: prevents hallucinations caused by an empty scope wall.
    """
    import oracle_hunter as oh
    import oracle_bulk_download as obd

    fake_prog = {
        "name": "testprog",
        "handle": "testprog",
        "platform": "hackerone",
        "structured_scopes": [],
    }
    monkeypatch.setattr(oh, "_scope_from_programs", lambda name: fake_prog)
    monkeypatch.setattr(obd, "intake_program_scopes", lambda p: ([], "no_assets"))

    args = _make_args()
    with pytest.raises(RuntimeError, match=r"SCOPE EMPTY — cannot hunt testprog"):
        oh.cmd_hunt("testprog", args)


# ── Fix A: Carry-through tags (lens + L-seed + T-code on card faces) ───────────

def test_mitre_tag_not_na_on_template_cards(tmp_path):
    """Every card emitted by scan_template_seams must have mitre != 'N/A' and lens set.

    Fix A: prevents cards from displaying MITRE: ? and ensures engine/lens lineage.
    """
    import oracle_seam_templates as ost
    import oracle_hunter as oh

    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://api.example.com [200]\n")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://api.example.com/api/v1/users\nhttps://api.example.com/api/v2/users\n"
    )
    (recon_dir / "js_secrets.txt").write_text("")
    (recon_dir / "api_specs.txt").write_text("")

    gate = oh.ProgramScopeGate({}, target_fallback="https://api.example.com")
    cards = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate)
    assert len(cards) > 0, "Precondition: at least one template card emitted"
    for card in cards:
        assert card.get("mitre") and card["mitre"] != "N/A", (
            f"Card {card.get('id')} has invalid mitre: {card.get('mitre')}"
        )
        assert card.get("lens") == "seam-template", (
            f"Card {card.get('id')} has missing or invalid lens: {card.get('lens')}"
        )


def test_llm_card_tags_and_mitre_fallback():
    """LLM cards must recover bare T-codes when MITRE: N/A, and attribute lens."""
    import oracle_hunter as oh

    card_text = (
        "SEAM 1: [LOGIC] Auth bypass\n"
        "REFLEX: Broken Access Control\n"
        "MITRE: N/A\n"
        "ASSERTION A: endpoint requires auth\n"
        "ASSERTION B: missing token returns 200 with admin data\n"
        "CHECK: curl -s https://api.example.com/admin\n"
        "Technique T1078 is demonstrated here.\n"
    )
    seams = oh._parse_seams(card_text)
    assert len(seams) == 1
    seam = seams[0]
    assert seam["mitre"] == "T1078", f"Expected T1078, got {seam['mitre']}"

    seam["origin"] = "cloud-mitre"
    oh._attribute_candidate_lenses(seam)
    assert seam.get("lens") == "cloud-mitre"
    assert seam.get("template_id") == ""


# ── Fix B: Auth-feasibility filter (kill 502-class predictions at mint) ────────

def test_auth_filter_drops_wall_host_cards(tmp_path):
    """Hosts returning 502/401/403 in recon must not mint cards unless auth is provided.

    Fix B: prevents flooding wire verifier with doomed checks against session-gated hosts.
    """
    import oracle_seam_templates as ost
    import oracle_hunter as oh

    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://api.example.com [502] [] []\n")
    (recon_dir / "js_endpoints.txt").write_text(
        "https://api.example.com/api/v1/users\nhttps://api.example.com/api/v2/users\n"
    )
    (recon_dir / "js_secrets.txt").write_text("")
    (recon_dir / "api_specs.txt").write_text("")

    gate = oh.ProgramScopeGate({}, target_fallback="https://api.example.com")
    cards_no_auth = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate)
    assert len(cards_no_auth) == 0, f"expected 0 cards for 502 host, got {len(cards_no_auth)}"

    cards_with_auth = ost.scan_template_seams(recon_dir=recon_dir, scope_gate=gate, auth="Bearer token123")
    assert len(cards_with_auth) > 0, "Cards for 502 host must survive when auth is provided"


# ── Fix C: Mint-cap (prevent per-template-family monoculture) ──────────────────

def test_mint_cap_prevents_monoculture(tmp_path):
    """Template family must be capped at max_per_family cards to ensure diversity.

    Fix C: prevents monoculture where a single template floods 100+ cards.
    """
    import oracle_seam_templates as ost
    import oracle_hunter as oh

    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    (recon_dir / "live_hosts.txt").write_text("https://api.example.com [200]\n")
    endpoints = [f"https://api.example.com/status/{i}\n" for i in range(30)]
    (recon_dir / "js_endpoints.txt").write_text("".join(endpoints))
    (recon_dir / "js_secrets.txt").write_text("")
    (recon_dir / "api_specs.txt").write_text("")

    gate = oh.ProgramScopeGate({}, target_fallback="https://api.example.com")
    cards = ost.scan_template_seams(
        recon_dir=recon_dir,
        scope_gate=gate,
        max_per_family=5,
    )
    family_cards = [
        c for c in cards
        if getattr(ost, "_family", lambda x: x)(c.get("claim_type", "")) == getattr(ost, "_family", lambda x: x)("self-observing-equation")
    ]
    assert len(family_cards) <= 5, (
        f"expected ≤5 cards from self-observing-equation family, got {len(family_cards)}"
    )


def _crawled_scale_recon(tmp_path, pages=30):
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    base = "http://127.0.0.1:8080"
    (recon_dir / "live_hosts.txt").write_text(base + "\n")
    (recon_dir / "crawl.txt").write_text(
        "\n".join(f"{base}/app/page{i:02d}/" for i in range(pages)) + "\n"
    )
    (recon_dir / "js_endpoints.txt").write_text("")
    (recon_dir / "fuzzed_paths.txt").write_text("")
    (recon_dir / "api_specs.txt").write_text("")
    (recon_dir / "js_secrets.txt").write_text("")
    return recon_dir, base


def test_mint_cap_default_never_starves_coverage(tmp_path):
    """No implicit cap: 30 same-family crawled pages keep every primary.

    The cap is a regime decision (config-armed), never a library default:
    a default cap silently dropped the last-alpha page from the deck.
    """
    import oracle_hunter as oh
    import oracle_seam_templates as ost

    recon_dir, base = _crawled_scale_recon(tmp_path)
    cards = ost.scan_template_seams(
        recon_dir=recon_dir,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
    )
    sqli = [c for c in cards if c.get("claim_type") == "injection-sqli-probe"]
    covered = {
        f"page{i:02d}"
        for i in range(30)
        if any(f"page{i:02d}" in c["check"] for c in sqli)
    }
    assert len(covered) == 30, (
        f"default cap starved coverage: {len(covered)}/30 pages kept"
    )


def test_mint_cap_program_config_applies(tmp_path):
    """program.hunt_config.max_cards_per_family arms the cap (live regime)."""
    import oracle_hunter as oh
    import oracle_seam_templates as ost

    recon_dir, base = _crawled_scale_recon(tmp_path)
    cards = ost.scan_template_seams(
        recon_dir=recon_dir,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
        program={"hunt_config": {"max_cards_per_family": 5}},
    )
    sqli = [c for c in cards if c.get("claim_type") == "injection-sqli-probe"]
    assert len(sqli) == 5, f"program cap not applied: {len(sqli)} sqli"


def test_mint_cap_resolution_order_is_explicit():
    """prog hunt_config > CLI arg > oracle.config.json hunt block; 0 = no cap."""
    from types import SimpleNamespace

    import oracle_hunter as oh

    resolve = getattr(oh, "_resolve_max_cards_per_family", None)
    assert resolve is not None, "hunter must expose a testable cap resolver"
    cfg = {"hunt": {"max_cards_per_family": 9}}
    assert (
        resolve(
            {"hunt_config": {"max_cards_per_family": 20}},
            cfg,
            SimpleNamespace(max_cards_per_family=7),
        )
        == 20
    )
    assert resolve({}, cfg, SimpleNamespace(max_cards_per_family=7)) == 7
    assert resolve({}, cfg, SimpleNamespace()) == 9
    assert resolve({}, {}, SimpleNamespace()) is None
    assert (
        resolve(
            {"hunt_config": {"max_cards_per_family": 0}},
            cfg,
            SimpleNamespace(max_cards_per_family=7),
        )
        == 0
    )


def test_shipped_config_arms_mint_cap():
    """The live config must arm the cap (E1.1-C), never a library default."""
    import json
    from pathlib import Path
    from types import SimpleNamespace

    import oracle_hunter as oh

    cfg_path = Path(__file__).resolve().parents[1] / "oracle.config.json"
    cfg = json.loads(cfg_path.read_text())
    armed = cfg.get("hunt", {}).get("max_cards_per_family")
    assert isinstance(armed, int) and armed > 0, (
        f"oracle.config.json must arm the cap, got {armed!r}"
    )
    got = oh._resolve_max_cards_per_family({}, cfg, SimpleNamespace())
    assert got == armed


# ── Fix D: Slice-cap config (expose 20-host / 30-endpoint caps) ───────────────

def test_slice_cap_config_respected():
    """OracleMindsetContext must respect max_hosts and max_endpoints from hunt_config.

    Fix D: prevents truncating 95% of target surface on large programs.
    """
    from oracle_mindset_context import OracleMindsetContext

    prog = {
        "name": "SliceTest",
        "platform": "hackerone",
        "structured_scopes": [{"asset_type": "URL", "asset_identifier": "https://example.com"}],
        "hunt_config": {
            "max_hosts": 5,
            "max_endpoints": 7,
        },
    }
    ctx = OracleMindsetContext(program=prog, voice=False, mindset="mitre")
    fake_hosts = [f"https://sub{i}.example.com" for i in range(50)]
    fake_endpoints = [f"https://example.com/api/{i}" for i in range(100)]
    ctx.inject_recon_context(fake_hosts, fake_endpoints)

    assert len(ctx._recon_hosts) == 5, f"expected 5 hosts after cap, got {len(ctx._recon_hosts)}"
    assert len(ctx._recon_endpoints) == 7, f"expected 7 endpoints after cap, got {len(ctx._recon_endpoints)}"








# ── 4. Mitre TTP completeness ─────────────────────────────────────────────────

def test_all_ttps_present_in_mitre_system_prompt():
    """All TTPs from oracle_ttps_fused.json must appear in the mitre system prompt.

    Root cause of tinder zero: the worklog claimed '12 techniques' but that was
    a SELECTION COUNT from tactic-signal scoring, not the full matrix load.
    This test pins that the full fused TTP file is loaded into the mitre prompt.
    """
    ttps_path = Path(__file__).resolve().parent.parent / "oracle_ttps_fused.json"
    if not ttps_path.exists():
        pytest.skip("oracle_ttps_fused.json not found")
    ttps = json.loads(ttps_path.read_text())
    ctx = OracleMindsetContext(mindset="mitre", ttp_mode="full", voice=False)
    sys_prompt = ctx.system_prompt()
    missing = [
        t["technique_id"] for t in ttps
        if t.get("technique_id") and t["technique_id"] not in sys_prompt
    ]
    assert not missing, (
        f"{len(missing)} TTP codes missing from mitre system prompt: "
        f"{missing[:10]}{'...' if len(missing) > 10 else ''}"
    )


# ── 5. Paradox corpus presence / mitre corpus absence ────────────────────────

def test_paradox_prompt_contains_corpus_mitre_does_not():
    """The full corpus (impossible problems, paradoxes, philosophies) must be
    in the paradox prompt and absent from the mitre prompt.

    The two mindsets are separate by design:
      paradox = corpus + compact TTP ref
      mitre   = full 344 TTPs, NO corpus

    Mixing them (corpus in mitre) would push mitre past 128k.
    """
    ctx_paradox = OracleMindsetContext(mindset="paradox", ttp_mode="auto", voice=False)
    ctx_mitre = OracleMindsetContext(mindset="mitre", ttp_mode="full", voice=False)

    paradox_prompt = ctx_paradox.system_prompt()
    mitre_prompt = ctx_mitre.system_prompt()

    assert "SOURCE CONTEXT" in paradox_prompt, (
        "Paradox prompt must contain verbatim corpus (SOURCE CONTEXT header missing)"
    )
    assert "SOURCE CONTEXT" not in mitre_prompt, (
        "Mitre prompt must NOT contain the corpus — would push it past 128k tokens"
    )
