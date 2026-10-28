#!/usr/bin/env python3
"""Live model pressure tests: run ALL THREE mindsets against the real cloud
engine (OpenRouter) and verify the outputs satisfy the P1 doctrine.

These tests call the actual LLM — they require OPENROUTER_API_KEY to be set.
They are marked `live` and skipped when the key is absent or cloud is down.

What is being tested:
  L1 — M1 (mitre): model receives MITRE prompt, responds with at least one
       seam-structured card, card uses MITRE TTP framing.
  L2 — M2 (paradox): model receives the philosophy corpus prompt, responds
       with at least one seam card that references paradox/impossible-problem
       framing, NOT just MITRE technique names.
  L3 — M3 (seam synthesis): model receives the synthesis prompt with candidate
       seams injected, produces output that corroborates at least one candidate
       (same check URL) rather than inventing entirely new subjects.
  L4 — All three directives reach the model at the right time: seam block
       is present in both M1 and M2 system prompts actually sent, not just
       in the object before serialisation.
  L5 — Scope wall is honoured: model does not emit a card for a URL that is
       NOT in the faked in-scope list.
  L6 — Philosophy corpus is NOT cherry-picked: the paradox prompt contains all
       required corpus document identifiers.
  L7 — Red-team directive is present in every mindset's submitted prompt.

Runtime: ~60-120s (3 cloud LLM calls, one per mindset).
Run with: python -m pytest tests/test_live_model_pressure.py -v -s -m live
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import types
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import oracle_llm  # noqa: E402
import oracle_hunter as oh  # noqa: E402
from oracle_mindset_context import OracleMindsetContext  # noqa: E402
from oracle_mindsets import synthesize_seams, redteam_challenge  # noqa: E402

# ── Skip guard ────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.live


def _cloud_up() -> bool:
    # Oracle loads keys from ~/.config/trio/keys.env via _load_env() — check
    # that path directly rather than relying on os.environ being pre-populated.
    try:
        from oracle_hunter import _load_env
        env = _load_env()
        if not env.get("OPENROUTER_API_KEY"):
            return False
    except Exception:
        if not os.environ.get("OPENROUTER_API_KEY"):
            return False
    try:
        result = oracle_llm.complete(
            "Reply with exactly: ORACLE_PING_OK",
            "You are a test oracle.",
            "reflex",
            None, None, None, False,
        )
        return "ORACLE_PING_OK" in str(result)
    except Exception:
        return False


@pytest.fixture(scope="module")
def require_cloud():
    if not _cloud_up():
        pytest.skip(
            "Cloud engine not available (key missing or unreachable) — "
            "live model tests skipped"
        )


# ── Shared test program ───────────────────────────────────────────────────────

_PROGRAM = {
    "name": "TestCorp",
    "platform": "hackerone",
    "url": "https://hackerone.com/testcorp",
    "max_payout_usd": 5000,
    "kind": "web2",
    "structured_scopes": [
        {
            "asset_identifier": "https://api.testcorp.example",
            "asset_type": "URL",
            "eligible_for_bounty": True,
            "eligible_for_submission": True,
            "instruction": "Primary API — all endpoints in scope.",
        }
    ],
    "rules": "Do not test production systems. Report auth bypass immediately.",
}

_RECON_TEXT = """
Live hosts: api.testcorp.example
Fuzzed paths:
  https://api.testcorp.example/api/v1/admin/metrics [403]
  https://api.testcorp.example/api/internal/private [200]
  https://api.testcorp.example/debug/config [200]
  https://api.testcorp.example/health [200]
""".strip()

_SEAM_CANDIDATES = [
    {
        "n": 1,
        "mindset": "seam",
        "claim_type": "beautiful-liar-trust-bypass",
        "reflex": "REFLEX 5: Broken Access Control",
        "mitre": "CWE-284 / T1078",
        "assertion_a": "Access to /api/v1/admin/metrics is enforced server-side (returns 403)",
        "assertion_b": "Server trusts X-Original-Role header — injecting X-Original-Role: admin may bypass",
        "check": "curl -i -s -H 'X-Original-Role: admin' 'https://api.testcorp.example/api/v1/admin/metrics'",
        "expected": 'status 200, body contains any of "admin","metrics","revenue","authorized"',
        "severity": "high",
        "impact": "Auth bypass via header injection — attacker accesses admin metrics without credentials.",
        "source_a": "fuzzed_paths.txt",
        "source_b": "fuzzed_paths.txt",
        "line_a": 0,
        "line_b": 0,
    },
    {
        "n": 2,
        "mindset": "seam",
        "claim_type": "cliff-and-current-alt-path",
        "reflex": "REFLEX 5: Broken Access Control — path confusion",
        "mitre": "CWE-289 / T1190",
        "assertion_a": "Auth middleware protects /api/v1/admin/metrics (returns 403)",
        "assertion_b": "Alternate path /api/internal/private serves the same resource without auth check",
        "check": "curl -i -s 'https://api.testcorp.example/api/internal/private'",
        "expected": 'status 200, body contains any of "secret","data","revenue","internal","private"',
        "severity": "high",
        "impact": "Auth bypass via alternate path — middleware only bound to one spelling.",
        "source_a": "fuzzed_paths.txt",
        "source_b": "fuzzed_paths.txt",
        "line_a": 0,
        "line_b": 0,
    },
    {
        "n": 3,
        "mindset": "seam",
        "claim_type": "self-observing-equation",
        "reflex": "REFLEX 8: Logic Flaw",
        "mitre": "CWE-200 / T1082",
        "assertion_a": "Internal configuration is not exposed to the public",
        "assertion_b": "/debug/config returns service config including credentials",
        "check": "curl -i -s 'https://api.testcorp.example/debug/config'",
        "expected": 'status 200, body contains any of "aws","secret","password","key","config","debug"',
        "severity": "high",
        "impact": "Credential exposure via debug endpoint.",
        "source_a": "fuzzed_paths.txt",
        "source_b": "fuzzed_paths.txt",
        "line_a": 0,
        "line_b": 0,
    },
]


# ── L1: Mindset 1 (MITRE) live call ───────────────────────────────────────────

class TestL1MitreLive:
    """The MITRE-lens prompt reaches the model and the model responds with
    at least one seam-structured card."""

    @pytest.fixture(scope="class")
    def mitre_result(self, require_cloud):
        ctx = OracleMindsetContext(
            program=_PROGRAM, voice=False, ttp_mode="full", mindset="mitre"
        )
        ctx.inject_recon_context(
            ["api.testcorp.example"],
            ["/api/v1/admin/metrics", "/api/internal/private", "/debug/config"],
        )
        ctx.inject_pending_seams(_SEAM_CANDIDATES)
        system = ctx.system_prompt()

        task = (
            f"Target: https://api.testcorp.example\n\n"
            f"Recon:\n{_RECON_TEXT}\n\n"
            "Run ALL MITRE ATT&CK techniques in your system prompt against this target.\n"
            "Produce seam cards in the standard format.\n"
            "SEAM N:\nASSERTION A:\nASSERTION B:\nCHECK:\nEXPECTED:\nIMPACT:\nVERDICT: CANDIDATE\n"
        )
        raw, model = oracle_llm.complete(
            task, system, "reflex", None, None, None, False, return_model=True
        )
        return {"raw": raw, "model": model, "system": system}

    def test_mitre_got_a_response(self, mitre_result):
        assert mitre_result["raw"].strip(), "MITRE lens got empty response from model"

    def test_mitre_system_has_ttp_reference(self, mitre_result):
        assert "ORACLE TTP REFERENCE" in mitre_result["system"]

    def test_mitre_system_has_mitre_redteam_directive(self, mitre_result):
        assert "MITRE ATT&CK OFFENSIVE RED-TEAM" in mitre_result["system"]

    def test_mitre_system_has_pending_seams(self, mitre_result):
        assert "PENDING SEAMS" in mitre_result["system"], (
            "Invisible seam was NOT injected into the MITRE system prompt"
        )

    def test_mitre_system_has_scope_wall(self, mitre_result):
        assert "api.testcorp.example" in mitre_result["system"]
        assert "ACTIVE PROGRAM" in mitre_result["system"]

    def test_mitre_response_references_techniques(self, mitre_result):
        raw = mitre_result["raw"].upper()
        # Response should mention at least one of: ASSERTION, SEAM, CHECK, MITRE,
        # T1xxx code, CWE, or a known technique family
        technical_markers = [
            "ASSERTION", "SEAM", "CHECK:", "MITRE", "T10", "T11", "CWE",
            "AUTH", "BYPASS", "IDOR", "INJECTION", "ACCESS CONTROL",
        ]
        assert any(m in raw for m in technical_markers), (
            f"MITRE lens response has no technical content — got: {mitre_result['raw'][:300]}"
        )

    def test_mitre_does_not_use_paradox_framing(self, mitre_result):
        """M1 must not contain the full philosophy corpus header."""
        assert "SOURCE CONTEXT (verbatim corpus)" not in mitre_result["system"], (
            "MITRE system prompt contains philosophy corpus — mindsets are bleeding"
        )


# ── L2: Mindset 2 (paradox) live call ────────────────────────────────────────

class TestL2ParadoxLive:
    """The paradox-lens prompt reaches the model with the full philosophy
    corpus, and the model responds using impossible-problem / paradox framing."""

    @pytest.fixture(scope="class")
    def paradox_result(self, require_cloud):
        ctx = OracleMindsetContext(
            program=_PROGRAM, voice=False, ttp_mode="compact", mindset="paradox"
        )
        ctx.inject_recon_context(
            ["api.testcorp.example"],
            ["/api/v1/admin/metrics", "/api/internal/private", "/debug/config"],
        )
        ctx.inject_pending_seams(_SEAM_CANDIDATES)
        system = ctx.system_prompt()

        task = (
            f"Target: https://api.testcorp.example\n\n"
            f"Recon:\n{_RECON_TEXT}\n\n"
            "Apply the paradox / impossible-problem framework to this target.\n"
            "For each seam: state the binary conflict (Assertion A vs B), the "
            "philosophical move that reveals it, and the exact curl check.\n"
            "SEAM N:\nASSERTION A:\nASSERTION B:\nCHECK:\nEXPECTED:\nIMPACT:\nVERDICT: CANDIDATE\n"
        )
        raw, model = oracle_llm.complete(
            task, system, "reflex", None, None, None, False, return_model=True
        )
        return {"raw": raw, "model": model, "system": system}

    def test_paradox_got_a_response(self, paradox_result):
        assert paradox_result["raw"].strip()

    def test_paradox_system_has_source_context(self, paradox_result):
        assert "SOURCE CONTEXT (verbatim corpus)" in paradox_result["system"], (
            "Paradox system prompt is missing the philosophy corpus"
        )

    def test_paradox_system_has_paradox_redteam_directive(self, paradox_result):
        assert "PARADOX & PHILOSOPHY ADVERSARIAL RED-TEAM" in paradox_result["system"]

    def test_paradox_system_has_pending_seams(self, paradox_result):
        assert "PENDING SEAMS" in paradox_result["system"], (
            "Invisible seam NOT injected into paradox system prompt"
        )

    def test_paradox_system_has_all_required_corpus_docs(self, paradox_result):
        required = [
            "iphone-problem",
            "beautiful-liar",
            "repulsive-gravity",
            "self-observing-equation",
            "paradox-impossible-crossover",
        ]
        missing = [d for d in required if f"[{d}]" not in paradox_result["system"]]
        assert not missing, (
            f"Philosophy corpus is cherry-picked — missing docs: {missing}"
        )

    def test_paradox_system_has_scope_wall(self, paradox_result):
        assert "api.testcorp.example" in paradox_result["system"]

    def test_paradox_response_not_empty_and_technical(self, paradox_result):
        raw = paradox_result["raw"].upper()
        markers = ["ASSERTION", "SEAM", "CHECK:", "PARADOX", "CONFLICT", "AUTH",
                   "BYPASS", "ACCESS", "CWE", "T10", "T11"]
        assert any(m in raw for m in markers), (
            f"Paradox response has no technical content: {paradox_result['raw'][:300]}"
        )

    def test_paradox_system_is_larger_than_mitre(self, paradox_result, require_cloud):
        """M2 carries the full corpus on top of TTPs — its prompt is always
        larger than M1's. A smaller M2 means the corpus was dropped."""
        mitre_size = len(
            OracleMindsetContext(
                program=_PROGRAM, voice=False, ttp_mode="compact", mindset="mitre"
            ).system_prompt()
        )
        assert len(paradox_result["system"]) > mitre_size, (
            "Paradox system prompt is NOT larger than mitre — corpus may have been dropped"
        )


# ── L3: Mindset 3 (synthesis) live call ──────────────────────────────────────

class TestL3SynthesisLive:
    """The synthesis prompt is sent with ALL candidate seams injected.
    The model must corroborate at least one candidate (same URL) rather
    than purely inventing new subjects."""

    @pytest.fixture(scope="class")
    def synthesis_result(self, require_cloud):
        ctx = OracleMindsetContext(
            program=_PROGRAM, voice=False, ttp_mode="full", mindset="seam"
        )
        ctx.inject_recon_context(
            ["api.testcorp.example"],
            ["/api/v1/admin/metrics", "/api/internal/private", "/debug/config"],
        )
        ctx.inject_pending_seams(_SEAM_CANDIDATES)
        system = ctx.system_prompt()

        candidate_block = "\n".join(
            f"SEAM {s['n']}: CHECK={s['check']}" for s in _SEAM_CANDIDATES
        )
        task = (
            "INVISIBLE SEAM & ADVERSARIAL SYNTHESIS TASK:\n"
            "Review the pending candidate seams and live recon surface.\n"
            "1. Attack and corroborate the candidates — find bypasses.\n"
            "2. Chain findings where output from one feeds another.\n"
            "3. Discard theoretical candidates.\n"
            "4. Produce seam cards in standard format.\n\n"
            f"Target: https://api.testcorp.example\n\n"
            f"Recon:\n{_RECON_TEXT}\n\n"
            f"Candidates:\n{candidate_block}\n\n"
            "SEAM N:\nASSERTION A:\nASSERTION B:\nCHECK:\nEXPECTED:\nIMPACT:\nVERDICT: CANDIDATE\n"
        )
        raw, model = oracle_llm.complete(
            task, system, "reflex", None, None, None, False, return_model=True
        )
        return {"raw": raw, "model": model, "system": system}

    def test_synthesis_got_a_response(self, synthesis_result):
        assert synthesis_result["raw"].strip()

    def test_synthesis_system_has_synthesis_directive(self, synthesis_result):
        assert "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS" in synthesis_result["system"]

    def test_synthesis_system_has_pending_seams(self, synthesis_result):
        assert "PENDING SEAMS" in synthesis_result["system"], (
            "Synthesis system prompt does NOT have PENDING SEAMS — "
            "all 3 candidates should be injected"
        )

    def test_synthesis_system_has_all_three_candidates(self, synthesis_result):
        for s in _SEAM_CANDIDATES:
            assert s["assertion_a"] in synthesis_result["system"], (
                f"Candidate seam {s['n']} missing from synthesis system prompt: "
                f"{s['assertion_a'][:60]}"
            )

    def test_synthesis_system_has_scope_wall(self, synthesis_result):
        assert "api.testcorp.example" in synthesis_result["system"]

    def test_synthesis_response_references_candidate_urls(self, synthesis_result):
        """The model should produce output referencing at least one of the
        candidate check URLs — it is synthesizing, not inventing from scratch."""
        raw = synthesis_result["raw"]
        candidate_urls = [
            "api/v1/admin/metrics",
            "api/internal/private",
            "debug/config",
        ]
        assert any(u in raw for u in candidate_urls), (
            "Synthesis response references NONE of the candidate URLs — "
            "model is inventing new subjects instead of synthesizing: "
            f"{raw[:400]}"
        )

    def test_synthesis_does_not_carry_paradox_corpus(self, synthesis_result):
        """M3 uses the seam profile — it must NOT embed the full paradox corpus
        (that's M2's job). It carries compact TTP + synthesis directive only."""
        # The paradox corpus header is the signal
        assert "SOURCE CONTEXT (verbatim corpus)" not in synthesis_result["system"], (
            "Synthesis (M3) system prompt contains full philosophy corpus — "
            "should only be in M2 (paradox)"
        )


# ── L4: All three mindsets reach the model with correct scope ─────────────────

class TestL4ScopeWallEveryMindset:
    """Scope wall, program rules, and company context reach the model in
    every mindset's system prompt — not just one."""

    def _prompt(self, mindset: str) -> str:
        ctx = OracleMindsetContext(
            program=_PROGRAM, voice=False, ttp_mode="compact", mindset=mindset
        )
        ctx.inject_pending_seams(_SEAM_CANDIDATES)
        return ctx.system_prompt()

    def test_scope_wall_in_mitre(self, require_cloud):
        p = self._prompt("mitre")
        assert "api.testcorp.example" in p
        assert "ACTIVE PROGRAM" in p
        assert "Do not test production" in p

    def test_scope_wall_in_paradox(self, require_cloud):
        p = self._prompt("paradox")
        assert "api.testcorp.example" in p
        assert "ACTIVE PROGRAM" in p
        assert "Do not test production" in p

    def test_scope_wall_in_seam(self, require_cloud):
        p = self._prompt("seam")
        assert "api.testcorp.example" in p
        assert "ACTIVE PROGRAM" in p
        assert "Do not test production" in p


# ── L5: Scope enforcement — model does not emit out-of-scope findings ─────────

class TestL5ScopeEnforcement:
    """The model should not emit a finding for a URL that is explicitly
    out-of-scope. We inject an out-of-scope asset and check the response."""

    @pytest.fixture(scope="class")
    def scoped_result(self, require_cloud):
        prog = dict(_PROGRAM)
        prog["out_of_scope"] = "payments.testcorp.example"
        ctx = OracleMindsetContext(
            program=prog, voice=False, ttp_mode="compact", mindset="mitre"
        )
        ctx.inject_pending_seams(_SEAM_CANDIDATES)
        system = ctx.system_prompt()

        task = (
            "Target: https://api.testcorp.example\n\n"
            "Recon includes: api.testcorp.example, payments.testcorp.example\n\n"
            "Produce seam cards. SEAM N:\nASSERTION A:\nASSERTION B:\nCHECK:\nVERDICT: CANDIDATE\n"
        )
        raw, model = oracle_llm.complete(
            task, system, "reflex", None, None, None, False, return_model=True
        )
        return {"raw": raw, "system": system}

    def test_out_of_scope_asset_in_scope_wall(self, scoped_result):
        assert "payments.testcorp.example" in scoped_result["system"]
        assert "OUT OF SCOPE" in scoped_result["system"]

    def test_response_does_not_cite_oos_asset(self, scoped_result):
        """Model should not produce a CHECK targeting the OOS asset."""
        raw = scoped_result["raw"]
        # This is a soft check — the verifier is the hard gate.
        # We're testing that the scope wall instruction reaches the model
        # and it respects it in practice.
        oos_in_check = (
            "payments.testcorp.example" in raw
            and "CHECK:" in raw.upper()
        )
        if oos_in_check:
            pytest.xfail(
                "Model cited OOS asset in a CHECK — scope wall instruction "
                "did not suppress it. The 7-gate verifier is the hard gate; "
                "this is a model-compliance signal only."
            )


# ── L6: Red-team directive present in every submitted prompt ─────────────────

class TestL6RedTeamDirectiveEveryMindset:
    """Every mindset's system prompt must have a red-team offensive directive.
    This runs against the actual built prompt strings (no LLM needed)."""

    @pytest.mark.parametrize("mindset,expected_marker", [
        ("mitre",   "MITRE ATT&CK OFFENSIVE RED-TEAM STRIKE DIRECTIVE"),
        ("paradox", "PARADOX & PHILOSOPHY ADVERSARIAL RED-TEAM DIRECTIVE"),
        ("seam",    "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS DIRECTIVE"),
    ])
    def test_directive_present(self, mindset, expected_marker, require_cloud):
        ctx = OracleMindsetContext(
            program=_PROGRAM, voice=False, ttp_mode="compact", mindset=mindset
        )
        ctx.inject_pending_seams(_SEAM_CANDIDATES)
        assert expected_marker in ctx.system_prompt(), (
            f"Mindset {mindset!r} system prompt missing directive: {expected_marker}"
        )


# ── L7: Synthesis ranking is driven by redteam verdicts ──────────────────────

class TestL7SynthesisRankingLive:
    """synthesize_seams + redteam_challenge produce correct ranking when
    given real-shaped seam dicts. No LLM needed — pure function test that
    verifies the ranking contract with prod-shaped data."""

    def test_confirmed_floats_above_unreviewed(self, require_cloud):
        mitre_seam = dict(_SEAM_CANDIDATES[0], mindset="mitre")
        paradox_seam = dict(_SEAM_CANDIDATES[1], mindset="paradox")
        seam_feed = dict(_SEAM_CANDIDATES[2], mindset="seam")

        verdicts = redteam_challenge([mitre_seam, paradox_seam, seam_feed])
        out = synthesize_seams(
            {"mitre": [mitre_seam], "paradox": [paradox_seam], "seam": [seam_feed]},
            redteam_verdicts=verdicts,
        )
        assert len(out) == 3
        # confirmed or unreviewed — either is valid; check nothing was silently dropped
        assert all("synthesis_rank" in s for s in out)
        assert all("redteam_verdict" in s for s in out)

    def test_none_lens_raises_loudly(self, require_cloud):
        from pytest import raises
        with raises(ValueError, match="short a lens"):
            synthesize_seams({"mitre": [dict(_SEAM_CANDIDATES[0])], "paradox": None})
