#!/usr/bin/env python3
"""Wiring tests: invisible seam is injected into BOTH M1 and M2 prompts
BEFORE oracle_llm.complete is called for each lens.

These are fully deterministic — no cloud, no actual LLM calls.
oracle_llm.complete is monkeypatched to capture what system prompt was sent.

The gap being closed: previous tests verified that inject_pending_seams()
produces the right prompt string, but none verified that cmd_hunt actually
calls inject before the LLM submit fires, and that both the mitre context
and the paradox context receive the seam block before their engine call.
"""
from __future__ import annotations

import http.server
import sys
import tempfile
import threading
import types
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import bad_code_app  # noqa: E402
import oracle_hunter as oh  # noqa: E402
import oracle_llm  # noqa: E402
from oracle_mindset_context import OracleMindsetContext  # noqa: E402


# ── Helpers ───────────────────────────────────────────────────────────────────

def _args(**over) -> types.SimpleNamespace:
    base = dict(
        cloud=True, model=None, verify=False, auto=True, fast_triage=False,
        min_payout=0, max_payout=0, auto_pick=False, testnet=True, code=None,
        auth=None, cookie=None, mindset=None, from_scan4me=False, scan4me_top=1,
        seam_allow_new=False, handoff=None, schedule=None, pick=1,
        account_a=None, account_b=None, auto_provision=None,
        prompt_login=False, researcher=None,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def _fake_program(base_url: str) -> dict:
    """Minimal program dict so cmd_hunt builds a real scope wall and injects seams.

    Without a program, prog=None: scope wall is empty and _inv_seams stays []
    because the template engine needs scope to produce candidates.
    The wiring tests need a non-None program to exercise the real injection path.
    """
    host = base_url.replace("http://", "").replace("https://", "")
    return {
        "name": "wiring-testbed",
        "platform": "hackerone",
        "url": base_url,
        "max_payout_usd": 1000,
        "kind": "web2",
        "structured_scopes": [
            {
                "asset_identifier": base_url,
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "rules": "Wiring test only.",
    }


def _make_recon(recon_dir: Path, base: str) -> None:
    paths = [
        f"{base}/debug/config [200]",
        f"{base}/api/v1/admin/metrics [403]",
        f"{base}/api/internal/private [200]",
        f"{base}/api/v1/users [200]",
        f"{base}/static/.env.bak [200]",
        f"{base}/health [200]",
    ]
    (recon_dir / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
    (recon_dir / "live_hosts.txt").write_text(base + "\n")
    (recon_dir / "clean_live_hosts.txt").write_text(base + "\n")
    (recon_dir / "known_urls.txt").write_text(
        "\n".join(p.split(" ")[0] for p in paths) + "\n"
    )
    (recon_dir / "js_endpoints.txt").write_text(
        f"{base}/api/v1/users\n{base}/api/v2/users\n"
    )
    for f in ("js_secrets.txt", "api_specs.txt"):
        (recon_dir / f).write_text("")


# ── Fixture: server + captured LLM calls ─────────────────────────────────────

class _Capture:
    """Accumulates (system_prompt, task, mindset_label) for every LLM submit."""
    def __init__(self):
        self.calls: List[Dict[str, str]] = []

    def fake_complete(self, prompt, system, task_type, *a, return_model=False, **kw):
        self.calls.append({"system": system or "", "prompt": prompt or ""})
        if return_model:
            return "TARGET CLEAN\n", "fake-model"
        return "TARGET CLEAN\n"


@pytest.fixture(scope="module")
def wiring_capture(tmp_path_factory):
    """Spin up bad_code_app, monkeypatch oracle_llm.complete, run cmd_hunt
    with verify=False so the deterministic verifier doesn't fire real HTTP.
    Returns the Capture object with every LLM system-prompt string.

    We inject a fake program so cmd_hunt builds a real scope wall and the
    template engine produces _inv_seams — without a program, prog=None and
    the injection path is never reached.
    """
    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), bad_code_app.VulnerableHandler
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"

    recon_dir = tmp_path_factory.mktemp("wiring_recon")
    _make_recon(recon_dir, base)
    fake_prog = _fake_program(base)

    cap = _Capture()
    orig_complete = oracle_llm.complete
    orig_collaborate = oracle_llm.collaborate
    orig_cloud_lane = oracle_llm.cloud_lane_available
    orig_recon = oh.recon
    orig_scope = oh._scope_from_programs
    from oracle_mindset_context import ProgramWorkspace as _PW
    orig_download = _PW.download_assets
    # ws.recon_dir is set from the workspace path (not the oh.recon() result).
    # Patch the property so cmd_hunt uses our pre-built recon dir throughout.
    orig_recon_dir_prop = _PW.__dict__.get("recon_dir")

    oracle_llm.complete = cap.fake_complete
    # The later local second vote calls collaborate(); this fixture tests
    # prompt wiring, not model routing. Return deterministic role records so
    # the suite never reaches Databricks/OmniCLI/Ollama.
    oracle_llm.collaborate = lambda *a, **k: {
        "scout": {
            "status": "ok",
            "backend": "stub",
            "model": "stub",
            "output": "TARGET CLEAN",
        },
        "adversary": {
            "status": "ok",
            "backend": "stub",
            "model": "stub",
            "output": "no issue",
        },
        "private_reviewer": {
            "status": "ok",
            "backend": "stub",
            "model": "stub",
            "output": "no issue",
        },
    }
    # complete() is faked, so lane availability must be faked too: with no
    # API keys (clean CI) cloud_lane_available() is False and cmd_hunt
    # never submits an engine pass, making the wiring unobservable.
    oracle_llm.cloud_lane_available = lambda cfg, env: True
    # oh.recon() is called early for host discovery; point it at our dir too.
    oh.recon = lambda *a, **kw: recon_dir
    oh._scope_from_programs = lambda name: fake_prog
    _PW.download_assets = lambda self, **kw: []
    # Override recon_dir property so template scan, scope gate, and all recon
    # reads use our pre-built recon directory.
    _PW.recon_dir = property(lambda self: recon_dir)

    try:
        oh.cmd_hunt(base, _args())
    except (SystemExit, Exception):
        pass
    finally:
        oracle_llm.complete = orig_complete
        oracle_llm.collaborate = orig_collaborate
        oracle_llm.cloud_lane_available = orig_cloud_lane
        oh.recon = orig_recon
        oh._scope_from_programs = orig_scope
        _PW.download_assets = orig_download
        if orig_recon_dir_prop is None:
            del _PW.recon_dir
        else:
            _PW.recon_dir = orig_recon_dir_prop
        httpd.shutdown()

    return cap


# ── W1: M1 (mitre) prompt carries seam block ────────────────────────────────

class TestW1MitreReceivesSeamBlock:
    """Every call to oracle_llm.complete for the mitre lens must carry
    PENDING SEAMS in the system prompt — the invisible seam is injected
    before the engine submit fires."""

    def _mitre_systems(self, cap: _Capture) -> List[str]:
        return [
            c["system"] for c in cap.calls
            if "MITRE ATT&CK" in c["system"] or "TTP REFERENCE" in c["system"]
        ]

    def test_mitre_engine_called_at_all(self, wiring_capture):
        assert self._mitre_systems(wiring_capture), (
            "No call to oracle_llm.complete had a MITRE system prompt — "
            "mitre lens never submitted"
        )

    def test_mitre_prompt_has_pending_seams(self, wiring_capture):
        for sys_prompt in self._mitre_systems(wiring_capture):
            assert "PENDING SEAMS" in sys_prompt, (
                "MITRE engine call did NOT receive PENDING SEAMS block — "
                "invisible seam was not injected before mitre submit"
            )

    def test_mitre_prompt_has_scope_wall(self, wiring_capture):
        for sys_prompt in self._mitre_systems(wiring_capture):
            assert "ACTIVE PROGRAM" in sys_prompt or "127.0.0.1" in sys_prompt, (
                "MITRE engine call missing scope wall"
            )


# ── W2: M2 (paradox) prompt carries seam block ───────────────────────────────

class TestW2ParadoxReceivesSeamBlock:
    """The paradox (Mindset 2) engine call must carry PENDING SEAMS —
    the invisible seam is injected into BOTH lenses before either fires."""

    def _paradox_systems(self, cap: _Capture) -> List[str]:
        return [
            c["system"] for c in cap.calls
            if "PARADOX" in c["system"] and "SOURCE CONTEXT" in c["system"]
        ]

    def test_paradox_engine_called_at_all(self, wiring_capture):
        assert self._paradox_systems(wiring_capture), (
            "No call to oracle_llm.complete had a PARADOX + SOURCE CONTEXT "
            "system prompt — paradox lens never submitted"
        )

    def test_paradox_prompt_has_pending_seams(self, wiring_capture):
        for sys_prompt in self._paradox_systems(wiring_capture):
            assert "PENDING SEAMS" in sys_prompt, (
                "PARADOX engine call did NOT receive PENDING SEAMS block — "
                "invisible seam was not injected before paradox submit"
            )

    def test_paradox_prompt_has_full_corpus(self, wiring_capture):
        for sys_prompt in self._paradox_systems(wiring_capture):
            assert "SOURCE CONTEXT" in sys_prompt, (
                "PARADOX engine call missing SOURCE CONTEXT (philosophy corpus)"
            )

    def test_paradox_prompt_has_scope_wall(self, wiring_capture):
        for sys_prompt in self._paradox_systems(wiring_capture):
            assert "ACTIVE PROGRAM" in sys_prompt or "127.0.0.1" in sys_prompt


# ── W3: M3 (seam synthesis) prompt carries ALL candidate seams ───────────────

class TestW3SynthesisReceivesAllCandidates:
    """The Mindset 3 synthesis call must carry PENDING SEAMS with the
    full merged candidate set (both lenses + template feed)."""

    def _seam_systems(self, cap: _Capture) -> List[str]:
        return [
            c["system"] for c in cap.calls
            if "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS" in c["system"]
        ]

    def test_m3_synthesis_called_at_all(self, wiring_capture):
        assert self._seam_systems(wiring_capture), (
            "No call to oracle_llm.complete had an INVISIBLE SEAM SYNTHESIS "
            "system prompt — Mindset 3 never ran"
        )

    def test_m3_prompt_has_pending_seams(self, wiring_capture):
        for sys_prompt in self._seam_systems(wiring_capture):
            assert "PENDING SEAMS" in sys_prompt, (
                "Mindset 3 synthesis call did NOT receive PENDING SEAMS — "
                "candidate seam feed was not injected before M3 submit"
            )

    def test_m3_prompt_has_scope_wall(self, wiring_capture):
        for sys_prompt in self._seam_systems(wiring_capture):
            assert "ACTIVE PROGRAM" in sys_prompt or "127.0.0.1" in sys_prompt


# ── W4: All three mindset directives are distinct ────────────────────────────

class TestW4DistinctDirectivesPerMindset:
    """Each mindset must carry its own directive — not the same string
    in all three. Proves differentiation, not just presence."""

    def test_three_distinct_directives_present_across_all_calls(self, wiring_capture):
        directives = {
            "mitre": any(
                "MITRE ATT&CK OFFENSIVE RED-TEAM" in c["system"]
                for c in wiring_capture.calls
            ),
            "paradox": any(
                "PARADOX & PHILOSOPHY ADVERSARIAL RED-TEAM" in c["system"]
                for c in wiring_capture.calls
            ),
            "seam": any(
                "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS" in c["system"]
                for c in wiring_capture.calls
            ),
        }
        missing = [k for k, v in directives.items() if not v]
        assert not missing, (
            f"Missing red-team directives in submitted LLM calls: {missing}"
        )

    def test_no_call_carries_all_three_directives(self, wiring_capture):
        """Each LLM call is for ONE mindset — never a mixture."""
        for i, c in enumerate(wiring_capture.calls):
            present = [
                d for d in (
                    "MITRE ATT&CK OFFENSIVE RED-TEAM",
                    "PARADOX & PHILOSOPHY ADVERSARIAL RED-TEAM",
                    "INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS",
                )
                if d in c["system"]
            ]
            assert len(present) <= 1, (
                f"LLM call {i} carries {len(present)} mindset directives — "
                f"mindsets are leaking into each other: {present}"
            )
