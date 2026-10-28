#!/usr/bin/env python3
"""End-to-end Three-Mindset + Invisible Seam + Wire Verifier Scenario Gauntlet.

Exercises the complete Oracle architecture against BOTH:
1. A realistic multi-file "shit code" repository (broken contracts across
   README.md, config.schema.json, subdirectory Python modules, and Solidity
   contracts with missing NatSpec guards, alongside safe controls), AND
2. The live HTTP vulnerable testbed (`vuln_testbed_full.py`),
across all 6 critical operational scenarios:
   - Scenario A (Invisible Seam on Shit Code + Evidence Spine):
     Universal claim-vs-reality extraction (doc-code, type-hint, config-fallback,
     Solidity NatSpec guard), subdirectory static verification, and rejection
     after code remediation.
   - Scenario B (Mindset 1 + Mindset 2 Full Prompt & Scope Wall):
     Full 344 MITRE TTPs in M1, all 21 corpus documents verbatim in M2,
     untrimmed multi-section bounty rules/scope/assets/company context, and
     injected Invisible Seam pre-pass findings.
   - Scenario C (Cross-Mindset Corroboration with Different Phrasing):
     M1 (`mitre`) and M2 (`paradox`) independently identify the same live wire
     vulnerability using different natural-language phrasing; M3's
     `second_seam_pass` marks them `corroborated`, `apply_mindset3_gates`
     confirms both, `synthesize_seams` ranks them at the top, and the 5-gate
     wire verifier confirms them against the live HTTP server.
   - Scenario D (Cross-Mindset Contradiction / Conflict Resolution):
     One lens claims a route is exploitable while the other lens claims the
     boundary is enforced; M3's `second_seam_pass` marks `m3_seam_conflict=True`
     (`conflicted`), `apply_mindset3_gates` demotes both to `unreviewed` so stale
     isolated confirmations cannot bypass conflict resolution, and the live
     5-gate wire verifier acts as the sole arbiter on the wire.
   - Scenario E (Adversarial Red-Team & 5-Gate Wire Rejection of Noise):
     Self-defeating cards (`Assertion A == Assertion B`), out-of-scope URLs,
     non-seam expected statuses (`403`), and benign live endpoints (`/health`,
     `/api/v1/secrets`) are challenged by Red Team and rejected by the 5-gate
     wire verifier (0 false positives).
   - Scenario F (Mindset 3 No-Invention Gate & Compound Exploit Chaining):
     M3 synthesis cards on unseen subjects are dropped by `corroborate_synth_seams`
     while corroborated synthesis cards survive and chain into Critical
     multi-step exploit paths via `chain_seams`.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
from oracle_bulk_download import _extract_policy_from_assets  # noqa: E402
from oracle_code_seam import scan_repository_seams  # noqa: E402
from oracle_corpus import DOCUMENTS  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)
from oracle_evidence import verify_finding  # noqa: E402
from oracle_mindset_context import OracleMindsetContext  # noqa: E402
from oracle_mindsets import (  # noqa: E402
    apply_mindset3_gates,
    redteam_challenge_by_lens,
    seam_candidate_key,
    second_seam_pass,
    synthesize_seams,
)

BASE = "http://127.0.0.1:8765"


def _build_shit_code_repo(repo: Path) -> None:
    """Create a realistic messy multi-file repository with contract vs. code seams."""
    (repo / "README.md").write_text(
        "# Acme Payment Gateway\n\n"
        "### `verify_api_token(token)`\n\n"
        "Raises ValueError when the token is empty or malformed.\n\n"
        "### `load_signing_secret(config)`\n\n"
        "Requires `signing_secret` in config and raises KeyError if missing.\n",
        encoding="utf-8",
    )
    (repo / "config.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["api_key", "signing_secret"],
                "properties": {
                    "api_key": {"type": "string"},
                    "signing_secret": {"type": "string"},
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    src = repo / "src" / "auth"
    src.mkdir(parents=True, exist_ok=True)
    (src / "service.py").write_text(
        "def verify_api_token(token: str) -> bool:\n"
        '    """Raises ValueError when the token is empty or malformed."""\n'
        "    if not token:\n"
        "        return False\n"
        "    return True\n\n"
        "def get_active_roles(user_id: str) -> list[str]:\n"
        '    """Returns the active role list for user_id."""\n'
        "    if not user_id:\n"
        "        return None\n"
        "    return ['member']\n\n"
        "def load_api_key(config: dict) -> str:\n"
        "    return config.get('api_key', 'hardcoded-dev-fallback-key')\n",
        encoding="utf-8",
    )
    contracts = repo / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)
    (contracts / "Treasury.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n\n"
        "contract Treasury {\n"
        "    uint256 public feeBps;\n\n"
        "    /// @notice Only the owner can call setFeeBps. Reverts otherwise.\n"
        "    function setFeeBps(uint256 newFee) public {\n"
        "        feeBps = newFee;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )


def _wait_up(timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            return True
        except Exception:
            time.sleep(0.25)
    return False


def test_full_scenario_gauntlet():
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(ROOT / "tests" / "vuln_testbed_full.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_up(10), "vuln_testbed_full.py failed to start on 127.0.0.1:8765"

    try:
        with tempfile.TemporaryDirectory(prefix="oracle_gauntlet_") as td:
            base_dir = Path(td)
            repo_dir = base_dir / "shit_code_repo"
            recon_dir = base_dir / "recon"
            assets_dir = base_dir / "assets"
            repo_dir.mkdir()
            recon_dir.mkdir()
            assets_dir.mkdir()

            # ── Scenario A: Invisible Seam on "Shit Code" + Evidence Spine ──
            _build_shit_code_repo(repo_dir)
            code_seams = scan_repository_seams(repo_dir)
            assert len(code_seams) >= 4, f"Expected >=4 seams on shit code, got {len(code_seams)}"

            # Verify we caught doc-code, type-hint, config-fallback, and Solidity NatSpec seams
            claim_types = {s.get("claim_type") for s in code_seams}
            assert "doc-code" in claim_types
            assert "type-hint" in claim_types
            assert "config-fallback" in claim_types
            assert any(str(s.get("source_b", "")).endswith("Treasury.sol") for s in code_seams)

            # Verify subdirectory static_seam evidence confirmation (src/auth/service.py vs root README.md)
            subdir_seams = [
                s for s in code_seams if "service.py" in str(s.get("source_b", ""))
            ]
            assert subdir_seams, "Expected subdirectory service.py seams"
            for s in subdir_seams:
                v = verify_finding(s["evidence"])
                assert v["verdict"] == "STATIC_CONFIRMED", v

            # ── Scenario B: Mindset 1 + Mindset 2 Full Prompts & Scope Wall ──
            (assets_dir / "program_page.txt").write_text(
                "Program Rules\n"
                "Stay strictly inside the authorized target assets.\n"
                "Safe Harbor\n"
                "Good-faith security research is authorized under this policy.\n"
                "Out of Scope\n"
                "Do not test third-party social media accounts. POLICY_FULL_TAIL_MARKER\n",
                encoding="utf-8",
            )
            policy_text = _extract_policy_from_assets(assets_dir, "hackerone")
            assert "Safe Harbor" in policy_text
            assert "POLICY_FULL_TAIL_MARKER" in policy_text

            prog = {
                "name": "Acme-Gauntlet",
                "platform": "hackerone",
                "url": "https://hackerone.com/acme-gauntlet",
                "company": "Acme Financial Corp",
                "policy_text": policy_text,
                "structured_scopes": [
                    {
                        "asset_identifier": BASE,
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "instruction": "Primary staging gateway — full scope note intact.",
                    }
                ],
            }
            scope_gate = oh.ProgramScopeGate(prog, target_fallback=BASE)

            # Seed recon surface + run seam_prepass (combining code seams + template seams)
            (recon_dir / "live_hosts.txt").write_text(BASE + "\n", encoding="utf-8")
            (recon_dir / "fuzzed_paths.txt").write_text(
                f"{BASE}/health [200]\n"
                f"{BASE}/debug/config [200]\n"
                f"{BASE}/.env [200]\n"
                f"{BASE}/package.json [200]\n"
                f"{BASE}/api/v1/admin/metrics [403]\n"
                f"{BASE}/api/internal/dashboard [200]\n"
                f"{BASE}/api/v1/secrets [403]\n"
                f"{BASE}/api/internal/secrets [200]\n"
                f"{BASE}/api/profile/7 [200]\n"
                f"{BASE}/api/profile/8 [200]\n",
                encoding="utf-8",
            )
            (recon_dir / "js_endpoints.txt").write_text(
                f"{BASE}/health\n"
                f"{BASE}/debug/config\n"
                f"{BASE}/.env\n"
                f"{BASE}/package.json\n"
                f"{BASE}/api/v1/admin/metrics\n"
                f"{BASE}/api/internal/dashboard\n"
                f"{BASE}/api/v1/secrets\n"
                f"{BASE}/api/internal/secrets\n"
                f"{BASE}/api/profile/7\n"
                f"{BASE}/api/profile/8\n",
                encoding="utf-8",
            )
            (recon_dir / "api_specs.txt").write_text("", encoding="utf-8")
            (recon_dir / "js_secrets.txt").write_text("", encoding="utf-8")

            tmpl_errors = []
            pre_code, pre_tpl, pre_w3 = oh.seam_prepass(
                repo_path=repo_dir,
                recon_dir=recon_dir,
                program=prog,
                scope_gate=scope_gate,
                errors=tmpl_errors,
            )
            assert not tmpl_errors, tmpl_errors
            prepass_seams = pre_code + pre_tpl + pre_w3
            assert len(prepass_seams) > len(code_seams)

            mitre_ctx = OracleMindsetContext(program=prog, voice=True, mindset="mitre")
            paradox_ctx = OracleMindsetContext(program=prog, voice=True, mindset="paradox")
            mitre_ctx.inject_pending_seams(prepass_seams)
            paradox_ctx.inject_pending_seams(prepass_seams)

            mitre_prompt = mitre_ctx.system_prompt()
            paradox_prompt = paradox_ctx.system_prompt()

            # Mindset 1 has all 342 MITRE TTPs + full policy + Invisible Seam
            assert "All 342 techniques mapped to the 11 reflexes" in mitre_prompt
            assert mitre_prompt.count("You never said:") == 342
            assert "POLICY_FULL_TAIL_MARKER" in mitre_prompt
            assert "PENDING SEAMS" in mitre_prompt

            # Mindset 2 has all 21 corpus documents verbatim + full policy + Invisible Seam
            for doc in DOCUMENTS:
                assert f"[{doc.identifier}]" in paradox_prompt, doc.identifier
            assert "POLICY_FULL_TAIL_MARKER" in paradox_prompt
            assert "PENDING SEAMS" in paradox_prompt

            # ── Scenarios C, D, E, F: M1 + M2 -> Red Team -> M3 -> Wire Verify ──
            # 1. Corroborated live bug (Beautiful Liar header bypass on /api/v1/admin/metrics)
            #    described in DIFFERENT natural-language phrasing by M1 and M2:
            m1_admin = {
                "n": 101,
                "id": "M1_ADMIN",
                "mindset": "mitre",
                "origin": "cloud-mitre",
                "reflex": "REFLEX 5: Broken Access Control",
                "mitre": "T1550 / CWE-285",
                "assertion_a": "Admin metrics endpoint requires valid admin bearer token",
                "assertion_a_source": f"{BASE}/api/v1/admin/metrics (403 baseline)",
                "assertion_b": "Supplying X-Original-Role: admin bypasses bearer token check and returns revenue metrics",
                "check": f"curl -i -s -H 'X-Original-Role: admin' '{BASE}/api/v1/admin/metrics'",
                "expected": 'status 200, body contains "total_revenue"',
                "severity": "high",
                "impact": "Unauthenticated attacker reads internal revenue metrics",
            }
            m2_admin = {
                "n": 102,
                "id": "M2_ADMIN",
                "mindset": "paradox",
                "origin": "cloud-paradox",
                "reflex": "REFLEX 5: Beautiful Liar",
                "mitre": "T1550 / CWE-290",
                "assertion_a": "Gateway enforces administrator identity before serving /api/v1/admin/metrics",
                "assertion_a_source": f"{BASE}/api/v1/admin/metrics (403 baseline)",
                "assertion_b": "The endpoint trusts the unverified X-Original-Role header from the caller",
                "check": f"curl -i -s -H 'X-Original-Role: admin' '{BASE}/api/v1/admin/metrics'",
                "expected": 'status 200, body contains "role_effective"',
                "severity": "high",
                "impact": "Privilege escalation to admin metrics via header spoofing",
            }

            # 2. Conflicted live subject (/api/v1/secrets): M1 claims it leaks, M2 says it enforces 403
            m1_conflict = {
                "n": 103,
                "id": "M1_CONFLICT",
                "mindset": "mitre",
                "origin": "cloud-mitre",
                "reflex": "REFLEX 5: Auth Bypass",
                "mitre": "T1190 / CWE-306",
                "assertion_a": "/api/v1/secrets requires authentication",
                "assertion_a_source": f"{BASE}/api/v1/secrets",
                "assertion_b": "Unauthenticated caller can read secrets directly",
                "check": f"curl -i -s '{BASE}/api/v1/secrets'",
                "expected": 'status 200, body contains "secret"',
                "severity": "high",
                "impact": "Secret exposure",
            }
            m2_conflict = {
                "n": 104,
                "id": "M2_CONFLICT",
                "mindset": "paradox",
                "origin": "cloud-paradox",
                "reflex": "REFLEX 5: Boundary Check",
                "mitre": "T1190 / CWE-306",
                "assertion_a": "/api/v1/secrets requires authentication",
                "assertion_a_source": f"{BASE}/api/v1/secrets",
                "assertion_b": "Only an authenticated caller can read /api/v1/secrets; unauthenticated requests return 403",
                "check": f"curl -i -s '{BASE}/api/v1/secrets'",
                "expected": "status 403",
                "severity": "low",
                "impact": "Boundary enforced",
            }

            # 3. Noise / Out-of-scope / Benign control cards:
            m1_oos = {
                "n": 105,
                "id": "M1_OOS",
                "mindset": "mitre",
                "origin": "cloud-mitre",
                "reflex": "REFLEX 1: Out of Scope Probe",
                "mitre": "T1190",
                "assertion_a": "External host restricts access",
                "assertion_a_source": "https://evil.out-of-scope.example/api",
                "assertion_b": "External host returns 200",
                "check": "curl -i -s 'https://evil.out-of-scope.example/api'",
                "expected": "status 200",
                "severity": "medium",
            }
            m2_benign = {
                "n": 106,
                "id": "M2_BENIGN",
                "mindset": "paradox",
                "origin": "cloud-paradox",
                "reflex": "REFLEX 7: Health Endpoint",
                "mitre": "T1082",
                "assertion_a": "/health only returns status",
                "assertion_a_source": f"{BASE}/health",
                "assertion_b": "/health leaks secret credentials",
                "check": f"curl -i -s '{BASE}/health'",
                "expected": 'status 200, body contains "aws_secret_key_mock"',
                "severity": "medium",
            }

            candidates = oh._merge_seams(
                prepass_seams,
                [m1_admin, m2_admin, m1_conflict, m2_conflict, m1_oos, m2_benign],
            )
            by_id = {s.get("id"): s for s in candidates if s.get("id")}

            # Isolated pre-M3 red-team gates per lens
            pre_verdicts, pre_counts = redteam_challenge_by_lens(
                candidates,
                in_scope=lambda u: bool(scope_gate.is_in_scope(u)[0]),
            )
            assert pre_verdicts[seam_candidate_key(by_id["M1_ADMIN"])] == "confirmed"
            assert pre_verdicts[seam_candidate_key(by_id["M2_ADMIN"])] == "confirmed"
            assert pre_verdicts[seam_candidate_key(by_id["M1_OOS"])] == "rejected"
            assert pre_verdicts[seam_candidate_key(by_id["M2_CONFLICT"])] == "rejected"

            # Mindset 3 no-invention gate (`corroborate_synth_seams`)
            m3_corroborated_synth = {
                "n": 201,
                "id": "M3_SYNTH",
                "mindset": "seam",
                "origin": "cloud-seam-synth",
                "reflex": "REFLEX 5: Beautiful Liar Compound Bypass",
                "mitre": "T1550 / CWE-290",
                "assertion_a": "Admin metrics requires verified admin token",
                "assertion_a_source": f"{BASE}/api/v1/admin/metrics (403 baseline)",
                "assertion_b": "X-Original-Role: admin spoofs administrator role on /api/v1/admin/metrics",
                "check": f"curl -i -s -H 'X-Original-Role: admin' '{BASE}/api/v1/admin/metrics'",
                "expected": 'status 200, body contains "total_revenue"',
                "severity": "high",
                "impact": "Unauthenticated attacker spoofs admin header to read revenue metrics",
            }
            m3_invented_synth = {
                "n": 202,
                "id": "M3_INVENTED",
                "mindset": "seam",
                "origin": "cloud-seam-synth",
                "reflex": "REFLEX 8: Hallucinated Route",
                "mitre": "T1190",
                "assertion_a": "Nonexistent endpoint requires auth",
                "assertion_b": "Nonexistent endpoint is public",
                "check": f"curl -i -s '{BASE}/api/v99/never_existed'",
                "expected": "status 200",
                "severity": "high",
            }
            kept_synth, dropped_synth = oh.corroborate_synth_seams(
                [m3_corroborated_synth, m3_invented_synth],
                candidates,
                allow_new=False,
            )
            assert len(kept_synth) == 1 and kept_synth[0]["id"] == "M3_SYNTH"
            assert len(dropped_synth) == 1 and dropped_synth[0]["id"] == "M3_INVENTED"

            candidates = oh._merge_seams(candidates, kept_synth)

            # Mindset 3 second seam pass + fresh red-team gates (`apply_mindset3_gates`)
            candidates, m3_verdicts, m3_counts = apply_mindset3_gates(
                candidates,
                in_scope=lambda u: bool(scope_gate.is_in_scope(u)[0]),
            )
            by_id = {s.get("id"): s for s in candidates if s.get("id")}

            # Scenario C check: M1 + M2 + M3 on /api/v1/admin/metrics are corroborated and confirmed
            assert by_id["M1_ADMIN"]["m3_seam_state"] == "corroborated"
            assert by_id["M2_ADMIN"]["m3_seam_state"] == "corroborated"
            assert set(by_id["M1_ADMIN"]["m3_seam_sources"]) == {"mitre", "paradox", "seam"}
            assert by_id["M1_ADMIN"]["m3_redteam_verdict"] == "confirmed"
            assert by_id["M2_ADMIN"]["m3_redteam_verdict"] == "confirmed"

            # Scenario D check: Conflicted /api/v1/secrets cards are flagged conflicted
            # and M1's isolated confirmation is demoted to unreviewed
            assert by_id["M1_CONFLICT"]["m3_seam_state"] == "conflicted"
            assert by_id["M1_CONFLICT"]["m3_seam_conflict"] is True
            assert by_id["M1_CONFLICT"]["m3_redteam_verdict"] == "unreviewed"

            # Mindset 3 synthesis & ranking
            from oracle_mindsets import build_seam_sets

            seam_sets = build_seam_sets(
                ["mitre", "paradox", "seam"],
                candidates,
                {"cloud-mitre": "seams", "cloud-paradox": "seams", "seam": "seams"},
            )
            ranked = synthesize_seams(seam_sets, redteam_verdicts=m3_verdicts)
            # Top-ranked cards must be the 3-lens corroborated confirmed cards
            assert ranked[0]["m3_seam_state"] == "corroborated"
            assert ranked[0]["redteam_verdict"] == "confirmed"

            # Live 5-Gate Wire Verifier execution across HTTP candidates
            wire_confirmed = []
            confirmed_list = []
            for s in ranked:
                check = str(s.get("check") or "")
                if not check.startswith("curl"):
                    continue
                rc, out, err = oh._run_check(check)
                if "[BLOCKED]" in err:
                    continue
                status = extract_status_from_curl_output(out)
                url = check.split("'")[-2] if "'" in check else check
                v = verify_seam_card(s, [url], status=status, body=out)
                if v["verdict"] == "CONFIRMED":
                    path = urlsplit(url).path
                    wire_confirmed.append((s.get("mindset"), path))
                    confirmed_list.append({"seam": s, "output": out[:200]})

            confirmed_paths = {p for _, p in wire_confirmed}
            # True vulnerabilities confirm on the wire across all 3 mindsets:
            assert ("mitre", "/api/v1/admin/metrics") in wire_confirmed
            assert ("paradox", "/api/v1/admin/metrics") in wire_confirmed
            assert ("seam", "/api/v1/admin/metrics") in wire_confirmed
            assert "/api/v1/admin/metrics" in confirmed_paths
            assert "/api/internal/secrets" in confirmed_paths
            assert "/debug/config" in confirmed_paths
            assert "/.env" in confirmed_paths
            # Conflicted / benign / guarded paths NEVER confirm on the wire:
            assert "/api/v1/secrets" not in confirmed_paths
            assert "/health" not in confirmed_paths

            # Compound exploit chaining over confirmed seams
            chains = [
                c for c in mitre_ctx.chain_seams(confirmed_list) if c.get("type") == "chain"
            ]
            assert len(chains) >= 1, "Expected compound exploit chains from confirmed seams"

            # ── Scenario G: PoC Teardown, Workspace Persistence & Report Generation ──
            from oracle_mindset_context import ProgramWorkspace

            td_res = oh.teardown_poc(
                by_id["M1_ADMIN"],
                by_id["M1_ADMIN"]["check"],
                recon_urls=[f"{BASE}/api/v1/admin/metrics"],
                gate=scope_gate,
            )
            assert td_res["verdict"] == "PASS", td_res
            assert td_res["broke_proof"] is False

            ws = ProgramWorkspace(prog, base=base_dir / "targets")
            prog_json = ws.save_program_json()
            brief_md = ws.save_program_brief(mitre_ctx)
            assert prog_json.exists() and brief_md.exists()

            for item in confirmed_list:
                f_path = ws.save_finding(
                    {**item["seam"], "verify_verdict": "CONFIRMED"},
                    evidence=item["output"],
                )
                assert f_path.exists()

            chain_report = oh._format_chain_report(chains[0], prog["name"])
            saved_report = ws.save_report(chain_report, label="compound_chain_TOP")
            assert saved_report.exists()
            assert "Finding" in chain_report
    finally:
        if started is not None:
            started.terminate()
            try:
                started.wait(timeout=3)
            except Exception:
                started.kill()


if __name__ == "__main__":
    test_full_scenario_gauntlet()
    print("FULL SCENARIO GAUNTLET (SHIT CODE + 3 MINDSETS + RED TEAM + WIRE VERIFY): PASS")
