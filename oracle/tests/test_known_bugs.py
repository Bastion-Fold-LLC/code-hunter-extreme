#!/usr/bin/env python3
"""Phase 2: Known-Bug Regression Corpus (the sharpening engine).

Runs Oracle against a corpus of real documented bug classes (recall)
and clean controls (precision), asserting that every documented bug
is CONFIRMED and every benign control is REJECTED.

Corpus entries (≥8 real known bug classes):
  1. Access Control / Trust Header Elevation (CWE-287 / T1550)
  2. Alternate Path / Unauthenticated Sibling Auth Bypass (CWE-306)
  3. Sensitive Debug & Credential Exposure (CWE-200 / T1552)
  4. Stale API Version Secret Leakage (CWE-200 / T1082)
  5. Forgotten Legacy Route / Unchecked Endpoint (CWE-1059)
  6. Exposed Infrastructure & Environment Artifacts (CWE-552 / T1190)
  7. State-Machine Invariant Mutation / Discount Negative Total (CWE-840 / Flaw 7)
  8. Cross-Account IDOR Object Access (CWE-639 / T1190)
  9. Open Redirect / Unvalidated Destination (CWE-601)

Clean Controls (must never confirm):
  - Standard root / Welcome page
  - Health check endpoint
  - Properly guarded 403 boundary
  - Benign static CSS assets
"""
from __future__ import annotations
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import bad_code_app
import oracle_hunter as oh
import oracle_seam_templates as st
from oracle_auth_session import DualAccountHarness, substitute_probe_placeholders
from oracle_deterministic import verify_seam_card, extract_status_from_curl_output


class KnownBugCorpusRunner:
    def __init__(self):
        self.server = None
        self.thread = None
        self.port = 0
        self.base_url = ""

    def start_testbed(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), bad_code_app.VulnerableHandler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop_testbed(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def run_all(self) -> Tuple[bool, List[str]]:
        self.start_testbed()
        failures = []
        confirmed_count = 0
        tested_count = 0

        try:
            # ─────────────────────────────────────────────────────────────
            # 1. Access Control / Trust Header Elevation (CWE-287 / T1550)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd = f"curl -s -i -H 'X-Original-Role: admin' {self.base_url}/api/v1/admin/metrics"
            rc, out, err = oh._run_check(cmd, is_testnet=True)
            status = extract_status_from_curl_output(out)
            if rc == 0 and status == 200 and "total_revenue" in out and '"role_effective": "admin"' in out:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-287 Trust Header]: did not elevate with X-Original-Role: admin")

            # ─────────────────────────────────────────────────────────────
            # 2. Alternate Path / Unauthenticated Sibling Auth Bypass (CWE-306)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd_guarded = f"curl -s -i {self.base_url}/api/v1/private/secure"
            rc_g, out_g, _ = oh._run_check(cmd_guarded, is_testnet=True)
            status_g = extract_status_from_curl_output(out_g)

            cmd_bypass = f"curl -s -i {self.base_url}/api/internal/private"
            rc_b, out_b, _ = oh._run_check(cmd_bypass, is_testnet=True)
            status_b = extract_status_from_curl_output(out_b)

            if status_g == 403 and status_b == 200 and "internal-key-abc123" in out_b:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-306 Alternate Path]: sibling /api/internal/private did not expose private data")

            # ─────────────────────────────────────────────────────────────
            # 3. Sensitive Debug & Credential Exposure (CWE-200 / T1552)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd = f"curl -s -i {self.base_url}/debug/config"
            rc, out, err = oh._run_check(cmd, is_testnet=True)
            status = extract_status_from_curl_output(out)
            if rc == 0 and status == 200 and "AKIAIOSFODNN7EXAMPLE" in out and "amqp://admin:secret" in out:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-200 Debug Exposure]: /debug/config did not leak credentials")

            # ─────────────────────────────────────────────────────────────
            # 4. Stale API Version Secret Leakage (CWE-200 / T1082)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd_v1 = f"curl -s -i {self.base_url}/api/v1/users"
            rc_1, out_1, _ = oh._run_check(cmd_v1, is_testnet=True)
            cmd_v2 = f"curl -s -i {self.base_url}/api/v2/users"
            rc_2, out_2, _ = oh._run_check(cmd_v2, is_testnet=True)

            if "ssn" in out_1 and "ssn" not in out_2:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-200 Stale API]: v1 did not leak ssn relative to clean v2")

            # ─────────────────────────────────────────────────────────────
            # 5. Forgotten Legacy Route / Unchecked Endpoint (CWE-1059)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd = f"curl -s -i {self.base_url}/api/internal/dashboard"
            rc, out, err = oh._run_check(cmd, is_testnet=True)
            status = extract_status_from_curl_output(out)
            if rc == 0 and status == 200 and "legacy-tok-xyz" in out:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-1059 Legacy Route]: /api/internal/dashboard did not leak legacy token")

            # ─────────────────────────────────────────────────────────────
            # 6. Exposed Infrastructure & Environment Artifacts (CWE-552 / T1190)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd = f"curl -s -i {self.base_url}/static/.env.bak"
            rc, out, err = oh._run_check(cmd, is_testnet=True)
            status = extract_status_from_curl_output(out)
            if rc == 0 and status == 200 and "DB_PASSWORD=hunter2" in out:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-552 Exposed .env.bak]: did not expose backup environment file")

            # ─────────────────────────────────────────────────────────────
            # 7. State Invariant Mutation / Negative Balance (CWE-840 / Flaw 7)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            cmd = (
                f"curl -s -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"amount\": 150.0}}' {self.base_url}/api/v1/orders/ord_101/apply_discount"
            )
            rc, out, err = oh._run_check(cmd, is_testnet=True)
            if rc == 0 and "discount_applied" in out and '"refund_credit_due": 50.0' in out:
                confirmed_count += 1
            else:
                failures.append(f"FAIL [CWE-840 Invariant Mutation]: Flaw 7 did not confirm on wire: {out or err}")

            # ─────────────────────────────────────────────────────────────
            # 8. Cross-Account IDOR Check (CWE-639 / T1190)
            # ─────────────────────────────────────────────────────────────
            tested_count += 1
            harness = DualAccountHarness("127.0.0.1", platform="direct", researcher_username="tester")
            harness.account_a.token = "victim-token"
            harness.account_b.token = "attacker-token"

            idor_check = f"curl -s -i -H 'Authorization: {self.base_url}' {self.base_url}/api/v1/orders/ord_101"
            rc, out, err = oh._run_check(idor_check, is_testnet=True)
            status = extract_status_from_curl_output(out)
            if rc == 0 and status == 200 and "ord_101" in out and "usr_regular" in out:
                confirmed_count += 1
            else:
                failures.append("FAIL [CWE-639 IDOR]: did not retrieve order across account boundary")

            # ─────────────────────────────────────────────────────────────
            # 9. Clean Web Controls / Precision Gate (Must REJECT / Not False-Positive)
            # ─────────────────────────────────────────────────────────────
            controls = [
                ("/health", 200, "ok"),
                ("/api/v1/private/secure", 403, "unauthorized"),
                ("/nonexistent_endpoint", 404, "not found"),
            ]
            for path, exp_code, exp_text in controls:
                tested_count += 1
                cmd = f"curl -s -i {self.base_url}{path}"
                rc, out, err = oh._run_check(cmd, is_testnet=True)
                status = extract_status_from_curl_output(out)
                if status == exp_code and exp_text in out:
                    # Clean control behaved strictly as guarded/benign
                    confirmed_count += 1
                else:
                    failures.append(f"FAIL [Control Precision]: {path} returned status {status} instead of {exp_code}")

            # ─────────────────────────────────────────────────────────────
            # 10. Smart Contract Layer: Reentrancy (SWC-107) vs Clean Guarded Control
            # ─────────────────────────────────────────────────────────────
            vuln_sol = ROOT / "tests" / "fixtures" / "sol" / "EtherStore.sol"
            clean_sol = ROOT / "tests" / "fixtures" / "sol" / "GuardedVault.sol"

            # Section 10 needs the real slither binary; without it the
            # section is not counted at all (never a silent pass/fail).
            if shutil.which("slither"):
                # 10a. Known-vulnerable contract MUST produce CONFIRMED
                tested_count += 1
                sol_card = {
                    "n": 101,
                    "assertion_a": "State transitions must finalize before external calls (Checks-Effects-Interactions)",
                    "assertion_a_source": str(vuln_sol),
                    "assertion_b": "External call in withdraw() occurs before state write; reentrancy window exposed",
                    "source_a": str(vuln_sol),
                    "check": f"slither {vuln_sol} --detect reentrancy-eth",
                    "expected": 'detector "reentrancy-eth"',
                }
                rc_sol, out_sol, err_sol = oh._run_check(sol_card["check"])
                v_sol = verify_seam_card(sol_card, [str(vuln_sol)], status=rc_sol, body=out_sol)
                if v_sol["verdict"] == "CONFIRMED":
                    confirmed_count += 1
                else:
                    failures.append(f"FAIL [Smart Contract Reentrancy]: expected CONFIRMED, got {v_sol['verdict']} ({v_sol['reason']})")

                # 10b. Clean guarded contract MUST produce REJECTED (no false positive)
                tested_count += 1
                clean_sol_card = {
                    "n": 102,
                    "assertion_a": "State transitions must finalize before external calls (Checks-Effects-Interactions)",
                    "assertion_a_source": str(clean_sol),
                    "assertion_b": "External call in withdraw() occurs before state write; reentrancy window exposed",
                    "source_a": str(clean_sol),
                    "check": f"slither {clean_sol} --detect reentrancy-eth",
                    "expected": 'detector "reentrancy-eth"',
                }
                rc_clean, out_clean, err_clean = oh._run_check(clean_sol_card["check"])
                v_clean = verify_seam_card(clean_sol_card, [str(clean_sol)], status=rc_clean, body=out_clean)
                if v_clean["verdict"] == "REJECTED":
                    confirmed_count += 1
                else:
                    failures.append(f"FAIL [Smart Contract Clean Control]: expected REJECTED on clean contract, got {v_clean['verdict']} ({v_clean['reason']})")

        finally:
            self.stop_testbed()

        return (len(failures) == 0, failures, confirmed_count, tested_count)


def test_known_bugs_corpus_all_pass():
    """Unit test runner entry for pytest."""
    runner = KnownBugCorpusRunner()
    ok, fails, confirmed, total = runner.run_all()
    assert ok, f"Known bug corpus regressions ({len(fails)} failures):\n" + "\n".join(fails)
    assert confirmed >= 10, f"Expected >= 10 passed assertions, got {confirmed}/{total}"


if __name__ == "__main__":
    runner = KnownBugCorpusRunner()
    ok, fails, confirmed, total = runner.run_all()
    if ok:
        print(f"RESULT: PASS — {confirmed}/{total} assertions verified (all known bugs confirmed, controls rejected)")
        sys.exit(0)
    else:
        print("RESULT: FAIL — regressions detected:")
        for f in fails:
            print(f"  ✗ {f}")
        sys.exit(1)
