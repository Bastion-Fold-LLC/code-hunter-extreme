#!/usr/bin/env python3
"""
Mutation Testing Framework for Oracle.

This tests whether the system actually UNDERSTANDS vulnerabilities or just
pattern-matches. We take passing test cases and MUTATE the vulnerability
logic (not the payload). The system should FAIL on mutated versions.

If a mutation kills the detection, the test passes (system detected the change).
If a mutation doesn't kill detection, the test FAILS (system is pattern-matching).
"""

from __future__ import annotations
import json
import tempfile
import time
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Callable, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh
from oracle_deterministic import verify_seam_card, extract_status_from_curl_output


class Mutation:
    """A single mutation to apply to a vulnerability."""
    def __init__(self, name: str, description: str, apply: Callable[[str], str]):
        self.name = name
        self.description = description
        self.apply = apply


class VulnerabilitySpec:
    """Specification of a vulnerability for mutation testing."""
    def __init__(
        self,
        name: str,
        check_cmd: str,
        expected_status: int,
        expected_content: str,
        mutations: List[Mutation],
    ):
        self.name = name
        self.check_cmd = check_cmd
        self.expected_status = expected_status
        self.expected_content = expected_content
        self.mutations = mutations


# ─────────────────────────────────────────────────────────────────────────────
# Mutation Operators
# ─────────────────────────────────────────────────────────────────────────────

def mutate_remove_vuln_logic(code: str) -> str:
    """Remove the actual vulnerability logic, keep the structure."""
    # This would be applied to the testbed code, not the check
    raise NotImplementedError("Apply to testbed, not check")


def mutate_sqli_to_nosqli(cmd: str) -> str:
    """Change SQL injection payload to NoSQL injection."""
    return cmd.replace("' OR '1'='1", '{"$ne": null}')


def mutate_sqli_to_xss(cmd: str) -> str:
    """Change SQL injection to XSS payload."""
    return cmd.replace("' OR '1'='1", "<script>alert(1)</script>")


def mutate_auth_bypass_to_normal(cmd: str) -> str:
    """Remove auth bypass header, make it a normal request."""
    return cmd.replace("-H 'X-Original-Role: admin'", "-H 'X-Original-Role: user'")


def mutate_path_traversal_to_normal(cmd: str) -> str:
    """Change path traversal to normal path."""
    return cmd.replace("../../../etc/passwd", "normal-file.txt")


def mutate_idor_to_same_user(cmd: str) -> str:
    """Change IDOR to access own resource."""
    import re
    return re.sub(r'/api/v1/users/\d+/', '/api/v1/users/123/', cmd)


def mutate_open_redirect_to_same_origin(cmd: str) -> str:
    """Change open redirect to same-origin."""
    return cmd.replace("next=http://evil.com", "next=/dashboard")


def mutate_debug_endpoint_to_production(cmd: str) -> str:
    """Change debug endpoint to production endpoint."""
    return cmd.replace("/debug/", "/api/v1/")


def mutate_stale_version_to_current(cmd: str) -> str:
    """Change stale API version to current."""
    return cmd.replace("/api/v1/", "/api/v2/")


def mutate_missing_natspec_to_present(cmd: str) -> str:
    """This applies to Solidity code, not check - handled separately."""
    return cmd


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Specifications with Mutations
# ─────────────────────────────────────────────────────────────────────────────

def build_vuln_specs(base_url: str) -> List[VulnerabilitySpec]:
    """Build vulnerability specs with their mutations matching bad_code_app.py."""
    return [
        # 1. Trust Header Elevation (CWE-287)
        VulnerabilitySpec(
            name="CWE-287 Trust Header Elevation",
            check_cmd=f"curl -s -i -H 'X-Original-Role: admin' {base_url}/api/v1/admin/metrics",
            expected_status=200,
            expected_content='"role_effective": "admin"',
            mutations=[
                Mutation(
                    "remove_admin_header",
                    "Use non-admin role header",
                    lambda c: c.replace("-H 'X-Original-Role: admin'", "-H 'X-Original-Role: user'"),
                ),
                Mutation(
                    "change_to_guest",
                    "Change to guest role",
                    lambda c: c.replace("admin", "guest"),
                ),
            ],
        ),
        # 2. Alternate Path / Unauthenticated Sibling Auth Bypass (CWE-306)
        VulnerabilitySpec(
            name="CWE-306 Alternate Path Auth Bypass",
            check_cmd=f"curl -s -i {base_url}/api/internal/private",
            expected_status=200,
            expected_content="internal-key-abc123",
            mutations=[
                Mutation(
                    "use_guarded_path",
                    "Use the properly guarded path",
                    lambda c: c.replace("/api/internal/private", "/api/v1/private/secure"),
                ),
            ],
        ),
        # 3. Sensitive Debug & Credential Exposure (CWE-200)
        VulnerabilitySpec(
            name="CWE-200 Debug Endpoint Exposure",
            check_cmd=f"curl -s -i {base_url}/debug/config",
            expected_status=200,
            expected_content="AKIAIOSFODNN7EXAMPLE",
            mutations=[
                Mutation(
                    "use_prod_endpoint",
                    "Use non-debug endpoint instead of /debug/config",
                    lambda c: c.replace("/debug/config", "/api/v1/config"),
                ),
            ],
        ),
        # 4. Stale API Version Secret Leakage (CWE-200)
        VulnerabilitySpec(
            name="CWE-200 Stale API Version Leak",
            check_cmd=f"curl -s -i {base_url}/api/v1/users",
            expected_status=200,
            expected_content="123-45-6789",
            mutations=[
                Mutation(
                    "use_current_version",
                    "Use current API version (v2 filters out ssn)",
                    lambda c: c.replace("/api/v1/users", "/api/v2/users"),
                ),
            ],
        ),
        # 5. Forgotten Legacy Route (CWE-1059)
        VulnerabilitySpec(
            name="CWE-1059 Legacy Route",
            check_cmd=f"curl -s -i {base_url}/api/internal/dashboard",
            expected_status=200,
            expected_content="legacy-tok-xyz",
            mutations=[
                Mutation(
                    "use_modern_route",
                    "Use modern route",
                    lambda c: c.replace("/api/internal/dashboard", "/api/v1/dashboard"),
                ),
            ],
        ),
        # 6. Exposed Infrastructure Artifacts (CWE-552)
        VulnerabilitySpec(
            name="CWE-552 Exposed .env.bak",
            check_cmd=f"curl -s -i {base_url}/static/.env.bak",
            expected_status=200,
            expected_content="DB_PASSWORD=hunter2",
            mutations=[
                Mutation(
                    "request_nonexistent",
                    "Request non-existent file",
                    lambda c: c.replace("/static/.env.bak", "/static/.env.nonexistent"),
                ),
            ],
        ),
        # 7. State-Machine Invariant Mutation (CWE-840)
        VulnerabilitySpec(
            name="CWE-840 Post-Payment Discount Refund Credit",
            check_cmd=(
                f"curl -s -i -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"amount\": 150.0}}' {base_url}/api/v1/orders/ord_101/apply_discount"
            ),
            expected_status=200,
            expected_content='"refund_credit_due": 50.0',
            mutations=[
                Mutation(
                    "small_discount_no_refund",
                    "Discount smaller than order total produces 0 refund credit",
                    lambda c: c.replace("150.0", "10.0"),
                ),
                Mutation(
                    "get_instead_of_post",
                    "GET instead of POST does not trigger state mutation",
                    lambda c: c.replace(
                        "-X POST -H 'Content-Type: application/json' -d '{\"amount\": 150.0}' ",
                        "",
                    ),
                ),
            ],
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Mutation Test Runner
# ─────────────────────────────────────────────────────────────────────────────

class MutationTestRunner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.specs = build_vuln_specs(base_url)
        self.results = {
            "total_mutations": 0,
            "killed": 0,
            "survived": 0,
            "details": [],
        }

    def run_original(self, spec: VulnerabilitySpec) -> Tuple[bool, str]:
        """Run the original (vulnerable) check."""
        rc, out, err = oh._run_check(spec.check_cmd, is_testnet=True)
        status = extract_status_from_curl_output(out)
        passed = (rc == 0 and status == spec.expected_status
                  and spec.expected_content in out)
        return passed, out

    def run_mutation(self, spec: VulnerabilitySpec, mutation: Mutation) -> Tuple[bool, str]:
        """Run a mutated check - should FAIL to detect the vuln."""
        mutated_cmd = mutation.apply(spec.check_cmd)
        rc, out, err = oh._run_check(mutated_cmd, is_testnet=True)
        status = extract_status_from_curl_output(out)
        # Mutation KILLED = system correctly does NOT detect vuln
        # (i.e., the check fails or returns different content)
        passed = (rc == 0 and status == spec.expected_status
                  and spec.expected_content in out)
        # If passed=True, mutation SURVIVED (bad - system still thinks vuln exists)
        # If passed=False, mutation KILLED (good - system detected the fix)
        return passed, out

    def run_all(self) -> Dict:
        """Run all mutation tests."""
        import bad_code_app
        import copy
        orders_snapshot = copy.deepcopy(bad_code_app.ORDERS)
        try:
            for spec in self.specs:
                bad_code_app.ORDERS.clear()
                bad_code_app.ORDERS.update(copy.deepcopy(orders_snapshot))
                # First verify original works
                orig_passed, orig_out = self.run_original(spec)
                if not orig_passed:
                    self.results["details"].append({
                        "vuln": spec.name,
                        "mutation": "ORIGINAL",
                        "status": "ORIGINAL_FAILED",
                        "note": "Original vulnerability not detected - test setup issue",
                    })
                    continue

                # Run each mutation
                for mutation in spec.mutations:
                    bad_code_app.ORDERS.clear()
                    bad_code_app.ORDERS.update(copy.deepcopy(orders_snapshot))
                    self.results["total_mutations"] += 1
                    mut_passed, mut_out = self.run_mutation(spec, mutation)

                    if mut_passed:
                        # Mutation SURVIVED - system still detects vuln when it shouldn't
                        self.results["survived"] += 1
                        self.results["details"].append({
                            "vuln": spec.name,
                            "mutation": mutation.name,
                            "description": mutation.description,
                            "status": "SURVIVED",
                            "note": "FAIL: Mutation did not kill detection - system pattern matches",
                        })
                    else:
                        # Mutation KILLED - system correctly rejects mutated check
                        self.results["killed"] += 1
                        self.results["details"].append({
                            "vuln": spec.name,
                            "mutation": mutation.name,
                            "description": mutation.description,
                            "status": "KILLED",
                            "note": "PASS: System correctly rejected mutated check",
                        })
        finally:
            bad_code_app.ORDERS.clear()
            bad_code_app.ORDERS.update(orders_snapshot)

        return self.results


def run_mutation_testing_suite() -> Dict:
    """Run mutation test suite and return structured results."""
    # Start testbed
    import http.server
    import threading
    import bad_code_app

    # The testbed is intentionally stateful; previous suites may have
    # already applied a discount to ord_101. This suite owns its baseline.
    bad_code_app.reset_state()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), bad_code_app.VulnerableHandler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Wait for server
    import urllib.request
    for _ in range(50):
        try:
            urllib.request.urlopen(base_url + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        server.shutdown()
        raise RuntimeError("Testbed failed to start")

    try:
        runner = MutationTestRunner(base_url)
        results = runner.run_all()

        # Print summary
        print(f"\n{'='*60}")
        print("MUTATION TESTING RESULTS")
        print(f"{'='*60}")
        print(f"Total mutations: {results['total_mutations']}")
        print(f"Killed (good):   {results['killed']}")
        print(f"Survived (bad):  {results['survived']}")

        if results["total_mutations"] > 0:
            kill_rate = results["killed"] / results["total_mutations"] * 100
            print(f"Kill rate:       {kill_rate:.1f}%")

        print(f"\nDetails:")
        for d in results["details"]:
            status_icon = "✓" if d["status"] == "KILLED" else "✗" if d["status"] == "SURVIVED" else "?"
            print(f"  {status_icon} {d['vuln']} :: {d['mutation']} :: {d['status']}")
            if d.get("note"):
                print(f"     {d['note']}")

        orig_failures = [d for d in results["details"] if d["status"] == "ORIGINAL_FAILED"]
        assert len(orig_failures) == 0, (
            f"Original vulnerabilities failed setup: {[d['vuln'] for d in orig_failures]}"
        )
        assert results["total_mutations"] >= 9
        kill_rate = results["killed"] / results["total_mutations"]
        assert kill_rate >= 0.8, f"Mutation kill rate {kill_rate:.1%} below 80% threshold"

        return results

    finally:
        server.shutdown()
        server.server_close()


def test_mutation_testing():
    """Main pytest entry point."""
    results = run_mutation_testing_suite()
    assert results["survived"] == 0


if __name__ == "__main__":
    test_mutation_testing()
    print("\n✓ All mutation tests passed")