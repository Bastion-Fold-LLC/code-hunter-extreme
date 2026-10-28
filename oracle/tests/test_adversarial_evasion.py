#!/usr/bin/env python3
"""
Adversarial Evasion Corpus Test.

Tests whether Oracle can distinguish between:
- REAL exploits (should CONFIRM)
- Checks that LOOK like exploits but AREN'T (should REJECT)

This catches systems that pattern-match on exploit-like strings
without understanding the actual vulnerability logic.

Categories:
1. Auth bypass mimics (header present but wrong value)
2. SQLi mimics (payload in wrong parameter/context)
3. Path traversal mimics (encoded but normalized)
4. IDOR mimics (accessing own resource)
5. XSS mimics (payload in non-reflected context)
6. SSRF mimics (internal IP but not reachable)
7. Deserialization mimics (data not actually deserialized)
8. XXE mimics (XML but parser has XXE disabled)
"""

from __future__ import annotations
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh
from oracle_deterministic import verify_seam_card, extract_status_from_curl_output
from oracle_hunter import ProgramScopeGate
from oracle_mindsets import redteam_challenge_by_lens, seam_candidate_key


class EvasionCheck:
    """A check that mimics an exploit but shouldn't work."""
    def __init__(
        self,
        name: str,
        category: str,
        check_cmd: str,
        description: str,
        why_it_fails: str,
    ):
        self.name = name
        self.category = category
        self.check_cmd = check_cmd
        self.description = description
        self.why_it_fails = why_it_fails


def build_evasion_corpus(base_url: str) -> List[EvasionCheck]:
    """Build the adversarial evasion corpus."""
    return [
        # ─── Auth Bypass Mimics ───
        EvasionCheck(
            name="auth_bypass_wrong_header_value",
            category="auth_bypass",
            check_cmd=f"curl -s -i -H 'X-Original-Role: superadmin' {base_url}/api/v1/admin/metrics",
            description="Header name matches but value is not 'admin'",
            why_it_fails="Server only checks for exact 'admin' value",
        ),
        EvasionCheck(
            name="auth_bypass_wrong_header_name",
            category="auth_bypass",
            check_cmd=f"curl -s -i -H 'X-Role: admin' {base_url}/api/v1/admin/metrics",
            description="Header value is admin but name is wrong",
            why_it_fails="Server only reads X-Original-Role header",
        ),
        EvasionCheck(
            name="auth_bypass_case_sensitive",
            category="auth_bypass",
            check_cmd=f"curl -s -i -H 'X-Original-Role: Admin' {base_url}/api/v1/admin/metrics",
            description="Case mismatch on header value",
            why_it_fails="String comparison is case-sensitive",
        ),
        EvasionCheck(
            name="auth_bypass_multiple_headers",
            category="auth_bypass",
            check_cmd=f"curl -s -i -H 'X-Original-Role: user' -H 'X-Original-Role: admin' {base_url}/api/v1/admin/metrics",
            description="Multiple headers, first wins",
            why_it_fails="Server uses first header value, not last",
        ),

        # ─── SQL Injection Mimics ───
        EvasionCheck(
            name="sqli_in_user_agent",
            category="sqli",
            check_cmd=f"curl -s -i -A \"' OR '1'='1\" {base_url}/api/v1/products",
            description="SQLi payload in User-Agent header",
            why_it_fails="User-Agent not used in SQL query",
        ),
        EvasionCheck(
            name="sqli_in_referer",
            category="sqli",
            check_cmd=f"curl -s -i -e \"' OR '1'='1\" {base_url}/api/v1/products",
            description="SQLi payload in Referer header",
            why_it_fails="Referer not used in SQL query",
        ),
        EvasionCheck(
            name="sqli_wrong_parameter",
            category="sqli",
            check_cmd=f"curl -s -i '{base_url}/api/v1/search?q=test' OR '1'='1'",
            description="SQLi in query param but wrong param name",
            why_it_fails="Vulnerable param is 'id', not 'q'",
        ),
        EvasionCheck(
            name="sqli_encoded_but_decoded",
            category="sqli",
            check_cmd=f"curl -s -i '{base_url}/api/v1/users?id=1%27%20OR%20%271%27%3D%271'",
            description="URL-encoded SQLi - but server double-decodes",
            why_it_fails="Server decodes once, payload becomes literal string",
        ),
        EvasionCheck(
            name="sqli_post_body_not_query",
            category="sqli",
            check_cmd=f"curl -s -i -X POST {base_url}/api/v1/login -d \"username=admin'--&password=x\"",
            description="SQLi in POST body but vuln is in GET param",
            why_it_fails="Vulnerable endpoint only reads GET parameters",
        ),

        # ─── Path Traversal Mimics ───
        EvasionCheck(
            name="path_traversal_double_encoded",
            category="path_traversal",
            check_cmd=f"curl -s -i '{base_url}/api/v1/file?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd'",
            description="Double-encoded path traversal",
            why_it_fails="Server decodes once, gets single-encoded (safe) path",
        ),
        EvasionCheck(
            name="path_traversal_url_encoded_slash",
            category="path_traversal",
            check_cmd=f"curl -s -i '{base_url}/api/v1/file?path=..%2f..%2fetc%2fpasswd'",
            description="Forward slash encoded, backslash not",
            why_it_fails="Server normalizes path after single decode",
        ),
        EvasionCheck(
            name="path_traversal_with_null_byte",
            category="path_traversal",
            check_cmd=f"curl -s -i '{base_url}/api/v1/file?path=../../../etc/passwd%00.txt'",
            description="Null byte injection attempt",
            why_it_fails="Modern servers (Python 3+, Node.js) handle null bytes safely",
        ),
        EvasionCheck(
            name="path_traversal_windows_style",
            category="path_traversal",
            check_cmd=f"curl -s -i '{base_url}/api/v1/file?path=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'",
            description="Windows-style path on Linux server",
            why_it_fails="Server runs on Linux, backslash not path separator",
        ),

        # ─── IDOR Mimics ───
        EvasionCheck(
            name="idor_own_resource",
            category="idor",
            check_cmd=f"curl -s -i {base_url}/api/v1/users/123/profile",
            description="Accessing own user ID (123)",
            why_it_fails="This is AUTHORIZED access, not IDOR",
        ),
        EvasionCheck(
            name="idor_nonexistent_user",
            category="idor",
            check_cmd=f"curl -s -i {base_url}/api/v1/users/999999/profile",
            description="Accessing non-existent user",
            why_it_fails="Returns 404, not data leak",
        ),
        EvasionCheck(
            name="idor_different_resource_type",
            category="idor",
            check_cmd=f"curl -s -i {base_url}/api/v1/posts/123",
            description="Accessing post ID 123 (not user)",
            why_it_fails="Different resource type, different authorization",
        ),

        # ─── XSS Mimics ───
        EvasionCheck(
            name="xss_in_json_api",
            category="xss",
            check_cmd=f"curl -s -i -H 'Content-Type: application/json' -d '{{\"name\":\"<script>alert(1)</script>\"}}' {base_url}/api/v1/profile",
            description="XSS payload in JSON API",
            why_it_fails="API returns JSON, not HTML - no script execution",
        ),
        EvasionCheck(
            name="xss_in_non_reflected_param",
            category="xss",
            check_cmd=f"curl -s -i '{base_url}/api/v1/search?q=<script>alert(1)</script>'",
            description="XSS payload in search but results not reflected",
            why_it_fails="Search results returned as JSON, not rendered HTML",
        ),
        EvasionCheck(
            name="xss_encoded_output",
            category="xss",
            check_cmd=f"curl -s -i '{base_url}/api/v1/comment?text=<script>alert(1)</script>'",
            description="XSS payload but output is HTML-encoded",
            why_it_fails="Server properly encodes output",
        ),

        # ─── SSRF Mimics ───
        EvasionCheck(
            name="ssrf_localhost_blocked",
            category="ssrf",
            check_cmd=f"curl -s -i '{base_url}/api/v1/fetch?url=http://localhost:22'",
            description="SSRF to localhost SSH",
            why_it_fails="Server blocks private IP ranges",
        ),
        EvasionCheck(
            name="ssrf_metadata_blocked",
            category="ssrf",
            check_cmd=f"curl -s -i '{base_url}/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/'",
            description="SSRF to AWS metadata",
            why_it_fails="Server blocks link-local addresses",
        ),
        EvasionCheck(
            name="ssrf_dns_rebinding",
            category="ssrf",
            check_cmd=f"curl -s -i '{base_url}/api/v1/fetch?url=http://rebind.example.com'",
            description="DNS rebinding attempt",
            why_it_fails="Server validates DNS resolves to public IP",
        ),

        # ─── Deserialization Mimics ───
        EvasionCheck(
            name="deserialization_json_not_java",
            category="deserialization",
            check_cmd=f"curl -s -i -H 'Content-Type: application/json' -d '{{\"@class\":\"java.lang.Runtime\"}}' {base_url}/api/v1/import",
            description="Java deserialization payload sent to JSON endpoint",
            why_it_fails="Endpoint uses JSON parser, not Java deserializer",
        ),
        EvasionCheck(
            name="deserialization_yaml_safe_load",
            category="deserialization",
            check_cmd=f"curl -s -i -H 'Content-Type: application/yaml' -d '!!python/object/apply:os.system [\"id\"]' {base_url}/api/v1/import",
            description="YAML deserialization payload",
            why_it_fails="Server uses yaml.safe_load, not unsafe_load",
        ),

        # ─── XXE Mimics ───
        EvasionCheck(
            name="xxe_disabled_parser",
            category="xxe",
            check_cmd=f"curl -s -i -H 'Content-Type: application/xml' -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>' {base_url}/api/v1/xml",
            description="XXE payload but parser has external entities disabled",
            why_it_fails="XML parser configured with FEATURE_SECURE_PROCESSING",
        ),

        # ─── Command Injection Mimics ───
        EvasionCheck(
            name="cmd_injection_in_sanitized_param",
            category="cmd_injection",
            check_cmd=f"curl -s -i '{base_url}/api/v1/ping?host=8.8.8.8;id'",
            description="Command injection in ping parameter",
            why_it_fails="Server uses allowlist validation, not shell execution",
        ),
        EvasionCheck(
            name="cmd_injection_encoded",
            category="cmd_injection",
            check_cmd=f"curl -s -i '{base_url}/api/v1/ping?host=8.8.8.8%3Bid'",
            description="URL-encoded command injection",
            why_it_fails="Input validated before decoding",
        ),
    ]


class EvasionTestRunner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.checks = build_evasion_corpus(base_url)
        self.results = {
            "total": 0,
            "rejected": 0,
            "falsely_confirmed": 0,
            "errors": 0,
            "details": [],
        }

    def run_check(self, check: EvasionCheck) -> Tuple[bool, str, Dict]:
        """Run a single evasion check. Should be REJECTED."""
        rc, out, err = oh._run_check(check.check_cmd, is_testnet=True)
        status = extract_status_from_curl_output(out)

        # Build a seam card claiming the mimic exploit succeeded with a vulnerability marker
        seam = {
            "n": 1,
            "origin": "local-paradox",
            "mindset": "paradox",
            "assertion_a": f"Endpoint {self.base_url} enforces strict validation against {check.category}",
            "assertion_a_source": "program_page.txt:1",
            "assertion_b": f"Mimic probe {check.name} bypasses {check.category} controls on {self.base_url}",
            "check": check.check_cmd,
            "expected": '200 + "role_effective": "admin"',
        }

        # Run deterministic verification against actual wire output
        v = verify_seam_card(
            seam,
            recon_urls=[self.base_url],
            status=status,
            body=out or "",
        )

        # Also run red-team challenge
        verdicts, _counts = redteam_challenge_by_lens(
            [seam], in_scope=lambda u: u.startswith(self.base_url)
        )
        rt_verdict = verdicts.get(seam_candidate_key(seam), "rejected")

        # Evasion check PASSES if deterministic verification rejects it (verdict != "CONFIRMED")
        confirmed = v.get("verdict") == "CONFIRMED"
        evasion_rejected = not confirmed

        return evasion_rejected, str(status), {
            "verification": v,
            "redteam_verdict": rt_verdict,
            "status_code": status,
        }

    def run_all(self) -> Dict:
        """Run all evasion checks."""
        for check in self.checks:
            self.results["total"] += 1

            try:
                rejected, status, details = self.run_check(check)

                if rejected:
                    self.results["rejected"] += 1
                    self.results["details"].append({
                        "check": check.name,
                        "category": check.category,
                        "result": "REJECTED",
                        "status_code": status,
                        "why_it_fails": check.why_it_fails,
                    })
                else:
                    self.results["falsely_confirmed"] += 1
                    self.results["details"].append({
                        "check": check.name,
                        "category": check.category,
                        "result": "FALSELY_CONFIRMED",
                        "status_code": status,
                        "why_it_fails": check.why_it_fails,
                        "details": details,
                    })

            except Exception as e:
                self.results["errors"] += 1
                self.results["details"].append({
                    "check": check.name,
                    "category": check.category,
                    "result": "ERROR",
                    "error": str(e),
                })

        return self.results


def run_adversarial_evasion_suite() -> Dict:
    """Run the adversarial evasion suite and return structured results."""
    # Start testbed
    import http.server
    import threading
    import bad_code_app

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
        runner = EvasionTestRunner(base_url)
        results = runner.run_all()

        # Print summary
        print(f"\n{'='*60}")
        print("ADVERSARIAL EVASION TEST RESULTS")
        print(f"{'='*60}")
        print(f"Total checks:         {results['total']}")
        print(f"Correctly rejected:   {results['rejected']}")
        print(f"Falsely confirmed:    {results['falsely_confirmed']}")
        print(f"Errors:               {results['errors']}")

        if results["total"] > 0:
            rejection_rate = results["rejected"] / results["total"] * 100
            print(f"Rejection rate:       {rejection_rate:.1f}%")

        print(f"\nBy Category:")
        categories = {}
        for d in results["details"]:
            cat = d["category"]
            if cat not in categories:
                categories[cat] = {"rejected": 0, "falsely_confirmed": 0}
            if d["result"] == "REJECTED":
                categories[cat]["rejected"] += 1
            elif d["result"] == "FALSELY_CONFIRMED":
                categories[cat]["falsely_confirmed"] += 1

        for cat, counts in sorted(categories.items()):
            total = counts["rejected"] + counts["falsely_confirmed"]
            rate = counts["rejected"] / total * 100 if total > 0 else 0
            print(f"  {cat}: {counts['rejected']}/{total} rejected ({rate:.0f}%)")

        print(f"\nDetails:")
        for d in results["details"]:
            icon = "✓" if d["result"] == "REJECTED" else "✗" if d["result"] == "FALSELY_CONFIRMED" else "?"
            print(f"  {icon} {d['check']} :: {d['result']}")

        # Assert: rejection rate should be high (>90%)
        if results["total"] > 0:
            rejection_rate = results["rejected"] / results["total"]
            assert rejection_rate >= 0.9, \
                f"Evasion rejection rate {rejection_rate:.1%} below 90% threshold"

        # Assert: zero falsely confirmed critical evasions
        critical_falsely = [d for d in results["details"]
                           if d["result"] == "FALSELY_CONFIRMED"
                           and d["category"] in ("auth_bypass", "sqli", "path_traversal")]
        assert len(critical_falsely) == 0, \
            f"Critical evasions falsely confirmed: {[d['check'] for d in critical_falsely]}"

        return results

    finally:
        server.shutdown()
        server.server_close()


def test_adversarial_evasion():
    """Main pytest entry point."""
    results = run_adversarial_evasion_suite()
    assert results["total"] > 0
    assert results["falsely_confirmed"] == 0


if __name__ == "__main__":
    test_adversarial_evasion()
    print("\n✓ All adversarial evasion tests passed")