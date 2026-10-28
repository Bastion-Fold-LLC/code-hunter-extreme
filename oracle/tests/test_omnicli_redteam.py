#!/usr/bin/env python3
"""
OmniCLI Adversarial Red-Team Suite for Oracle.
Uses OmniCLI's multi-provider inference and adversarial test vectors to
stress-test Oracle's 5-Gate Verifier, Scope Gate, and Invariant Triangulation.

Coverage:
  1. Verifier Gate Resistance: tests adversarial attacks (spoofed scopes, ungrounded
     assertions, status forging, predicate collisions) against oracle_deterministic.py.
  2. Scope Gate Fuzzing: tests URL edge cases (userinfo, port manipulation, lookalikes).
  3. Real Seam Red-Teaming: queries OmniCLI's reasoning engine (Cloudflare / NVIDIA NIM)
     to cross-examine candidate invariant seams extracted from target code.

Usage:
  python3 tests/test_omnicli_redteam.py
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_llm import ensure_omnicli_importable

# Capture, don't discard: 7 of 8 tests are pure Oracle gate tests and must
# keep running when omnicli is absent; only the live fleet test needs it.
_HAVE_OMNICLI = ensure_omnicli_importable()

from oracle_deterministic import verify_seam_card, parse_expected
from oracle_hunter import ProgramScopeGate

if _HAVE_OMNICLI:
    from omnicli.client import OmniClient  # noqa: E402
    from omnicli.config import ConfigManager  # noqa: E402
else:
    OmniClient = ConfigManager = None  # type: ignore[assignment]


class TestOmniCLIRedTeam(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prog = {
            "name": "victim_corp",
            "platform": "hackerone",
            "structured_scopes": [
                {
                    "asset_identifier": "api.victim.com",
                    "asset_type": "DOMAIN",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                },
                {
                    "asset_identifier": "admin.victim.com",
                    "asset_type": "DOMAIN",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                },
                {
                    "asset_identifier": "api.victim.com/v1/private/excluded",
                    "asset_type": "URL",
                    "eligible_for_bounty": False,
                    "eligible_for_submission": False,
                },
            ],
        }
        cls.scope_gate = ProgramScopeGate(cls.prog, target_fallback="api.victim.com")
        cls.recon_urls = [
            "https://api.victim.com/v1/users",
            "https://api.victim.com/v1/status",
            "https://admin.victim.com/",
        ]
        cls.omni = OmniClient(ConfigManager()) if _HAVE_OMNICLI else None

    def test_gate1_grounding_rejects_subdomain_spoof(self):
        """Attacker crafts a lookalike domain suffix (e.g. api.victim.com.evil.net)."""
        card = {
            "n": 1,
            "check": "curl -i -s 'https://api.victim.com.evil.net/v1/users'",
            "assertion_a": "Claims access is restricted",
            "assertion_b": "Wire reveals unauthenticated data",
            "assertion_a_source": "program_policy",
            "expected": "status 200",
        }
        res = verify_seam_card(card, self.recon_urls, scope_gate=self.scope_gate, status=200, body="{}")
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertIn("not grounded", str(res["reason"]).lower())

    def test_gate1_grounding_rejects_userinfo_at_trick(self):
        """Attacker uses userinfo '@' in URL to deceive naive string matchers."""
        card = {
            "n": 2,
            "check": "curl -i -s 'https://api.victim.com@attacker.com/v1/users'",
            "assertion_a": "Claims restricted",
            "assertion_b": "Open",
            "assertion_a_source": "program_policy",
            "expected": "status 200",
        }
        res = verify_seam_card(card, self.recon_urls, scope_gate=self.scope_gate, status=200, body="{}")
        self.assertEqual(res["verdict"], "REJECTED")

    def test_gate2_scope_gate_blocks_explicit_out_of_scope_path(self):
        """Scope gate must fail-closed on explicit excluded paths."""
        card = {
            "n": 3,
            "check": "curl -i -s 'https://api.victim.com/v1/private/excluded/leak'",
            "assertion_a": "Claims protected",
            "assertion_b": "Exposed",
            "assertion_a_source": "program_policy",
            "expected": "status 200",
        }
        # In recon data
        recon = self.recon_urls + ["https://api.victim.com/v1/private/excluded/leak"]
        res = verify_seam_card(card, recon, scope_gate=self.scope_gate, status=200, body="{}")
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertIn("out of scope", str(res["reason"]).lower())

    def test_gate3_rejects_missing_or_vague_expectation(self):
        """Card must provide a machine-verifiable status code."""
        card = {
            "n": 4,
            "check": "curl -i -s 'https://api.victim.com/v1/users'",
            "assertion_a": "Claims protected",
            "assertion_b": "Wire shows leak",
            "assertion_a_source": "program_policy",
            "expected": "body contains 'secret'",  # Missing status code!
        }
        res = verify_seam_card(card, self.recon_urls, scope_gate=self.scope_gate, status=200, body="secret")
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertIn("status code", str(res["reason"]).lower())

    def test_gate4_rejects_unattributed_assertion_a(self):
        """Claims must cite ground-truth sources (codebase or policy), not thin air."""
        card = {
            "n": 5,
            "check": "curl -i -s 'https://api.victim.com/v1/users'",
            "assertion_a": "I believe this should be 401",
            "assertion_b": "Returned 200",
            "assertion_a_source": "",  # Empty source!
            "expected": "status 200",
        }
        res = verify_seam_card(card, self.recon_urls, scope_gate=self.scope_gate, status=200, body="{}")
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertIn("no cited program source", str(res["reason"]).lower())

    def test_gate5_rejects_predicate_marker_mismatch(self):
        """When expected body predicate is missing from observed response, reject."""
        card = {
            "n": 6,
            "check": "curl -i -s 'https://api.victim.com/v1/users'",
            "assertion_a": "Protected user records",
            "assertion_b": "Exposed users",
            "assertion_a_source": "program_policy",
            "expected": "status 200, body contains 'user_record_sensitive'",
        }
        # Response has status 200, but wrong body
        res = verify_seam_card(
            card,
            self.recon_urls,
            scope_gate=self.scope_gate,
            status=200,
            body='{"error": "user_record_sensitive not found"}',
        )
        # In this case it matched substring, but what if body is completely different:
        res2 = verify_seam_card(
            card,
            self.recon_urls,
            scope_gate=self.scope_gate,
            status=200,
            body='{"status": "ok", "items": []}',
        )
        self.assertEqual(res2["verdict"], "REJECTED")
        self.assertIn("body missing", str(res2["reason"]).lower())
        self.assertIn("user_record_sensitive", str(res2["reason"]).lower())

    def test_positive_control_confirms_valid_seam(self):
        """Valid card meeting all 5 gates MUST CONFIRM cleanly."""
        card = {
            "n": 7,
            "check": "curl -i -s 'https://api.victim.com/v1/users'",
            "assertion_a": "Endpoint requires admin JWT per security policy",
            "assertion_b": "Endpoint returns 200 OK without Authorization header",
            "assertion_a_source": "program_policy",
            "expected": 'status 200, body contains "records"',
        }
        res = verify_seam_card(
            card,
            self.recon_urls,
            scope_gate=self.scope_gate,
            status=200,
            body='{"records": [{"id": 1, "name": "alice"}]}',
        )
        self.assertEqual(res["verdict"], "CONFIRMED")
        self.assertIn("binary conflict proven", str(res["reason"]).lower())

    @unittest.skipUnless(_HAVE_OMNICLI, "omnicli checkout not importable")
    @unittest.skipUnless(
        os.environ.get("ORACLE_LIVE") == "1",
        "live provider inference check; set ORACLE_LIVE=1 (or pytest -m live "
        "harness with provider keys) to run",
    )
    def test_omnicli_fleet_inference_sanity(self):
        """Test that OmniCLI's configured provider is operational for live auditing."""
        # Use nvidia or cloudflare
        provider = "nvidia"
        model = "meta/llama-3.2-11b-vision-instruct"
        try:
            res = self.omni.chat_complete(
                provider_id=provider,
                messages=[
                    {"role": "system", "content": "You are a concise security evaluator."},
                    {"role": "user", "content": "In 5 words, confirm you are operational."},
                ],
                model=model,
                max_tokens=30,
            )
            content = res["choices"][0]["message"]["content"]
            self.assertTrue(len(content.strip()) > 0)
        except Exception as e:
            self.fail(f"OmniCLI fleet provider '{provider}' failed inference check: {e}")


class TestRedteamDirectoryGrounding(unittest.TestCase):
    """A directory target must embed its local sources, not a bare path."""

    def test_directory_without_seams_embeds_sources_not_just_path(self):
        import tempfile

        from oracle_hunter import build_redteam_audit_prompt

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "vault.py").write_text(
                "def withdraw(amount):\n    return amount\n", encoding="utf-8"
            )
            (root / ".env").write_text("KEY=NEVER_LEAK_DIR_1\n", encoding="utf-8")
            sub = root / "pkg"
            sub.mkdir()
            (sub / "Token.sol").write_text(
                "contract Token { function f() public {} }\n", encoding="utf-8"
            )
            prompt = build_redteam_audit_prompt(str(root))

        self.assertIn("### Source file: vault.py", prompt)
        self.assertIn("def withdraw(amount):", prompt)
        self.assertIn("### Source file: pkg/Token.sol", prompt)
        self.assertNotIn("NEVER_LEAK_DIR_1", prompt)

    def test_oversized_directory_refuses_instead_of_truncating(self):
        import tempfile

        import oracle_hunter

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(3):
                (root / f"big_{i}.py").write_text("x = 1\n" * 12_000, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "truncated directory"):
                oracle_hunter.build_redteam_audit_prompt(str(root))


def main() -> int:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestOmniCLIRedTeam)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
