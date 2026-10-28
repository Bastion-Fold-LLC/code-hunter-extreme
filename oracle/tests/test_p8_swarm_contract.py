#!/usr/bin/env python3
"""
P8 Oracle-OmniCLI contract tests — swarm member shapes and red-team source gate.

All tests are offline / no live API calls:
  - members fallback: stubs run_orchestration with list- and dict-shaped members
  - red-team prompt: builds the Oracle audit prompt over tmp fixtures and checks
    the OmniCLI source-block gate plus a FakeClient red-team run (no early-FAIL)

    python3 -m pytest tests/test_p8_swarm_contract.py -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_llm
from oracle_llm import BackendError, OmniCLIBackend, ensure_omnicli_importable

_HAVE_OMNICLI = ensure_omnicli_importable()
_requires_omnicli = unittest.skipUnless(
    _HAVE_OMNICLI, "omnicli checkout not importable"
)

from oracle_hunter import build_redteam_audit_prompt  # noqa: E402


class TestOmniCLIMembersFallback(unittest.TestCase):
    """OmniCLIBackend must handle the real run_orchestration members shape."""

    def _backend_with(self, result):
        backend = OmniCLIBackend("reflex", env={})
        backend._load = lambda: (
            lambda: MagicMock(),
            lambda cfg: MagicMock(),
            lambda *args, **kwargs: result,
        )
        return backend

    def test_final_synthesis_preferred(self):
        backend = self._backend_with({"members": [], "final": "SYNTH"})
        self.assertEqual(backend.complete("sys", "prompt"), "SYNTH")

    def test_list_members_fallback_concatenates_answers(self):
        """run_orchestration returns members as a LIST of per-member records."""
        backend = self._backend_with(
            {
                "members": [
                    {
                        "provider": "pa",
                        "model": "m1",
                        "family": "openai",
                        "answer": "AAA",
                        "error": None,
                    },
                    {
                        "provider": "pb",
                        "model": "m2",
                        "family": "meta",
                        "answer": "",
                        "error": "RuntimeError: down",
                    },
                ],
                "final": "",
            }
        )
        out = backend.complete("sys", "prompt")
        self.assertIn("[pa:m1]", out)
        self.assertIn("AAA", out)
        self.assertNotIn("m2", out)  # empty answers are skipped, not blank sections

    def test_dict_members_fallback_still_supported(self):
        """Legacy dict shape (name -> response text) keeps working."""
        backend = self._backend_with(
            {
                "members": {"alpha": "RESP-A", "beta": ""},
                "final": "",
            }
        )
        out = backend.complete("sys", "prompt")
        self.assertIn("[alpha]", out)
        self.assertIn("RESP-A", out)
        self.assertNotIn("[beta]", out)

    def test_empty_synthesis_raises(self):
        backend = self._backend_with({"members": [], "final": ""})
        with self.assertRaises(BackendError):
            backend.complete("sys", "prompt")
        failed = self._backend_with(
            {
                "members": [
                    {
                        "provider": "pa",
                        "model": "m1",
                        "family": "openai",
                        "answer": "",
                        "error": "RuntimeError: down",
                    }
                ],
                "final": None,
            }
        )
        with self.assertRaises(BackendError):
            failed.complete("sys", "prompt")

    def test_system_prompt_passes_through_unflattened(self):
        seen = {}

        def fake_run(*args, **kwargs):
            seen["args"] = args
            seen["kwargs"] = kwargs
            return {"members": [], "final": "SYNTH"}

        backend = OmniCLIBackend("reflex", env={})
        backend._load = lambda: (
            lambda: MagicMock(),
            lambda cfg: MagicMock(),
            fake_run,
        )
        backend.complete("SYS-PROMPT", "user task")
        self.assertEqual(seen["kwargs"]["system"], "SYS-PROMPT")
        self.assertEqual(seen["args"][3], "user task")
        self.assertNotIn("[SYSTEM]", seen["args"][3])
        self.assertNotIn("[TASK]", seen["args"][3])


class TestRedteamPromptSourceGate(unittest.TestCase):
    """Oracle's red-team prompt must pass OmniCLI's _SOURCE_BLOCK gate."""

    @_requires_omnicli
    def test_file_target_embeds_source_block(self):
        from omnicli.evidence import extract_sources_from_prompt

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "vuln.py"
            src.write_text("password = 'hardcoded'\n", encoding="utf-8")
            prompt = build_redteam_audit_prompt(str(src))
        sources = extract_sources_from_prompt(prompt)
        self.assertIn("vuln.py", sources)
        self.assertIn("hardcoded", sources["vuln.py"])

    @_requires_omnicli
    def test_seams_dir_embeds_source_block(self):
        from omnicli.evidence import extract_sources_from_prompt

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "seams.json").write_text('{"seams": []}\n', encoding="utf-8")
            prompt = build_redteam_audit_prompt(tmp)
        sources = extract_sources_from_prompt(prompt)
        self.assertIn("seams.json", sources)
        self.assertIn("seams", sources["seams.json"])

    def test_finding_text_preserved(self):
        prompt = build_redteam_audit_prompt("some-program", finding="ASSERT-123")
        self.assertIn("ASSERT-123", prompt)
        self.assertIn("some-program", prompt)

    def test_file_target_embeds_whole_file_not_truncation(self):
        body = "".join(f"line {i:04d}: payload data here\n" for i in range(500))
        assert len(body) > 4000
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.py"
            target.write_text(body, encoding="utf-8")
            prompt = build_redteam_audit_prompt(str(target))
        self.assertIn("### Source file: target.py", prompt)
        self.assertIn("line 0000: payload data here", prompt)
        self.assertIn("line 0499: payload data here", prompt)

    def test_oversized_source_refuses_instead_of_truncating(self):
        import oracle_hunter

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "huge.py"
            target.write_text(
                "x = 1\n" * (oracle_hunter.ORACLE_AUDIT_SOURCE_CAP // 6 + 10),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Refusing to ground"):
                build_redteam_audit_prompt(str(target))

    @_requires_omnicli
    def test_redteam_runs_without_early_fail_on_fixture(self):
        from omnicli.orchestrate import swarm_redteam

        class FakeClient:
            def __init__(self):
                self.calls = 0

            def chat_complete(self, provider_id, messages, model=None, **kwargs):
                self.calls += 1
                return {
                    "choices": [{"message": {"content": "NO ACTIONABLE CANDIDATE"}}]
                }

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "vuln.py"
            src.write_text("password = 'hardcoded'\n", encoding="utf-8")
            prompt = build_redteam_audit_prompt(str(src))
        cfg = MagicMock()
        client = FakeClient()
        result = swarm_redteam(
            cfg,
            client,
            prompt,
            synth=False,
            swarm=[("p", "openai/test")],
        )
        self.assertTrue(result["members"])
        self.assertGreater(client.calls, 0)
        self.assertNotIn("was not run", result.get("final") or "")


def main() -> int:
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
