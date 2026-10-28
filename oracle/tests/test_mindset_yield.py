#!/usr/bin/env python3
"""Mindset yield ledger — the full-service invariant (user law, 2026-10-21).

A hunt that requested and got mindsets effective owes the run CARDS from
each of them. A mindset that produced zero cards is UNSERVED, and an
unserved mindset means the hunt failed — its banner must say so, not
shrug. A lens TARGET CLEAN verdict only counts as served when regime
receipts (endpoints actually served in the authenticated regime) prove
the lens had materials; otherwise it is an unearned clean.

Fail-first receipts (RED pre-patch): mindset_yield_ledger /
yield_unserved did not exist; the tinder run minted 146 seam cards but
0 mitre cards and 0 paradox cards and finished without any yield
accounting at all.
"""

import unittest

from oracle_mindsets import (
    mindset_yield_ledger,
    sut_format_lines,
    yield_unserved,
)


def _seam(mindset, n=1):
    return {"mindset": mindset, "origin": f"{mindset}-template", "n": n}


class TestMindsetYieldLedger(unittest.TestCase):
    def test_all_served_when_every_mindset_minted(self):
        seams = [_seam("seam") for _ in range(5)]
        seams += [_seam("mitre") for _ in range(3)]
        seams += [_seam("paradox") for _ in range(2)]
        ledger = mindset_yield_ledger(["seam", "mitre", "paradox"], seams, {})
        self.assertEqual(yield_unserved(ledger), [])
        by = {e["mindset"]: e for e in ledger}
        self.assertEqual(by["seam"]["cause"], "minted")
        self.assertEqual(by["mitre"]["minted"], 3)

    def test_context_only_zero_is_unserved(self):
        # tinder truth: 146 seam cards, 0 mitre, 0 paradox
        seams = [_seam("seam") for _ in range(146)]
        ledger = mindset_yield_ledger(
            ["seam", "mitre", "paradox"],
            seams,
            {"mitre": "clean", "paradox": "clean"},
        )
        self.assertEqual(yield_unserved(ledger), ["mitre", "paradox"])
        self.assertEqual(ledger[0]["cause"], "minted")

    def test_clean_claim_without_receipts_is_unearned(self):
        ledger = mindset_yield_ledger(
            ["paradox"], [], {"paradox": "clean"}, regime_receipts={}
        )
        self.assertEqual(yield_unserved(ledger), ["paradox"])

    def test_clean_claim_with_regime_receipts_is_qualified(self):
        receipts = {"paradox": {"endpoints_served_200": 8, "session_regime": True}}
        ledger = mindset_yield_ledger(
            ["paradox"], [], {"paradox": "clean"}, regime_receipts=receipts
        )
        self.assertEqual(yield_unserved(ledger), [])
        self.assertEqual(ledger[0]["cause"], "qualified-clean")

    def test_error_and_empty_lens_are_unserved(self):
        ledger = mindset_yield_ledger(
            ["mitre", "paradox"],
            [],
            {"mitre": "error", "paradox": "empty"},
        )
        self.assertEqual(yield_unserved(ledger), ["mitre", "paradox"])

    def test_served_boundary_is_three_not_two(self):
        receipts = {"mitre": {"endpoints_served_200": 2, "session_regime": True}}
        ledger = mindset_yield_ledger(
            ["mitre"], [], {"mitre": "clean"}, regime_receipts=receipts
        )
        self.assertEqual(yield_unserved(ledger), ["mitre"])
        receipts["mitre"]["endpoints_served_200"] = 3
        ledger = mindset_yield_ledger(
            ["mitre"], [], {"mitre": "clean"}, regime_receipts=receipts
        )
        self.assertEqual(yield_unserved(ledger), [])

    def test_engine_tag_outcomes_translate_to_mindset_names(self):
        # Live truth: _lens_outcomes keys are engine origin tags
        # (cloud-mitre / local-paradox), never the mindset names.
        receipts = {
            "mitre": {"endpoints_served_200": 8, "session_regime": True},
            "paradox": {"endpoints_served_200": 8, "session_regime": True},
        }
        ledger = mindset_yield_ledger(
            ["mitre", "paradox"],
            [],
            {"cloud-mitre": "clean", "local-paradox": "clean"},
            regime_receipts=receipts,
        )
        self.assertEqual(yield_unserved(ledger), [])

    def test_poisoned_string_receipts_degrade_without_crash(self):
        receipts = {"mitre": {"endpoints_served_200": "abc"}}
        ledger = mindset_yield_ledger(
            ["mitre"], [], {"mitre": "clean"}, regime_receipts=receipts
        )
        self.assertEqual(yield_unserved(ledger), ["mitre"])

    def test_unserved_mindsets_fail_the_hunt_loudly(self):
        # Owner decision 2026-10-25: lens-zero fails loud, never a shrug.
        # The hunt banner already said SYSTEM FAILURE; the process must
        # now actually fail (report is written before this fires).
        import oracle_hunter as oh

        oh._die_on_unserved_mindsets([])  # all served: no-op
        with self.assertRaises(SystemExit):
            oh._die_on_unserved_mindsets(["mitre", "paradox"])

    def test_lines_render_current_truth(self):
        seams = [_seam("seam") for _ in range(2)]
        ledger = mindset_yield_ledger(["seam", "mitre"], seams, {})
        lines = sut_format_lines(ledger)
        self.assertIn("seam=2 minted", lines[0])
        self.assertIn("mitre=0", lines[1])


if __name__ == "__main__":
    unittest.main()
