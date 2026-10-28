#!/usr/bin/env python3
"""Cage admission wiring — lens cards must pass the cage before the deck.

RED-first receipt (pre-patch): _cage_admit_parsed did not exist; the lens
parse loop merged every parsed SEAM card straight into the deck, so a
prose card with no status prediction, no sourced claim, or no grounded
check was credited as lens output.
"""

import unittest

import oracle_hunter as oh

SCOPE = ["*.gotinder.com", "tinder.com"]


def _seam(**kw):
    seam = {
        "assertion_a": "docs claim profile views require Plus",
        "assertion_a_source": "https://tinder.com/policy",
        "assertion_b": "GET /v2/profile returns is_plus to a basic account",
        "check": "curl -i -s https://api.gotinder.com/v2/profile",
        "expected": 'status 200, body contains "is_plus"',
        "mitre": "T1190",
        "frame": "paradox",
    }
    seam.update(kw)
    return seam


class TestCageAdmissionWiring(unittest.TestCase):
    def test_lens_pass_admits_only_caged_cards(self):
        parsed = [
            _seam(),
            _seam(expected="", check="curl -i -s /v2/profile"),
        ]
        admitted, rejected = oh._cage_admit_parsed(
            parsed, "cloud-mitre", SCOPE
        )
        self.assertEqual(len(admitted), 1)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            admitted[0]["cage_receipt"]["asset"], "api.gotinder.com"
        )
        self.assertTrue(rejected[0]["reasons"])

    def test_all_rejected_pass_is_failed_not_credited(self):
        raw = "**SEAM 1**\n- Assertion A: docs claim X\n- Expected: maybe\n"
        admitted, rejected = oh._cage_admit_parsed(
            [_seam(expected="maybe")], "cloud-mitre", SCOPE
        )
        self.assertEqual(admitted, [])
        self.assertEqual(len(rejected), 1)
        outcome = oh.lens_outcome(raw, admitted)
        self.assertEqual(outcome, "empty")
        self.assertTrue(oh.pass_failed(outcome))

    def test_paradox_lens_without_frame_is_rejected(self):
        admitted, rejected = oh._cage_admit_parsed(
            [_seam(frame="")], "cloud-paradox", SCOPE
        )
        self.assertEqual(admitted, [])
        self.assertTrue(
            any("frame" in reason for reason in rejected[0]["reasons"])
        )

    def test_out_of_scope_card_never_enters_deck(self):
        admitted, rejected = oh._cage_admit_parsed(
            [_seam(check="curl -i -s https://evil.example.com/x")],
            "cloud-mitre",
            SCOPE,
        )
        self.assertEqual(admitted, [])
        self.assertEqual(len(rejected), 1)

    def test_target_clean_cannot_erase_cage_rejection(self):
        raw = (
            "TARGET CLEAN — no seams\n"
            "**SEAM 1**\n- Expected: maybe\n"
        )
        admitted, rejected = oh._cage_admit_parsed(
            [_seam(expected="maybe")], "cloud-mitre", SCOPE
        )
        outcome = oh._lens_outcome_after_cage(raw, admitted, rejected)
        self.assertEqual(outcome, "empty")
        self.assertTrue(oh.pass_failed(outcome))
        self.assertEqual(
            oh._lens_outcome_after_cage("TARGET CLEAN", [], []), "clean"
        )


if __name__ == "__main__":
    unittest.main()
