#!/usr/bin/env python3
"""Mindset cages — a mindset is a CAGE for OmniCLI, never a suggestion.

User architecture (2026-10-21): OmniCLI output must be structurally
forced through the mindset's cage: required fields, frame identity,
observation basis, wire prediction, and rule-compliance — or the card
does not exist. And provider lanes are assigned to mindsets in parallel
by configuration (half on M1, half on M2, all converge on M3).

Fail-first receipts (RED pre-patch): oracle_mindset_cages did not exist;
the live pipeline accepted any prose/classification as a "pass" and
minted cards from one un-caged template family.
"""

import unittest

from oracle_mindset_cages import (
    admit_seam_card,
    validate_mindset_card,
    resolve_mindset_pools,
)

SCOPE = ["*.tinder.com", "*.gotinder.com", "com.tinder", "547702041"]
GOOD_BASE = {
    "asset": "api.gotinder.com",
    "claim": "server enforces Plus tier on profile views",
    "prediction": {"status": 200, "contains": "is_plus"},
    "evidence_basis": "observed HAR: GET /v2/profile in session A",
    "rule_compliance": {"checked": True, "violations": []},
}


def _card(**kw):
    c = dict(GOOD_BASE)
    c.update(kw)
    return c


class TestMindsetCages(unittest.TestCase):
    def test_mitre_card_requires_technique_code(self):
        ok, why = validate_mindset_card("mitre", _card(), SCOPE)
        self.assertFalse(ok)
        self.assertTrue(any("technique" in w for w in why))
        ok, why = validate_mindset_card(
            "mitre", _card(technique="T1190"), SCOPE
        )
        self.assertTrue(ok, why)

    def test_paradox_card_requires_declared_frame(self):
        ok, why = validate_mindset_card("paradox", _card(), SCOPE)
        self.assertFalse(ok)
        for frame in ("paradox", "impossible", "iphone"):
            ok, why = validate_mindset_card(
                "paradox", _card(frame=frame), SCOPE
            )
            self.assertTrue(ok, why)
        ok, why = validate_mindset_card(
            "paradox", _card(frame="vibes"), SCOPE
        )
        self.assertFalse(ok)

    def test_suggestion_shapes_are_rejected(self):
        # prose-only "maybe check this" card: no prediction, no basis
        ok, why = validate_mindset_card(
            "mitre",
            {"asset": "api.gotinder.com", "technique": "T1190"},
            SCOPE,
        )
        self.assertFalse(ok)
        self.assertGreaterEqual(len(why), 2)

    def test_out_of_scope_asset_rejected(self):
        ok, why = validate_mindset_card(
            "mitre", _card(asset="evil.example.com", technique="T1190"), SCOPE
        )
        self.assertFalse(ok)
        self.assertTrue(any("scope" in w for w in why))

    def test_rule_violation_rejected(self):
        ok, why = validate_mindset_card(
            "mitre",
            _card(
                technique="T1190",
                rule_compliance={
                    "checked": True,
                    "violations": ["mass account creation"],
                },
            ),
            SCOPE,
        )
        self.assertFalse(ok)
        ok, why = validate_mindset_card(
            "mitre",
            _card(rule_compliance={"checked": False, "violations": []}),
            SCOPE,
        )
        self.assertFalse(ok)

    def test_synthesis_requires_both_parent_mindsets(self):
        ok, why = validate_mindset_card(
            "synthesis",
            _card(merged_from=["mitre", "paradox"]),
            SCOPE,
        )
        self.assertTrue(ok, why)
        ok, why = validate_mindset_card(
            "synthesis", _card(merged_from=["mitre"]), SCOPE
        )
        self.assertFalse(ok)

    def test_unknown_mindset_is_a_cage_error(self):
        ok, why = validate_mindset_card("chaos", _card(), SCOPE)
        self.assertFalse(ok)

    def test_empty_containers_never_satisfy_required_fields(self):
        for field in ("claim", "evidence_basis"):
            for empty in ([], {}, 0):
                ok, why = validate_mindset_card(
                    "mitre",
                    _card(technique="T1190", **{field: empty}),
                    SCOPE,
                )
                self.assertFalse(ok, f"{field}={empty!r} passed the cage")
                self.assertTrue(any(field in w for w in why))
        ok, why = validate_mindset_card(
            "mitre", _card(asset=0, technique="T1190"), SCOPE
        )
        self.assertFalse(ok)

    def test_boolean_status_is_not_a_status(self):
        # bool is a subclass of int in Python; True must never pass as 200.
        ok, why = validate_mindset_card(
            "mitre",
            _card(technique="T1190", prediction={"status": True}),
            SCOPE,
        )
        self.assertFalse(ok)
        self.assertTrue(any("status" in w for w in why))

    def test_empty_header_prediction_rejected(self):
        ok, why = validate_mindset_card(
            "mitre",
            _card(technique="T1190", prediction={"header": ""}),
            SCOPE,
        )
        self.assertFalse(ok)
        ok, why = validate_mindset_card(
            "mitre",
            _card(technique="T1190", prediction={"header": {"x": "y"}}),
            SCOPE,
        )
        self.assertTrue(ok, why)

    def test_scope_matching_mirrors_program_scope_gate(self):
        # wildcard covers apex (gate regex: zero or more labels)
        ok, why = validate_mindset_card(
            "mitre", _card(asset="tinder.com", technique="T1190"), SCOPE
        )
        self.assertTrue(ok, why)
        # asset URLs are reduced to their host for matching
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="https://API.GOTINDER.COM/v2/x", technique="T1190"),
            SCOPE,
        )
        self.assertTrue(ok, why)
        # suffix-boundary attack must fail closed
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="api.gotinder.com.evil.com", technique="T1190"),
            SCOPE,
        )
        self.assertFalse(ok)
        # bare (non-wildcard) host is exact: no implicit subdomain grant
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="api.tinder.com", technique="T1190"),
            ["tinder.com"],
        )
        self.assertFalse(ok)
        ok, why = validate_mindset_card(
            "mitre", _card(asset="tinder.com", technique="T1190"),
            ["tinder.com"],
        )
        self.assertTrue(ok, why)

    def test_hostile_url_text_never_smuggles_scope(self):
        # live gate treats these hosts as out-of-scope; the cage must too
        for asset in (
            "https://evil?x.gotinder.com/",
            "https://evil#x.gotinder.com/",
            "https://evil:443.gotinder.com/",
            "evil.com;.gotinder.com",
            "https://evil.com@api.gotinder.com/",
        ):
            ok, why = validate_mindset_card(
                "mitre", _card(asset=asset, technique="T1190"), SCOPE
            )
            self.assertFalse(ok, f"hostile asset passed: {asset!r}")

    def test_path_scoped_grant_fails_closed(self):
        scope = ["https://wolt.com/en/x"]
        for asset in ("wolt.com", "https://wolt.com/other",
                      "https://wolt.com/en/x"):
            ok, why = validate_mindset_card(
                "mitre", _card(asset=asset, technique="T1190"), scope
            )
            self.assertFalse(ok, f"path grant widened to host: {asset!r}")

    def test_out_of_scope_rules_reject_apex_and_subdomains(self):
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="secret.gotinder.com", technique="T1190"),
            SCOPE,
            out_of_scope=["secret.gotinder.com"],
        )
        self.assertFalse(ok)
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="deep.secret.gotinder.com", technique="T1190"),
            SCOPE,
            out_of_scope=["secret.gotinder.com"],
        )
        self.assertFalse(ok)
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="api.gotinder.com", technique="T1190"),
            SCOPE,
            out_of_scope=["secret.gotinder.com"],
        )
        self.assertTrue(ok, why)

    def test_leading_dot_wildcard_covers_subdomains(self):
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="api.tinder.com", technique="T1190"),
            [".tinder.com"],
        )
        self.assertTrue(ok, why)

    def test_raw_list_rejects_what_gate_rejects(self):
        # numeric-only identifier: ProgramScopeGate drops it (is_digit)
        ok, why = validate_mindset_card(
            "mitre", _card(asset="547702041", technique="T1190"), SCOPE
        )
        self.assertFalse(ok)
        # malformed labels the gate's label regex can never match
        for asset in (
            "evil..gotinder.com",
            "evil!.gotinder.com",
            "evil.com..gotinder.com",
            "tinder.com.",
        ):
            ok, why = validate_mindset_card(
                "mitre", _card(asset=asset, technique="T1190"), SCOPE
            )
            self.assertFalse(ok, f"malformed host admitted: {asset!r}")
        # IPv6 literal grants are unusable in raw-list mode: fail closed
        ok, why = validate_mindset_card(
            "mitre", _card(asset="[::1]", technique="T1190"), ["[::1]"]
        )
        self.assertFalse(ok)

    def test_path_scoped_oos_rule_fails_closed(self):
        # An exclusion the raw layer cannot express must reject, not skip.
        ok, why = validate_mindset_card(
            "mitre",
            _card(asset="https://wolt.com/other", technique="T1190"),
            ["*.wolt.com"],
            out_of_scope=["https://wolt.com/en/x"],
        )
        self.assertFalse(ok)

    def test_live_gate_object_is_authoritative(self):
        class Gate:
            def __init__(self, verdict):
                self.verdict = verdict

            def is_in_scope(self, _asset):
                return self.verdict

        ok, why = validate_mindset_card(
            "mitre", _card(technique="T1190"), Gate((False, "OUT"))
        )
        self.assertFalse(ok)
        ok, why = validate_mindset_card(
            "mitre", _card(technique="T1190"), Gate((True, ""))
        )
        self.assertTrue(ok, why)


class TestSeamAdmission(unittest.TestCase):
    """Producer bridge: parsed SEAM cards are admitted only inside a cage."""

    def _seam(self, **kw):
        seam = {
            "assertion_a": "docs claim profile views require Plus",
            "assertion_a_source": "https://tinder.com/policy",
            "assertion_b": (
                "GET /v2/profile returns is_plus to a basic account"
            ),
            "check": "curl -i -s https://api.gotinder.com/v2/profile",
            "expected": 'status 200, body contains "is_plus"',
            "mitre": "T1190",
            "frame": "paradox",
        }
        seam.update(kw)
        return seam

    def test_complete_mitre_seam_is_admitted_with_receipt(self):
        ok, why, receipt = admit_seam_card("mitre", self._seam(), SCOPE)
        self.assertTrue(ok, why)
        self.assertEqual(receipt["asset"], "api.gotinder.com")
        self.assertEqual(receipt["prediction"], {"status": 200,
                                                 "contains": "is_plus"})
        self.assertTrue(receipt["rule_compliance"]["checked"])
        self.assertEqual(receipt["technique"], "T1190")

    def test_paradox_seam_requires_declared_frame(self):
        ok, why, _ = admit_seam_card(
            "paradox", self._seam(frame=""), SCOPE
        )
        self.assertFalse(ok)
        self.assertTrue(any("frame" in w for w in why))
        ok, why, _ = admit_seam_card(
            "paradox", self._seam(frame="iphone"), SCOPE
        )
        self.assertTrue(ok, why)

    def test_missing_or_statusless_prediction_rejected(self):
        for expected in ("", "body contains \"x\"", "200 maybe"):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(expected=expected), SCOPE
            )
            self.assertFalse(ok, f"weak prediction admitted: {expected!r}")

    def test_check_must_carry_an_in_scope_url(self):
        for check in (
            "",
            "curl -i -s /v2/profile",
            "curl -i -s https://evil.example.com/v2/profile",
        ):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(check=check), SCOPE
            )
            self.assertFalse(ok, f"check admitted: {check!r}")

    def test_unsourced_claim_rejected(self):
        for source in (
            "",
            "N/A",
            "N/A.",
            "model knowledge",
            "inferred",
            "Tinder policy page",
        ):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(assertion_a_source=source), SCOPE
            )
            self.assertFalse(ok, f"unsourced claim admitted: {source!r}")
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(assertion_a_source="program_policy_20261021.md"),
            SCOPE,
        )
        self.assertTrue(ok, why)
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                assertion_a_source="https://hackerone.com/tinder"
            ),
            SCOPE,
        )
        self.assertTrue(ok, why)
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                assertion_a_source="https://evil.example.com/policy"
            ),
            SCOPE,
        )
        self.assertFalse(ok)
        self.assertTrue(any("evidence source" in w for w in why))

    def test_half_card_rejected(self):
        ok, why, _ = admit_seam_card(
            "mitre", self._seam(assertion_b=""), SCOPE
        )
        self.assertFalse(ok)
        ok, why, _ = admit_seam_card(
            "mitre", self._seam(assertion_a=""), SCOPE
        )
        self.assertFalse(ok)

    def test_mitre_requires_real_technique(self):
        for technique in ("", "N/A", "unknown"):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(mitre=technique), SCOPE
            )
            self.assertFalse(ok, f"technique admitted: {technique!r}")

    def test_destructive_check_rejected_by_rule_scanner(self):
        for check in (
            "curl -i -s -X DELETE https://api.gotinder.com/v2/profile",
            "curl -i -s --request DELETE "
            "https://api.gotinder.com/v2/profile",
            "curl -i -s -XDELETE https://api.gotinder.com/v2/profile",
            "curl -i -s --request=DELETE "
            "https://api.gotinder.com/v2/profile",
            "curl -i -s https://api.gotinder.com/v2/profile "
            "-d 'drop table users'",
        ):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(check=check), SCOPE
            )
            self.assertFalse(ok, f"destructive check admitted: {check!r}")
            self.assertTrue(any("rule" in w.lower() for w in why))

    def test_encoded_and_shell_quoted_destructive_bypasses_rejected(self):
        for check in (
            "curl -i -s -X%20DELETE "
            "https://api.gotinder.com/v2/profile",
            "curl -i -s -X 'DELE'TE "
            "https://api.gotinder.com/v2/profile",
            "curl -i -s -X \"DELETE\" "
            "https://api.gotinder.com/v2/profile",
            "curl -i -s 'https://api.gotinder.com/v2/profile"
            "?q=DROP%20TABLE%20users'",
            "curl -i -s 'https://api.gotinder.com/v2/profile"
            "?q=DR%4fP%20TABLE%20users'",
            "curl -i -s 'https://api.gotinder.com/v2/profile"
            "?q=RM%20-RF%20/'",
            "curl -i -s -d '_method=DELETE' "
            "https://api.gotinder.com/v2/profile",
        ):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(check=check), SCOPE
            )
            self.assertFalse(ok, f"bypass admitted: {check!r}")
            self.assertTrue(any("rule" in w.lower() for w in why))

    def test_ordinary_delete_word_in_get_is_not_destructive(self):
        for check in (
            "curl -i -s "
            "'https://api.gotinder.com/v2/profile?action=delete'",
            "curl -i -s "
            "https://api.gotinder.com/v2/delete-account",
        ):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(check=check), SCOPE
            )
            self.assertTrue(ok, why)

    def test_negated_vague_or_unquoted_prediction_rejected(self):
        for expected in (
            "no status 200",
            "status 200 maybe",
            'status 200, body contains x',
            'status 200, body contains ""',
            "status 2000",
            "status 99",
            "status 600",
        ):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(expected=expected), SCOPE
            )
            self.assertFalse(ok, f"weak prediction admitted: {expected!r}")

    def test_technique_and_frame_must_lead_the_field(self):
        for technique in ("x T1190", "T1190evil", "see T1190"):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(mitre=technique), SCOPE
            )
            self.assertFalse(ok, f"technique admitted: {technique!r}")
        ok, why, _ = admit_seam_card(
            "mitre", self._seam(mitre="T1190 — Exploit Public App"), SCOPE
        )
        self.assertTrue(ok, why)
        for frame in ("not a paradox", "paradoxical", "maybe impossible"):
            ok, why, _ = admit_seam_card(
                "paradox", self._seam(frame=frame), SCOPE
            )
            self.assertFalse(ok, f"frame admitted: {frame!r}")
        ok, why, _ = admit_seam_card(
            "paradox", self._seam(frame="iPhone"), SCOPE
        )
        self.assertTrue(ok, why)

    def test_every_check_url_must_be_in_scope(self):
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                check="curl -i -s https://api.gotinder.com/x "
                "https://evil.example.com/y"
            ),
            SCOPE,
        )
        self.assertFalse(ok)
        self.assertTrue(any("scope" in w for w in why))
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                check="curl -i -s https://api.gotinder.com/x "
                "https://api.gotinder.com/y"
            ),
            SCOPE,
        )
        self.assertTrue(ok, why)

    def test_path_scoped_gate_is_authoritative(self):
        class _Gate:
            def is_in_scope(self, target):
                if "://" not in target:
                    target = "https://" + target
                return ("/allowed" in target, "")

        gate = _Gate()
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                assertion_a_source="policy.md",
                check="curl -i -s https://api.gotinder.com/blocked",
            ),
            gate,
        )
        self.assertFalse(ok)
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                assertion_a_source="policy.md",
                check="curl -i -s https://api.gotinder.com/allowed",
            ),
            gate,
        )
        self.assertTrue(ok, why)

    def test_malformed_or_unverified_packet_rejected(self):
        for packet in ("nope", 42, {}, {"verified": False}):
            ok, why, _ = admit_seam_card(
                "mitre", self._seam(), SCOPE, packet=packet
            )
            self.assertFalse(ok, f"packet admitted: {packet!r}")
        ok, why, receipt = admit_seam_card(
            "mitre",
            self._seam(),
            SCOPE,
            packet={"verified": True, "rules_sha256": "abc123"},
        )
        self.assertTrue(ok, why)
        self.assertTrue(
            receipt["rule_compliance"]["basis"].startswith("packet:")
        )

    def test_bare_out_of_scope_hostname_is_not_evidence(self):
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(assertion_a_source="evil.example.com"),
            SCOPE,
        )
        self.assertFalse(ok)
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                assertion_a_source="https://hackerone.com.evil.com/x"
            ),
            SCOPE,
        )
        self.assertFalse(ok)
        ok, why, _ = admit_seam_card(
            "mitre",
            self._seam(
                assertion_a_source="https://tinder.com/policy and "
                "https://evil.example.com/x"
            ),
            SCOPE,
        )
        self.assertFalse(ok)


class TestMindsetPools(unittest.TestCase):
    def test_default_halves_split_and_full_synthesis(self):
        lanes = ["a", "b", "c", "d"]
        pools = resolve_mindset_pools(lanes)
        self.assertEqual(pools["mitre"], ["a", "b"])
        self.assertEqual(pools["paradox"], ["c", "d"])
        self.assertEqual(pools["synthesis"], ["a", "b", "c", "d"])

    def test_odd_count_is_balanced(self):
        lanes = ["a", "b", "c"]
        pools = resolve_mindset_pools(lanes)
        self.assertEqual(pools["mitre"], ["a", "b"])
        self.assertEqual(pools["paradox"], ["c"])
        self.assertEqual(pools["synthesis"], ["a", "b", "c"])

    def test_single_lane_is_declared_regime(self):
        pools = resolve_mindset_pools(["solo"])
        self.assertEqual(pools["mitre"], ["solo"])
        self.assertEqual(pools["paradox"], ["solo"])
        self.assertEqual(pools["synthesis"], ["solo"])

    def test_config_override_and_unknown_lanes_filtered(self):
        cfg = {"mindset_pools": {"mitre": ["a", "zzz"], "paradox": ["b"]}}
        pools = resolve_mindset_pools(["a", "b", "c"], cfg)
        self.assertEqual(pools["mitre"], ["a"])
        self.assertEqual(pools["paradox"], ["b"])
        self.assertEqual(pools["synthesis"], ["a", "b", "c"])
        with self.assertRaises(ValueError):
            resolve_mindset_pools(["a"], {"mindset_pools": {"mitre": ["zzz"]}})

    def test_override_lists_are_deduped(self):
        cfg = {
            "mindset_pools": {
                "mitre": ["a", "a"],
                "paradox": ["b", "b"],
                "synthesis": ["a", "b", "a"],
            }
        }
        pools = resolve_mindset_pools(["a", "b", "c"], cfg)
        self.assertEqual(pools["mitre"], ["a"])
        self.assertEqual(pools["paradox"], ["b"])
        self.assertEqual(pools["synthesis"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
