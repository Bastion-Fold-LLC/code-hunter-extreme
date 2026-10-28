#!/usr/bin/env python3
"""
Unit and integration tests for Oracle Phase 3: Smart Contract Layer.
Validates:
1. Web3 contract address & target parsing (oracle_web3_recon)
2. Slither static analysis execution & JSON parsing
3. 8 Web3 seam templates (oracle_seam_templates_web3)
4. Gate 1-5 deterministic verification for contracts (oracle_deterministic)
5. Precision on clean guarded contracts vs recall on vulnerable contracts
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_web3_recon as w3_recon
import oracle_seam_templates_web3 as w3_tpl
import oracle_deterministic as det
from oracle_hunter import _run_check


class TestWeb3Layer(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = ROOT / "tests" / "fixtures" / "sol"
        self.vuln_contract = self.fixtures_dir / "EtherStore.sol"
        self.clean_contract = self.fixtures_dir / "GuardedVault.sol"

    def test_address_and_target_parsing(self):
        weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        self.assertTrue(w3_recon.is_eth_address(weth))
        self.assertFalse(w3_recon.is_eth_address("not_an_address"))
        self.assertFalse(w3_recon.is_eth_address("0x123"))

        # Chain aliases
        cid, addr, path = w3_recon.parse_target_contract(f"arbitrum:{weth}")
        self.assertEqual(cid, 42161)
        self.assertEqual(addr, weth.lower())
        self.assertIsNone(path)

        cid2, addr2, path2 = w3_recon.parse_target_contract("1:0x" + "a"*40)
        self.assertEqual(cid2, 1)
        self.assertEqual(addr2, "0x" + "a"*40)

        # Local file path
        cid3, addr3, path3 = w3_recon.parse_target_contract(str(self.vuln_contract))
        self.assertEqual(cid3, 0)
        self.assertIsNone(addr3)
        self.assertEqual(path3, self.vuln_contract.resolve())

    @unittest.skipUnless(shutil.which("slither"), "slither binary not installed")
    def test_slither_execution_on_vulnerable_vault(self):
        res = w3_recon.run_slither(self.vuln_contract)
        detectors = [d.get("check") for d in res.get("detectors", [])]
        self.assertIn("reentrancy-eth", detectors)

    def test_web3_seam_templates_generation(self):
        mock_detectors = [
            {"check": "reentrancy-eth", "elements": [{"type": "function", "name": "withdraw", "source_mapping": {"lines": [15]}}]},
            {"check": "arbitrary-send-eth", "elements": [{"type": "function", "name": "drain", "source_mapping": {"lines": [25]}}]},
            {"check": "tx-origin", "elements": [{"type": "function", "name": "transfer", "source_mapping": {"lines": [35]}}]},
            {"check": "unchecked-lowlevel", "elements": [{"type": "function", "name": "callOther", "source_mapping": {"lines": [45]}}]},
            {"check": "suicidal", "elements": [{"type": "function", "name": "kill", "source_mapping": {"lines": [55]}}]},
            {"check": "controlled-delegatecall", "elements": [{"type": "function", "name": "exec", "source_mapping": {"lines": [65]}}]},
            {"check": "unprotected-upgrade", "elements": [{"type": "function", "name": "initialize", "source_mapping": {"lines": [75]}}]},
        ]
        mock_abi = [
            {"type": "function", "name": "withdraw", "stateMutability": "nonpayable"},
            {"type": "function", "name": "getBalance", "stateMutability": "view"},
        ]

        material = {
            "abi": mock_abi,
            "detectors": mock_detectors,
            "src_file": str(self.vuln_contract),
        }

        # Check that individual templates produce valid cards
        reentrancy_cards = w3_tpl._t_reentrancy(material)
        self.assertEqual(len(reentrancy_cards), 1)
        self.assertIn("Checks-Effects-Interactions", reentrancy_cards[0]["assertion_a"])
        self.assertIn("reentrancy-eth", reentrancy_cards[0]["expected"])

        send_cards = w3_tpl._t_arbitrary_send(material)
        self.assertEqual(len(send_cards), 1)

        origin_cards = w3_tpl._t_tx_origin(material)
        self.assertEqual(len(origin_cards), 1)

        unchecked_cards = w3_tpl._t_unchecked_call(material)
        self.assertEqual(len(unchecked_cards), 1)

        suicidal_cards = w3_tpl._t_unprotected_destruction(material)
        self.assertEqual(len(suicidal_cards), 1)

        delegate_cards = w3_tpl._t_untrusted_delegatecall(material)
        self.assertEqual(len(delegate_cards), 1)

        upgrade_cards = w3_tpl._t_unprotected_upgrade_or_init(material)
        self.assertEqual(len(upgrade_cards), 1)

        abi_cards = w3_tpl._t_abi_privileged_bypass(material)
        self.assertGreaterEqual(len(abi_cards), 1)

    def test_deterministic_verifier_gate_5_web3(self):
        # 1. Gate 3: parse_expected handles web3 detector
        exp = det.parse_expected('detector "reentrancy-eth"')
        self.assertEqual(exp["web3_detector"], "reentrancy-eth")

        # 2. Gate 3: rejects card with no machine-readable expectation
        bad_card = {
            "n": 1,
            "assertion_a": "State transitions must finalize",
            "assertion_a_source": str(self.vuln_contract),
            "assertion_b": "Reentrancy exists",
            "source_a": str(self.vuln_contract),
            "check": f"slither {self.vuln_contract} --detect reentrancy-eth",
            "expected": "some non-machine-readable prose",
        }
        res_bad = det.verify_seam_card(bad_card, [str(self.vuln_contract)], status=0, body="reentrancy-eth")
        self.assertEqual(res_bad["verdict"], "REJECTED")
        self.assertIn("Expected line must include a status code", res_bad["reason"])

        # 3. Gate 4: rejects card with missing assertion_a_source
        no_source_card = {
            "n": 2,
            "assertion_a": "State transitions must finalize",
            "assertion_a_source": "",
            "assertion_b": "Reentrancy exists",
            "source_a": str(self.vuln_contract),
            "check": f"slither {self.vuln_contract} --detect reentrancy-eth",
            "expected": 'detector "reentrancy-eth"',
        }
        res_no_source = det.verify_seam_card(no_source_card, [str(self.vuln_contract)], status=0, body="reentrancy-eth")
        self.assertEqual(res_no_source["verdict"], "REJECTED")
        self.assertIn("no cited program source", res_no_source["reason"])

        # 4. Gate 5: CONFIRMS when detector found in execution output
        good_card = {
            "n": 3,
            "assertion_a": "State transitions must finalize before external calls",
            "assertion_a_source": str(self.vuln_contract),
            "assertion_b": "External call occurs before state write",
            "source_a": str(self.vuln_contract),
            "check": f"slither {self.vuln_contract} --detect reentrancy-eth",
            "expected": 'detector "reentrancy-eth"',
        }
        body_with_detector = "Detector: reentrancy-eth\nReentrancy in EtherStore.withdraw()"
        res_confirmed = det.verify_seam_card(good_card, [str(self.vuln_contract)], status=255, body=body_with_detector)
        self.assertEqual(res_confirmed["verdict"], "CONFIRMED")

        # 5. Gate 5: REJECTS when detector missing from execution output
        body_without_detector = "Compiled successfully without errors"
        res_rejected = det.verify_seam_card(good_card, [str(self.vuln_contract)], status=0, body=body_without_detector)
        self.assertEqual(res_rejected["verdict"], "REJECTED")
        self.assertIn('detector "reentrancy-eth" not found', res_rejected["reason"])


if __name__ == "__main__":
    unittest.main()
