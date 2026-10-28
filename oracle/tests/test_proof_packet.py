#!/usr/bin/env python3
"""Tests for Proof Packet generation and tamper-verification.

Validates that generate_proof_packet produces a cryptographically sealed receipt
and verify_proof_packet accepts valid packets while rejecting tampered, missing,
or altered payloads.
"""

import copy
import pytest

from oracle_foundation import generate_proof_packet, verify_proof_packet


class DummyScopeGate:
    """Mock ProgramScopeGate for testing scope verification inclusion."""

    def __init__(self, allowed_domains: list[str]):
        self.allowed = allowed_domains

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        for dom in self.allowed:
            if dom in target:
                return True, f"{target} matches in-scope {dom}"
        return False, f"{target} is out of scope"


@pytest.fixture
def sample_seam():
    return {
        "id": "SEAM-42",
        "n": 42,
        "check": "curl -i -s https://api.example.com/v1/user/101",
        "assertion_a": "Policy requires bearer token for user 101 data",
        "assertion_b": "Unauthenticated GET /v1/user/101 returns 200 with PII",
        "assertion_a_source": "https://example.com/docs/api_policy.md",
        "expected": {"status": 200, "contains": "email"},
        "impact": "IDOR allowing unauthorized account access",
    }


@pytest.fixture
def sample_verification_result():
    return {
        "verdict": "CONFIRMED",
        "reason": "HTTP 200 received with PII payload without Authorization header",
        "observed": {"status": 200, "email": "victim@example.com"},
        "expected": {"status": 200, "contains": "email"},
        "url": "https://api.example.com/v1/user/101",
        "strength": "STRONG",
    }


def test_generate_proof_packet_structure_and_validity(sample_seam, sample_verification_result):
    """Test generating a valid proof packet and verifying its signature."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)

    assert packet["version"] == "1.0"
    assert packet["schema"] == "product.ai/proof-packet/v1"
    assert packet["signature_algorithm"] == "HMAC-SHA256"
    assert isinstance(packet["signature"], str)
    assert len(packet["signature"]) == 64
    assert packet["seam"]["id"] == "SEAM-42"
    assert packet["verification"]["verdict"] == "CONFIRMED"
    assert packet["scope_gate"] == {}

    # Verify signature passes
    assert verify_proof_packet(packet) is True

    # Verification is non-destructive (idempotent)
    assert verify_proof_packet(packet) is True


def test_scope_gate_in_scope_inclusion(sample_seam, sample_verification_result):
    """Scope gate inclusion records passed=True when URL is within scope."""
    gate = DummyScopeGate(["api.example.com"])
    packet = generate_proof_packet(sample_seam, sample_verification_result, scope_gate=gate)

    assert packet["scope_gate"]["passed"] is True
    assert packet["scope_gate"]["target"] == "https://api.example.com/v1/user/101"
    assert "matches in-scope" in packet["scope_gate"]["reason"]

    assert verify_proof_packet(packet) is True


def test_scope_gate_out_of_scope_inclusion(sample_seam, sample_verification_result):
    """Scope gate inclusion records passed=False when URL is outside scope."""
    gate = DummyScopeGate(["other-domain.org"])
    packet = generate_proof_packet(sample_seam, sample_verification_result, scope_gate=gate)

    assert packet["scope_gate"]["passed"] is False
    assert packet["scope_gate"]["target"] == "https://api.example.com/v1/user/101"
    assert "out of scope" in packet["scope_gate"]["reason"]

    assert verify_proof_packet(packet) is True


def test_tampered_verdict_fails_verification(sample_seam, sample_verification_result):
    """Flipping verdict from CONFIRMED to REJECTED breaks the HMAC signature."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)
    tampered = copy.deepcopy(packet)
    tampered["verification"]["verdict"] = "REJECTED"

    assert verify_proof_packet(tampered) is False


def test_tampered_seam_fails_verification(sample_seam, sample_verification_result):
    """Modifying check or seam ID breaks verification."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)

    tampered_id = copy.deepcopy(packet)
    tampered_id["seam"]["id"] = "TAMPERED-ID"
    assert verify_proof_packet(tampered_id) is False

    tampered_check = copy.deepcopy(packet)
    tampered_check["seam"]["check"] = "curl -i https://evil.attacker.com"
    assert verify_proof_packet(tampered_check) is False


def test_tampered_timestamp_fails_verification(sample_seam, sample_verification_result):
    """Modifying the timestamp invalidates the packet."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)
    tampered = copy.deepcopy(packet)
    tampered["timestamp"] = "1970-01-01T00:00:00+00:00"

    assert verify_proof_packet(tampered) is False


def test_injected_fields_fail_verification(sample_seam, sample_verification_result):
    """Injecting extra keys into the signed envelope invalidates the packet."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)
    tampered = copy.deepcopy(packet)
    tampered["backdoor"] = "injected_payload"

    assert verify_proof_packet(tampered) is False


def test_tampered_scope_gate_fails_verification(sample_seam, sample_verification_result):
    """Tampering with scope gate results invalidates the packet."""
    gate = DummyScopeGate(["other-domain.org"])
    packet = generate_proof_packet(sample_seam, sample_verification_result, scope_gate=gate)
    tampered = copy.deepcopy(packet)
    tampered["scope_gate"]["passed"] = True  # Attempted fraud

    assert verify_proof_packet(tampered) is False


def test_tampered_signature_fails_verification(sample_seam, sample_verification_result):
    """Corrupting characters of the signature hash fails verification."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)
    tampered = copy.deepcopy(packet)
    tampered["signature"] = "0" * 64

    assert verify_proof_packet(tampered) is False


def test_missing_or_corrupt_signature_fails(sample_seam, sample_verification_result):
    """Missing, empty, non-string, or wrong algorithm signatures fail gracefully."""
    packet = generate_proof_packet(sample_seam, sample_verification_result)

    # Missing signature key
    no_sig = copy.deepcopy(packet)
    del no_sig["signature"]
    assert verify_proof_packet(no_sig) is False

    # None / empty / non-string signature
    none_sig = copy.deepcopy(packet)
    none_sig["signature"] = None
    assert verify_proof_packet(none_sig) is False

    empty_sig = copy.deepcopy(packet)
    empty_sig["signature"] = ""
    assert verify_proof_packet(empty_sig) is False

    num_sig = copy.deepcopy(packet)
    num_sig["signature"] = 12345
    assert verify_proof_packet(num_sig) is False

    # Tampered signature algorithm
    bad_algo = copy.deepcopy(packet)
    bad_algo["signature_algorithm"] = "HMAC-MD5"
    assert verify_proof_packet(bad_algo) is False


def test_non_dict_inputs_fail_verification():
    """Non-dict inputs fail safely without exceptions."""
    assert verify_proof_packet(None) is False
    assert verify_proof_packet("not a dict") is False
    assert verify_proof_packet([1, 2, 3]) is False
    assert verify_proof_packet({}) is False


def test_seam_id_fallback_to_n(sample_verification_result):
    """Seam without 'id' uses 'n'."""
    seam_without_id = {"n": 99, "check": "check_cmd"}
    packet = generate_proof_packet(seam_without_id, sample_verification_result)
    assert packet["seam"]["id"] == 99
    assert verify_proof_packet(packet) is True
