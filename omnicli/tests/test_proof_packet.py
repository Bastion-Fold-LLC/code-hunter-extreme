"""Unit tests for OmniCLI Proof Packet (Anatomy of a Verdict protocol)."""

import copy
from datetime import datetime, timezone, timedelta
import json
import pytest

from omnicli.proof_packet import (
    create_proof_packet,
    verify_proof_packet,
    compute_staleness,
    proof_packet_from_redteam_result,
    VERDICT_VERIFIED,
    VERDICT_CONFIDENT_NO,
    VERDICT_INVALIDATED,
    VERDICT_UNVERIFIED,
    DECAY_SLOW,
    DECAY_MODERATE,
    DECAY_RAPID,
    STALENESS_FRESH,
    STALENESS_AGING,
    STALENESS_STALE,
)


@pytest.fixture
def sample_automated_test():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": "FUNCTIONAL",
        "tier": "PLATFORM_ADAPTER",
        "session_id": "sess-test-12345",
    }


@pytest.fixture
def sample_human_consensus():
    return {
        "independent_verifications": 3,
        "positive": 3,
        "weighted_confidence": 0.95,
    }


@pytest.fixture
def sample_fleet_signal():
    return {
        "recent_successes": 15,
        "recent_failures": 0,
        "trend": "STABLE",
    }


@pytest.fixture
def sample_health():
    return {
        "score": 0.95,
        "decay_rate": DECAY_SLOW,
        "last_verified": datetime.now(timezone.utc).isoformat(),
        "staleness": STALENESS_FRESH,
    }


def test_create_and_verify_valid_proof_packet(
    sample_automated_test, sample_human_consensus, sample_fleet_signal, sample_health
):
    packet = create_proof_packet(
        code="cve_2026_test_check",
        merchant="api.example.com",
        verdict=VERDICT_VERIFIED,
        confidence=0.95,
        automated_test=sample_automated_test,
        human_consensus=sample_human_consensus,
        fleet_signal=sample_fleet_signal,
        health=sample_health,
        forensic_anchors={"actor": "tester", "target": "api.example.com"},
    )

    assert packet["verdict"] == VERDICT_VERIFIED
    assert packet["signature_algorithm"] == "HMAC-SHA256"
    assert "signature" in packet
    assert len(packet["signature"]) == 64

    is_valid, reason = verify_proof_packet(packet)
    assert is_valid is True
    assert reason == "OK"


def test_verify_rejects_tampered_verdict(
    sample_automated_test, sample_human_consensus, sample_fleet_signal, sample_health
):
    packet = create_proof_packet(
        code="auth_bypass",
        merchant="target_service",
        verdict=VERDICT_CONFIDENT_NO,
        confidence=0.92,
        automated_test=sample_automated_test,
        human_consensus=sample_human_consensus,
        fleet_signal=sample_fleet_signal,
        health=sample_health,
    )
    tampered = copy.deepcopy(packet)
    tampered["verdict"] = VERDICT_VERIFIED

    is_valid, reason = verify_proof_packet(tampered)
    assert is_valid is False
    assert "mismatch" in reason.lower()


def test_verify_rejects_tampered_confidence(
    sample_automated_test, sample_human_consensus, sample_fleet_signal, sample_health
):
    packet = create_proof_packet(
        code="sql_injection",
        merchant="db_service",
        verdict=VERDICT_VERIFIED,
        confidence=0.50,
        automated_test=sample_automated_test,
        human_consensus=sample_human_consensus,
        fleet_signal=sample_fleet_signal,
        health=sample_health,
    )
    tampered = copy.deepcopy(packet)
    tampered["confidence"] = 0.99

    is_valid, reason = verify_proof_packet(tampered)
    assert is_valid is False
    assert "mismatch" in reason.lower()


def test_verify_rejects_tampered_evidence(
    sample_automated_test, sample_human_consensus, sample_fleet_signal, sample_health
):
    packet = create_proof_packet(
        code="ssrf",
        merchant="web_service",
        verdict=VERDICT_VERIFIED,
        confidence=0.88,
        automated_test=sample_automated_test,
        human_consensus=sample_human_consensus,
        fleet_signal=sample_fleet_signal,
        health=sample_health,
    )
    tampered = copy.deepcopy(packet)
    tampered["evidence"]["automated_test"]["result"] = "EXPIRED"

    is_valid, reason = verify_proof_packet(tampered)
    assert is_valid is False
    assert "mismatch" in reason.lower()


def test_verify_rejects_missing_signature(
    sample_automated_test, sample_human_consensus, sample_fleet_signal, sample_health
):
    packet = create_proof_packet(
        code="xss",
        merchant="frontend",
        verdict=VERDICT_VERIFIED,
        confidence=0.80,
        automated_test=sample_automated_test,
        human_consensus=sample_human_consensus,
        fleet_signal=sample_fleet_signal,
        health=sample_health,
    )
    del packet["signature"]

    is_valid, reason = verify_proof_packet(packet)
    assert is_valid is False
    assert "signature" in reason.lower()


def test_staleness_computation():
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    # SLOW (<=30d fresh, <=90d aging, >90d stale)
    t_fresh = now - timedelta(days=10)
    assert compute_staleness(t_fresh, DECAY_SLOW, now=now) == STALENESS_FRESH

    t_aging = now - timedelta(days=45)
    assert compute_staleness(t_aging, DECAY_SLOW, now=now) == STALENESS_AGING

    t_stale = now - timedelta(days=100)
    assert compute_staleness(t_stale, DECAY_SLOW, now=now) == STALENESS_STALE

    # RAPID (<=1d fresh, <=3d aging, >3d stale)
    t_rapid_fresh = now - timedelta(hours=12)
    assert compute_staleness(t_rapid_fresh, DECAY_RAPID, now=now) == STALENESS_FRESH

    t_rapid_aging = now - timedelta(days=2)
    assert compute_staleness(t_rapid_aging, DECAY_RAPID, now=now) == STALENESS_AGING

    t_rapid_stale = now - timedelta(days=5)
    assert compute_staleness(t_rapid_stale, DECAY_RAPID, now=now) == STALENESS_STALE


def test_proof_packet_from_redteam_result_confident_no():
    # Clean run with no findings -> CONFIDENT_NO
    gate_clean = {
        "status": "PASS_GROUNDING_ONLY",
        "candidate_count": 0,
        "security_conclusion": "NO_VULNERABILITY_CONFIRMED",
        "passing_members": ["groq:m1", "nvidia:m2"],
        "provider_warnings": [],
    }
    packet = proof_packet_from_redteam_result(
        target_identifier="my_app.py",
        claim_or_finding="audit my_app.py for vulnerabilities",
        evidence_gate_result=gate_clean,
        session_id="sess-clean-99",
    )
    assert packet["verdict"] == VERDICT_CONFIDENT_NO
    assert packet["confidence"] >= 0.90
    assert packet["merchant"] == "my_app.py"

    is_valid, _ = verify_proof_packet(packet)
    assert is_valid is True


def test_proof_packet_from_redteam_result_verified():
    # Finding confirmed by gate -> VERIFIED
    gate_confirmed = {
        "status": "PASS_GROUNDING_ONLY",
        "candidate_count": 1,
        "security_conclusion": "VULNERABILITY_CONFIRMED",
        "passing_members": ["groq:m1", "nvidia:m2", "openrouter:m3"],
        "provider_warnings": [],
    }
    packet = proof_packet_from_redteam_result(
        target_identifier="vuln_service",
        claim_or_finding="SQL injection in /login",
        evidence_gate_result=gate_confirmed,
        session_id="sess-vuln-01",
    )
    assert packet["verdict"] == VERDICT_VERIFIED
    assert packet["confidence"] >= 0.95

    is_valid, _ = verify_proof_packet(packet)
    assert is_valid is True
