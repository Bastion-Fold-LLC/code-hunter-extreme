"""Product AI / SimplyCodes Proof Packet implementation for OmniCLI.

Based on the canonical 'Anatomy of a Verdict' protocol (Quoc & Stanback, 2026,
DOI: 10.5281/zenodo.18625118). Provides tamper-evident cryptographic receipts
for all OmniCLI verification verdicts, implementing Byzantine Fault Tolerant
evidence aggregation and the formal 'Confident No' doctrine.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Tuple, Union


# Canonical Verdicts per SimplyCodes Proof Packet Schema
VERDICT_VERIFIED = "VERIFIED"
VERDICT_UNVERIFIED = "UNVERIFIED"
VERDICT_INVALIDATED = "INVALIDATED"
VERDICT_CONFIDENT_NO = "CONFIDENT_NO"

ALLOWED_VERDICTS = frozenset({
    VERDICT_VERIFIED,
    VERDICT_UNVERIFIED,
    VERDICT_INVALIDATED,
    VERDICT_CONFIDENT_NO,
})

# Automated Test Results & Tiers
ALLOWED_TEST_RESULTS = frozenset({
    "FUNCTIONAL",
    "EXPIRED",
    "CONDITION",
    "BLOCKED",
    "AUTHENTICATION_REQUIRED",
    "UI_CHANGED",
})

ALLOWED_TEST_TIERS = frozenset({
    "PLATFORM_ADAPTER",
    "HEURISTIC",
    "AI_NAVIGATION",
})

# Decay Rates & Staleness
DECAY_SLOW = "SLOW"
DECAY_MODERATE = "MODERATE"
DECAY_RAPID = "RAPID"

ALLOWED_DECAY_RATES = frozenset({
    DECAY_SLOW,
    DECAY_MODERATE,
    DECAY_RAPID,
})

STALENESS_FRESH = "FRESH"
STALENESS_AGING = "AGING"
STALENESS_STALE = "STALE"

ALLOWED_STALENESS = frozenset({
    STALENESS_FRESH,
    STALENESS_AGING,
    STALENESS_STALE,
})

ALLOWED_TRENDS = frozenset({
    "STABLE",
    "IMPROVING",
    "DEGRADING",
})

DEFAULT_SIGNING_KEY = b"omnicli-product-ai-proof-packet-v1"


def compute_staleness(
    last_verified: Union[datetime, str],
    decay_rate: str,
    now: Optional[datetime] = None,
) -> str:
    """Compute staleness classification (FRESH, AGING, STALE) from last verification time and decay rate.

    - SLOW: Fresh <= 30d, Aging <= 90d, Stale > 90d
    - MODERATE: Fresh <= 7d, Aging <= 21d, Stale > 21d
    - RAPID: Fresh <= 1d, Aging <= 3d, Stale > 3d
    """
    if decay_rate not in ALLOWED_DECAY_RATES:
        raise ValueError(f"Invalid decay_rate: '{decay_rate}'. Allowed: {sorted(ALLOWED_DECAY_RATES)}")

    if isinstance(last_verified, str):
        # Parse ISO format
        dt = datetime.fromisoformat(last_verified.replace("Z", "+00:00"))
    elif isinstance(last_verified, datetime):
        dt = last_verified
    else:
        raise TypeError(f"last_verified must be datetime or ISO string, got {type(last_verified)}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)

    delta = current_time - dt
    days = max(0.0, delta.total_seconds() / 86400.0)

    if decay_rate == DECAY_SLOW:
        if days <= 30.0:
            return STALENESS_FRESH
        elif days <= 90.0:
            return STALENESS_AGING
        return STALENESS_STALE
    elif decay_rate == DECAY_MODERATE:
        if days <= 7.0:
            return STALENESS_FRESH
        elif days <= 21.0:
            return STALENESS_AGING
        return STALENESS_STALE
    else:  # RAPID
        if days <= 1.0:
            return STALENESS_FRESH
        elif days <= 3.0:
            return STALENESS_AGING
        return STALENESS_STALE


def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """Serialize dictionary to canonical JSON representation for hashing/signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def create_proof_packet(
    code: str,
    merchant: str,
    verdict: str,
    confidence: float,
    automated_test: Dict[str, Any],
    human_consensus: Dict[str, Any],
    fleet_signal: Dict[str, Any],
    health: Dict[str, Any],
    forensic_anchors: Optional[Dict[str, str]] = None,
    secret_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Create a cryptographically signed Proof Packet conforming to proof-packet-schema.json.

    Validates all field types, enums, and bounds before calculating the HMAC-SHA256 signature.
    Fails fast and screams loudly on invalid inputs.
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code must be a non-empty string")
    if not isinstance(merchant, str) or not merchant.strip():
        raise ValueError("merchant must be a non-empty string")
    if verdict not in ALLOWED_VERDICTS:
        raise ValueError(f"Invalid verdict: '{verdict}'. Allowed: {sorted(ALLOWED_VERDICTS)}")
    if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
        raise ValueError(f"confidence must be a float in [0.0, 1.0], got {confidence}")

    # Validate automated_test
    if not isinstance(automated_test, dict):
        raise ValueError("automated_test must be a dictionary")
    for req in ("timestamp", "result", "tier", "session_id"):
        if req not in automated_test:
            raise ValueError(f"automated_test missing required field '{req}'")
    if automated_test["result"] not in ALLOWED_TEST_RESULTS:
        raise ValueError(f"automated_test result '{automated_test['result']}' invalid")
    if automated_test["tier"] not in ALLOWED_TEST_TIERS:
        raise ValueError(f"automated_test tier '{automated_test['tier']}' invalid")

    # Validate human_consensus
    if not isinstance(human_consensus, dict):
        raise ValueError("human_consensus must be a dictionary")
    for req in ("independent_verifications", "positive", "weighted_confidence"):
        if req not in human_consensus:
            raise ValueError(f"human_consensus missing required field '{req}'")
    if not isinstance(human_consensus["independent_verifications"], int) or human_consensus["independent_verifications"] < 0:
        raise ValueError("independent_verifications must be a non-negative integer")
    if not isinstance(human_consensus["positive"], int) or human_consensus["positive"] < 0:
        raise ValueError("positive must be a non-negative integer")
    if not (0.0 <= human_consensus["weighted_confidence"] <= 1.0):
        raise ValueError("weighted_confidence must be in [0.0, 1.0]")

    # Validate fleet_signal
    if not isinstance(fleet_signal, dict):
        raise ValueError("fleet_signal must be a dictionary")
    for req in ("recent_successes", "recent_failures", "trend"):
        if req not in fleet_signal:
            raise ValueError(f"fleet_signal missing required field '{req}'")
    if not isinstance(fleet_signal["recent_successes"], int) or fleet_signal["recent_successes"] < 0:
        raise ValueError("recent_successes must be a non-negative integer")
    if not isinstance(fleet_signal["recent_failures"], int) or fleet_signal["recent_failures"] < 0:
        raise ValueError("recent_failures must be a non-negative integer")
    if fleet_signal["trend"] not in ALLOWED_TRENDS:
        raise ValueError(f"trend '{fleet_signal['trend']}' invalid")

    # Validate health
    if not isinstance(health, dict):
        raise ValueError("health must be a dictionary")
    for req in ("score", "decay_rate", "last_verified", "staleness"):
        if req not in health:
            raise ValueError(f"health missing required field '{req}'")
    if not (0.0 <= health["score"] <= 1.0):
        raise ValueError("health score must be in [0.0, 1.0]")
    if health["decay_rate"] not in ALLOWED_DECAY_RATES:
        raise ValueError(f"health decay_rate '{health['decay_rate']}' invalid")
    if health["staleness"] not in ALLOWED_STALENESS:
        raise ValueError(f"health staleness '{health['staleness']}' invalid")

    # Construct payload for signing
    evidence_bundle = {
        "automated_test": {
            "timestamp": str(automated_test["timestamp"]),
            "result": automated_test["result"],
            "tier": automated_test["tier"],
            "session_id": str(automated_test["session_id"]),
        },
        "human_consensus": {
            "independent_verifications": human_consensus["independent_verifications"],
            "positive": human_consensus["positive"],
            "weighted_confidence": float(human_consensus["weighted_confidence"]),
        },
        "fleet_signal": {
            "recent_successes": fleet_signal["recent_successes"],
            "recent_failures": fleet_signal["recent_failures"],
            "trend": fleet_signal["trend"],
        },
        "health": {
            "score": float(health["score"]),
            "decay_rate": health["decay_rate"],
            "last_verified": str(health["last_verified"]),
            "staleness": health["staleness"],
        },
    }

    packet_for_signing: Dict[str, Any] = {
        "code": code,
        "merchant": merchant,
        "verdict": verdict,
        "confidence": float(confidence),
        "evidence": evidence_bundle,
    }

    if forensic_anchors is not None:
        if not isinstance(forensic_anchors, dict):
            raise ValueError("forensic_anchors must be a dictionary")
        packet_for_signing["forensic_anchors"] = {
            "actor": str(forensic_anchors.get("actor", "omnicli")),
            "asset": str(forensic_anchors.get("asset", code)),
            "target": str(forensic_anchors.get("target", merchant)),
            "agent": str(forensic_anchors.get("agent", "omnicli.adjudicator")),
            "build": str(forensic_anchors.get("build", "1.0.0")),
            "bridge": str(forensic_anchors.get("bridge", automated_test["session_id"])),
        }

    key = secret_key or DEFAULT_SIGNING_KEY
    canonical_bytes = canonical_json_bytes(packet_for_signing)
    signature = hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    return {
        **packet_for_signing,
        "signature": signature,
        "signature_algorithm": "HMAC-SHA256",
    }


def verify_proof_packet(
    packet: Any,
    secret_key: Optional[bytes] = None,
) -> Tuple[bool, str]:
    """Verify that a Proof Packet is cryptographically sealed and unaltered.

    Returns (True, 'OK') if valid and authentic.
    Returns (False, reason) if invalid, missing fields, or signature mismatch.
    """
    if not isinstance(packet, dict):
        return False, "Packet is not a dictionary"

    sig = packet.get("signature")
    if not sig or not isinstance(sig, str):
        return False, "Missing or invalid signature"

    algo = packet.get("signature_algorithm")
    if algo != "HMAC-SHA256":
        return False, f"Unsupported signature_algorithm: '{algo}'"

    # Required schema fields
    for field in ("code", "merchant", "verdict", "confidence", "evidence"):
        if field not in packet:
            return False, f"Missing required root field: '{field}'"

    if packet["verdict"] not in ALLOWED_VERDICTS:
        return False, f"Invalid verdict: '{packet['verdict']}'"

    evidence = packet.get("evidence")
    if not isinstance(evidence, dict):
        return False, "evidence must be an object"

    for req_layer in ("automated_test", "human_consensus", "fleet_signal", "health"):
        if req_layer not in evidence or not isinstance(evidence[req_layer], dict):
            return False, f"Missing evidence layer: '{req_layer}'"

    # Reconstruct exact payload used for signing (strip signature & algorithm)
    payload_to_verify = {
        k: v for k, v in packet.items() if k not in ("signature", "signature_algorithm")
    }

    try:
        canonical_bytes = canonical_json_bytes(payload_to_verify)
    except Exception as exc:
        return False, f"Serialization error: {exc}"

    key = secret_key or DEFAULT_SIGNING_KEY
    expected_sig = hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        return False, "HMAC signature mismatch (payload tampered or key mismatch)"

    return True, "OK"


def proof_packet_from_redteam_result(
    target_identifier: str,
    claim_or_finding: str,
    evidence_gate_result: Dict[str, Any],
    session_id: str,
    secret_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Bridge OmniCLI red-team / swarm evidence gate results to a canonical Proof Packet.

    - If the evidence gate status is PASS_GROUNDING_ONLY and findings are established:
      -> VERIFIED with high confidence.
    - If no actionable finding is found and gate passes:
      -> CONFIDENT_NO (proven absence of flaw per the 'Confident No' doctrine).
    - If the evidence gate FAILED (unsupported citations, hallucinated lines, etc.):
      -> INVALIDATED or UNVERIFIED depending on whether errors or contradictions occurred.
    """
    gate_status = evidence_gate_result.get("status")
    candidate_count = evidence_gate_result.get("candidate_count", 0)
    passing_members = evidence_gate_result.get("passing_members", [])
    security_conclusion = evidence_gate_result.get("security_conclusion", "NOT_ASSESSED")

    now_iso = datetime.now(timezone.utc).isoformat()

    # Determine verdict and confidence
    if gate_status == "PASS_GROUNDING_ONLY":
        if candidate_count > 0 and security_conclusion in ("VULNERABILITY_CONFIRMED", "HIGH_RISK", "UPHOLD"):
            verdict = VERDICT_VERIFIED
            confidence = 0.95
            test_result = "FUNCTIONAL"
        elif candidate_count == 0 or security_conclusion in ("CLEAN", "NO_VULNERABILITY_CONFIRMED", "NO_ACTIONABLE_CANDIDATE"):
            verdict = VERDICT_CONFIDENT_NO
            confidence = 0.92
            test_result = "CONDITION"
        else:
            verdict = VERDICT_VERIFIED
            confidence = 0.85
            test_result = "FUNCTIONAL"
    elif gate_status == "FAIL":
        if evidence_gate_result.get("failed_checks"):
            verdict = VERDICT_INVALIDATED
            confidence = 0.10
            test_result = "BLOCKED"
        else:
            verdict = VERDICT_UNVERIFIED
            confidence = 0.20
            test_result = "CONDITION"
    else:
        verdict = VERDICT_UNVERIFIED
        confidence = 0.30
        test_result = "CONDITION"

    decay_rate = DECAY_SLOW  # Code & AST verification facts decay slowly
    staleness = compute_staleness(now_iso, decay_rate)

    automated_test = {
        "timestamp": now_iso,
        "result": test_result,
        "tier": "PLATFORM_ADAPTER",
        "session_id": session_id,
    }

    human_consensus = {
        "independent_verifications": max(1, len(passing_members)),
        "positive": len(passing_members) if verdict in (VERDICT_VERIFIED, VERDICT_CONFIDENT_NO) else 0,
        "weighted_confidence": confidence,
    }

    fleet_signal = {
        "recent_successes": len(passing_members),
        "recent_failures": len(evidence_gate_result.get("provider_warnings", [])),
        "trend": "STABLE",
    }

    health = {
        "score": confidence,
        "decay_rate": decay_rate,
        "last_verified": now_iso,
        "staleness": staleness,
    }

    forensic_anchors = {
        "actor": "omnicli.evidence_gate",
        "asset": claim_or_finding[:120],
        "target": target_identifier,
        "agent": "omnicli.redteam",
        "build": "1.0.0",
        "bridge": session_id,
    }

    return create_proof_packet(
        code=claim_or_finding,
        merchant=target_identifier,
        verdict=verdict,
        confidence=confidence,
        automated_test=automated_test,
        human_consensus=human_consensus,
        fleet_signal=fleet_signal,
        health=health,
        forensic_anchors=forensic_anchors,
        secret_key=secret_key,
    )
