"""Unit tests for OmniCLI Kinetic Axiom (Axiomatic Intelligence protocol)."""

from datetime import datetime, timezone, timedelta
import pytest

from omnicli.axiom import (
    KineticAxiom,
    MutationTrigger,
    QuadVectors,
    EPISTEMIC_PHYSICAL,
    EPISTEMIC_TRANSACTIONAL,
    EPISTEMIC_SENTIMENT,
)
from omnicli.proof_packet import (
    DECAY_SLOW,
    DECAY_MODERATE,
    DECAY_RAPID,
    STALENESS_FRESH,
    STALENESS_STALE,
)


def test_kinetic_axiom_creation_and_decay():
    axiom = KineticAxiom(
        claim="Function calculate_tax is pure with no external I/O",
        confidence_score=0.98,
        epistemic_type=EPISTEMIC_PHYSICAL,
        vectors=QuadVectors(
            physics_measurement="AST: no calls to os, sys, requests, socket",
            consensus_signal="Unanimous true positive from 4 models",
        ),
    )

    assert axiom.decay_rate == DECAY_SLOW
    assert axiom.staleness() == STALENESS_FRESH
    d = axiom.to_dict()
    assert d["protocol"] == "Axiomatic Intelligence"
    assert d["version"] == "1.0.0"
    assert d["doi"] == "10.5281/zenodo.18190481"
    assert d["claim"] == axiom.claim
    assert d["confidence_score"] == 0.98


def test_kinetic_axiom_mutation_triggers():
    triggers = [
        MutationTrigger("git_commit_change", "*"),
        MutationTrigger("package_version_bump", "major"),
    ]
    axiom = KineticAxiom(
        claim="Library argon2 is safe against GPU timing attacks",
        confidence_score=0.90,
        epistemic_type=EPISTEMIC_PHYSICAL,
        mutation_triggers=triggers,
    )

    # Irrelevant event does not fire
    fired = axiom.evaluate_mutation_triggers([{"type": "user_login", "value": "admin"}])
    assert fired == []

    # Matching event with wildcard threshold fires
    fired = axiom.evaluate_mutation_triggers([{"type": "git_commit_change", "value": "a1b2c3d"}])
    assert fired == ["git_commit_change"]

    # Matching event with matching threshold fires
    fired = axiom.evaluate_mutation_triggers([{"type": "package_version_bump", "value": "major"}])
    assert fired == ["package_version_bump"]

    # Matching event with non-matching threshold does not fire
    fired = axiom.evaluate_mutation_triggers([{"type": "package_version_bump", "value": "minor"}])
    assert fired == []


def test_kinetic_axiom_roundtrip_dict():
    original = KineticAxiom(
        claim="Endpoint /api/balance requires bearer token",
        confidence_score=0.95,
        epistemic_type=EPISTEMIC_TRANSACTIONAL,
        mutation_triggers=[MutationTrigger("route_reconfigured", "*")],
        vectors=QuadVectors(
            marketing_thesis="Docs state auth is required",
            proprietary_ore="HTTP 401 on unauthenticated request",
        ),
    )
    d = original.to_dict()
    restored = KineticAxiom.from_dict(d)

    assert restored.claim == original.claim
    assert restored.confidence_score == original.confidence_score
    assert restored.epistemic_type == original.epistemic_type
    assert restored.decay_rate == DECAY_MODERATE
    assert len(restored.mutation_triggers) == 1
    assert restored.mutation_triggers[0].trigger_type == "route_reconfigured"
    assert restored.vectors.proprietary_ore == "HTTP 401 on unauthenticated request"
