"""Kinetic Axiom implementation for OmniCLI.

Based on the official Axiomatic Intelligence protocol (Quoc, 2026,
DOI: 10.5281/zenodo.18190481). Implements post-probabilistic quad-vector truth
adjudication, epistemic classification, variable decay rates, and signal-gated
mutation triggers for verifiable security and software assertions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Union

from omnicli.proof_packet import (
    DECAY_MODERATE,
    DECAY_RAPID,
    DECAY_SLOW,
    compute_staleness,
)


EPISTEMIC_PHYSICAL = "Physical"
EPISTEMIC_TRANSACTIONAL = "Transactional"
EPISTEMIC_SENTIMENT = "Sentiment"

ALLOWED_EPISTEMIC_TYPES = frozenset({
    EPISTEMIC_PHYSICAL,
    EPISTEMIC_TRANSACTIONAL,
    EPISTEMIC_SENTIMENT,
})

EPISTEMIC_TO_DECAY = {
    EPISTEMIC_PHYSICAL: DECAY_SLOW,
    EPISTEMIC_TRANSACTIONAL: DECAY_MODERATE,
    EPISTEMIC_SENTIMENT: DECAY_RAPID,
}


@dataclass(frozen=True)
class MutationTrigger:
    """Condition that forces re-verification when observed in real-world signal."""
    trigger_type: str
    threshold: str

    def to_dict(self) -> Dict[str, str]:
        return {"trigger_type": self.trigger_type, "threshold": self.threshold}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MutationTrigger:
        if not isinstance(data, dict):
            raise ValueError("MutationTrigger data must be a dict")
        ttype = data.get("trigger_type")
        thresh = data.get("threshold", "")
        if not isinstance(ttype, str) or not ttype.strip():
            raise ValueError("trigger_type must be a non-empty string")
        return cls(trigger_type=ttype.strip(), threshold=str(thresh).strip())


@dataclass
class QuadVectors:
    """The Quad-Vector Architecture for adversarial truth collision."""
    marketing_thesis: str = ""       # Vector 1: Subjective/promoted claims
    physics_measurement: str = ""    # Vector 2: Deterministic AST, code syntax, bytes
    consensus_signal: str = ""       # Vector 3: Multi-model independent council consensus
    proprietary_ore: str = ""        # Vector 4: Real dynamic telemetry, HTTP traffic

    def to_dict(self) -> Dict[str, str]:
        return {
            "marketing_thesis": self.marketing_thesis,
            "physics_measurement": self.physics_measurement,
            "consensus_signal": self.consensus_signal,
            "proprietary_ore": self.proprietary_ore,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> QuadVectors:
        if not data:
            return cls()
        return cls(
            marketing_thesis=str(data.get("marketing_thesis", "")),
            physics_measurement=str(data.get("physics_measurement", "")),
            consensus_signal=str(data.get("consensus_signal", "")),
            proprietary_ore=str(data.get("proprietary_ore", "")),
        )


@dataclass
class KineticAxiom:
    """The atomic unit of verified truth under the Axiomatic Intelligence protocol."""
    claim: str
    confidence_score: float
    epistemic_type: str
    mutation_triggers: List[MutationTrigger] = field(default_factory=list)
    vectors: QuadVectors = field(default_factory=QuadVectors)
    last_verified: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    proof_packet: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.claim, str) or not self.claim.strip():
            raise ValueError("KineticAxiom claim must be a non-empty string")
        if not isinstance(self.confidence_score, (int, float)) or not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError(f"confidence_score must be between 0.0 and 1.0, got {self.confidence_score}")
        if self.epistemic_type not in ALLOWED_EPISTEMIC_TYPES:
            raise ValueError(f"Invalid epistemic_type: '{self.epistemic_type}'. Allowed: {sorted(ALLOWED_EPISTEMIC_TYPES)}")

    @property
    def decay_rate(self) -> str:
        return EPISTEMIC_TO_DECAY[self.epistemic_type]

    def staleness(self, now: Optional[datetime] = None) -> str:
        return compute_staleness(self.last_verified, self.decay_rate, now=now)

    def evaluate_mutation_triggers(self, observed_events: List[Dict[str, Any]]) -> List[str]:
        """Check observed events against mutation triggers.

        Returns list of trigger_types that fired, requiring re-verification.
        """
        fired = []
        for trigger in self.mutation_triggers:
            for event in observed_events:
                event_type = event.get("type") or event.get("trigger_type")
                if event_type == trigger.trigger_type:
                    # Check threshold if specified
                    if trigger.threshold:
                        event_val = event.get("value") or event.get("change")
                        if str(event_val) == trigger.threshold or trigger.threshold == "*":
                            fired.append(trigger.trigger_type)
                            break
                    else:
                        fired.append(trigger.trigger_type)
                        break
        return fired

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to canonical schema definition matching axioms.json."""
        return {
            "protocol": "Axiomatic Intelligence",
            "version": "1.0.0",
            "doi": "10.5281/zenodo.18190481",
            "entity": "Kinetic_Axiom",
            "claim": self.claim,
            "confidence_score": float(self.confidence_score),
            "epistemic_type": self.epistemic_type,
            "decay_rate": self.decay_rate,
            "staleness": self.staleness(),
            "last_verified": self.last_verified,
            "mutation_triggers": [t.to_dict() for t in self.mutation_triggers],
            "vectors": self.vectors.to_dict(),
            "proof_packet": self.proof_packet,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KineticAxiom:
        if not isinstance(data, dict):
            raise ValueError("KineticAxiom data must be a dictionary")
        claim = data.get("claim")
        if not isinstance(claim, str):
            raise ValueError("Missing or invalid claim")
        conf = data.get("confidence_score", 0.0)
        etype = data.get("epistemic_type", EPISTEMIC_PHYSICAL)
        triggers = [
            MutationTrigger.from_dict(t) for t in data.get("mutation_triggers", [])
        ]
        vectors = QuadVectors.from_dict(data.get("vectors"))
        last_v = data.get("last_verified") or datetime.now(timezone.utc).isoformat()
        packet = data.get("proof_packet")
        return cls(
            claim=claim,
            confidence_score=float(conf),
            epistemic_type=etype,
            mutation_triggers=triggers,
            vectors=vectors,
            last_verified=last_v,
            proof_packet=packet,
        )
