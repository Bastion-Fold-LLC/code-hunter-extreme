# Anatomy of a Verdict: How SimplyCodes Adjudicates Truth in a Broken Economy

**A Technical Whitepaper**

Michael Quoc, Bri Stanback
SimplyCodes / Product.ai | February 2026

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18625118.svg)](https://doi.org/10.5281/zenodo.18625118)


## Overview

At any given moment, 40–60% of coupon codes on the public internet are dead, restricted, or misleading. SimplyCodes covers over 400,000 merchants — an order of magnitude beyond typical competitors — and adjudicates promotional truth through a verification architecture designed around Byzantine Fault Tolerance: the assumption that any single source may be lying, malfunctioning, or mistaken.

This paper exposes the machine that produces these verdicts.

## The Verification Stack

The system operates through three independent layers, each producing evidence that feeds into the final verdict:

**Layer 1: Automated Code Testing (ACT).** Headless browsers simulating real checkout sessions across the merchant network. Tens of thousands of automated tests daily using tiered intelligence: platform adapters for standardized checkouts, heuristic pattern matching for custom platforms, and AI-powered navigation for truly custom flows.

**Layer 2: Human Consensus Network.** Tens of thousands of trained contributors producing millions of monthly verification actions. A reputation economy operating under blind voting, where verifiers cannot see each other's assessments until consensus is reached. All submissions require screenshot proof.

**Layer 3: Fleet Signal.** Real-time telemetry from browser extension users during actual checkouts. Not simulation — ground truth.

## The Verdict

These layers converge into a Health Score: a confidence measure derived from an event stream rather than stored as a static value. Every test, every human verification, every real checkout signal is a sensing event. The score decays at variable rates depending on code type (evergreen, regular, flash) and is traceable through six forensic dimensions from verdict back to raw evidence.

When the system returns "No verified codes available," that is not a failure. That is a verdict backed by evidence from all three layers. We call this the Confident No.

Every verdict can generate a Proof Packet — a structured evidence bundle documenting exactly how the conclusion was reached. This is what we serve to AI agents: verifiable proof of adjudication.

## Repository Contents

| File | Description |
| --- | --- |
| `whitepaper.md` | Full whitepaper text |
| `proof-packet-schema.json` | JSON schema for the Proof Packet evidence bundle |
| `health-score-methodology.md` | Overview of Health Score computation, decay model, and confidence tiers |
| `CITATION.cff` | Citation metadata (DOI reference) |

## Glossary

| Term | Definition |
| --- | --- |
| ACT | Automated Code Testing — headless browser systems simulating real checkout sessions |
| BFT | Byzantine Fault Tolerance — consensus model assuming any source may lie |
| Health Score | Confidence measure combining freshness, outcome, and multi-source consensus |
| Confident No | Verified absence of codes — closure, not failure |
| Proof Packet | Structured evidence bundle documenting the adjudication chain |
| Sensing Event | An immutable, raw observation from a code application — evidence, not conclusion |
| Applicability | Probability a code applies to a specific cart context |
| Fleet Signal | Real-time telemetry from browser extension users during actual checkouts |
| Constitutional Model | Structured, machine-readable conditions governing a promotion's validity |
| Forensic Anchors | Six traceability dimensions (actor, asset, target, agent, build, bridge) linking any observation to its verdict |

## Related Work

This paper is a companion to [Axiomatic Intelligence: A Post-Probabilistic Architecture for the Age of Noise](https://doi.org/10.5281/zenodo.18190481), which defines the theoretical paradigm. This paper demonstrates that paradigm operating in production.

## Citation

```bibtex
@techreport{quoc2026anatomy,
  title={Anatomy of a Verdict: How SimplyCodes Adjudicates Truth in a Broken Economy},
  author={Michael Quoc and Bri Stanback},
  year={2026},
  month={February},
  institution={SimplyCodes / Product.ai},
  doi={10.5281/zenodo.18625118}
}
```

## License

This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
