#!/usr/bin/env python3
"""Red-team the TRUST CORE: try to force a false CONFIRMED through the 5 gates,
and try to fabricate a bogus Critical chain. Every attack MUST fail safely
(REJECT / no chain). A single attack that CONFIRMS or chains is a hole.

This is the coverage the 2026-10-04 audit was missing: nobody had attacked the
verifier's "can't be fooled" claim or the (new) chaining engine. Runs with no
network — pure adversarial inputs. Exit 0 = the core held.

    python3 tests/test_redteam_verifier.py
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from oracle_deterministic import verify_seam_card          # noqa: E402
from oracle_hunter import ProgramScopeGate                 # noqa: E402
from oracle_mindset_context import OracleMindsetContext     # noqa: E402

PROG = {"name": "victim", "platform": "hackerone", "structured_scopes": [
    {"asset_identifier": "api.victim.com", "asset_type": "DOMAIN",
     "eligible_for_bounty": True, "eligible_for_submission": True}]}
GATE = ProgramScopeGate(PROG, target_fallback="api.victim.com")
RECON = ["http://api.victim.com/"]


def _seam(check, expected="status 200", src="program_policy"):
    return {"n": 1, "check": check, "assertion_a": "claims protected",
            "assertion_b": "open", "assertion_a_source": src, "expected": expected}


# Each: (name, seam, status, body) — ALL must REJECT.
ATTACKS = [
    ("lookalike-host grounding bypass",
     _seam("curl -i -s 'http://api.victim.com.evil.com/x'"), 200, "HTTP/1.1 200 OK\n\nx"),
    ("userinfo @-trick host confusion",
     _seam("curl -i -s 'http://api.victim.com@evil.com/x'"), 200, "HTTP/1.1 200 OK\n\nx"),
    ("out-of-scope host",
     _seam("curl -i -s 'http://other.com/x'"), 200, "HTTP/1.1 200 OK\n\nx"),
    ("no status code in Expected (Gate 3)",
     _seam("curl -i -s 'http://api.victim.com/x'", expected="body contains anything"),
     200, "HTTP/1.1 200 OK\n\nx"),
    ("no claim source (Gate 4)",
     _seam("curl -i -s 'http://api.victim.com/x'", src=""), 200, "HTTP/1.1 200 OK\n\nx"),
    ("wire mismatch: expected 200, boundary returns 403 (Gate 5)",
     _seam("curl -i -s 'http://api.victim.com/x'", expected="status 200"),
     403, "HTTP/1.1 403 Forbidden\n\n{\"error\":\"forbidden\"}"),
    ("body predicate forge: marker absent",
     _seam("curl -i -s 'http://api.victim.com/x'",
           expected='status 200, body contains "AWS_SECRET"'),
     200, "HTTP/1.1 200 OK\n\n{\"status\":\"ok\"}"),
]


def run_verifier_redteam():
    fails = []
    for name, seam, status, body in ATTACKS:
        v = verify_seam_card(seam, RECON, scope_gate=GATE, status=status, body=body)
        if v["verdict"] == "CONFIRMED":
            fails.append(f"  HOLE: verifier CONFIRMED an attack — {name}")
    return fails


def run_chain_redteam():
    fails = []
    ctx = OracleMindsetContext(program={"name": "t", "platform": "direct"},
                               voice=False, mindset="mitre")
    # Bogus: outputs and preconditions do NOT match (keyword-similar, not equal).
    bogus = [
        {"seam": {"n": 1, "impact": "low", "assertion_a": "a"}, "chain_outputs": ["internal_urls"]},
        {"seam": {"n": 2, "impact": "low", "assertion_a": "b"}, "chain_preconditions": ["internal_url"]},
    ]
    chains = [c for c in ctx.chain_seams(bogus) if c.get("type") == "chain"]
    if chains:
        fails.append("  HOLE: chain formed on NON-matching output/precondition (keyword guess)")
    # Positive control: an exact binding MUST chain (proves the test can detect chains).
    # #22: the sink's executed check consumes the binding (wire-grounded edge).
    real = [
        {"seam": {"n": 1, "impact": "low", "assertion_a": "a"}, "chain_outputs": ["internal_url"]},
        {"seam": {"n": 2, "impact": "low", "assertion_a": "b",
                 "check": "curl -s http://h.test/internal_url"}, "chain_preconditions": ["internal_url"]},
    ]
    if not [c for c in ctx.chain_seams(real) if c.get("type") == "chain"]:
        fails.append("  BROKEN: exact-binding chain did NOT form (chain engine dead)")
    return fails


def main() -> int:
    fails = run_verifier_redteam() + run_chain_redteam()
    print(f"red-team: {len(ATTACKS)} verifier attacks + 2 chain attacks")
    if fails:
        print("RESULT: FAIL — a red-team attack succeeded")
        print("\n".join(fails))
        return 1
    print("RESULT: PASS — verifier rejected every forge, chain engine resisted fabrication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
