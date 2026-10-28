#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: fuse, parse_tactics, clean_description
# TOPICS: none
"""Fuse Bugbase's MITRE ATT&CK TTP library with the Oracle mindset.

Reads the scraped Bugbase MITRE data (recon/bugbase_mitre/) and emits, per TTP,
an Oracle-shaped hunt template: which discovery reflex drives it, which paradox
frames it, a tactic-specific "you never said" seed, and blank Assertion A / B /
one-curl / verdict / impact slots to fill per target.

Deterministic: tactic -> reflex is a fixed table, no model in the loop. Fails
loudly on missing inputs rather than guessing.

Outputs:
    oracle_ttps_fused.json    machine-consumable (oracle_hunter.py / oracle.py)
    ORACLE_TTP_PLAYBOOK.md    human-readable playbook

Usage:
    python3 oracle_ttp_fuse.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
SRC_JSON = HERE / "recon" / "bugbase_mitre" / "all_ttps.json"
SRC_TACTIC_MD = HERE / "recon" / "bugbase_mitre" / "mitre_all_ttps.md"
OUT_JSON = HERE / "oracle_ttps_fused.json"
OUT_MD = HERE / "ORACLE_TTP_PLAYBOOK.md"

# The 11 reflexes, each with the paradox that teaches it (from ORACLE_SYSTEM_PROMPT.md).
# 1-5 = discovery reflexes (mapped from ATT&CK tactic)
# 6-8 = closing motions (applied to every finding)
# 9-11 = cross-cutting reflexes (trust-claim bypass, alternate-path auth gap, forgotten infrastructure)
REFLEXES: Dict[int, Dict[str, str]] = {
    1: {
        "name": "SPEC-AUDIT",
        "paradox": "The Mirror That Remembers",
        "move": "For every protection the target claims, ask by what layer it is enforced. "
        "The claim minus the enforcement layer is the test.",
    },
    2: {
        "name": "DECOUPLE",
        "paradox": "Vacuum Consciousness",
        "move": "Split every assumed binding: authn != authz, token != credential, "
        "identity != ownership, input != vector.",
    },
    3: {
        "name": "AXIOM-REWRITE",
        "paradox": "Repulsive Gravity",
        "move": "When a test seems blocked, the blocking rule is the variable. Change the key, "
        "the sink, the channel; do not fight the filter on its own axiom.",
    },
    4: {
        "name": "AMBIGUITY IS THE VECTOR",
        "paradox": "Single-Token Language",
        "move": "Find the undefined term in the docs/flow and pin it. The bug lives in the ambiguity.",
    },
    5: {
        "name": "HIERARCHICAL RECALL",
        "paradox": "Universe Without Death",
        "move": "Map the target to a class already broken (BOLA, IDOR, open redirect); pull the "
        "known break, then confirm it applies.",
    },
    6: {
        "name": "CLEAN vs NOT-YET-FOUND",
        "paradox": "Observer That Consumes Observation",
        "move": "State honestly: actually clean (server recomputes, real check) or not-yet-found "
        "(a seam exists, not isolated). The anti-false-positive reflex.",
    },
    7: {
        "name": "RECURSIVE VALIDATION",
        "paradox": "The Self-Observing Equation",
        "move": "A finding is real only when one reproducible command's output IS the proof. "
        "If it needs a paragraph to argue, it is not found yet.",
    },
    8: {
        "name": "BINARY CONFLICT + ONE CHECK",
        "paradox": "The iPhone Problem",
        "move": "Surface only the two irreconcilable assertions plus one reproducible check. "
        "Never dump the log.",
    },
    9: {
        "name": "TRUST-CLAIM BYPASS",
        "paradox": "The Beautiful Liar",
        "move": "The server claims a role or identity is validated — but the claim is just a story it tells. "
        "The actual enforcement layer never existed or trusts the client. "
        "Inject the claim directly (X-Original-Role: admin) and observe.",
    },
    10: {
        "name": "ALTERNATE-PATH AUTH GAP",
        "paradox": "The Cliff and the Current",
        "move": "The auth middleware says stay in your lane — except it only covers the documented path. "
        "The current flows around the cliff. Jump off: try the path the auth rule never reached "
        "(internal alias, legacy route, mobile API, alternate spelling).",
    },
    11: {
        "name": "FORGOTTEN INFRASTRUCTURE",
        "paradox": "The Invisible Architect",
        "move": "The builder becomes invisible the moment the building becomes infrastructure. "
        "Nobody thinks about who invented paper. The scaffolding used to build the app "
        "(dependency files, build configs, lockfiles, backup configs, Dockerfiles) "
        "was never meant to be permanent, but it's still there, served from the web root. "
        "Check: plain GET. Expected: non-HTML body containing version strings, credentials, or config keys.",
    },
}

# Discovery reflexes (1-5) map deterministically from ATT&CK tactic.
# 6-8 are closing motions applied to every finding.
# 9-11 are cross-cutting reflexes (trust-claim bypass, alternate-path auth gap, forgotten infrastructure).
TACTIC_TO_REFLEX: Dict[str, int] = {
    "RECONNAISSANCE": 11,
    "COLLECTION": 1,
    "DISCOVERY": 11,
    "INITIAL ACCESS": 1,
    "CREDENTIAL ACCESS": 2,
    "PRIVILEGE ESCALATION": 2,
    "LATERAL MOVEMENT": 10,
    "PERSISTENCE": 10,
    "DEFENSE EVASION": 9,
    "COMMAND AND CONTROL": 9,
    "RESOURCE DEVELOPMENT": 11,
    "EXECUTION": 4,
    "EXFILTRATION": 5,
    "IMPACT": 5,
}

# Tactic-specific "you never said" seed — the opening question for the hunt.
TACTIC_SEED: Dict[str, str] = {
    "RECONNAISSANCE": "You never said the scaffolding is removed — only that the app is deployed.",
    "COLLECTION": "You never said the data store checks who reads it — only that the UI hides it.",
    "DISCOVERY": "You never said the hidden resource rejects enumeration — only that it is unlinked.",
    "INITIAL ACCESS": "You never said the server verifies the session — only that the login page exists.",
    "CREDENTIAL ACCESS": "You never said the token IS the credential — the real check may be elsewhere, or nowhere.",
    "PRIVILEGE ESCALATION": "You never said authentication equals authorization — you proved WHO, not that you MAY.",
    "LATERAL MOVEMENT": "You never said the auth rule reaches every path — the current flows around the cliff.",
    "PERSISTENCE": "You never said the old path is revoked — the alternate route stays open.",
    "DEFENSE EVASION": "You never said the server validates the claim — the filter's story is a lie.",
    "COMMAND AND CONTROL": "You never said the server verifies the command — it trusts the client's story.",
    "RESOURCE DEVELOPMENT": "You never said the build artifact is removed — the scaffolding stays served.",
    "EXECUTION": "You never defined how this input is interpreted — the undefined sink is the door.",
    "EXFILTRATION": "You never said this data-egress shape is new — it is a class already broken.",
    "IMPACT": "You never said this destructive action is guarded — it maps to a known harm class.",
}

TEMPLATE_SLOTS = {
    "assertion_a": "",  # what the docs / policy / UI claims
    "assertion_b": "",  # what the wire protocol actually does
    "binary_verdict": "",  # which assertion is false, and why
    "reproducible_check": "",  # ONE command whose output decides it
    "impact": "",  # one sentence: real harm to a real user who did nothing unusual
    "status": "not-yet-found",  # reflex 6: not-yet-found | clean | confirmed
}


def parse_tactics(md_path: Path) -> Dict[str, str]:
    """Return {ttp_code: TACTIC} parsed from the tactic-grouped MITRE markdown."""
    if not md_path.exists():
        raise FileNotFoundError(f"missing tactic source: {md_path}")
    code_to_tactic: Dict[str, str] = {}
    current = None
    for line in md_path.read_text(encoding="utf-8").splitlines():
        tactic_match = re.match(r"^## ([A-Z][A-Z &]+)\s*$", line)
        if tactic_match:
            current = tactic_match.group(1).strip()
            continue
        code_match = re.match(r"^### (T\d{4}(?:\.\d{3})?):", line)
        if code_match and current:
            code_to_tactic[code_match.group(1)] = current
    if not code_to_tactic:
        raise ValueError(f"parsed zero TTP->tactic pairs from {md_path}")
    return code_to_tactic


def clean_description(modal: str) -> str:
    """Strip the scraped modal boilerplate down to the description body."""
    marker = "Description\n"
    idx = modal.find(marker)
    body = modal[idx + len(marker) :] if idx != -1 else modal
    for tail in ("\nName\n", "\nPermissions_required\n", "\nPermissions\n"):
        cut = body.find(tail)
        if cut != -1:
            body = body[:cut]
    return body.strip()


def fuse() -> List[dict]:
    """Build the fused TTP records."""
    if not SRC_JSON.exists():
        raise FileNotFoundError(f"missing TTP source: {SRC_JSON}")
    ttps = json.loads(SRC_JSON.read_text(encoding="utf-8"))
    tactics = parse_tactics(SRC_TACTIC_MD)

    fused: List[dict] = []
    unmapped: List[str] = []
    for code in sorted(ttps):
        entry = ttps[code]
        tactic = tactics.get(code)
        if tactic is None:
            unmapped.append(code)
            continue
        reflex_id = TACTIC_TO_REFLEX[tactic]  # KeyError = unknown tactic, fail loud
        reflex = REFLEXES[reflex_id]
        fused.append(
            {
                "code": code,
                "name": entry["name"],
                "tactic": tactic,
                "description": clean_description(entry.get("modal", "")),
                "primary_reflex": reflex_id,
                "reflex_name": reflex["name"],
                "paradox": reflex["paradox"],
                "reflex_move": reflex["move"],
                "you_never_said": TACTIC_SEED[tactic],
                "closing_motions": {
                    "6_clean_vs_not_found": REFLEXES[6]["move"],
                    "7_recursive_validation": REFLEXES[7]["move"],
                    "8_binary_conflict": REFLEXES[8]["move"],
                    "9_trust_claim_bypass": REFLEXES[9]["move"],
                    "10_alternate_path_auth_gap": REFLEXES[10]["move"],
                    "11_forgotten_infrastructure": REFLEXES[11]["move"],
                },
                "template": dict(TEMPLATE_SLOTS),
            }
        )

    if unmapped:
        raise ValueError(
            f"{len(unmapped)} TTP(s) had no tactic in {SRC_TACTIC_MD.name} "
            f"— refusing to emit a fused library short those techniques: "
            f"{', '.join(unmapped)}"
        )
    return fused


def write_json(fused: List[dict]) -> None:
    """Write the machine-consumable fused library."""
    OUT_JSON.write_text(
        json.dumps(fused, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def write_md(fused: List[dict]) -> None:
    """Write the human-readable playbook, grouped by tactic."""
    lines: List[str] = [
        "# THE ORACLE — TTP PLAYBOOK",
        "",
        "Bugbase's MITRE ATT&CK TTP library, fused with the Oracle mindset. Each technique "
        'carries its driving reflex, the paradox that teaches it, a "you never said" seed, '
        "and blank Assertion A/B + one-curl slots to fill per target.",
        "",
        f"**{len(fused)} techniques** across {len({f['tactic'] for f in fused})} tactics. "
        "Reflexes 6/7/8 (clean-vs-not-found, recursive validation, binary-conflict) and "
        "Reflexes 9/10/11 (trust-claim bypass, alternate-path auth gap, forgotten infrastructure) "
        "apply to every finding.",
        "",
    ]
    by_tactic: Dict[str, List[dict]] = {}
    for f in fused:
        by_tactic.setdefault(f["tactic"], []).append(f)

    for tactic in sorted(by_tactic):
        group = by_tactic[tactic]
        rid = group[0]["primary_reflex"]
        lines += [
            f"## {tactic}",
            f"**Primary reflex:** {rid}. {REFLEXES[rid]['name']} — *{REFLEXES[rid]['paradox']}*  ",
            f"**You never said:** {TACTIC_SEED[tactic]}",
            "",
        ]
        for f in group:
            lines += [
                f"### {f['code']}: {f['name']}",
                f"{f['description'] or '(no description scraped)'}",
                "",
                "Assertion A (claim): _______  ",
                "Assertion B (wire): _______  ",
                "Binary verdict: _______  ",
                "Reproducible check (one command): _______  ",
                "Impact (one sentence): _______  ",
                "Status: not-yet-found",
                "",
            ]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    """Generate the fused JSON and Markdown playbook."""
    fused = fuse()
    write_json(fused)
    write_md(fused)
    print(f"[ok] fused {len(fused)} TTPs -> {OUT_JSON.name} + {OUT_MD.name}")


if __name__ == "__main__":
    main()
