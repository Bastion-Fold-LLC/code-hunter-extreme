#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: scan_repository_seams, generate_code_audit_report, seam_engine_status, print_seam_cards  # noqa: E501
# TOPICS: none
"""
Oracle Code Seam Engine
Folds Invisible Seam's deterministic assertion auditing into Oracle Hunter.

Connects:
  - Inside-Out (Invisible Seam): Repo/doc/schema AST contradiction detection & deterministic test execution.
  - Outside-In (Oracle Hunter): 8 security reflexes, Safe-Mode wire scope gating, and compound threat modeling.

invisible_seam is resolved portably:
  1. INVISIBLE_SEAM_PATH env var (single path, or os.pathsep-separated list —
     point it at the directory containing the invisible_seam package, e.g.
     the src/ dir of a src-layout checkout),
  2. portable home-relative editable-install checkouts (~/invisible-seam/src,
     ~/invisible-seam),
  3. a plain import (pip-installed invisible_seam anywhere on sys.path).

If none of those resolve, the engine reports UNAVAILABLE distinctly via
SeamUnavailableError / seam_engine_status() — it never silently returns []
(which is indistinguishable from "engine ran and found nothing").
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# ── Ensure invisible_seam is importable (portable resolution) ──────────────────
# Order: INVISIBLE_SEAM_PATH env var → portable home-relative checkouts →
# plain pip-style import.  No machine-specific hardcoded paths.


class SeamUnavailableError(RuntimeError):
    """Raised when the Invisible Seam engine cannot be imported.

    Distinct from "scan ran and found zero seams": callers must treat this as
    engine-unavailable, not as a clean bill of health.
    """


def _seam_path_candidates() -> List[Path]:
    """Build the sys.path candidate list for resolving invisible_seam."""
    candidates: List[Path] = []
    env = os.environ.get("INVISIBLE_SEAM_PATH", "")
    for part in env.split(os.pathsep):
        part = part.strip().strip('"').strip("'")
        if part:
            candidates.append(Path(part).expanduser())
    try:
        home = Path.home()
    except RuntimeError:  # extremely defensive: no resolvable home
        home = None
    if home is not None:
        candidates.extend(
            [
                home / "invisible-seam" / "src",
                home / "invisible-seam",
            ]
        )
    return candidates


_SEAM_PATHS_TRIED: List[str] = []
for _candidate in _seam_path_candidates():
    _SEAM_PATHS_TRIED.append(str(_candidate))
    try:
        if _candidate.is_dir() and str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
    except OSError:
        continue

try:
    from invisible_seam.models import Seam, SeamCandidate
    from invisible_seam.extractors.doc_extractor import extract_claims
    from invisible_seam.extractors.config_extractor import extract_config_claims
    from invisible_seam.matchers.code_matcher import match_claims

    try:
        from invisible_seam.matchers.solidity_matcher import match_solidity_doc_claim
    except ImportError:
        match_solidity_doc_claim = None
    from invisible_seam.classifier.seam_classifier import classify
    from invisible_seam.checker.check_runner import write_check, run_check

    _INVISIBLE_SEAM_AVAILABLE = True
    _INVISIBLE_SEAM_IMPORT_ERROR = ""
except ImportError as e:
    _INVISIBLE_SEAM_AVAILABLE = False
    _INVISIBLE_SEAM_IMPORT_ERROR = str(e)


def seam_engine_status() -> Dict[str, Any]:
    """Report whether the Invisible Seam engine resolved, and how / why not.

    Returns {"available": bool, "reason": str, "paths_tried": [...]} so
    callers and reports can render "engine unavailable" distinctly from
    "0 seams found".
    """
    if _INVISIBLE_SEAM_AVAILABLE:
        return {
            "available": True,
            "reason": "invisible_seam imported successfully",
            "paths_tried": list(_SEAM_PATHS_TRIED),
        }
    hint = (
        "Set INVISIBLE_SEAM_PATH to the directory containing the "
        "invisible_seam package (e.g. the src/ dir of a checkout), "
        "or pip-install invisible_seam."
    )
    return {
        "available": False,
        "reason": f"invisible_seam not importable: {_INVISIBLE_SEAM_IMPORT_ERROR}. {hint}",
        "paths_tried": list(_SEAM_PATHS_TRIED),
    }


try:
    from rich.console import Console
    from rich.text import Text
    from rich.rule import Rule

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]


def _program_scope_gate(claim_file: Path, program: Optional[Dict]) -> Tuple[bool, str]:
    """
    Check whether a seam's source file is relevant to this program's scope.

    Returns (in_scope: bool, reason: str).

    No program context → pass through (can't gate without it).
    Plugin slug present → only flag files under that slug's directory.
    out_of_scope_patterns list → skip matching files.
    Out-of-scope files are dropped by the caller (fail closed). All verdicts
    downstream belong to the 5-gate deterministic verifier, not any model pass.
    """
    file_str = str(claim_file).lower()
    # Vendored / generated code is never the program's bug — skip it with or
    # without program context (a jquery.min.js "finding" is always noise).
    for vendored in (
        "node_modules",
        "/vendor/",
        "third_party",
        "third-party",
        ".min.js",
        "jquery",
        "bootstrap",
        "site-packages",
        "/dist/",
        "/build/",
        ".git/",
    ):
        if vendored in file_str:
            return False, f"vendored/generated code ({vendored})"
    if not program:
        return True, "no-program-context"
    plugin_slug = (
        (program.get("plugin_slug") or program.get("slug") or "")
        .lower()
        .replace("-", "_")
    )
    if plugin_slug and plugin_slug not in file_str:
        return False, f"file not under plugin slug '{plugin_slug}'"
    for pat in program.get("out_of_scope_patterns", []):
        if pat.lower() in file_str:
            return False, f"matches out-of-scope pattern '{pat}'"
    return True, "in-scope"


def _map_seam_to_security_reflex(
    seam: Seam, candidate: SeamCandidate, claim_type: str = ""
) -> Tuple[str, str, str]:
    """
    Map an Invisible Seam finding into Oracle's 8 Security Reflexes & MITRE/CWE ontology.
    Returns (reflex, mitre, impact_description).
    """
    text_corpus = f"{seam.assertion_a} {seam.assertion_b} {seam.question or ''}".lower()

    # 1. Check for credential/secret/auth fallback
    if any(
        k in text_corpus
        for k in [
            "api_key",
            "secret",
            "password",
            "token",
            "auth",
            "credential",
            "admin",
            "private_key",
        ]
    ):
        if seam.classification == "PARADOX":
            return (
                "REFLEX 5: Authentication & Hardcoded Fallback Conflict",
                "CWE-798: Use of Hard-coded Credentials / CWE-1188: Insecure Default Initialization",
                "Security schema marks authentication credential as strictly required, but runtime code silently accepts an insecure default fallback.",  # noqa: E501
            )
        else:
            return (
                "REFLEX 5: Authentication Fail-Open / Bypassed Check",
                "CWE-287: Improper Authentication / CWE-754: Improper Check for Exceptional Conditions",
                "Authentication routine promises strict validation/exception on empty/malformed tokens, but fails open by returning False or continuing execution.",  # noqa: E501
            )

    # 2. Config / Schema fallback
    if "config" in text_corpus or "schema" in text_corpus or "default" in text_corpus:
        if seam.classification == "PARADOX":
            return (
                "REFLEX 1: Specification Inconsistency & Boundary Contradiction",
                "CWE-1068: Inconsistency Between Implementation and Documented Design",
                "Irreconcilable architectural contradiction between specification requirement and runtime implementation.",  # noqa: E501
            )
        return (
            "REFLEX 7: Configuration Drift & Silent Fallback Leakage",
            "CWE-16: Configuration Weakness / CWE-1068",
            "Runtime code silently applies hardcoded fallback values, violating documented fail-fast integrity constraints.",  # noqa: E501
        )

    # 3. Type hint / Null dereference / Return inconsistency
    if "return" in text_corpus or "none" in text_corpus or "list" in text_corpus:
        return (
            "REFLEX 2: Object Reference / Type Confusion & Null Pointer Risk",
            "CWE-476: NULL Pointer Dereference / CWE-843: Type Confusion",
            "Function promises never to return None or to maintain strict typing, but returns unhandled None or incompatible types under empty states.",  # noqa: E501
        )

    # 4. Default / Generic Logic Seam
    return (
        "REFLEX 8: Logic Flaw & Underspecified Contract Violation",
        "CWE-754: Improper Check for Exceptional Conditions",
        "Documented operational contract directly contradicts code AST behavior, creating reachable exploit or error condition.",  # noqa: E501
    )


def scan_repository_seams(
    repo_path: Path,
    program: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    """
    Execute Invisible Seam extraction and deterministic verification across a repository.
    Converts findings into Oracle Seam Cards with reflexive security mapping.

    Raises SeamUnavailableError when the invisible_seam engine is not importable —
    never a silent [] (which is indistinguishable from "engine ran, found nothing").
    """
    if not _INVISIBLE_SEAM_AVAILABLE:
        status = seam_engine_status()
        raise SeamUnavailableError(
            "Invisible Seam engine unavailable — scan did not run "
            "(this is NOT '0 seams found'). " + status["reason"]
        )

    repo = Path(repo_path).resolve()
    if not repo.exists() or not repo.is_dir():
        raise FileNotFoundError(
            f"Repository path does not exist or is not a directory: {repo}"
        )

    # Extract universal behavioral claims with monotonic non-colliding IDs
    doc_claims = extract_claims(repo)
    cfg_claims = extract_config_claims(repo, start_id=len(doc_claims) + 1)
    claims = [
        c
        for c in (list(doc_claims) + list(cfg_claims))
        if _program_scope_gate(c.source_file, program)[0]
    ]

    if not claims:
        return []

    candidates = match_claims(claims, repo)
    # P9: route claims the generic matcher dropped to the Solidity matcher.
    # match_claims is Python-AST-first: a claim whose subject also names a
    # Python function never reaches the Solidity fallback, so the .sol finding
    # would be lost. First-wins (no duplicate cards): only unmatched,
    # subject-bearing claims are routed, and the matcher itself fails closed
    # (None) on non-guard claims or unknown functions.
    if match_solidity_doc_claim is not None and any(repo.rglob("*.sol")):
        matched_ids = {c.claim_id for c in candidates}
        for claim in claims:
            if claim.id in matched_ids or claim.subject is None:
                continue
            try:
                extra = match_solidity_doc_claim(claim, repo)
            except (OSError, ValueError):
                continue
            if extra is not None:
                candidates.append(extra)
    claim_map = {c.id: c for c in claims}

    oracle_seams: List[Dict[str, Any]] = []
    seam_counter = 1

    # Program metadata for scope gating and card enrichment
    prog_name = (program or {}).get("name", "")
    prog_platform = (program or {}).get("platform", "")
    prog_rules = (program or {}).get("rules_text", "") or (program or {}).get(
        "policy_text", ""
    )

    for candidate in candidates:
        if not candidate.conflict:
            continue

        claim = claim_map.get(candidate.claim_id)
        if not claim:
            continue

        # ── Scope gate: skip seams outside the program's target files ─────────
        in_scope, scope_reason = _program_scope_gate(claim.source_file, program)
        if not in_scope:
            continue

        seam = classify(candidate, claim)
        canonical_id = f"S{seam_counter:03d}"
        seam = type(seam)(**{**seam.__dict__, "id": canonical_id})

        claim_type = getattr(claim, "type", "")
        check_output = ""

        if seam.classification == "FIXABLE":
            # For FIXABLE seams, write and execute the deterministic test check
            seam = write_check(seam, repo)
            seam = run_check(seam, repo)
            if seam.verdict == "CLOSED":
                # Executed check proved claim holds; false alarm dismissed
                continue
            check_output = f"Executed {seam.check} -> Verdict: {seam.verdict}"

        reflex, mitre, impact = _map_seam_to_security_reflex(
            seam, candidate, claim_type=claim_type
        )

        # Build auditable raw seam card text matching Oracle Hunter format
        # Include program context so the LLM reflex pass has full scope/rules
        raw_card = (
            f"SEAM #{seam_counter}: [{seam.classification}] {reflex}\n"
            f"REFLEX: {reflex}\n"
            f"MITRE: {mitre}\n"
            f"ASSERTION A: {seam.assertion_a} ({seam.source_a.name}:{seam.line_a})\n"
            f"ASSERTION B: {seam.assertion_b} ({seam.source_b.name}:{seam.line_b})\n"
            f"IMPACT: {impact}\n"
        )
        if prog_name:
            raw_card += f"PROGRAM: {prog_name} [{prog_platform}]\n"
        if prog_rules:
            raw_card += f"PROGRAM RULES: {prog_rules}\n"
        if seam.check:
            raw_card += f"CHECK: {seam.check}\n"
        if seam.question:
            raw_card += f"PARADOX QUESTION: {seam.question}\n"
        raw_card += f"VERDICT: {seam.verdict}\n"

        # Binary-card contract (oracle_foundation.validate_card_shape):
        # every emitted card must carry a one-line check and an expected
        # outcome, or the hunt code-lens confirm path can never confirm
        # this class. Static cards point at the localized extractor
        # evidence; executed FIXABLE cards cite their check output.
        _check_final = seam.check or (
            f"# Static finding localized by extractor at "
            f"{Path(str(seam.source_b)).name}:{seam.line_b}"
        )
        _expected = (
            "executed/localized evidence in check_output confirms Assertion B"
            if (check_output or "").strip()
            else "manual review of the localized claim pair (see check)"
        )
        _seam_dict: Dict[str, Any] = {
                "n": seam_counter,
                "id": canonical_id,
                "classification": seam.classification,
                "claim_type": claim_type,
                "reflex": reflex,
                "mitre": mitre,
                "impact": impact,
                "assertion_a": seam.assertion_a,
                "assertion_b": seam.assertion_b,
                "source_a": str(seam.source_a),
                "line_a": seam.line_a,
                "source_b": str(seam.source_b),
                "line_b": seam.line_b,
                "check": _check_final,
                "expected": _expected,
                "verdict": seam.verdict,
                "question": seam.question,
                "check_output": check_output,
                "program": prog_name,
                "platform": prog_platform,
                "raw": raw_card.strip(),
                "origin": "invisible-seam",
        }
        # Shared evidence spine: every card also carries a typed,
        # machine-verifiable finding (see oracle_evidence). Best-effort:
        # a card without evidence stays exactly as before.
        try:
            from oracle_evidence import finding_from_code_seam

            _seam_dict["evidence"] = finding_from_code_seam(_seam_dict)
        except Exception:
            pass
        oracle_seams.append(_seam_dict)
        seam_counter += 1

    return oracle_seams


def print_seam_cards(seams: List[Dict[str, Any]]) -> None:
    """Render seam cards cleanly to console."""
    if not seams:
        if RICH and console:
            console.print(
                "[dim green]No seams found. All code contracts and specifications match reality.[/dim green]"
            )
        else:
            print(
                "No seams found. All code contracts and specifications match reality."
            )
        return

    if RICH and console:
        for s in seams:
            console.print(Rule(style="dim cyan"))
            title_style = (
                "bold yellow" if s["classification"] == "FIXABLE" else "bold magenta"
            )
            verdict_style = (
                "bold green"
                if s["verdict"] in ("RESOLVED", "CERTAIN")
                else "bold yellow"
            )

            header = Text()
            header.append(
                f"SEAM #{s['n']} [{s['classification']}]  ", style=title_style
            )
            header.append(f"{s['reflex']}  ", style="bold white")
            header.append(f"[{s['verdict']}]", style=verdict_style)
            console.print(header)

            console.print(
                Text.assemble(("MITRE/CWE:    ", "bold blue"), (s["mitre"], "blue"))
            )
            console.print(
                Text.assemble(
                    ("Assertion A:  ", "bold cyan"),
                    (s["assertion_a"], "cyan"),
                    (f" ({Path(s['source_a']).name}:{s['line_a']})", "dim cyan"),
                )
            )
            console.print(
                Text.assemble(
                    ("Assertion B:  ", "bold red"),
                    (s["assertion_b"], "red"),
                    (f" ({Path(s['source_b']).name}:{s['line_b']})", "dim red"),
                )
            )
            console.print(
                Text.assemble(
                    ("Impact:       ", "bold yellow"), (s["impact"], "yellow")
                )
            )
            if s.get("check"):
                console.print(
                    Text.assemble(
                        ("Proof Check:  ", "bold green"), (s["check"], "green")
                    )
                )
            if s.get("question"):
                console.print(
                    Text.assemble(
                        ("Question:     ", "bold magenta"), (s["question"], "magenta")
                    )
                )
        console.print(Rule(style="dim cyan"))
    else:
        for s in seams:
            print("-" * 70)
            print(
                f"SEAM #{s['n']} [{s['classification']}] {s['reflex']} [{s['verdict']}]"
            )
            print(f"MITRE:        {s['mitre']}")
            print(
                f"Assertion A:  {s['assertion_a']} ({Path(s['source_a']).name}:{s['line_a']})"
            )
            print(
                f"Assertion B:  {s['assertion_b']} ({Path(s['source_b']).name}:{s['line_b']})"
            )
            print(f"Impact:       {s['impact']}")
            if s.get("check"):
                print(f"Proof Check:  {s['check']}")
            if s.get("question"):
                print(f"Question:     {s['question']}")
        print("-" * 70)


def _audit_evidence_tier(s: Dict[str, Any]) -> Tuple[str, str]:
    """Map a static seam to an honest evidence tier.

    Returns (tier, evidence). CONFIRMED only when a deterministic check was
    actually executed (non-empty check_output, not purely static extractor
    tagging) — enforcing the rule that static findings and UI inferences
    are never promoted to CONFIRMED without executed test execution.
    Everything else is a CANDIDATE.
    """
    evidence = (s.get("check_output") or "").strip()
    if evidence and not evidence.startswith("Extractor confirmed:"):
        return "CONFIRMED", evidence
    return "CANDIDATE", evidence


def generate_code_audit_report(
    repo_name: str,
    seams: List[Dict[str, Any]],
    compound_report: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a comprehensive white-hat code audit report in Markdown format."""
    n_confirmed = sum(1 for s in seams if _audit_evidence_tier(s)[0] == "CONFIRMED")
    n_candidate = len(seams) - n_confirmed
    lines = [
        f"# Oracle White-Hat Security Code Audit: {repo_name}",
        "",
        "## Executive Summary",
        f"- **Target Repository:** `{repo_name}`",
        "- **Verification Engine:** Oracle Seam Reflex (Powered by Invisible Seam + 8 Oracle Reflexes)",
        f"- **Total Code Seams Detected:** {len(seams)}",
        f"- **Confirmed (executed deterministic check):** {n_confirmed}",
        f"- **Candidates (static analysis, no executed check):** {n_candidate}",
        f"- **Architectural Paradoxes:** {sum(1 for s in seams if s['classification'] == 'PARADOX')}",
        "",
        "---",
        "",
        "## Vulnerability & Seam Details",
        "",
    ]

    for s in seams:
        tier, evidence = _audit_evidence_tier(s)
        lines += [
            f"### Seam #{s['n']}: {s['reflex']}",
            f"- **Classification:** `{s['classification']}` | **Verdict:** `{s['verdict']}`",
            f"- **Evidence tier:** `{tier}`"
            + (" — static finding, check not executed" if tier == "CANDIDATE" else ""),
            f"- **Taxonomy:** `{s['mitre']}`",
            f"- **Assertion A (Contract/Claim):** `{s['assertion_a']}` ({Path(s['source_a']).name}:{s['line_a']})",
            f"- **Assertion B (Code Behavior):** `{s['assertion_b']}` ({Path(s['source_b']).name}:{s['line_b']})",
            f"- **Security Impact:** {s['impact']}",
        ]
        if s.get("check"):
            lines.append(f"- **Deterministic PoC Check:** `{s['check']}`")
        if evidence:
            lines.append(f"- **Executed check evidence:** `{evidence[:500]}`")
        if s.get("question"):
            lines.append(f"- **Architectural Question:** {s['question']}")
        lines.append("")

    if compound_report and compound_report.get("report"):
        lines += [
            "---",
            "",
            "## Compound Threat Modeling (Multi-Seam Chain Analysis)",
            "",
            compound_report["report"],
            "",
        ]

    return "\n".join(lines)
