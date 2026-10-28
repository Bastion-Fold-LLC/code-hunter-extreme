#!/usr/bin/env python3
# LAYER: seal
# DEST: basilisk
# ENDPOINTS: finding_from_code_seam, verify_finding, dedupe_findings
# TOPICS: evidence, verification, findings
"""Shared evidence spine for Oracle findings.

Every producer (Invisible Seam today; template/Web3/Omni adapters next)
normalizes into one finding shape with a *typed* check:

    {kind: static_seam | command | http | manual, ...machine fields...}

Free-text ``check``/``expected`` prose cannot be verified. A typed check
can be dispatched deterministically. Static confirmation is deliberately
labeled STATIC_CONFIRMED — it proves the cited code pattern persists,
not that it is exploitable against a live target.
"""
from __future__ import annotations

import hashlib
import os
import shlex
from pathlib import Path
from typing import Any, Dict, List

def _fingerprint(location: Dict[str, Any], bug_class: str, assertion_b: str) -> str:
    raw = "|".join(
        [
            str(location.get("file", "")),
            str(location.get("line", "")),
            bug_class,
            assertion_b.strip().lower(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _check_spec(seam: Dict[str, Any], location: Dict[str, Any]) -> Dict[str, Any]:
    claim_type = str(seam.get("claim_type") or seam.get("classification") or "")
    check = str(seam.get("check") or "").strip()
    if check.startswith(("slither", "forge", "cast", "pytest")):
        return {"kind": "command", "argv": shlex.split(check)}
    if check.startswith("curl") or "http://" in check or "https://" in check:
        return {"kind": "http", "check": check, "expected": seam.get("expected", "")}
    if location.get("file") and int(location.get("line") or 0) > 0:
        return {
            "kind": "static_seam",
            "claim_type": claim_type,
            "file": location["file"],
            "line": location["line"],
        }
    return {"kind": "manual", "check": check}


def finding_from_code_seam(seam: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one oracle_code_seam card into the shared language-agnostic finding shape."""
    source_a = str(seam.get("source_a") or "")
    source_b = str(seam.get("source_b") or "")
    file = source_b or source_a
    line = seam.get("line_b") or seam.get("line_a") or 0
    location = {
        "file": file,
        "line": int(line or 0),
        "source_a": source_a,
        "source_b": source_b,
    }
    claim_type = str(seam.get("claim_type") or seam.get("classification") or "")
    bug_class = str(seam.get("reflex") or claim_type or "unknown")
    assertion_b = str(seam.get("assertion_b") or "")
    return {
        "schema": "oracle.evidence/v1",
        "fingerprint": _fingerprint(location, bug_class, assertion_b),
        "origin": str(seam.get("origin") or "invisible-seam"),
        "bug_class": bug_class,
        "claim_type": claim_type,
        "assertion_a": str(seam.get("assertion_a") or ""),
        "assertion_b": assertion_b,
        "location": location,
        "check_spec": _check_spec(seam, location),
        "evidence_tier": "CANDIDATE",
        "mitre": seam.get("mitre", ""),
        "reflex": seam.get("reflex", ""),
    }


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Order-preserving dedupe by finding fingerprint."""
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        fp = str(finding.get("fingerprint") or "")
        if fp and fp in seen:
            continue
        seen.add(fp)
        out.append(finding)
    return out


def _resolve_scan_root(file: Path, loc: Dict[str, Any]) -> Path:
    dirs = [str(file.resolve().parent)]
    for key in ("source_a", "source_b"):
        raw = str(loc.get(key) or "").strip()
        if raw:
            p = Path(raw)
            if p.exists():
                dirs.append(str(p.resolve().parent if p.is_file() else p.resolve()))
    try:
        common = Path(os.path.commonpath(dirs))
        if common.is_dir():
            return common
    except ValueError:
        pass
    return file.resolve().parent


def _verify_static_seam(finding: Dict[str, Any]) -> Dict[str, Any]:
    spec = finding.get("check_spec") or {}
    loc = finding.get("location") or {}
    file = Path(str(loc.get("file") or ""))
    line = int(loc.get("line") or 0)
    if not file.is_file():
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"evidence file missing: {file}",
            "tier": "CANDIDATE",
        }
    try:
        from oracle_code_seam import scan_repository_seams, seam_engine_status

        status = seam_engine_status()
        if not status["available"]:
            return {
                "verdict": "INCONCLUSIVE",
                "reason": status["reason"],
                "tier": "CANDIDATE",
            }
        scan_root = _resolve_scan_root(file, loc)
        seams = scan_repository_seams(scan_root)
    except Exception as exc:
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"static seam verifier unavailable: {exc}",
            "tier": "CANDIDATE",
        }
    resolved = file.resolve()
    expected_type = str(spec.get("claim_type") or finding.get("claim_type") or "")
    for s in seams:
        cand_file = str(s.get("source_b") or s.get("source_a") or "")
        cand_line = int(s.get("line_b") or s.get("line_a") or 0)
        cand_type = str(s.get("claim_type") or s.get("classification") or "")
        try:
            same_file = Path(cand_file).resolve() == resolved
        except OSError:
            same_file = cand_file == str(file)
        if same_file and cand_line == line and (not expected_type or cand_type == expected_type):
            return {
                "verdict": "STATIC_CONFIRMED",
                "reason": "Seam conflict reproduced at the cited location",
                "tier": "STATIC_CONFIRMED",
            }
    return {
        "verdict": "REJECTED",
        "reason": "Seam conflict no longer present at the cited location",
        "tier": "CANDIDATE",
    }


def verify_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch one normalized finding to its deterministic verifier."""
    kind = str((finding.get("check_spec") or {}).get("kind") or "")
    if kind in ("static_seam", "static_ast"):
        return _verify_static_seam(finding)
    return {
        "verdict": "INCONCLUSIVE",
        "reason": f"check kind {kind!r} is verified by its existing engine, not here",
        "tier": str(finding.get("evidence_tier") or "CANDIDATE"),
    }
