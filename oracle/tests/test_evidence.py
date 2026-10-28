"""Shared evidence spine: code-seam findings become typed, verifiable checks."""
from __future__ import annotations

from pathlib import Path

import pytest

from oracle_code_seam import scan_repository_seams, seam_engine_status
from oracle_evidence import dedupe_findings, finding_from_code_seam, verify_finding

_SEAM_STATUS = seam_engine_status()
requires_seam_engine = pytest.mark.skipif(
    not _SEAM_STATUS["available"],
    reason=_SEAM_STATUS["reason"],
)

README_CONTRACT = (
    "# Auth Service\n\n"
    "### `authenticate(token)`\n\n"
    "Raises ValueError when the token is empty.\n"
)

BAD = '''
def authenticate(token: str) -> bool:
    """Raises ValueError when the token is empty."""
    if not token:
        return False
    return True
'''

SAFE = '''
def authenticate(token: str) -> bool:
    """Raises ValueError when the token is empty."""
    if not token:
        raise ValueError("empty token")
    return True
'''


def _seam(tmp_path: Path, source: str):
    (tmp_path / "README.md").write_text(README_CONTRACT, encoding="utf-8")
    sub = tmp_path / "src"
    sub.mkdir(exist_ok=True)
    (sub / "app.py").write_text(source, encoding="utf-8")
    seams = scan_repository_seams(tmp_path)
    assert len(seams) >= 1, seams
    return seams[0]


@requires_seam_engine
def test_code_seam_finding_carries_typed_static_check(tmp_path):
    seam = _seam(tmp_path, BAD)
    finding = seam["evidence"]
    assert finding["check_spec"]["kind"] == "static_seam"
    assert "language" not in finding["check_spec"]
    assert finding["location"]["line"] >= 1
    assert finding["evidence_tier"] == "CANDIDATE"
    assert finding_from_code_seam(seam)["fingerprint"] == finding["fingerprint"]


@requires_seam_engine
def test_static_verifier_confirms_subdirectory_seam_then_rejects_after_fix(tmp_path):
    seam = _seam(tmp_path, BAD)
    finding = seam["evidence"]
    assert verify_finding(finding)["verdict"] == "STATIC_CONFIRMED"
    (tmp_path / "src" / "app.py").write_text(SAFE, encoding="utf-8")
    assert verify_finding(finding)["verdict"] == "REJECTED"


def _manual_finding(tmp_path: Path):
    """Language-agnostic finding that does not need the seam engine installed."""
    return finding_from_code_seam(
        {
            "claim_type": "doc-code",
            "reflex": "REFLEX 5: Authentication Fail-Open / Bypassed Check",
            "assertion_a": "Endpoint requires authenticated session",
            "assertion_b": "Handler executes without checking session",
            "source_a": str(tmp_path / "README.md"),
            "line_a": 10,
            "source_b": str(tmp_path / "handler.ext"),
            "line_b": 42,
            "check": "# static",
            "origin": "invisible-seam",
        }
    )


def test_static_verifier_missing_file_is_inconclusive(tmp_path):
    finding = _manual_finding(tmp_path)
    finding["location"] = dict(finding["location"], file=str(tmp_path / "gone.ext"))
    assert verify_finding(finding)["verdict"] == "INCONCLUSIVE"


def test_dedupe_findings_by_fingerprint(tmp_path):
    finding = _manual_finding(tmp_path)
    assert dedupe_findings([finding, dict(finding)]) == [finding]
