"""Oracle enforcement clean-signal: TARGET CLEAN match, lens outcomes, verdict flag."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
from oracle_mindset_context import ProgramWorkspace


def test_is_target_clean_matches_literal_line_only():
    assert oh.is_target_clean("TARGET CLEAN")
    assert oh.is_target_clean("some prose\nTARGET CLEAN\nmore prose")
    assert oh.is_target_clean("  TARGET CLEAN.  ")
    assert not oh.is_target_clean("No conflicts found. The surface looks clean.")
    assert not oh.is_target_clean("report clean findings below")
    assert not oh.is_target_clean("")
    assert not oh.is_target_clean(None)


def test_lens_outcome_four_way_split():
    seam = {"n": 1}
    assert oh.lens_outcome("TARGET CLEAN", []) == "clean"
    assert oh.lens_outcome("TARGET CLEAN", None) == "clean"
    assert oh.lens_outcome(" prose without cards ", []) == "empty"
    assert oh.lens_outcome(None, []) == "error"
    assert oh.lens_outcome("", []) == "error"
    assert oh.lens_outcome("[no backend produced output] x", []) == "error"
    assert oh.lens_outcome("TARGET CLEAN", [seam]) == "seams"  # cards win
    assert oh.lens_outcome("whatever", [seam]) == "seams"


def test_parse_seams_matches_target_clean_explicitly():
    assert oh._parse_seams("TARGET CLEAN", target_base="http://x") == []
    assert oh._parse_seams("All surfaces genuinely clean → TARGET CLEAN") == []


def test_parse_seams_strips_think_blocks():
    """<think> reasoning from DeepSeek/dahl must not be parsed as card content."""
    # think block mentions SEAM 1 — without stripping this creates a spurious card
    raw = (
        "<think>I might output SEAM 1 here as part of thinking</think>\n"
        "TARGET CLEAN"
    )
    assert oh._parse_seams(raw) == []

    # think block before real card — card must still be parsed correctly
    raw_with_card = (
        "<think>Let me think about SEAM 1 …</think>\n\n"
        "**SEAM 1**\n"
        "- Assertion A: Docs say auth required\n"
        "- Assertion B: Wire returns 200 without token\n"
        "- Reproducible check: `curl -i -s http://t.example/api/v1/admin`\n"
        "- Expected: status 200, body contains \"admin\"\n"
        "- Impact: Unauth admin access\n"
    )
    cards = oh._parse_seams(raw_with_card)
    assert len(cards) == 1
    assert "admin" in cards[0].get("expected", "")


def _seam():
    return {
        "n": 1,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without creds",
        "check": "curl -s http://h.test/api/user/2",
        "expected": "status 200",
        "reflex": "SPEC-AUDIT",
        "impact": "stub impact",
        "mitre": "T1190",
        "severity": "high",
    }


def _ws_results(confirmed: bool):
    return {
        1: {
            "seam": _seam(),
            "check": _seam()["check"],
            "output": "VULN" if confirmed else "nothing",
            "verdict": "CONFIRMED — stub" if confirmed else "CANDIDATE — stub",
            "confirmed": confirmed,
        }
    }


def test_finalize_snapshot_carries_verdict_flag(tmp_path):
    recon = tmp_path / "recon"
    recon.mkdir()
    ws = ProgramWorkspace({"name": "Lab", "platform": "lab"}, base=tmp_path)
    oh._finalize_verify(
        _ws_results(False),
        [_seam()],
        "lab-target",
        ws,
        recon_dir=recon,
        teardown_runner=lambda c: (0, "clean", ""),
        teardown_evaluator=lambda s, o: {"verdict": "PASS", "notes": "", "attacks": []},
    )
    snaps = sorted(ws.reports_dir.glob("report_verify_results*"))
    assert snaps, "no verify_results snapshot saved"
    snap = json.loads(snaps[-1].read_text(encoding="utf-8"))
    assert snap["summary"]["verdict"] == "zero-confirmed"


def test_finalize_snapshot_confirmed_and_hunt_meta(tmp_path, monkeypatch):
    recon = tmp_path / "recon"
    recon.mkdir()
    ws = ProgramWorkspace({"name": "Lab", "platform": "lab"}, base=tmp_path)
    meta = {"lens_outcomes": {"cloud-mitre": "clean"}, "tactic_coverage": {"dropped": []}}
    # Snapshot shape only: never let a confirmed seam reach the live PoC
    # synthesizer (cloud/local model calls make this test non-hermetic).
    monkeypatch.setattr(oh, "_synthesize_poc", lambda *a, **k: "# stub poc\n")
    oh._finalize_verify(
        _ws_results(True),
        [_seam()],
        "lab-target",
        ws,
        recon_dir=recon,
        teardown_runner=lambda c: (0, "VULN", ""),
        teardown_evaluator=lambda s, o: {
            "verdict": "CONFIRMED" if "VULN" in o else "REJECTED",
            "reason": "stub",
        },
        hunt_meta=meta,
    )
    snaps = sorted(ws.reports_dir.glob("report_verify_results*"))
    snap = json.loads(snaps[-1].read_text(encoding="utf-8"))
    assert snap["summary"]["verdict"] == "confirmed"
    assert snap["hunt"]["lens_outcomes"] == {"cloud-mitre": "clean"}
