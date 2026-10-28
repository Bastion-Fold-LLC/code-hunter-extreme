"""Oracle enforcement structural: _seam_sets from selected lenses, not observed keys."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_mindsets as om


def _seam(mindset, n=1):
    return {
        "n": n,
        "mindset": mindset,
        "assertion_a": "A",
        "assertion_b": "B",
        "check": f"curl -s http://h.test/{mindset}/{n}",
        "expected": "status 200",
        "severity": "high",
    }


def test_clean_lens_contributes_empty_list_not_missing_key():
    sets = om.build_seam_sets(
        ["mitre", "paradox", "seam"],
        [_seam("seam")],
        {"cloud-mitre": "clean", "local-paradox": "clean"},
    )
    assert sets["mitre"] == [] and sets["paradox"] == []
    assert len(sets["seam"]) == 1
    out = om.synthesize_seams(sets)  # must not raise: clean is an output object
    assert len(out) == 1


def test_errored_lens_is_none_and_synthesize_refuses():
    sets = om.build_seam_sets(
        ["mitre", "paradox", "seam"],
        [_seam("seam")],
        {"local-tactic:INITIAL ACCESS": "error", "local-paradox": "clean"},
    )
    assert sets["mitre"] is None  # selected but no output object
    assert sets["paradox"] == []
    with pytest.raises(ValueError, match="short a lens"):
        om.synthesize_seams(sets)


def test_unselected_lens_is_omitted():
    sets = om.build_seam_sets(["seam"], [_seam("seam")], {})
    assert sets == {"seam": sets["seam"]}
    out = om.synthesize_seams(sets)
    assert len(out) == 1


def test_seam_feed_empty_means_ran_clean():
    sets = om.build_seam_sets(["seam"], [], {})
    assert sets == {"seam": []}
    assert om.synthesize_seams(sets) == []


def test_deduped_lens_is_clean_not_missing():
    # A lens whose cards all deduped into another lens's copies ran fine —
    # its "seams" outcome must not become a missing marker.
    sets = om.build_seam_sets(
        ["mitre", "paradox"],
        [_seam("paradox")],
        {"cloud-mitre": "seams", "cloud-paradox": "seams"},
    )
    assert sets["mitre"] == []
    assert om.synthesize_seams(sets)


def test_mixed_error_and_clean_is_clean():
    sets = om.build_seam_sets(
        ["mitre"],
        [],
        {"local-tactic:A": "error", "local-tactic:B": "clean"},
    )
    assert sets["mitre"] == []
