"""Oracle enforcement #10: tactic attempted-vs-returned + no-cloud fail-loud."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh


def _meta(*tactics):
    return [
        {"label": f"local-{t}", "origin": f"local-tactic:{t}"} for t in tactics
    ] + [{"label": "local-paradox", "origin": "local-paradox"}]


def test_full_sweep_no_drops():
    cov = oh.tactic_coverage(
        _meta("A", "B"),
        {"local-tactic:A": "seams", "local-tactic:B": "clean", "local-paradox": "empty"},
    )
    assert cov == {"attempted": ["A", "B"], "returned": ["A", "B"], "dropped": []}
    oh._raise_on_tactic_drops_no_cloud(cov, True)  # must not raise


def test_drops_recorded_and_named():
    cov = oh.tactic_coverage(
        _meta("A", "B", "C"),
        {"local-tactic:A": "seams", "local-tactic:B": "error"},
    )
    assert cov["attempted"] == ["A", "B", "C"]
    assert cov["returned"] == ["A"]
    assert cov["dropped"] == ["B", "C"]  # error + never-recorded both count


def test_no_cloud_drops_are_fatal():
    cov = {"attempted": ["A", "B"], "returned": ["A"], "dropped": ["B"]}
    with pytest.raises(RuntimeError, match="B"):
        oh._raise_on_tactic_drops_no_cloud(cov, True)


def test_cloud_mode_drops_only_warn():
    cov = {"attempted": ["A", "B"], "returned": ["A"], "dropped": ["B"]}
    oh._raise_on_tactic_drops_no_cloud(cov, False)  # must not raise


def test_no_tactic_passes_no_coverage():
    cov = oh.tactic_coverage([{"origin": "cloud-mitre"}], {"cloud-mitre": "seams"})
    assert cov == {"attempted": [], "returned": [], "dropped": []}


def test_raise_on_tactic_drops_always_fatal_unless_allowed():
    cov = {"attempted": ["A", "B"], "returned": ["A"], "dropped": ["B"]}
    with pytest.raises(RuntimeError, match="Tactic sweep incomplete"):
        oh._raise_on_tactic_drops(cov, allow_incomplete=False)
    oh._raise_on_tactic_drops(cov, allow_incomplete=True)  # must not raise
    oh._raise_on_tactic_drops({"attempted": ["A"], "returned": ["A"], "dropped": []})

