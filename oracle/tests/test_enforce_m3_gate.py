"""Oracle enforcement M3: synthesis corroborates, invention needs the flag."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh


def _seam(url, n=1):
    return {
        "n": n,
        "assertion_a": "A",
        "assertion_b": "B",
        "check": f"curl -s '{url}'",
        "expected": "status 200",
    }


def test_corroboration_keeps_known_subjects_only():
    existing = [_seam("http://h.test/api/user/2")]
    rt = [
        _seam("http://h.test/api/user/2", n=1),  # same subject, corroborated
        _seam("http://h.test/api/admin", n=2),  # brand-new subject
    ]
    kept, dropped = oh.corroborate_synth_seams(rt, existing)
    assert [s["n"] for s in kept] == [1]
    assert [s["n"] for s in dropped] == [2]


def test_allow_new_keeps_everything():
    rt = [_seam("http://h.test/api/admin")]
    kept, dropped = oh.corroborate_synth_seams(rt, [], allow_new=True)
    assert len(kept) == 1 and dropped == []


def test_default_drops_all_when_no_candidates():
    rt = [_seam("http://h.test/api/admin")]
    kept, dropped = oh.corroborate_synth_seams(rt, [])
    assert kept == [] and len(dropped) == 1


def test_query_params_distinguish_subjects():
    existing = [_seam("http://h.test/api?user=1")]
    rt = [_seam("http://h.test/api?user=2")]
    kept, dropped = oh.corroborate_synth_seams(rt, existing)
    assert kept == [] and len(dropped) == 1  # distinct subject, not corroboration


def test_hunt_parser_has_no_seam_invention_toggle():
    import subprocess

    root = Path(__file__).resolve().parent.parent
    r = subprocess.run(
        [sys.executable, str(root / "oracle_hunter.py"), "hunt", "--help"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert "--seam-allow-new" not in r.stdout
