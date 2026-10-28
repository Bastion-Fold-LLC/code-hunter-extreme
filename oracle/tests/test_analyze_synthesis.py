"""#18: standalone analyze runs the hunt's synthesis contract, not a legacy path."""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh


@pytest.fixture(autouse=True)
def _restore_cloud_flags():
    # cmd_analyze flips the process-global no-cloud flags via
    # _apply_no_cloud — restore them so later tests (router cascade,
    # cloud-first) see a pristine backend environment.
    import oracle_llm

    try:
        import oracle_programs as _op
    except Exception:
        _op = None
    prev_llm = oracle_llm.no_cloud_enabled()
    prev_op = _op.NO_CLOUD if _op is not None else None
    yield
    oracle_llm.set_no_cloud(prev_llm)
    if _op is not None:
        _op.NO_CLOUD = prev_op


_RAW = """**SEAM 1**
- Assertion A: Admin API requires a token
- Assertion B: Wire returns admin data without a token
- Bug Type: TYPE_2_LOGIC
- Reflex: Reflex 2 — DECOUPLE
- MITRE: T1078
- Reproducible check: `curl -i -s http://127.0.0.1:8765/api/admin`
- Expected: status 200
- Impact: data exposure

**SEAM 2**
- Assertion A: Login rate-limits guesses
- Assertion B: Wire accepts unlimited guesses
- Reflex: Reflex 5 — RATE
- Reproducible check: `curl -i -s http://127.0.0.1:8765/login`
- Expected: status 200
- Impact: credential stuffing
"""


def _args(**over):
    base = dict(cloud=False, model="m")
    base.update(over)
    return types.SimpleNamespace(**base)


def test_analyze_routes_through_synthesis(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "run_reflexes", lambda *a, **k: _RAW)
    captured = {}
    monkeypatch.setattr(
        oh,
        "_write_report",
        lambda name, rd, raw, seams, *a, **k: captured.setdefault(
            "seams", seams
        )
        or Path("r.md"),
    )
    seams, raw = oh.cmd_analyze(str(tmp_path), _args())
    assert raw == _RAW
    assert len(seams) == 2 and captured["seams"] is seams
    for s in seams:
        assert s["mindset"] == "mitre"
        assert s["synthesis_rank"] in (1, 2)
        assert s["redteam_verdict"] in ("confirmed", "unreviewed", "rejected")
        assert s["agreement"] == 1  # single lens: no corroboration
        assert s["bug_type"].startswith("TYPE_")
    by_n = {s["n"]: s for s in seams}
    assert by_n[1]["bug_type"] == "TYPE_2_LOGIC"  # model-declared kept


def test_analyze_clean_verdict_reports_zero_seams(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "run_reflexes", lambda *a, **k: "TARGET CLEAN\n")
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    seams, _ = oh.cmd_analyze(str(tmp_path), _args())
    assert seams == []


def test_analyze_without_output_object_dies(monkeypatch, tmp_path):
    monkeypatch.setattr(
        oh, "run_reflexes", lambda *a, **k: "[no recon data found]"
    )
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    with pytest.raises(SystemExit):
        oh.cmd_analyze(str(tmp_path), _args())
