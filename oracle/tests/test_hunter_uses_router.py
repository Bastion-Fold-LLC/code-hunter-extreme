import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def test_correlate_routes_through_complete(monkeypatch):
    seen = {}

    def fake_complete(prompt, system, task_type, **kw):
        seen["task"] = task_type
        return "## Compound Threat Analysis\n- Composite Severity: High"

    import oracle_llm
    monkeypatch.setattr(oracle_llm, "complete", fake_complete)
    out = oh._correlate_seams(
        [{"seam": {"n": 1, "reflex": "r", "assertion_a": "a", "assertion_b": "b", "impact": "i"}},
         {"seam": {"n": 2, "reflex": "r", "assertion_a": "a", "assertion_b": "b", "impact": "i"}}],
        "target")
    assert seen["task"] == "correlate"
    assert out and "Compound" in out["summary"]
