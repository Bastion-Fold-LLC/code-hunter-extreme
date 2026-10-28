"""Oracle enforcement ladder: real L1 retry / L2 widen with recorded attempts."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh


def _meta(label, origin):
    return {"label": label, "origin": origin}


def test_l2_prefers_engine_that_did_not_serve_lens():
    # mitre ran local-only, paradox cloud-only, both engines up.
    metas = [
        _meta("local-INITIAL ACCESS", "local-tactic:INITIAL ACCESS"),
        _meta("openrouter-paradox", "cloud-paradox"),
    ]
    plans = oh.plan_ladder_l2(["mitre", "paradox", "seam"], metas, True, True)
    by_lens = {p["lens"]: p["engine"] for p in plans}
    assert by_lens == {"mitre": "cloud", "paradox": "local"}


def test_l2_never_plans_cloud_when_down():
    metas = [_meta("openrouter-mitre", "cloud-mitre")]
    plans = oh.plan_ladder_l2(["mitre", "paradox"], metas, False, True)
    assert plans and all(p["engine"] == "local" for p in plans)


def test_l2_no_engines_no_plans():
    assert oh.plan_ladder_l2(["mitre"], [], False, False) == []


def test_l2_skips_seam_and_unselected():
    plans = oh.plan_ladder_l2(["seam"], [], True, True)
    assert plans == []


def test_run_ladder_passes_collects_and_marks_failures():
    def complete(prompt, system, nc):
        if "boom" in prompt:
            raise RuntimeError("engine blew up")
        return ("TARGET CLEAN", "mock-model")

    specs = [
        {"label": "a", "origin": "o-a", "prompt": "fine", "system": "", "no_cloud": True},
        {"label": "b", "origin": "o-b", "prompt": "boom", "system": "", "no_cloud": True},
    ]
    out = oh.run_ladder_passes(specs, complete, budget_s=10)
    by_label = {s["label"]: (raw, model) for s, raw, model in out}
    assert by_label["a"] == ("TARGET CLEAN", "mock-model")
    assert by_label["b"][0] is None and "blew up" in by_label["b"][1]


def test_run_ladder_passes_budget_hit_marks_pending():
    def slow(prompt, system, nc):
        time.sleep(5)
        return ("late", "mock")

    specs = [{"label": "s", "origin": "o-s", "prompt": "x", "system": "", "no_cloud": True}]
    t0 = time.time()
    out = oh.run_ladder_passes(specs, slow, budget_s=1)
    assert time.time() - t0 < 4  # budget enforced, hung engine cancelled
    assert out[0][1] is None and "budget" in out[0][2]


def test_run_ladder_passes_empty_is_noop():
    assert oh.run_ladder_passes([], lambda *a: ("", "")) == []
