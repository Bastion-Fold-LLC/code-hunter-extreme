"""Minors: per-lens downstream prompts; report shows synthesis rank."""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
from oracle_hunt_filter import variant_sweep_plan
from oracle_mindset_context import ProgramWorkspace


def test_lens_prompt_picks_producing_lens():
    by_lens = {"mitre": "MITRE-SYS", "paradox": "PARADOX-SYS"}
    assert (
        oh._lens_prompt_for({"mindset": "mitre"}, "DEFAULT", by_lens)
        == "MITRE-SYS"
    )
    assert (
        oh._lens_prompt_for({"mindset": "paradox"}, "DEFAULT", by_lens)
        == "PARADOX-SYS"
    )
    # Deterministic feed + unknown lenses fall back to the shared default.
    assert (
        oh._lens_prompt_for({"mindset": "seam"}, "DEFAULT", by_lens)
        == "DEFAULT"
    )
    assert oh._lens_prompt_for({"mindset": "mitre"}, "DEFAULT", None) == "DEFAULT"


def test_lens_prompt_falls_back_to_origin_mapping():
    by_lens = {"mitre": "MITRE-SYS", "paradox": "PARADOX-SYS"}
    # No mindset tag: origin maps through mindset_of_origin.
    assert (
        oh._lens_prompt_for({"origin": "local-tactic:RECON"}, "DEFAULT", by_lens)
        == "MITRE-SYS"
    )
    assert (
        oh._lens_prompt_for({"origin": "cloud-paradox"}, "DEFAULT", by_lens)
        == "PARADOX-SYS"
    )


def test_verify_takes_no_mindset_prompt():
    # Verify is deterministic (wire decides) — the dead mindset_system
    # parameter was cut, not left to imply model reasoning.
    assert "mindset_system" not in inspect.signature(oh.verify_seams).parameters


def _seam(n, mindset):
    return {
        "n": n,
        "mindset": mindset,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without creds",
        "check": "curl -s http://h.test/api/user/2",
        "expected": "status 200",
        "reflex": "SPEC-AUDIT",
        "impact": "account takeover",
        "mitre": "T1078",
        "severity": "high",
    }


def test_poc_reasons_in_producing_lens(monkeypatch, tmp_path):
    ws = ProgramWorkspace({"name": "Lab", "platform": "lab"}, base=tmp_path)
    recon = tmp_path / "recon"
    recon.mkdir()
    seen = {}

    def fake_poc(seam, output, target, **kw):
        seen[seam["n"]] = kw.get("mindset_system")
        return "poc"

    def run(cmd):
        return (0, "VULN body", "") if cmd == _seam(1, "x")["check"] else (0, "clean", "")

    def evaluate(seam, body):
        return {"verdict": "CONFIRMED" if "VULN" in body else "REJECTED",
                "reason": "stub"}

    monkeypatch.setattr(oh, "_synthesize_poc", fake_poc)
    monkeypatch.setattr(oh, "_correlate_seams", lambda *a, **k: None)
    results = {
        1: {"seam": _seam(1, "mitre"), "check": _seam(1, "x")["check"],
            "output": "VULN", "verdict": "CONFIRMED — stub", "confirmed": True},
        2: {"seam": _seam(2, "paradox"), "check": _seam(2, "x")["check"],
            "output": "VULN", "verdict": "CONFIRMED — stub", "confirmed": True},
    }
    oh._finalize_verify(
        results,
        [_seam(1, "mitre"), _seam(2, "paradox")],
        "lab-target",
        ws,
        recon_dir=recon,
        mindset_system="DEFAULT-SYS",
        mindset_system_by_lens={"mitre": "MITRE-SYS", "paradox": "PARADOX-SYS"},
        teardown_runner=run,
        teardown_evaluator=evaluate,
    )
    assert seen == {1: "MITRE-SYS", 2: "PARADOX-SYS"}


def test_sweep_plan_carries_parent_lens():
    confirmed = {
        1: {"confirmed": True, "check": "curl -s http://a.test/x",
            "seam": dict(_seam(1, "mitre"), check="curl -s http://a.test/x")},
    }
    full_prog = {"structured_scopes": [
        {"asset_identifier": "https://b.test",
         "eligible_for_submission": True, "eligible_for_bounty": True},
    ]}
    hunt_prog = {"_hunt_filter": {"kept_idents": ["https://a.test"]}}
    plan = variant_sweep_plan(confirmed, full_prog, hunt_prog, {})
    assert plan, "expected a retargeted probe for the remaining asset"
    assert plan[0]["parent_mindset"] == "mitre"


def test_report_header_shows_synthesis_rank(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "REPORTS_DIR", tmp_path)
    seams = [dict(_seam(2, "paradox"), synthesis_rank=1),
             dict(_seam(1, "mitre"), synthesis_rank=2)]
    out = oh._write_report("lab", tmp_path, "raw", seams)
    text = out.read_text(encoding="utf-8")
    assert "### Seam 2 (synthesis rank 1)" in text
    assert "### Seam 1 (synthesis rank 2)" in text
    # Cards without a rank (pre-synthesis reports) render the bare header.
    out2 = oh._write_report("lab", tmp_path, "raw", [_seam(1, "mitre")])
    assert "### Seam 1\n" in out2.read_text(encoding="utf-8")
