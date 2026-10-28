"""PoC teardown: adversarial proof validation, strict demotion."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
from oracle_mindset_context import ProgramWorkspace  # noqa: E402

CHECK = "curl -s http://h.test/api/user/2"


def _seam(**over):
    base = {
        "n": 1,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without creds",
        "check": CHECK,
        "expected": "status 200",
        "reflex": "SPEC-AUDIT",
        "impact": "stub impact",
        "mitre": "T1190",
    }
    base.update(over)
    return base


def _evaluator(seam, body):
    if "VULN" in body:
        return {"verdict": "CONFIRMED", "reason": "stub"}
    return {"verdict": "REJECTED", "reason": "stub"}


def _runner_for(outputs):
    calls = []

    if callable(outputs):

        def run(cmd):
            calls.append(cmd)
            return outputs(cmd)

    else:

        def run(cmd):
            calls.append(cmd)
            i = min(len(calls) - 1, len(outputs) - 1)
            return outputs[i]

    run.calls = calls
    return run


def _attack(td, name):
    return next(a for a in td["attacks"] if a["name"] == name)


def test_pass_path_runs_all_attacks():
    def _out(cmd):
        if cmd == CHECK:
            return (0, "VULN body", "")
        return (0, "clean", "")

    runner = _runner_for(_out)
    td = oh.teardown_poc(_seam(), CHECK, runner=runner, evaluator=_evaluator)

    assert td["verdict"] == "PASS"
    assert td["broke_proof"] is False
    assert _attack(td, "replay")["result"] == "PASS"
    assert _attack(td, "evaluator_sanity")["result"] == "PASS"
    assert _attack(td, "id_swap")["result"] == "PASS"
    assert _attack(td, "fix_mutation")["result"] == "SKIP"


def test_flaky_replay_fails():
    runner = _runner_for([(0, "VULN", ""), (0, "clean", ""), (0, "VULN", "")])

    td = oh.teardown_poc(_seam(), CHECK, runner=runner, evaluator=_evaluator)

    assert td["verdict"] == "FAIL"
    assert td["broke_proof"] is True
    assert _attack(td, "replay")["result"] == "FAIL"
    assert "replay" in td["notes"]


def test_vacuous_evaluator_fails():
    def _always(seam, body):
        return {"verdict": "CONFIRMED", "reason": "stub"}

    td = oh.teardown_poc(
        _seam(),
        CHECK,
        runner=_runner_for([(0, "VULN", "")]),
        evaluator=_always,
    )

    assert td["verdict"] == "FAIL"
    assert _attack(td, "evaluator_sanity")["result"] == "FAIL"


def test_non_isolating_check_fails():
    td = oh.teardown_poc(
        _seam(),
        CHECK,
        runner=_runner_for([(0, "VULN", "")]),
        evaluator=_evaluator,
    )

    assert td["verdict"] == "FAIL"
    assert _attack(td, "id_swap")["result"] == "FAIL"


def test_digit_free_check_skips_swap():
    check = "curl -s http://h.test/health"
    td = oh.teardown_poc(
        _seam(check=check),
        check,
        runner=_runner_for([(0, "VULN", "")]),
        evaluator=_evaluator,
    )

    assert td["verdict"] == "PASS"
    assert _attack(td, "id_swap")["result"] == "SKIP"


def test_gate_blocked_control_skips():
    class _DenyGate:
        def validate_check(self, cmd, is_testnet=False):
            return (False, cmd, "denied")

    td = oh.teardown_poc(
        _seam(),
        CHECK,
        gate=_DenyGate(),
        runner=_runner_for([(0, "VULN", "")]),
        evaluator=_evaluator,
    )

    assert _attack(td, "id_swap")["result"] == "SKIP"
    assert "denied" in _attack(td, "id_swap")["detail"]


def test_teardown_confirmed_demotes_on_fail(tmp_path):
    results = {
        1: {
            "seam": _seam(),
            "check": CHECK,
            "output": "VULN",
            "verdict": "CONFIRMED — stub",
            "confirmed": True,
        },
        2: {
            "seam": _seam(n=2),
            "check": CHECK,
            "output": "",
            "verdict": "REJECTED — stub",
            "confirmed": False,
        },
    }
    runner = _runner_for([(0, "VULN", ""), (0, "clean", ""), (0, "VULN", "")])

    oh._teardown_confirmed(
        results,
        "lab-target",
        tmp_path,
        runner=runner,
        evaluator=_evaluator,
    )

    assert results[1]["confirmed"] is False
    assert results[1]["demoted_by_teardown"] is True
    assert results[1]["verdict"].startswith("TEARDOWN-FAILED")
    assert results[1]["teardown"]["verdict"] == "FAIL"
    assert results[2]["teardown"] is None


def test_finalize_persists_teardown_field(tmp_path):
    ws = ProgramWorkspace({"name": "Lab", "platform": "lab"}, base=tmp_path)
    recon = tmp_path / "recon"
    recon.mkdir()
    results = {
        1: {
            "seam": _seam(),
            "check": CHECK,
            "output": "VULN",
            "verdict": "CONFIRMED — stub",
            "confirmed": True,
        },
    }

    oh._finalize_verify(
        results,
        [_seam()],
        "lab-target",
        ws,
        recon_dir=recon,
        teardown_runner=_runner_for([(0, "clean", "")]),
        teardown_evaluator=_evaluator,
    )

    saved = json.loads(
        (ws.findings_dir / "finding_001.json").read_text(encoding="utf-8")
    )
    assert saved["verify_confirmed"] is False
    assert saved["verify_verdict"].startswith("TEARDOWN-FAILED")
    assert saved["poc_teardown"]["verdict"] == "FAIL"
    assert saved["poc_teardown"]["broke_proof"] is True
