import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "oracle-plan-gate" / "hooks" / "spec-guard.sh"


def _run_hook(tool_name, path, *, env=None):
    run_env = os.environ.copy()
    run_env.pop("ORACLE_PLAN_REPO", None)
    run_env.update(env or {})
    payload = json.dumps({"tool_name": tool_name, "tool_input": {"path": path}})
    return subprocess.run(
        ["sh", str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        env=run_env,
        check=False,
    )


def test_spec_guard_uses_override_repository(tmp_path):
    (tmp_path / "docs").mkdir()
    frozen = tmp_path / "docs" / "OWNER_MINDSET_SPEC.md"
    frozen.write_text("frozen\n", encoding="utf-8")
    result = _run_hook(
        "write_file",
        str(tmp_path / "docs" / frozen.name),
        env={"ORACLE_PLAN_REPO": str(tmp_path)},
    )
    assert result.returncode == 2
    assert "is frozen" in result.stderr


def test_spec_guard_derives_default_repository_from_hook_location():
    plan = ROOT / "docs" / "OWNER_MINDSET_FINISH_PLAN.md"
    result = _run_hook("write_file", str(plan))
    assert result.returncode == 2
    assert "is frozen" in result.stderr
