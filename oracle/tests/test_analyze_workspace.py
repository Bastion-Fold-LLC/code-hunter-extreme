"""Standalone analyze must resume a REAL hunt workspace.

Regression for the failure where `analyze targets/<Plat>/<slug>` collected
nothing (recon files live in recon/, the root was never descended) and
`analyze .../recon` derived target/scope from the literal folder name
"recon" (no program matched, the scope gate emptied every line).

These tests do NOT mock run_reflexes or _collect_recon — the old suite did,
which is exactly how the bug stayed hidden. Only the external model
boundary (oracle_llm.complete) is stubbed.
"""
import json
import socket
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
import oracle_llm


@pytest.fixture(autouse=True)
def _restore_cloud_flags():
    # cmd_analyze flips process-global no-cloud flags via _apply_no_cloud.
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


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _build_workspace(tmp_path: Path, port: int, scope_file: str = "hunt_scope.json"):
    ws = tmp_path / "targets" / "TestPlat" / "acme-widgets"
    recon = ws / "recon"
    recon.mkdir(parents=True)
    prog = {
        "name": "Acme Widgets",
        "handle": "acme-widgets",
        "platform": "TestPlat",
        "structured_scopes": [
            {
                "asset_identifier": "127.0.0.1",
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "out_of_scope": [],
    }
    (ws / scope_file).write_text(json.dumps(prog))
    (recon / "clean_live_hosts.txt").write_text(f"http://127.0.0.1:{port}\n")
    (recon / "known_urls.txt").write_text(
        f"http://127.0.0.1:{port}/api/users\n"
        "https://evil.example.org/secret\n"
    )
    return ws, recon


def test_resolver_hunt_root_and_recon_subdir(tmp_path):
    ws, recon = _build_workspace(tmp_path, _closed_port())
    for given in (ws, recon):
        rdir, tname, prog = oh._resolve_analyze_workspace(given)
        assert rdir == recon
        assert tname == "Acme Widgets"
        assert prog.get("structured_scopes"), "workspace scope must load"
        gate = oh.ProgramScopeGate(
            prog, target_fallback=oh._derive_target(prog, tname)
        )
        text = oh._collect_recon(rdir, max_chars=20000, scope_gate=gate)
        assert "/api/users" in text, "in-scope recon must survive the gate"
        assert "evil.example.org" not in text, "out-of-scope must be dropped"


def test_resolver_program_json_only(tmp_path):
    ws, recon = _build_workspace(tmp_path, _closed_port(), scope_file="program.json")
    rdir, tname, prog = oh._resolve_analyze_workspace(recon)
    assert rdir == recon
    assert tname == "Acme Widgets"
    assert prog.get("structured_scopes")


def test_resolver_recon_subdir_without_scope_files_uses_parent_slug(tmp_path, monkeypatch):
    recon = tmp_path / "targets" / "TestPlat" / "acme-widgets" / "recon"
    recon.mkdir(parents=True)
    monkeypatch.setattr(oh, "_scope_from_programs", lambda name: {})
    rdir, tname, prog = oh._resolve_analyze_workspace(recon)
    assert rdir == recon
    assert tname == "acme-widgets"  # never the literal "recon"
    assert prog == {}


def test_resolver_workspace_json_identity_without_scopes_is_preserved(tmp_path, monkeypatch):
    ws, recon = _build_workspace(tmp_path, _closed_port())
    (ws / "hunt_scope.json").write_text(
        json.dumps({"name": "Acme Widgets", "handle": "acme-widgets", "structured_scopes": []})
    )
    monkeypatch.setattr(oh, "_scope_from_programs", lambda name: {})
    rdir, tname, prog = oh._resolve_analyze_workspace(recon)
    assert rdir == recon
    assert tname == "Acme Widgets"
    assert prog.get("handle") == "acme-widgets"


def test_resolver_rejects_fuzzy_unrelated_program(monkeypatch, tmp_path):
    flat = tmp_path / "beta"
    flat.mkdir()
    (flat / "live_hosts.txt").write_text("https://beta.example.invalid\n")
    monkeypatch.setattr(
        oh,
        "_scope_from_programs",
        lambda name: {
            "name": "KU Leuven",
            "handle": "ku-leuven-betaling",
            "structured_scopes": [{"asset_identifier": "*.kuleuven.example"}],
        },
    )
    _rdir, tname, prog = oh._resolve_analyze_workspace(flat)
    assert tname == "beta"
    assert prog == {}  # substring/fuzzy match is not identity


def test_resolver_and_gate_accept_bare_string_scopes(tmp_path):
    ws, recon = _build_workspace(tmp_path, _closed_port())
    data = json.loads((ws / "hunt_scope.json").read_text())
    data["structured_scopes"] = "127.0.0.1"
    (ws / "hunt_scope.json").write_text(json.dumps(data))
    rdir, tname, prog = oh._resolve_analyze_workspace(recon)
    assert prog["structured_scopes"] == [{"asset_identifier": "127.0.0.1"}]
    gate = oh.ProgramScopeGate(prog, target_fallback=oh._derive_target(prog, tname))
    text = oh._collect_recon(rdir, max_chars=20000, scope_gate=gate)
    assert "/api/users" in text


def test_resolver_legacy_flat_dir(tmp_path):
    flat = tmp_path / "zz-legacy-flat-xyz"
    flat.mkdir()
    (flat / "live_hosts.txt").write_text("https://zz-legacy-flat-xyz.invalid\n")
    rdir, tname, _prog = oh._resolve_analyze_workspace(flat)
    assert rdir == flat
    assert tname == "zz-legacy-flat-xyz"


def _args():
    return types.SimpleNamespace(cloud=False, model="m")


@pytest.mark.parametrize("which", ["root", "recon"])
def test_cmd_analyze_resumes_real_workspace(monkeypatch, tmp_path, which):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    ws, recon = _build_workspace(tmp_path, _closed_port())
    prompts = {}

    def _fake_complete(task, system, **kwargs):
        prompts["task"] = task
        return "TARGET CLEAN"

    # Only the model boundary is stubbed; collection, scope gating, prompt
    # construction, parsing, mindset gates and synthesis all run for real.
    monkeypatch.setattr(oracle_llm, "complete", _fake_complete)
    reports = {}
    monkeypatch.setattr(
        oh,
        "_write_report",
        lambda name, rd, raw, seams, *a, **k: reports.setdefault("name", name)
        or Path("r.md"),
    )
    given = ws if which == "root" else recon
    seams, raw = oh.cmd_analyze(str(given), _args())
    assert raw == "TARGET CLEAN"  # i.e. NOT "[no recon data found]"
    assert seams == []
    assert "/api/users" in prompts["task"]
    assert "evil.example.org" not in prompts["task"]
    assert reports["name"] == "Acme Widgets"


def test_collect_recon_first_token_cannot_launder_trailing_host(tmp_path):
    ws, recon = _build_workspace(tmp_path, _closed_port())
    (recon / "dns.txt").write_text(
        "127.0.0.1 is fine\n"
        "127.0.0.1 CNAME evil.example.org\n"
        "127.0.0.1 A 203.0.113.9\n"
        "127.0.0.1 CNAME evil.xn--p1ai\n"
    )
    _rdir, tname, prog = oh._resolve_analyze_workspace(recon)
    gate = oh.ProgramScopeGate(prog, target_fallback=oh._derive_target(prog, tname))
    text = oh._collect_recon(recon, max_chars=20000, scope_gate=gate)
    assert "evil.example.org" not in text
    assert "203.0.113.9" not in text
    assert "evil.xn--p1ai" not in text


@pytest.mark.parametrize(
    "model_raw",
    ["some off-format prose with no cards and no verdict", "[no backend produced output] down"],
)
def test_cmd_analyze_failed_pass_dies(monkeypatch, tmp_path, model_raw):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    ws, _recon = _build_workspace(tmp_path, _closed_port())
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: model_raw)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    with pytest.raises(SystemExit):
        oh.cmd_analyze(str(ws), _args())
