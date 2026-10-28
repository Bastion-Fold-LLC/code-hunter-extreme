"""Report schema v2: site log, cross-ref skeleton, stable bug keys."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_mindset_context import (  # noqa: E402
    ProgramWorkspace,
    bug_key_for,
)


def _ws(tmp_path):
    prog = {"name": "Lab Target", "platform": "lab"}
    return ProgramWorkspace(prog, base=tmp_path)


def _seam(**over):
    base = {
        "n": 1,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without creds",
        "check": "curl -s http://h1.test/api/user/2",
        "expected": "status 200",
        "bug_type": "TYPE_2_LOGIC",
    }
    base.update(over)
    return base


def test_save_finding_writes_v2_fields(tmp_path):
    ws = _ws(tmp_path)
    out = ws.save_finding(_seam(), evidence="HTTP/1.1 200 OK")

    assert out.name == "finding_001.json"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert data["n"] == 1
    assert len(data["bug_key"]) == 64
    assert data["site_log"] == "site.log"
    assert data["xref"] == "findings/finding_001.xref.json"
    assert data["evidence_snippet"] == "HTTP/1.1 200 OK"


def test_xref_skeleton_empty_until_checked(tmp_path):
    ws = _ws(tmp_path)
    ws.save_finding(_seam())

    xref_path = ws.findings_dir / "finding_001.xref.json"
    xref = json.loads(xref_path.read_text(encoding="utf-8"))
    assert xref["finding"] == "finding_001.json"
    assert xref["schema_version"] == 2
    assert xref["checked_at"] is None
    assert xref["same_company_elsewhere"] == []
    assert xref["same_platform_others"] == []
    assert xref["other_platforms"] == []


def test_site_log_appended_as_jsonl(tmp_path):
    ws = _ws(tmp_path)
    ws.save_finding(_seam(verify_verdict="CONFIRMED"))

    lines = ws.site_log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event"] == "finding_saved"
    assert entry["finding"] == "finding_001.json"
    assert entry["verdict"] == "CONFIRMED"
    assert "ts" in entry


def test_log_of_logs_falls_back_locally_for_custom_base(tmp_path):
    ws = _ws(tmp_path)
    ws.save_finding(_seam())

    assert ws.log_of_logs_path.parent == ws.base
    lines = ws.log_of_logs_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    assert entry["platform"] == "lab"
    assert entry["slug"] == "lab_target"
    assert entry["finding"] == "finding_001.json"


def test_numbering_skips_xref_files(tmp_path):
    ws = _ws(tmp_path)
    first = ws.save_finding(_seam(n=0))
    second = ws.save_finding(_seam(n=0))

    assert first.name == "finding_001.json"
    assert second.name == "finding_002.json"


def test_bug_key_stable_across_hosts():
    a = _seam(check="curl -s http://h1.test/api/user/2")
    b = _seam(check="curl -s https://other.example:8443/api/user/2")
    assert bug_key_for(a) == bug_key_for(b)


def test_bug_key_collapses_bare_ips():
    a = _seam(check="curl -s 10.0.0.5/api")
    b = _seam(check="curl -s 192.168.1.9:8080/api")
    assert bug_key_for(a) == bug_key_for(b)


def test_bug_key_changes_with_shape():
    base = _seam()
    assert bug_key_for(base) != bug_key_for(
        _seam(check="curl -s http://h1.test/api/admin")
    )
    assert bug_key_for(base) != bug_key_for(_seam(bug_type="TYPE_1"))


def _scoped_ws(tmp_path, scopes):
    prog = {
        "name": "Lab Target",
        "platform": "lab",
        "structured_scopes": scopes,
    }
    return ProgramWorkspace(prog, base=tmp_path)


def _saved_scopes(tmp_path):
    out = tmp_path / "lab" / "lab_target" / "program.json"
    return json.loads(out.read_text())["structured_scopes"]


def test_save_program_json_refuses_scopeless_overwrite(tmp_path, capsys):
    scopes = [{"asset_identifier": "a.example", "asset_type": "url"}]
    _scoped_ws(tmp_path, scopes).save_program_json()
    out = _scoped_ws(tmp_path, []).save_program_json()
    assert out.is_file()
    assert _saved_scopes(tmp_path) == scopes
    assert "REFUSING" in capsys.readouterr().out


def test_save_program_json_allows_scoped_upgrade(tmp_path):
    scopes = [{"asset_identifier": "a.example", "asset_type": "url"}]
    _scoped_ws(tmp_path, []).save_program_json()
    _scoped_ws(tmp_path, scopes).save_program_json()
    assert _saved_scopes(tmp_path) == scopes


def test_save_program_json_writes_when_no_existing(tmp_path):
    out = _scoped_ws(tmp_path, []).save_program_json()
    assert json.loads(out.read_text())["structured_scopes"] == []


def test_save_program_json_overwrites_corrupt_existing(tmp_path):
    out = tmp_path / "lab" / "lab_target" / "program.json"
    out.parent.mkdir(parents=True)
    out.write_text("{not json")
    scopes = [{"asset_identifier": "a.example", "asset_type": "url"}]
    _scoped_ws(tmp_path, scopes).save_program_json()
    assert _saved_scopes(tmp_path) == scopes
