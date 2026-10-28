"""#15: broken templates are recorded in the report, never swallowed."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
import oracle_seam_templates as st
from oracle_hunter import ProgramScopeGate
from oracle_mindset_context import ProgramWorkspace


def _seed(recon: Path) -> None:
    base = "http://127.0.0.1:8765"
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "live_hosts.txt").write_text(base + "\n")
    (recon / "js_endpoints.txt").write_text(f"{base}/api/v1/orders\n")
    (recon / "fuzzed_paths.txt").write_text(f"{base}/debug/config [200]\n")
    (recon / "api_specs.txt").write_text("")
    (recon / "js_secrets.txt").write_text("")


def test_broken_template_recorded_and_hunt_continues(tmp_path, monkeypatch):
    _seed(tmp_path / "r")
    gate = ProgramScopeGate({}, target_fallback="http://127.0.0.1:8765")
    victim = next(t for t in st.TEMPLATES if "web" in t["applies"])

    def _boom(mat):
        raise RuntimeError("template blew up")

    monkeypatch.setitem(victim, "fn", _boom)
    errors = []
    cards = st.scan_template_seams(
        recon_dir=tmp_path / "r", scope_gate=gate, errors=errors
    )
    assert errors == [
        {"tid": victim["tid"], "error": "RuntimeError: template blew up"}
    ]
    assert cards, "one bad template must not kill the remaining coverage"


def test_template_errors_land_in_report_snapshot(tmp_path):
    ws = ProgramWorkspace({"name": "Lab", "platform": "lab"}, base=tmp_path)
    recon = tmp_path / "recon"
    recon.mkdir()
    oh._finalize_verify(
        {},
        [],
        "lab-target",
        ws,
        recon_dir=recon,
        hunt_meta={"template_errors": [{"tid": "T-WEB-01", "error": "boom"}]},
    )
    snapshots = sorted(ws.reports_dir.glob("report_verify_results*.md"))
    assert snapshots, "finalize must persist a verify-results snapshot"
    snap = json.loads(snapshots[-1].read_text(encoding="utf-8"))
    assert snap["hunt"]["template_errors"] == [
        {"tid": "T-WEB-01", "error": "boom"}
    ]
