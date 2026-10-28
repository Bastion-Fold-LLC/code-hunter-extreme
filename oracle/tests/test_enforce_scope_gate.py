"""Oracle enforcement #8: a missing scope gate must fail closed, never open."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_seam_templates as st
from oracle_hunter import ProgramScopeGate


def _seed(recon: Path) -> None:
    base = "http://127.0.0.1:8765"
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "live_hosts.txt").write_text(base + "\n")
    (recon / "js_endpoints.txt").write_text(f"{base}/api/v1/orders\n")
    (recon / "fuzzed_paths.txt").write_text(f"{base}/debug/config [200]\n")
    (recon / "api_specs.txt").write_text("")
    (recon / "js_secrets.txt").write_text("")


def test_none_gate_raises_loud(tmp_path):
    _seed(tmp_path / "r")
    with pytest.raises(ValueError, match="scope gate"):
        st.scan_template_seams(recon_dir=tmp_path / "r", scope_gate=None)
    with pytest.raises(ValueError, match="scope gate"):
        st.scan_template_seams(recon_dir=tmp_path / "r")  # default is also None


def test_url_in_scope_none_gate_raises():
    with pytest.raises(ValueError, match="scope gate"):
        st._url_in_scope("http://127.0.0.1:8765/x", None)


def test_explicit_gate_still_filters(tmp_path):
    _seed(tmp_path / "r")
    open_gate = ProgramScopeGate({}, target_fallback="http://127.0.0.1:8765")
    cards = st.scan_template_seams(recon_dir=tmp_path / "r", scope_gate=open_gate)
    assert cards, "loopback gate must admit loopback cards"
    closed_gate = ProgramScopeGate(
        {
            "structured_scopes": [
                {
                    "asset_identifier": "other.example.com",
                    "asset_type": "DOMAIN",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                }
            ]
        }
    )
    assert closed_gate.is_in_scope("http://127.0.0.1:8765/x")[0] is False
