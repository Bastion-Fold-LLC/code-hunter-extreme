import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def test_load_fused_ttps_keys_by_code(tmp_path, monkeypatch):
    p = tmp_path / "fused.json"
    p.write_text(json.dumps([
        {"code": "T1001", "name": "X", "paradox": "P", "reflex_move": "M",
         "you_never_said": "S", "reflex_name": "R", "primary_reflex": 3},
        {"code": "T1078", "name": "Y", "paradox": "P2", "reflex_move": "M2",
         "you_never_said": "S2", "reflex_name": "R2", "primary_reflex": 1},
    ]))
    monkeypatch.setattr(oh, "_FUSED_TTPS_PATH", p)
    monkeypatch.setattr(oh, "_FUSED_TTPS_CACHE", None)
    d = oh._load_fused_ttps()
    assert d["T1001"]["paradox"] == "P"
    assert d["T1078"]["reflex_move"] == "M2"


def test_load_fused_ttps_first_wins_on_duplicates(tmp_path, monkeypatch):
    """R3: appended overlay stubs must not clobber real ATT&CK records."""
    p = tmp_path / "fused.json"
    p.write_text(
        json.dumps(
            [
                {
                    "code": "T1078",
                    "name": "Valid Accounts",
                    "tactic": "PRIVILEGE ESCALATION",
                    "description": "Adversaries may obtain and abuse credentials.",
                },
                {
                    "code": "T1078",
                    "name": "Valid Accounts",
                    "tactic": "DEFENSE EVASION",
                    "description": "Valid Accounts — mapped to Oracle Reflex 9.",
                },
            ]
        )
    )
    monkeypatch.setattr(oh, "_FUSED_TTPS_PATH", p)
    monkeypatch.setattr(oh, "_FUSED_TTPS_CACHE", None)
    d = oh._load_fused_ttps()
    assert d["T1078"]["tactic"] == "PRIVILEGE ESCALATION"
    assert "Reflex 9" not in d["T1078"]["description"]


def test_load_fused_ttps_real_file_resolves_full_t1078(monkeypatch):
    """R3 on the real file: T1078 is the full record, not the idx-342 stub."""
    monkeypatch.setattr(oh, "_FUSED_TTPS_CACHE", None)
    d = oh._load_fused_ttps()
    assert d["T1078"]["tactic"] == "PRIVILEGE ESCALATION"
    assert len(d["T1078"]["description"]) > 200
    assert d["T1190"]["tactic"] == "INITIAL ACCESS"
    assert len(d["T1190"]["description"]) > 200


def test_load_fused_ttps_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(oh, "_FUSED_TTPS_PATH", tmp_path / "nope.json")
    monkeypatch.setattr(oh, "_FUSED_TTPS_CACHE", None)
    assert oh._load_fused_ttps() == {}


def test_format_ttp_line_enriched_when_fused_present():
    t = {"code": "T1001", "tactic": "C2", "name": "Data Obf",
         "permissions_required": "N/A", "description": "desc."}
    fused = {"T1001": {"paradox": "Repulsive Gravity", "reflex_move": "change the key",
                       "you_never_said": "you never said where", "reflex_name": "AXIOM-REWRITE",
                       "primary_reflex": 3}}
    line = oh._format_ttp_line(t, fused)
    assert "Repulsive Gravity" in line
    assert "change the key" in line
    assert "you never said where" in line
    assert ("do not copy" in line.lower()) or ("reason from" in line.lower())


def test_format_ttp_line_falls_back_without_fused():
    t = {"code": "T9999", "tactic": "X", "name": "N",
         "permissions_required": "User", "description": "some desc here."}
    line = oh._format_ttp_line(t, {})
    assert "T9999" in line and "some desc" in line
