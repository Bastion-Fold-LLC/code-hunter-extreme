"""Oracle enforcement #1: _render_ttp emits real ATT&CK text + .get hardening."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext, _TTP_DESC_CHARS


def _ctx():
    return OracleMindsetContext(program={}, voice=False)


def test_render_ttp_emits_description_text():
    desc = "Adversaries may obtain and abuse credentials of existing accounts."
    out = _ctx()._render_ttp(
        {
            "code": "T1078",
            "name": "Valid Accounts",
            "tactic": "PRIVILEGE ESCALATION",
            "description": desc,
            "primary_reflex": 9,
            "reflex_name": "R",
            "paradox": "P",
            "you_never_said": "S",
            "reflex_move": "M",
        }
    )
    assert desc in out  # real technique text, not just code+name
    assert "T1078" in out and "Valid Accounts" in out


def test_render_ttp_caps_long_descriptions():
    long_desc = "word " * 500  # 2500 chars
    out = _ctx()._render_ttp({"code": "T1", "name": "N", "description": long_desc})
    assert "…" in out
    assert len(out) < len(long_desc)
    assert out.index("…") - out.index("Technique:") <= _TTP_DESC_CHARS + 32


def test_render_ttp_missing_keys_never_raise():
    # Overlay stubs / partial records: every field is .get-hardened.
    out = _ctx()._render_ttp({"code": "T1078"})
    assert "T1078" in out
    assert "(no ATT&CK description)" in out
    out2 = _ctx()._render_ttp({})
    assert "?" in out2  # degraded placeholders, no KeyError


def test_ttp_block_carries_technique_text():
    ctx = OracleMindsetContext(program={}, voice=False, ttp_mode="compact")
    block = ctx._ttp_block()
    assert "Technique:" in block
    # At least one rendered record must carry non-placeholder technique text.
    assert "(no ATT&CK description)" not in block or block.count("Technique:") > block.count(
        "(no ATT&CK description)"
    )
