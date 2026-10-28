import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_ttp_fuse as fuse_mod


def _write_sources(tmp_path, ttps, md_text):
    src_json = tmp_path / "all_ttps.json"
    src_md = tmp_path / "mitre_all_ttps.md"
    src_json.write_text(json.dumps(ttps), encoding="utf-8")
    src_md.write_text(md_text, encoding="utf-8")
    return src_json, src_md


def test_fuse_fails_loud_naming_unmapped_ttps(tmp_path, monkeypatch):
    src_json, src_md = _write_sources(
        tmp_path,
        {
            "T1000": {"name": "Mapped One", "modal": "Description\nbody"},
            "T2000": {"name": "Unmapped One", "modal": "Description\nbody"},
        },
        "## DISCOVERY\n### T1000: Mapped One\n",
    )
    monkeypatch.setattr(fuse_mod, "SRC_JSON", src_json)
    monkeypatch.setattr(fuse_mod, "SRC_TACTIC_MD", src_md)

    with pytest.raises(ValueError, match="T2000"):
        fuse_mod.fuse()


def test_fuse_returns_every_mapped_ttp(tmp_path, monkeypatch):
    src_json, src_md = _write_sources(
        tmp_path,
        {"T1000": {"name": "Mapped One", "modal": "Description\nbody"}},
        "## DISCOVERY\n### T1000: Mapped One\n",
    )
    monkeypatch.setattr(fuse_mod, "SRC_JSON", src_json)
    monkeypatch.setattr(fuse_mod, "SRC_TACTIC_MD", src_md)

    fused = fuse_mod.fuse()
    assert [r["code"] for r in fused] == ["T1000"]
