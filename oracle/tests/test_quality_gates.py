#!/usr/bin/env python3
"""Phase 2: quality-gate config guard — bars exist, valid, and match the spec."""

import json
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent


def _gates():
    cfg = json.loads((_HERE / "oracle.config.json").read_text())
    assert "quality_gates" in cfg, "oracle.config.json must define quality_gates"
    return cfg["quality_gates"]


def test_gate_bars_present_and_in_range():
    g = _gates()
    for key in ("gate_precision_min", "gate_clean_fp_max"):
        assert 0 < g[key] < 1, f"{key} must be a (0,1) fraction, got {g[key]}"
    # P2-lock (doctrine #5): recall bar is zero-miss, so == 1.0 is legal.
    assert (
        0 < g["gate_recall_min"] <= 1
    ), f"gate_recall_min must be a (0,1] fraction, got {g['gate_recall_min']}"
    assert g["gate_flaw_cases"] + g["gate_clean_cases"] == g["gate_cases"]
    assert g["gate_cases"] > 0


def test_review_stages_present_and_ordered():
    g = _gates()
    assert 0 < g["review_stage1_precision"] < g["review_stage2_precision"] < 1
    assert 0 < g["review_stage1_window"] < g["review_stage2_window"]
    assert g["review_stage2_max_false_confirmed"] == 0


def test_gate_spec_references_config():
    spec = (_HERE / "docs" / "GATE_SPEC.md").read_text()
    assert "quality_gates" in spec
    assert "NON-BLOCKING" in spec
