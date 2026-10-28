#!/usr/bin/env python3
"""Intel honesty gates: scrapers must extract or report unknown, never hardcode.

Covers the deep-research intel-rot findings: literal payouts, unconditional
fast-triage flags, and dead-platform dispatch inside _scrape_* adapters.
"""

import ast
from pathlib import Path

from oracle_programs import (
    PLATFORMS,
    SCRAPERS,
    normalize_program_record,
)

SRC = Path(__file__).resolve().parent.parent / "oracle_programs.py"


def _scraper_literals():
    """Literal intel values hardcoded inside _scrape_* adapter bodies."""
    tree = ast.parse(SRC.read_text())
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("_scrape_"):
            continue
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Dict):
                continue
            for key, value in zip(sub.keys, sub.values):
                if not isinstance(key, ast.Constant):
                    continue
                if key.value == "fast_triage" and isinstance(value, ast.Constant):
                    if value.value is True:
                        hits.append((node.name, "fast_triage=True"))
                if key.value == "max_payout_usd" and isinstance(value, ast.Constant):
                    if isinstance(value.value, (int, float)) and not isinstance(
                        value.value, bool
                    ):
                        hits.append((node.name, f"max_payout_usd={value.value}"))
    return hits


def test_no_hardcoded_intel_in_scrapers():
    hits = _scraper_literals()
    assert hits == [], f"hardcoded intel literals must be extracted or None: {hits}"


def test_code4rena_not_dispatched():
    assert "code4rena" not in SCRAPERS
    assert "code4rena" not in PLATFORMS


def test_normalize_defaults_unknown_fields_to_none():
    rec = normalize_program_record(
        {"name": "x", "url": "https://example.com/p"}, "huntr"
    )
    assert rec is not None
    assert rec["max_payout_usd"] is None
    assert rec["fast_triage"] is None
    assert rec["reports_count"] is None
    assert rec["scope_status"] == "not-fetched"


def test_normalize_rejects_malformed():
    assert (
        normalize_program_record({"name": "", "url": "https://e.com"}, "huntr") is None
    )
    assert normalize_program_record({"name": "x", "url": "notaurl"}, "huntr") is None
    assert normalize_program_record("notadict", "huntr") is None
