#!/usr/bin/env python3
"""Phase 1: shared payout parser + None-sweep across score/filter/display."""

import pytest

from oracle_mindset_context import OracleMindsetContext
from oracle_programs import (
    _parse_codehawks_payout,
    _program_score,
    filter_programs,
    normalize_program_record,
    parse_payout,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (500, 500),
        (500.9, 500),
        ("$5,000", 5000),
        ("Up to $5,000", 5000),
        ("$500K", 500_000),
        ("$1.5M", 1_500_000),
        ("$2B", 2_000_000_000),
        ("500KB", 500),  # kilobytes, not money
        (None, None),
        ("", None),
        ("no money here", None),
        (True, None),
        (-500, None),
        (float("nan"), None),
    ],
)
def test_parse_payout_table(raw, expected):
    assert parse_payout(raw) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Pot 10K USDC up for grabs", (10_000, "10K USDC")),
        ("Rewards 500 USDC total", (500, "500 USDC")),
        ("Prize 2 ETH paid out", (None, "2 ETH")),
        ("Bounty $500K max", (500_000, "$500K")),
        ("Payout $750 flat", (750, "$750")),
        ("no payout info", (None, None)),
    ],
)
def test_codehawks_payout_table(text, expected):
    assert _parse_codehawks_payout(text) == expected


def test_normalize_zero_payout_becomes_none():
    rec = normalize_program_record(
        {"name": "x", "url": "https://e.com/p", "max_payout_usd": 0}, "huntr"
    )
    assert rec is not None
    assert rec["max_payout_usd"] is None


def test_normalize_keeps_positive_payout():
    rec = normalize_program_record(
        {"name": "x", "url": "https://e.com/p", "max_payout_usd": 500}, "huntr"
    )
    assert rec is not None
    assert rec["max_payout_usd"] == 500


def _prog(**kw):
    base = {"name": "n", "platform": "huntr", "kind": "web2", "url": "https://e.com"}
    base.update(kw)
    return base


def test_none_payout_survives_score_and_filter():
    progs = [
        _prog(max_payout_usd=None),
        _prog(max_payout_usd=None, offers_bounties=True),
        _prog(max_payout_usd=0),
        _prog(max_payout_usd=1000),
    ]
    for p in progs:
        assert isinstance(_program_score(p), float)
    assert isinstance(filter_programs(progs), list)
    assert isinstance(filter_programs(progs, min_payout=500), list)
    assert isinstance(
        filter_programs(progs, min_payout=500, include_variable=True), list
    )
    assert isinstance(filter_programs(progs, max_payout=500), list)


def test_none_payout_kept_only_with_variable_flag():
    unknown = _prog(max_payout_usd=None, offers_bounties=True)
    assert filter_programs([unknown], min_payout=500) == []
    assert filter_programs([unknown], min_payout=500, include_variable=True) == [
        unknown
    ]


def test_program_brief_survives_none_and_string_payout():
    for bad in (None, "abc"):
        ctx = OracleMindsetContext(
            program={
                "name": "x",
                "platform": "huntr",
                "url": "https://e.com",
                "kind": "web2",
                "max_payout_usd": bad,
                "structured_scopes": [],
            }
        )
        assert "$0" in ctx._program_brief()


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Launched 2024, $2.5M max bounty", 2_500_000),
        ("Launched 2024, $50000 max", 50_000),
        ("Launched 2024, 50000 max", None),  # no $ → unknown
        ("Top 10M users, pays $500", 500),
    ],
)
def test_parse_payout_require_symbol(text, expected):
    assert parse_payout(text, require_symbol=True) == expected


def test_max_gate_excludes_unknown_payout():
    assert filter_programs([_prog(max_payout_usd=None)], max_payout=500) == []
    assert filter_programs([_prog(max_payout_usd=100)], max_payout=500) != []


def test_codehawks_op_false_positive_stays_none():
    payout, raw = _parse_codehawks_payout("500 Operations completed")
    assert payout is None
    assert raw == "500 Op"
