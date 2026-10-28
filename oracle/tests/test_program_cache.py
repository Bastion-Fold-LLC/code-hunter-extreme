#!/usr/bin/env python3
"""Unit tests for program cache protection (H4 / Phase 1c)."""

import json
from pathlib import Path
import pytest
from oracle_programs import _load_cache, _save_cache


def test_empty_fetch_does_not_overwrite_populated_cache(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"

    # Pre-populate cache with valid data
    initial_data = {
        "fetched_at": "2026-10-04T00:00:00+00:00",
        "count": 2,
        "programs": [
            {"platform": "hackerone", "name": "prog_a"},
            {"platform": "bugcrowd", "name": "prog_b"},
        ],
    }
    cache_path.write_text(json.dumps(initial_data, indent=2))

    # Attempt to save empty programs list
    saved = _save_cache([], cache_file=cache_path)
    assert not saved, "Saving empty programs list should be rejected"

    # Verify cache file was not overwritten or corrupted
    on_disk = json.loads(cache_path.read_text())
    assert on_disk["count"] == 2
    assert len(on_disk["programs"]) == 2
    assert on_disk["programs"][0]["name"] == "prog_a"


def test_none_fetch_does_not_overwrite_cache(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    cache_path.write_text(json.dumps({"count": 1, "programs": [{"name": "test"}]}))

    saved = _save_cache(None, cache_file=cache_path)
    assert not saved

    on_disk = json.loads(cache_path.read_text())
    assert on_disk["count"] == 1


def test_valid_fetch_updates_cache(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    cache_path.write_text(json.dumps({"count": 1, "programs": [{"name": "old"}]}))

    new_programs = [{"platform": "immunefi", "name": "new_protocol"}]
    saved = _save_cache(new_programs, cache_file=cache_path)
    assert saved

    on_disk = json.loads(cache_path.read_text())
    assert on_disk["count"] == 1
    assert on_disk["programs"][0]["name"] == "new_protocol"


def test_corrupt_cache_json_ignored(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    cache_path.write_text("{not valid json")
    assert _load_cache(cache_file=cache_path) is None


def test_wrong_shape_cache_ignored(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    cache_path.write_text(json.dumps([{"name": "list-not-dict"}]))
    assert _load_cache(cache_file=cache_path) is None


def test_unreadable_timestamp_cache_ignored(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "fetched_at": "not-a-timestamp",
                "programs": [{"name": "x"}],
            }
        )
    )
    assert _load_cache(cache_file=cache_path) is None


def test_nonlist_programs_cache_ignored(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "fetched_at": "2026-10-10T00:00:00+00:00",
                "programs": {"name": "dict-not-list"},
            }
        )
    )
    assert _load_cache(cache_file=cache_path) is None


def test_partial_fetch_marked_incomplete(tmp_path: Path):
    """Partial fetch saves programs but envelope says complete=False with errors."""
    cache_path = tmp_path / "programs_cache.json"
    new_programs = [{"platform": "hackerone", "name": "survivor"}]
    saved = _save_cache(new_programs, cache_file=cache_path, errors=["bugcrowd: boom"])
    assert saved

    on_disk = json.loads(cache_path.read_text())
    assert on_disk["count"] == 1
    assert on_disk["complete"] is False
    assert on_disk["fetch_errors"] == ["bugcrowd: boom"]
    # still loadable — partial data beats no data, but marked
    assert _load_cache(cache_file=cache_path) == new_programs


def test_complete_fetch_marked_complete(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    new_programs = [{"platform": "hackerone", "name": "ok"}]
    assert _save_cache(new_programs, cache_file=cache_path)

    on_disk = json.loads(cache_path.read_text())
    assert on_disk["complete"] is True
    assert on_disk["fetch_errors"] == []


def test_fetch_all_programs_returns_errors():
    from unittest.mock import patch

    from oracle_programs import PLATFORMS, SCRAPERS, fetch_all_programs

    good = [{"platform": "x", "name": "good", "url": "https://example.test/good"}]
    with (
        patch.dict(SCRAPERS, {"ok": lambda: good}, clear=True),
        patch.dict(PLATFORMS, {"ok": {"label": "OK", "kind": "web2"}}, clear=True),
    ):
        programs, errors = fetch_all_programs(["ok"], return_errors=True)
    assert len(programs) == 1
    assert errors == []

    def _boom():
        raise RuntimeError("dead platform")

    with (
        patch.dict(SCRAPERS, {"bad": _boom}, clear=True),
        patch.dict(PLATFORMS, {"bad": {"label": "BAD"}}, clear=True),
    ):
        programs, errors = fetch_all_programs(["bad"], return_errors=True)
    assert programs == []
    assert errors == ["bad: dead platform"]

    with patch.dict(SCRAPERS, {"ok": lambda: good}, clear=True):
        _, errors = fetch_all_programs(["nope"], return_errors=True)
    assert errors == ["nope: unknown platform"]


def test_save_cache_writes_atomically_without_tmp_litter(tmp_path: Path):
    cache_path = tmp_path / "programs_cache.json"
    new_programs = [{"platform": "hackerone", "name": "ok"}]
    assert _save_cache(new_programs, cache_file=cache_path)

    # no temp file left behind, final file is complete valid JSON
    assert not cache_path.with_name(cache_path.name + ".tmp").exists()
    on_disk = json.loads(cache_path.read_text())
    assert on_disk["count"] == 1
    assert on_disk["programs"] == new_programs


def _list_args(**overrides):
    import argparse

    base = dict(
        refresh=True,
        platform=None,
        min_payout=0,
        fast_triage=False,
        web2=False,
        web3=False,
        top=5,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_cmd_list_filtered_refresh_leaves_shared_cache_untouched(
    tmp_path: Path, monkeypatch
):
    import oracle_programs

    cache_path = tmp_path / "programs_cache.json"
    original = {
        "fetched_at": "2026-10-10T00:00:00+00:00",
        "count": 1,
        "complete": True,
        "fetch_errors": [],
        "programs": [{"platform": "hackerone", "name": "full-world"}],
    }
    cache_path.write_text(json.dumps(original))
    monkeypatch.setattr(oracle_programs, "CACHE_FILE", cache_path)
    monkeypatch.setattr(oracle_programs, "_load_cache", lambda *a, **k: None)

    fetched = [
        {
            "platform": "hackerone",
            "name": "one-platform",
            "url": "https://hackerone.com/one-platform",
            "max_payout_usd": 1000,
            "fast_triage": False,
            "reports_count": 3,
            "launched_at": "",
        }
    ]
    monkeypatch.setattr(
        oracle_programs,
        "fetch_all_programs",
        lambda platforms=None, return_errors=False: (fetched, []),
    )
    calls = []
    monkeypatch.setattr(
        oracle_programs,
        "_save_cache",
        lambda programs, **kwargs: calls.append((programs, kwargs)),
    )

    oracle_programs.cmd_list(_list_args(platform="hackerone"))

    assert calls == []
    assert json.loads(cache_path.read_text()) == original


def test_cmd_list_unfiltered_refresh_saves_with_errors(tmp_path: Path, monkeypatch):
    import oracle_programs

    cache_path = tmp_path / "programs_cache.json"
    monkeypatch.setattr(oracle_programs, "CACHE_FILE", cache_path)
    monkeypatch.setattr(oracle_programs, "_load_cache", lambda *a, **k: None)

    fetched = [
        {
            "platform": "hackerone",
            "name": "x",
            "url": "https://hackerone.com/x",
            "max_payout_usd": 10,
        }
    ]
    monkeypatch.setattr(
        oracle_programs,
        "fetch_all_programs",
        lambda platforms=None, return_errors=False: (fetched, ["bugcrowd: down"]),
    )
    calls = []
    monkeypatch.setattr(
        oracle_programs,
        "_save_cache",
        lambda programs, **kwargs: calls.append((programs, kwargs)),
    )

    oracle_programs.cmd_list(_list_args())

    assert len(calls) == 1
    assert calls[0][1]["errors"] == ["bugcrowd: down"]


def test_scan_platforms_filtered_refresh_skips_cache_save(monkeypatch):
    import oracle_programs
    import oracle_scan
    import oracle_triage

    monkeypatch.setattr(oracle_programs, "_load_cache", lambda *a, **k: None)
    fetched = [
        {
            "platform": "hackerone",
            "name": "x",
            "kind": "web2",
            "max_payout_usd": 1000,
            "fast_triage": False,
            "reports_count": 3,
            "launched_at": "",
        }
    ]
    monkeypatch.setattr(
        oracle_programs,
        "fetch_all_programs",
        lambda platforms=None, return_errors=False: (fetched, []),
    )
    calls = []
    monkeypatch.setattr(
        oracle_programs,
        "_save_cache",
        lambda programs, **kwargs: calls.append((programs, kwargs)),
    )
    monkeypatch.setattr(oracle_triage, "load_config", lambda path: {})
    monkeypatch.setattr(oracle_triage, "score_programs", lambda values, *a, **k: values)

    cfg = oracle_scan._default_config()
    cfg["scan"]["platforms"] = "hackerone"
    cfg["scan"]["refresh_cache"] = True
    oracle_scan.scan_platforms(cfg)
    assert calls == []

    cfg["scan"]["platforms"] = "all"
    oracle_scan.scan_platforms(cfg)
    assert len(calls) == 1
