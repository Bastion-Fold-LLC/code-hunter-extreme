#!/usr/bin/env python3
"""Authenticated discovery gates: saved Chromium sessions + loud degradation.

Proves the Step 3 combo without a browser: CDP ensure/reuse behavior is
mocked, scraper CDP failure returns [] (never raises, never poisons), and
every scraper reuses the logged-in profile context.
"""

import ast
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import oracle_programs as op
from oracle_programs import _cdp_fetch, _ensure_chromium_cdp, _scrape_patchstack

SRC = Path(__file__).resolve().parent.parent / "oracle_programs.py"


def test_ensure_reuses_warm_browser_without_launch():
    with (
        patch.object(op, "_tabs_list", return_value=[{"type": "page"}]),
        patch.object(op.subprocess, "Popen") as popen,
    ):
        assert _ensure_chromium_cdp(port=19227) is True
    popen.assert_not_called()


def test_ensure_warns_when_browser_wont_start():
    with (
        patch.object(op, "_tabs_list", return_value=None),
        patch.object(op.subprocess, "Popen"),
        patch.object(op.time, "sleep"),
    ):
        assert _ensure_chromium_cdp(port=19227) is False


def test_cdp_fetch_none_when_ensure_fails():
    with patch.object(op, "_ensure_chromium_cdp", return_value=False):
        assert _cdp_fetch("https://example.com", port=19227) is None


def test_scraper_returns_empty_when_cdp_down():
    # patch() resolves its target even when mocking: without playwright
    # installed there is nothing to patch (the mock can't stand in for
    # a missing module), so skip instead of erroring at patch lookup.
    pytest.importorskip("playwright.async_api")
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(side_effect=RuntimeError("cdp down"))
    cm.__aexit__ = AsyncMock(return_value=False)
    with patch("playwright.async_api.async_playwright", return_value=cm):
        assert _scrape_patchstack() == []


def test_every_scraper_reuses_logged_in_profile_context():
    """Each _scrape_* adapter must prefer browser.contexts[0] (saved logins)."""
    tree = ast.parse(SRC.read_text())
    missing = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("_scrape_"):
            continue
        src = ast.get_source_segment(SRC.read_text(), node) or ""
        if "browser.contexts[0]" not in src and "contexts[0]" not in src:
            # Generic adapters without CDP are exempt only if they fetch no pages.
            if "page.goto" in src or "connect_over_cdp" in src:
                missing.append(node.name)
    assert missing == [], f"scrapers bypassing saved profile: {missing}"
