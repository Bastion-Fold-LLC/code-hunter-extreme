#!/usr/bin/env python3
"""Break-it round 3: _fetch normalizes schemeless URLs (crawl4ai ×127 fix)."""

import oracle_programs as op


def test_fetch_prepends_http_to_bare_host(monkeypatch):
    seen = []

    def fake_cdp(url, **kwargs):
        seen.append(url)
        return "z" * 201

    monkeypatch.setattr(op, "_cdp_fetch", fake_cdp)
    assert op._fetch("127.0.0.1:3000") == "z" * 201
    assert seen == ["http://127.0.0.1:3000"]


def test_fetch_leaves_schemed_urls_alone(monkeypatch):
    seen = []
    monkeypatch.setattr(
        op, "_cdp_fetch", lambda url, **kw: seen.append(url) or "z" * 201
    )
    op._fetch("https://example.com/")
    op._fetch("//example.com/x")
    assert seen == ["https://example.com/", "http://example.com/x"]


def test_browsers_explicit_path_wins(monkeypatch, tmp_path):
    target = tmp_path / "pw"
    (target / "chromium-9999").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(target))
    assert op._ensure_playwright_browsers() == str(target)


def test_browsers_falls_back_to_passwd_home(monkeypatch, tmp_path):
    import os
    import pwd

    real_cache = tmp_path / ".cache" / "ms-playwright"
    (real_cache / "chromium-9999").mkdir(parents=True)
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "sandbox"))
    fake_pw = pwd.struct_passwd(("u", "x", 0, 0, "", str(tmp_path), "/bin/sh"))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: fake_pw)
    # _ensure_playwright_browsers() pins PLAYWRIGHT_BROWSERS_PATH via a
    # direct os.environ write (invisible to monkeypatch): contain the fake
    # tmp path or every later browser launch in this process resolves
    # into a deleted tmp dir.
    sentinel = object()
    before = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", sentinel)
    try:
        got = op._ensure_playwright_browsers()
        assert got == str(real_cache)
    finally:
        if before is sentinel:
            os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
        else:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = before


def test_browsers_none_when_nowhere(monkeypatch, tmp_path):
    import pwd

    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "sandbox"))
    fake_pw = pwd.struct_passwd(
        ("u", "x", 0, 0, "", str(tmp_path / "empty"), "/bin/sh")
    )
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: fake_pw)
    assert op._ensure_playwright_browsers() is None
