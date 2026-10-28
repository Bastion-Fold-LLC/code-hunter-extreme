#!/usr/bin/env python3
"""Repo cloning must go through the single in-scope-gated hunter path."""

import oracle_hunter as oh
import oracle_scan as o_scan


def test_hunter_clone_skips_offscope_without_running_git(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(oh, "_run", lambda *a, **kw: calls.append(a) or (0, "", ""))
    out = oh._clone_program_repos(
        ["https://github.com/random-org/unrelated"],
        tmp_path,
        prog={"name": "Acme", "scope": "api.acme.com", "url": ""},
    )
    assert out == []
    assert calls == []


def test_hunter_clone_uses_separator_before_url(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, timeout=None):
        calls.append(argv)
        # Simulate a successful clone creating the destination dir.
        dest = argv[-1]
        from pathlib import Path

        Path(dest).mkdir(parents=True, exist_ok=True)
        return 0, "", ""

    monkeypatch.setattr(oh, "_run", fake_run)
    url = "https://github.com/acme/widgets"
    out = oh._clone_program_repos(
        [url], tmp_path, prog={"name": "Acme", "scope": "", "url": ""}
    )
    assert out and out[0].name == "acme_widgets"
    argv = calls[0]
    assert argv[argv.index(url) - 1] == "--"


def test_scan_clone_delegates_to_gated_hunter_path(tmp_path, monkeypatch):
    seen = {}

    def fake_gated(urls, dest_base, prog=None):
        seen["urls"] = list(urls)
        seen["dest"] = dest_base
        seen["prog"] = prog
        return [dest_base / "acme_widgets"]

    monkeypatch.setattr(oh, "_clone_program_repos", fake_gated)
    saved = o_scan._clone_repos_gated(
        {"https://github.com/acme/widgets"}, tmp_path, {"name": "Acme"}
    )
    assert saved == ["repo:acme_widgets"]
    assert seen["urls"] == ["https://github.com/acme/widgets"]
    assert seen["dest"] == tmp_path / "repos"
