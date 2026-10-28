#!/usr/bin/env python3
"""CLI secrets must never be literal argv values, and polite (controlled)
recon must be reachable — and default — on the live-traffic subcommands."""

import subprocess
import sys
from pathlib import Path

import pytest

import oracle_hunter as oh

ROOT = Path(__file__).resolve().parent.parent


def test_secret_arg_none_stays_none():
    assert oh._resolve_secret_arg(None, "--auth") is None


def test_secret_arg_from_env(monkeypatch):
    monkeypatch.setenv("ORACLE_TEST_TOKEN", "Bearer [REDACTED]")
    assert (
        oh._resolve_secret_arg("env:ORACLE_TEST_TOKEN", "--auth")
        == "Bearer [REDACTED]"
    )


def test_secret_arg_from_file(tmp_path):
    f = tmp_path / "tok.txt"
    f.write_text("session=abc\n", encoding="utf-8")
    assert oh._resolve_secret_arg(f"@{f}", "--cookie") == "session=abc"


def test_secret_arg_literal_rejected():
    with pytest.raises(SystemExit):
        oh._resolve_secret_arg("Bearer literal-secret", "--auth")


def test_secret_arg_missing_env_fails_loud(monkeypatch):
    monkeypatch.delenv("ORACLE_NOPE", raising=False)
    with pytest.raises(SystemExit):
        oh._resolve_secret_arg("env:ORACLE_NOPE", "--auth")


def _help(*argv):
    r = subprocess.run(
        [sys.executable, "oracle_hunter.py", *argv, "--help"],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
    )
    return r.stdout + r.stderr


def test_hunt_and_recon_expose_controlled_default_on():
    for sub in ("hunt", "recon"):
        out = _help(sub)
        assert "--controlled" in out, sub
        assert "--no-controlled" in out, sub


def test_secret_flags_document_indirection_not_literals():
    out = _help("hunt")
    assert "env:" in out
    assert "@FILE" in out or "@path" in out.lower()
