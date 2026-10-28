"""The operator CLI has one pipeline: prescan → scan → queue --execute.

`hunt <program>` is a one-off escape hatch. It must not re-resolve Scan4Me,
pick a handoff/schedule entry, or expose a partial-mindset selector.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "oracle_hunter.py", *argv],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )


def _help(sub: str) -> str:
    r = _run(sub, "--help")
    assert r.returncode == 0, r.stderr
    return r.stdout + r.stderr


def test_hunt_has_no_pipeline_input_or_mindset_flags():
    out = _help("hunt")
    for flag in (
        "--from-scan4me",
        "--scan4me-top",
        "--handoff",
        "--schedule",
        "--pick",
        "--mindset",
        "--auto-pick",
        "--fast-triage",
        "--min-payout",
        "--max-payout",
        "--no-verify",
        "--seam-allow-new",
        "--allow-incomplete-tactics",
    ):
        assert flag not in out, flag


def test_queue_has_no_mindset_or_integrity_bypass_flags():
    out = _help("queue")
    for flag in (
        "--mindset",
        "--no-verify",
        "--seam-allow-new",
        "--allow-incomplete-tactics",
    ):
        assert flag not in out, flag
    assert "--execute" in out


def test_scan_owns_number_and_download():
    out = _help("scan")
    assert "-N" in out
    assert "--download" in out


def test_hunt_requires_an_explicit_program():
    r = _run("hunt")
    assert r.returncode == 2
    assert "program" in (r.stdout + r.stderr).lower()


def test_removed_mindset_flag_is_rejected():
    r = _run("hunt", "example", "--mindset", "seam")
    assert r.returncode == 2
    assert "--mindset" in (r.stdout + r.stderr)


def test_oracle_scan_cli_is_retired():
    r = subprocess.run(
        [sys.executable, "oracle_scan.py", "--scan"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )
    assert r.returncode == 2
    text = r.stdout + r.stderr
    assert "retired" in text
    assert "oracle-hunter prescan --sync" in text
    assert "oracle-hunter scan -N 1 --download" in text


def test_product_bundle_commands_are_explicit_gates():
    bundle = _help("bundle")
    assert "workspace" in bundle
    assert "--out-dir" in bundle
    verify = _help("verify-download")
    assert "bundle" in verify
    assert "--json" in verify
    for out in (bundle, verify):
        for flag in ("--mindset", "--no-verify", "--seam-allow-new"):
            assert flag not in out
