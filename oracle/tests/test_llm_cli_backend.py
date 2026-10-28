import os, stat, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import pytest


def _fake_bin(tmp_path, name, body):
    p = tmp_path / name
    p.write_text("#!/usr/bin/env bash\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def test_cli_success(tmp_path, monkeypatch):
    _fake_bin(tmp_path, "fakecli", 'echo "SEAM 1 ok"\n')
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    b = L.CliBackend("fakecli", "fakecli -p")
    assert b.available() is True
    assert "SEAM 1 ok" in b.complete("sys", "prompt", timeout=10)


def test_cli_nonzero_raises(tmp_path, monkeypatch):
    _fake_bin(tmp_path, "failcli", 'echo "refused [cyber]" >&2\nexit 1\n')
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    b = L.CliBackend("failcli", "failcli -p")
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt", timeout=10)


def test_cli_unavailable_when_missing():
    b = L.CliBackend("nope-xyz", "nope-xyz -p")
    assert b.available() is False
