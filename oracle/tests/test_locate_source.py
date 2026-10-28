import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def test_explicit_path_returned(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    assert oh._locate_target_source("prog", str(d)) == d.resolve()


def test_explicit_missing_dies(tmp_path):
    with pytest.raises(SystemExit):
        oh._locate_target_source("prog", str(tmp_path / "nope"))


def test_autodiscovers_repo_under_targets(tmp_path, monkeypatch):
    targets = tmp_path / "targets" / "sherlock_aave" / "aave-v4"
    targets.mkdir(parents=True)
    (targets / "Hub.sol").write_text("contract Hub {}")
    monkeypatch.setattr(oh, "_HERE", tmp_path)
    got = oh._locate_target_source("aave", None)
    assert got == targets.resolve()


def test_none_when_only_screenshots(tmp_path, monkeypatch):
    (tmp_path / "targets" / "prog" / "screenshots").mkdir(parents=True)
    monkeypatch.setattr(oh, "_HERE", tmp_path)
    assert oh._locate_target_source("prog", None) is None
