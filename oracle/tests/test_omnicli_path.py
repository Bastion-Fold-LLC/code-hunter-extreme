"""OmniCLI checkout resolution without hardcoded usernames."""

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_llm as llm  # noqa: E402


def _fake_checkout(base: Path) -> Path:
    pkg = base / "omnicli"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("")
    return base


def test_env_home_wins(tmp_path, monkeypatch):
    home = _fake_checkout(tmp_path / "custom")
    monkeypatch.setenv("OMNICLI_HOME", str(home))
    assert llm.omnicli_home() == home


def test_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNICLI_HOME", str(tmp_path / "empty"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "nobody")
    assert llm.omnicli_home() is None


def test_no_hardcoded_username():
    assert not hasattr(llm, "_OMNICLI_PATH")
    src = inspect.getsource(llm.omnicli_home)
    assert "/home/" not in src
    assert "phantomcore" not in src


def test_ensure_finds_real_checkout():
    if llm.omnicli_home() is None or not llm.ensure_omnicli_importable():
        pytest.skip("no importable omnicli checkout on this machine")
    import omnicli  # noqa: F401


def test_env_home_is_authoritative_when_invalid(tmp_path, monkeypatch):
    # De-hardcode: an explicit OMNICLI_HOME controls resolution — an
    # invalid value must NOT silently fall through to layout guesses.
    fake_home = tmp_path / "home"
    _fake_checkout(fake_home / "tools" / "omnicli")
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setenv("OMNICLI_HOME", str(tmp_path / "does-not-exist"))
    assert llm.omnicli_home() is None
