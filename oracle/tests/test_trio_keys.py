"""Trio central key store: fallback when repo .env lacks the key."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402


def test_central_keys_fill_gaps(tmp_path, monkeypatch):
    central = tmp_path / "keys.env"
    central.write_text("TRIO_TEST_ONLY_KEY=from-central\n")
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", central)
    monkeypatch.delenv("TRIO_TEST_ONLY_KEY", raising=False)
    assert oh._load_env()["TRIO_TEST_ONLY_KEY"] == "from-central"


def test_repo_env_beats_central(tmp_path, monkeypatch):
    central = tmp_path / "keys.env"
    central.write_text("TRIO_TEST_ONLY_KEY=from-central\n")
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", central)
    monkeypatch.setenv("TRIO_TEST_ONLY_KEY", "from-process")
    assert oh._load_env()["TRIO_TEST_ONLY_KEY"] == "from-process"


def test_oracle_keys_fill_gaps(tmp_path, monkeypatch):
    """ORACLE_KEYS.env holds platform keys absent from .env (H1/Intigriti)."""
    keys = tmp_path / "ORACLE_KEYS.env"
    keys.write_text("TRIO_TEST_ONLY_KEY=from-oracle-keys\n")
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", tmp_path / "nope.env")
    monkeypatch.setattr(oh, "ORACLE_KEYS_FILE", keys)
    monkeypatch.delenv("TRIO_TEST_ONLY_KEY", raising=False)
    assert oh._load_env()["TRIO_TEST_ONLY_KEY"] == "from-oracle-keys"


def test_empty_placeholder_never_clobbers_real_key(tmp_path, monkeypatch):
    central = tmp_path / "keys.env"
    central.write_text("TRIO_TEST_ONLY_KEY=real-value\n")
    keys = tmp_path / "ORACLE_KEYS.env"
    keys.write_text("TRIO_TEST_ONLY_KEY=\n")
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", central)
    monkeypatch.setattr(oh, "ORACLE_KEYS_FILE", keys)
    monkeypatch.delenv("TRIO_TEST_ONLY_KEY", raising=False)
    assert oh._load_env()["TRIO_TEST_ONLY_KEY"] == "real-value"


def test_programs_loader_reads_oracle_keys(tmp_path, monkeypatch):
    import oracle_programs as op

    keys = tmp_path / "ORACLE_KEYS.env"
    keys.write_text("TRIO_TEST_ONLY_KEY=from-oracle-keys\n")
    monkeypatch.setattr(op, "ENV_FILE", tmp_path / "nope.env")
    monkeypatch.setattr(op, "ORACLE_KEYS_FILE", keys)
    monkeypatch.delenv("TRIO_TEST_ONLY_KEY", raising=False)
    assert op._load_env()["TRIO_TEST_ONLY_KEY"] == "from-oracle-keys"
    assert op._key("TRIO_TEST_ONLY_KEY") == "from-oracle-keys"


def test_placeholder_sentence_credential_reads_unset(tmp_path, monkeypatch):
    """A multi-word sentence in a credential slot is a placeholder note,
    not a key: loaders must treat it as unset so API tiers skip cleanly
    instead of firing doomed requests (or crashing Basic-auth encoding)."""
    keys = tmp_path / "ORACLE_KEYS.env"
    keys.write_text("SOME_API_KEY=replace me — paste real key here\n")
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", tmp_path / "nope.env")
    monkeypatch.setattr(oh, "ORACLE_KEYS_FILE", keys)
    monkeypatch.delenv("SOME_API_KEY", raising=False)
    assert "SOME_API_KEY" not in oh._load_env()

    import oracle_programs as op

    monkeypatch.setattr(op, "ENV_FILE", tmp_path / "nope.env")
    monkeypatch.setattr(op, "ORACLE_KEYS_FILE", keys)
    assert op._key("SOME_API_KEY") is None


def test_real_single_token_credential_survives_guard(tmp_path, monkeypatch):
    keys = tmp_path / "ORACLE_KEYS.env"
    keys.write_text("SOME_API_KEY=abc123DEF-_.singleToken\n")
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", tmp_path / "nope.env")
    monkeypatch.setattr(oh, "ORACLE_KEYS_FILE", keys)
    monkeypatch.delenv("SOME_API_KEY", raising=False)
    assert oh._load_env()["SOME_API_KEY"] == "abc123DEF-_.singleToken"


def test_programs_loader_env_precedence_matches_hunter(tmp_path, monkeypatch):
    """Both loaders: process env beats files; env-only whitespace
    placeholders are dropped from _load_env, not just filtered by _key."""
    import oracle_programs as op

    keys = tmp_path / "ORACLE_KEYS.env"
    keys.write_text("SOME_API_KEY=file-value\n")
    monkeypatch.setattr(op, "ENV_FILE", tmp_path / "nope.env")
    monkeypatch.setattr(op, "ORACLE_KEYS_FILE", keys)
    monkeypatch.setenv("SOME_API_KEY", "env-value")
    assert op._load_env()["SOME_API_KEY"] == "env-value"
    monkeypatch.setenv("SOME_API_KEY", "not a real key")
    assert "SOME_API_KEY" not in op._load_env()
    assert op._key("SOME_API_KEY") is None
    # Trio-central layer is visible to programs callers too (parity).
    central = tmp_path / "keys.env"
    central.write_text("TRIO_TEST_ONLY_KEY=from-central\n")
    monkeypatch.setattr(op, "TRIO_KEYS_FILE", central)
    monkeypatch.delenv("TRIO_TEST_ONLY_KEY", raising=False)
    assert op._load_env()["TRIO_TEST_ONLY_KEY"] == "from-central"
    # Empty process value never clobbers a real file key.
    monkeypatch.setenv("SOME_API_KEY", "")
    assert op._load_env()["SOME_API_KEY"] == "file-value"


def test_missing_central_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(oh, "TRIO_KEYS_FILE", tmp_path / "nope.env")
    monkeypatch.delenv("TRIO_TEST_ONLY_KEY", raising=False)
    assert "TRIO_TEST_ONLY_KEY" not in oh._load_env()
