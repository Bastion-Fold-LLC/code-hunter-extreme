"""Proof6 fixes: origin URLs, sanitized wordlist, bounded review."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
from oracle_deeprecon import _sanitized_wordlist  # noqa: E402
from oracle_foundation import SHELL_METACHARS, validate_card_shape  # noqa: E402
from oracle_mindset_context import (  # noqa: E402
    ProgramWorkspace,
    _raw_get,
    _spec_doc_urls,
)


def _card(**over):
    base = {
        "n": 1,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without auth",
        "check": "curl -s http://h.test/api",
        "expected": "status 200",
    }
    base.update(over)
    return base


def test_spec_doc_urls_keep_origin():
    urls = _spec_doc_urls(["http://localhost:32768/", "https://a.com/x"])
    assert "http://localhost:32768/openapi.json" in urls
    assert "http://localhost:32768/robots.txt" in urls
    assert "https://a.com/swagger.json" in urls
    assert not [u for u in urls if u.startswith("https://localhost/")]
    assert _spec_doc_urls(["not a url", ""]) == []


def test_sanitized_wordlist_strips_comments(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("# comment\n\napi\n  # indented\nadmin\n")
    out = _sanitized_wordlist(wl, tmp_path)
    assert out != wl
    assert out.read_text().splitlines() == ["api", "admin"]


def test_sanitized_wordlist_clean_passthrough(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("api\nadmin\n")
    assert _sanitized_wordlist(wl, tmp_path) == wl
    assert _sanitized_wordlist(tmp_path / "missing.txt", tmp_path).name == (
        "missing.txt"
    )


def test_unread_review_pass_stays_cut():
    # #17: the model_reviews pass had zero readers — cut, with its helper.
    # Locks the cut: no seam may grow a model_reviews key from the hunt path.
    assert not hasattr(oh, "_collaborate_bounded")
    assert not hasattr(oh, "REVIEW_DEADLINE_S")


def test_metachar_parity():
    assert SHELL_METACHARS == oh._SHELL_METACHARS


def test_op1_drops_metachar_cards():
    assert validate_card_shape(_card()) is None
    for meta in SHELL_METACHARS:
        check = f"curl -s http://h.test/a{meta}id"
        reason = validate_card_shape(_card(check=check))
        assert reason is not None
        assert "metachar" in reason


def test_raw_get_rejects_non_http():
    assert _raw_get("ftp://h.test/x") == ""
    assert _raw_get("") == ""


def test_raw_get_failure_returns_empty():
    assert _raw_get("http://127.0.0.1:9/", timeout=2) == ""
