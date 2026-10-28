"""Regression: _looks_client_rendered must actually run (NameError was swallowed)."""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_bulk_download import _looks_client_rendered
from oracle_discovery import _get


class _FakeResponse:
    def __init__(self, text):
        self._text = text.encode("utf-8")

    def read(self):
        return self._text


def _sherlock_ui(req, timeout=20):
    return _FakeResponse("bug-bounties self.__next_f Bug Bounty - Sherlock")


def test_detects_js_only_sherlock_ui():
    with patch("urllib.request.urlopen", side_effect=_sherlock_ui):
        assert _looks_client_rendered("http://example.com/x") is True


def test_rejects_other_pages():
    with patch(
        "urllib.request.urlopen", return_value=_FakeResponse("<html>hi</html>")
    ):
        assert _looks_client_rendered("http://example.com/x") is False


def test_network_failure_returns_false():
    with patch("urllib.request.urlopen", side_effect=TimeoutError("slow")):
        assert _looks_client_rendered("http://example.com/x") is False


def test_rejects_file_scheme_without_fetch():
    with patch("urllib.request.urlopen") as m:
        assert _looks_client_rendered("file:///etc/passwd") is False
        m.assert_not_called()


def test_discovery_get_rejects_non_http():
    with patch("urllib.request.urlopen") as m:
        with pytest.raises(ValueError):
            _get("file:///etc/passwd")
        m.assert_not_called()
