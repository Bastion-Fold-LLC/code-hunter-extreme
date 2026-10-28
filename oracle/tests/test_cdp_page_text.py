"""Saved-session CDP page fetch contract.

Regression: Chrome >= 111 answers GET /json/new with 405. The old
code used GET and swallowed the exception, so every live hunt's
authoritative program page died as CDP_RENDER_FAILED while the
browser was up the whole time. PUT is required, and failures must
surface their reason instead of a silent None.
"""
import json
import sys
import types
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_scan


class _FakeWS:
    def __init__(self):
        self._queue = [
            {"id": 1, "result": {}},
            {
                "id": 2,
                "result": {"result": {"value": "Program scope text " + "z" * 60}},
            },
        ]

    def send(self, _msg):
        pass

    def recv(self):
        return json.dumps(self._queue.pop(0))

    def close(self):
        pass


def test_cdp_page_text_creates_tab_with_put(monkeypatch):
    methods = []

    class _Resp:
        def read(self):
            return json.dumps(
                {"id": "TAB1", "webSocketDebuggerUrl": "ws://x/devtools/page/1"}
            ).encode()

    def _fake_urlopen(req, timeout=5):
        methods.append((req.get_method(), req.full_url))
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    fake_ws_mod = types.ModuleType("websocket")
    fake_ws_mod.create_connection = lambda url, timeout=15: _FakeWS()
    monkeypatch.setitem(sys.modules, "websocket", fake_ws_mod)
    monkeypatch.setattr("time.sleep", lambda s: None)

    out = oracle_scan._cdp_page_text("https://example.com/program", cdp_port=9227, wait=0)
    assert out and "Program scope text" in out
    assert ("PUT", "http://localhost:9227/json/new?about:blank") in methods


def test_cdp_page_text_failure_is_reported_not_silent(monkeypatch, capsys):
    def _fail(req, timeout=5):
        raise OSError("HTTP Error 405: Method Not Allowed")

    monkeypatch.setattr(urllib.request, "urlopen", _fail)
    out = oracle_scan._cdp_page_text("https://example.com/program", cdp_port=9227, wait=0)
    assert out is None
    assert "405" in capsys.readouterr().out
