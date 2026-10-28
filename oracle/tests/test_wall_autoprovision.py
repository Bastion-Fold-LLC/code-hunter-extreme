#!/usr/bin/env python3
"""Wall gap 4.2: 2-account IDOR auto-provisioning.

Loopback only: a juice-style stub (/api/Users registration + /rest/basket)
proves registration → JWT extraction → cross-account IDOR probe with zero
manual token injection.
"""

import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_auth_session import (
    AutoProvisionError,
    DualAccountHarness,
    auto_provision_accounts,
    evaluate_cross_account_idor,
)


class _JuiceStub(BaseHTTPRequestHandler):
    users = {}

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/api/Users":
            self._send(404, {"error": "nope"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length).decode())
        except ValueError:
            self._send(400, {"error": "bad json"})
            return
        email = data.get("email", "")
        if not email or "password" not in data:
            self._send(400, {"error": "email+password required"})
            return
        if email in type(self).users:
            self._send(400, {"error": "email already exists"})
            return
        type(self).users[email] = len(type(self).users) + 1
        # Juice nests the token under authentication.
        self._send(
            201, {"authentication": {"token": f"jwt-for-{email}"}, "id": len(type(self).users)}
        )

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "rest" and parts[1] == "basket":
            auth = self.headers.get("Authorization", "")
            self._send(200, {"id": parts[2], "for_user": auth})
            return
        self._send(404, {"error": "nope"})

    def log_message(self, *a):
        pass


def _serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _harness():
    return DualAccountHarness(
        target_domain="127.0.0.1",
        platform="generic",
        researcher_username="tester",
    )


def test_auto_provision_registers_two_jwt_accounts():
    _JuiceStub.users = {}
    server = _serve(_JuiceStub)
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        harness = _harness()
        minted = auto_provision_accounts(harness, f"{base}/api/Users", password="pw123456")
        assert set(minted) == {"a", "b"}
        assert harness.account_a.token == f"Bearer jwt-for-{harness.alias_a}"
        assert harness.account_b.token == f"Bearer jwt-for-{harness.alias_b}"
        assert harness.account_a.token != harness.account_b.token
        # The provisioned pair immediately drives a cross-account IDOR probe
        # (C2: the live token rides as a placeholder, resolved at execution).
        proof = evaluate_cross_account_idor(harness, f"{base}/rest/basket/{{id}}", "1")
        assert "__ORACLE_ACCOUNT_B_AUTH__" in proof["check"]
        assert f"{base}/rest/basket/1" in proof["check"]
    finally:
        server.shutdown()


def test_auto_provision_fails_loud_on_reject():
    _JuiceStub.users = {}
    server = _serve(_JuiceStub)
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        harness = _harness()
        auto_provision_accounts(harness, f"{base}/api/Users", password="pw123456")
        # Second run: emails already exist → loud failure, no half-pair.
        harness2 = _harness()
        with pytest.raises(AutoProvisionError):
            auto_provision_accounts(harness2, f"{base}/api/Users", password="pw123456")
        assert harness2.account_a.token is None
    finally:
        server.shutdown()


def test_auto_provision_rejects_tokenless_register():
    class _Empty(BaseHTTPRequestHandler):
        def do_POST(self):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = _serve(_Empty)
    try:
        with pytest.raises(AutoProvisionError):
            auto_provision_accounts(
                _harness(), f"http://127.0.0.1:{server.server_port}/reg"
            )
    finally:
        server.shutdown()
