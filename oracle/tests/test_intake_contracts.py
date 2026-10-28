#!/usr/bin/env python3
"""#8: non-DNS liveness leg — contract scope verifies via RPC codehash / repo URL.

Loopback only: the JSON-RPC and HTTP stubs bind 127.0.0.1 ephemeral ports.
No external network is touched.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_intake as intake

ADDR = "0x" + "ab" * 20


def _contract_prog(*idents):
    return {
        "name": "Web3",
        "handle": "web3",
        "platform": "immunefi",
        "url": "https://immunefi.com/web3",
        "structured_scopes": [
            {"asset_identifier": i, "asset_type": "SMART_CONTRACT"}
            for i in idents
        ],
    }


def test_derive_contract_targets_kinds():
    targets, skipped = intake.derive_contract_targets(
        _contract_prog(ADDR, "https://github.com/org/repo", "not-a-target")
    )
    assert [t["kind"] for t in targets] == ["evm-address", "repo-url"]
    assert len(skipped) == 1
    # Non-contract scope never yields contract targets.
    targets, _ = intake.derive_contract_targets(
        {"structured_scopes": [{"asset_identifier": "x.com", "asset_type": "URL"}]}
    )
    assert targets == []


def test_evm_address_without_rpc_is_unprobed_not_live():
    res = intake.default_contract_probe({"kind": "evm-address", "address": ADDR})
    assert res["live"] is False
    assert "no RPC" in res["error"]


class _RpcStub(BaseHTTPRequestHandler):
    code = "0x60806040"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode())
        assert body["method"] == "eth_getCode"
        assert body["params"][0] == ADDR
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": type(self).code}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def _serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_getcode_live_and_empty_against_loopback_rpc():
    server = _serve(_RpcStub)
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        res = intake.default_contract_probe(
            {"kind": "evm-address", "address": ADDR}, rpc_url=url
        )
        assert res["live"] is True
        _RpcStub.code = "0x"
        res = intake.default_contract_probe(
            {"kind": "evm-address", "address": ADDR}, rpc_url=url
        )
        assert res["live"] is False
        assert "no code" in res["error"]
    finally:
        server.shutdown()
        _RpcStub.code = "0x60806040"


class _RepoStub(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_repo_url_liveness_against_loopback_http():
    server = _serve(_RepoStub)
    try:
        url = f"http://127.0.0.1:{server.server_port}/org/repo"
        res = intake.default_contract_probe({"kind": "repo-url", "url": url})
        assert res["live"] is True
    finally:
        server.shutdown()
    res = intake.default_contract_probe(
        {"kind": "repo-url", "url": "http://127.0.0.1:1/nope"}
    )
    assert res["live"] is False


def test_scope_live_passes_via_contract_leg_only():
    def cprobe(target, rpc_url=None, timeout=8.0):
        assert rpc_url == "http://rpc.test"
        return {"target": "x", "kind": target["kind"], "live": True, "error": ""}

    chk = intake.check_scope_live(
        _contract_prog(ADDR),
        probe_fn=lambda h, t=8.0: {"host": h, "resolves": False, "live": False},
        contract_probe_fn=cprobe,
        rpc_url="http://rpc.test",
    )
    assert chk["pass"] is True
    assert "contracts live" in chk["reason"]
    assert chk["contracts_live_count"] == 1
    assert chk["hosts"] == []


def test_scope_live_contract_leg_needs_proof():
    def cprobe(target, rpc_url=None, timeout=8.0):
        return {"target": "x", "kind": target["kind"], "live": False, "error": "no code"}

    chk = intake.check_scope_live(_contract_prog(ADDR), contract_probe_fn=cprobe)
    assert chk["pass"] is False
    assert "stale scope" in chk["reason"]


def test_no_cloud_leaves_contracts_unprobed():
    def cprobe(target, rpc_url=None, timeout=8.0):  # pragma: no cover
        raise AssertionError("must not probe under --no-cloud")

    chk = intake.check_scope_live(
        _contract_prog(ADDR), contract_probe_fn=cprobe, no_cloud=True
    )
    assert chk["pass"] is False
    assert chk["contracts_probed"] == []
    assert len(chk["contracts"]) == 1
