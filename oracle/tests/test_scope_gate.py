#!/usr/bin/env python3
"""
Unit and Regression Tests for ProgramScopeGate & Deterministic Verification
──────────────────────────────────────────────────────────────────────────
Validates:
1. Program scope parsing (wildcards, apex domains, structured scopes, instructions).
2. Hard blocking of out-of-scope assets and 3rd-party CDNs/analytics.
3. Localhost leak protection on external targets.
4. Pre-flight check command validation and production safe-mode mutation downgrade.
5. Strict response evaluation (eliminating 401/403/530/404 false positives).
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

from oracle_hunter import (
    ProgramScopeGate,
    _assess_response,
    _distill_endpoints,
    _instruction_scope_tokens,
    _run_check,
)


def test_scope_gate_wildcard_matching():
    prog = {
        "name": "Test Program",
        "scope": "*.example.com\nexample.org",
        "out_of_scope": "secret.example.com\nlegacy.example.org",
    }
    gate = ProgramScopeGate(prog, "example.com")

    # In scope subdomains
    ok, reason = gate.is_in_scope("https://api.example.com/v1")
    assert ok, f"Expected in-scope: {reason}"

    ok, reason = gate.is_in_scope("https://sub.deep.example.com/test")
    assert ok, f"Expected in-scope: {reason}"

    # S4 semantics: '*.example.com' covers proper subdomains ONLY —
    # the apex needs its own explicit asset (bridge/Scan4Me parity).
    ok, reason = gate.is_in_scope("https://example.com/login")
    assert not ok, f"Expected apex out-of-scope under wildcard-only: {reason}"

    ok, reason = gate.is_in_scope("https://example.org/home")
    assert ok, f"Expected in-scope: {reason}"

    # Explicit out of scope
    ok, reason = gate.is_in_scope("https://secret.example.com/admin")
    assert not ok
    assert "EXPLICIT_OUT_OF_SCOPE" in reason

    ok, reason = gate.is_in_scope("https://legacy.example.org/status")
    assert not ok
    assert "EXPLICIT_OUT_OF_SCOPE" in reason


def test_scope_gate_rejects_public_suffix_wildcards():
    # S3: the execution gate must fail closed on registry-wide wildcards,
    # exactly as ingest (Scan4Me) and the bridge already do. A corrupt or
    # hostile *.com row in structured_scopes must never authorize probes.
    for rule in ("*.com", "*.co.uk", "*.io"):
        gate = ProgramScopeGate({"name": "E", "scope": rule}, "")
        assert not gate.is_in_scope("https://anything.com/x")[0], rule
        assert not gate.is_in_scope("https://anything.co.uk/x")[0], rule
        assert not gate.is_in_scope("https://com/x")[0], rule
    # Registrable wildcards keep working (incl. existing apex contract).
    gate = ProgramScopeGate({"name": "E", "scope": "*.example.co.uk"}, "")
    assert gate.is_in_scope("https://app.example.co.uk/x")[0]
    assert not gate.is_in_scope("https://app.other.co.uk/x")[0]
    gate = ProgramScopeGate({"name": "E", "scope": "*.example.com"}, "")
    assert gate.is_in_scope("https://api.example.com/x")[0]


def test_scope_gate_global_3rd_party_blocking():
    prog = {
        "name": "Target Corp",
        "scope": "*.targetcorp.com",
    }
    gate = ProgramScopeGate(prog, "targetcorp.com")

    third_parties = [
        "https://fonts.googleapis.com/css?family=Roboto",
        "https://www.google-analytics.com/analytics.js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "https://github.com/profile",
        "https://api.branch.io/v1/event",
        "https://app.intercom.io/widget",
    ]

    for tp in third_parties:
        ok, reason = gate.is_in_scope(tp)
        assert not ok, f"Expected 3rd party block for {tp}, got {reason}"
        assert "GLOBAL_3RD_PARTY_BLOCKED" in reason or "UNRECOGNIZED_HOST" in reason


def test_scope_gate_structured_scopes_with_instructions():
    prog = {
        "name": "Tinder Mock",
        "structured_scopes": [
            {
                "asset_identifier": "*.tinder.com",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            },
            {
                "asset_identifier": "go.tinder.com",
                "eligible_for_bounty": False,
                "eligible_for_submission": False,
            },
            {
                "asset_identifier": "AppsFlyer Subdomains",
                "eligible_for_bounty": False,
                "eligible_for_submission": False,
                "instruction": "* party.tinder.com\n* open.tinder.com\n* click.tinder.com",
            },
        ],
    }
    gate = ProgramScopeGate(prog, "tinder.com")

    # In scope
    ok, _ = gate.is_in_scope("https://auth.tinder.com/phone")
    assert ok

    # Explicit out of scope
    ok, reason = gate.is_in_scope("https://go.tinder.com/branch")
    assert not ok and "EXPLICIT_OUT_OF_SCOPE" in reason

    # Instruction subdomains
    ok, reason = gate.is_in_scope("https://party.tinder.com/room")
    assert not ok and "EXPLICIT_OUT_OF_SCOPE" in reason

    ok, reason = gate.is_in_scope("https://open.tinder.com/redirect")
    assert not ok and "EXPLICIT_OUT_OF_SCOPE" in reason


def test_instruction_placeholder_wildcard_grants_real_subdomains():
    # Royal/Matomo form: the platform puts the wildcard in prose, not in a
    # structured asset. Treat '$username' as one wildcard label so
    # foo.matomo.cloud is in scope without broadening beyond *.matomo.cloud.
    prog = {
        "name": "Matomo",
        "structured_scopes": [
            {
                "asset_identifier": "matomo.cloud",
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": (
                    "*$username.matomo.cloud* is also in scope, but please "
                    "limit tests to ones that don't affect the live instance."
                ),
            }
        ],
        "out_of_scope": [],
    }
    gate = ProgramScopeGate(prog)
    assert gate.is_in_scope("https://foo.matomo.cloud")[0] is True
    assert gate.is_in_scope("https://matomo.cloud")[0] is True
    assert gate.is_in_scope("https://evilmatomo.cloud")[0] is False


def test_instruction_excluded_clause_is_not_a_grant():
    in_tokens, out_tokens = _instruction_scope_tokens(
        "This host is in scope; *.example.com is excluded"
    )
    assert "*.example.com" not in in_tokens
    assert "*.example.com" in out_tokens


def test_instruction_do_not_test_clause_is_not_a_grant():
    in_tokens, out_tokens = _instruction_scope_tokens(
        "Do not test *.staging.example.com; *.example.com is in scope"
    )
    assert "*.staging.example.com" not in in_tokens
    assert "*.staging.example.com" in out_tokens
    assert "*.example.com" in in_tokens


def test_instruction_out_clause_wins_over_in_clause_for_same_token():
    in_tokens, out_tokens = _instruction_scope_tokens(
        "*.example.com is in scope; *.example.com is excluded"
    )
    assert "*.example.com" not in in_tokens
    assert "*.example.com" in out_tokens


def test_gate_never_grants_wildcard_from_exclusion_prose():
    prog = {
        "name": "Acme",
        "structured_scopes": [
            {
                "asset_identifier": "app.acme.com",
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": (
                    "app.acme.com is in scope; *.example.com is excluded"
                ),
            }
        ],
        "out_of_scope": [],
    }
    gate = ProgramScopeGate(prog)
    assert gate.is_in_scope("https://app.acme.com")[0] is True
    assert gate.is_in_scope("https://foo.example.com")[0] is False


def test_scope_gate_localhost_leak_protection():
    prog = {"name": "External Bounty", "scope": "*.bounty.com"}
    gate_external = ProgramScopeGate(prog, "bounty.com")

    # On external program, localhost/127.0.0.1 must be blocked
    ok, reason = gate_external.is_in_scope("http://127.0.0.1:3000/api")
    assert not ok
    assert "localhost leak" in reason

    # On local benchmark, localhost/127.0.0.1 is permitted
    gate_local = ProgramScopeGate({}, "127.0.0.1:8765")
    ok, reason = gate_local.is_in_scope("http://127.0.0.1:8765/debug")
    assert ok
    assert "local testbench allowed" in reason


def test_scope_gate_does_not_widen_exact_hosts_or_path_assets():
    exact_host = ProgramScopeGate({"scope": "app.example.com"}, "app.example.com")
    assert exact_host.is_in_scope("https://app.example.com/account")[0]
    assert not exact_host.is_in_scope("https://unapproved.app.example.com/private")[0]

    path_scoped = ProgramScopeGate(
        {"scope": "https://app.example.com/public-api"}, "app.example.com"
    )
    assert path_scoped.is_in_scope("https://app.example.com/public-api/v1")[0]
    assert not path_scoped.is_in_scope("https://app.example.com/admin/export")[0]


def test_runner_rejects_file_writes_uploads_and_unsafe_methods():
    blocked = [
        "curl -o /tmp/payload https://app.example.com/file",
        "curl -T /etc/passwd https://app.example.com/upload",
        "curl --data @/etc/passwd https://app.example.com/upload",
        "curl -X POST https://app.example.com/api",
        "wget https://app.example.com/file",
    ]
    for command in blocked:
        rc, _stdout, stderr = _run_check(command)
        assert rc == 1
        assert "[BLOCKED]" in stderr


def test_testnet_post_check_reaches_wire_and_confirms():
    """H3 / Phase 1b: testnet POST check reaches the wire in a real _run_check run."""
    import http.server
    import json
    import threading

    sys.path.insert(0, str(_HERE / "tests"))
    import bad_code_app

    VulnerableHandler = bad_code_app.VulnerableHandler

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # 1. On production (is_testnet=False), POST is blocked before reaching the wire
        blocked_cmd = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"amount\": 30.0}}' http://127.0.0.1:{port}/api/v1/orders/ord_101/apply_discount"
        rc, out, err = _run_check(blocked_cmd, is_testnet=False)
        assert rc == 1
        assert "[BLOCKED] check rejected: unsafe HTTP method" in err
        assert not out

        # 2. On testnet (is_testnet=True), POST reaches the wire and executes Flaw 7
        rc, out, err = _run_check(blocked_cmd, is_testnet=True)
        assert rc == 0, f"Expected 0 exit, got {rc}, err: {err}"
        assert "[BLOCKED]" not in err
        assert "discount_applied" in out
        data = json.loads(out)
        assert data["status"] == "discount_applied"
        assert data["order_id"] == "ord_101"
    finally:
        server.shutdown()
        server.server_close()


def test_preflight_allows_external_origin_header_without_external_request():
    gate = ProgramScopeGate({"scope": "app.example.com"}, "app.example.com")
    allowed, _, reason = gate.validate_check(
        "curl -i -s -H 'Origin: https://evil.example' https://app.example.com/api"
    )
    assert allowed, reason


def test_preflight_check_validation_and_safe_mode():
    prog = {"name": "Bank Target", "scope": "*.bank.com\n*.staging.bank.com"}
    gate = ProgramScopeGate(prog, "bank.com")

    # 1. Out of scope check command must be BLOCKED
    cmd_oos = "curl -i -s https://evil.com/leak"
    allowed, _, reason = gate.validate_check(cmd_oos)
    assert not allowed
    assert "BLOCKED" in reason

    # 2. Production destructive mutation must be DOWNGRADED to GET
    cmd_prod_del = "curl -i -s -X DELETE https://api.bank.com/v1/account/123 -d '{\"force\": true}'"
    allowed, safe_cmd, reason = gate.validate_check(cmd_prod_del, is_testnet=False)
    assert allowed
    assert "PRODUCTION SAFE MODE" in reason
    assert "-X GET" in safe_cmd
    assert "-d" not in safe_cmd
    assert "account/123" in safe_cmd

    # 3. Staging asset permits mutation even if is_testnet is False
    cmd_staging = (
        "curl -i -s -X POST https://api.staging.bank.com/v1/deposit -d '{\"amt\": 100}'"
    )
    allowed, safe_cmd, reason = gate.validate_check(cmd_staging, is_testnet=False)
    assert allowed
    assert "-X POST" in safe_cmd
    assert "VALIDATED" in reason

    # 4. Explicit is_testnet=True permits mutation
    allowed, safe_cmd, reason = gate.validate_check(cmd_prod_del, is_testnet=True)
    assert allowed
    assert "-X DELETE" in safe_cmd


def test_strict_evaluator_eliminates_false_positives():
    seam = {
        "n": 1,
        "assertion_a": "Claims endpoint requires authentication",
        "assertion_b": "Wire allows unauthenticated access",
        "impact": "Account data leak",
    }

    # 401 Unauthorized must be evaluated as FALSE_POSITIVE
    v_401 = _assess_response(
        "curl -i https://target.com/userinfo",
        'HTTP/2 401 Unauthorized\r\n\r\n{"error":"Unauthorized"}',
        "",
        seam,
    )
    assert "FALSE_POSITIVE" in v_401

    # 403 Forbidden must be evaluated as FALSE_POSITIVE
    v_403 = _assess_response(
        "curl -i https://target.com/admin",
        "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied",
        "",
        seam,
    )
    assert "FALSE_POSITIVE" in v_403

    # Cloudflare 530 error must be evaluated as FALSE_POSITIVE
    v_530 = _assess_response(
        "curl -i https://target.com/api",
        "HTTP/2 530\r\n\r\nError 530: Origin DNS error",
        "",
        seam,
    )
    assert "FALSE_POSITIVE" in v_530

    # 404 Not Found must be evaluated as FALSE_POSITIVE
    v_404 = _assess_response(
        "curl -i https://target.com/api/v9/debug",
        "HTTP/1.1 404 Not Found\r\n\r\nRoute does not exist",
        "",
        seam,
    )
    assert "FALSE_POSITIVE" in v_404

    # Public HTML landing page on API check must be evaluated as FALSE_POSITIVE
    v_html = _assess_response(
        "curl -i https://target.com/api/userinfo",
        "HTTP/2 200 OK\r\n\r\n<!DOCTYPE html><html><head><title>Home</title></head><body>Welcome</body></html>",
        "",
        seam,
    )
    assert "FALSE_POSITIVE" in v_html


def test_distill_endpoints_strips_static_assets():
    raw_urls = """
    https://target.com/assets/logo.png
    https://target.com/css/main.css?v=12
    https://target.com/js/app.js
    https://target.com/fonts/inter.woff2
    https://target.com/api/v1/auth/login
    https://target.com/api/v1/users/profile?id=10
    https://target.com/graphql
    """
    distilled = _distill_endpoints(raw_urls, max_items=10)
    for u in distilled:
        assert not u.endswith(".png")
        assert ".css" not in u
        assert not u.endswith(".woff2")
    assert any("/api/v1/auth/login" in u for u in distilled)
    assert any("/graphql" in u for u in distilled)


def test_auth_and_cookie_injection(tmp_path):
    import oracle_hunter

    seams = [
        {
            "n": 1,
            "reflex": "AUTH TEST",
            "assertion_a": "A",
            "assertion_b": "B",
            "impact": "Test",
            "check": "curl -i -s https://api.bank.com/v1/user/profile",
            "expected": "status 200",
        }
    ]
    gate = ProgramScopeGate({"scope": "*.bank.com"}, "bank.com")

    original_run_check = oracle_hunter._run_check
    captured_cmds = []

    def mock_run_check(cmd, timeout=30, **kw):
        captured_cmds.append(cmd)
        return 0, 'HTTP/2 200 OK\r\n\r\n{"user_id": 123}', ""

    oracle_hunter._run_check = mock_run_check
    try:
        oracle_hunter.verify_seams(
            seams,
            "bank.com",
            tmp_path,
            auto=True,
            scope_gate=gate,
            auth="sample_jwt_123",
            cookie="session_id=abc456",
        )
        assert captured_cmds
        for ran in captured_cmds:
            # Follow-up cards (Op2 reframes, harvest) legitimately
            # execute in-loop; injection must ride on EVERY command.
            assert '-H "Authorization: Bearer sample_jwt_123"' in ran
            assert '-H "Cookie: session_id=abc456"' in ran
    finally:
        oracle_hunter._run_check = original_run_check


def test_correlate_seams():
    import oracle_hunter

    # Case 1: single seam returns None
    assert oracle_hunter._correlate_seams([{"seam": {"n": 1}}], "target.com") is None

    # Case 2: two confirmed seams triggers compound threat correlation
    seams = [
        {
            "seam": {
                "n": 1,
                "reflex": "DECOUPLE",
                "assertion_a": "Auth required",
                "assertion_b": "User IDs leaked in debug",
                "impact": "Info leak",
            },
            "output": '{"user_id": 9999}',
        },
        {
            "seam": {
                "n": 2,
                "reflex": "INVARIANT",
                "assertion_a": "Strict ownership",
                "assertion_b": "Arbitrary profile fetched by id",
                "impact": "Profile access",
            },
            "output": '{"username": "victim"}',
        },
    ]
    import oracle_llm

    orig_complete = oracle_llm.complete
    oracle_llm.complete = (
        lambda *a, **k: "## Compound Threat Analysis\n- **Composite Severity:** Critical\n- **Correlated Findings:** Finding 1 + Finding 2"
    )
    try:
        corr = oracle_hunter._correlate_seams(seams, "target.com")
        assert corr is not None
        assert corr["count"] == 2
        assert "Compound Threat Analysis" in corr["summary"]
    finally:
        oracle_llm.complete = orig_complete


def test_unknown_program_scope_gate_restrictive():
    """H5 / Phase 1d: unknown program -> scope gate is RESTRICTIVE, not vacuously open or bare-name wildcard."""
    # 1. Empty program and bare program name fallback must not create a wildcard
    gate_bare = ProgramScopeGate({}, target_fallback="uniswap")
    assert gate_bare.raw_in_scope == []
    ok, reason = gate_bare.is_in_scope("https://evil.com/api")
    assert not ok
    assert "is not covered by program scope" in reason

    # Out-of-scope host must be rejected by pre-flight check validation
    allowed, _, reason = gate_bare.validate_check("curl -s https://evil.com/api")
    assert not allowed
    assert "Scope Gate BLOCKED" in reason

    # 2. Empty program with no fallback must reject all external hosts
    gate_empty = ProgramScopeGate(None, target_fallback="")
    assert gate_empty.raw_in_scope == []
    ok, reason = gate_empty.is_in_scope("https://target.com")
    assert not ok

    # 3. Direct target with valid domain fallback is scoped for that domain only
    gate_direct = ProgramScopeGate({}, target_fallback="target.com")
    ok, _ = gate_direct.is_in_scope("https://api.target.com")
    assert ok
    ok, _ = gate_direct.is_in_scope("https://other.com")
    assert not ok


def test_seed_hosts_keeps_loopback_port():
    from oracle_hunter import _seed_hosts

    gate = ProgramScopeGate(
        {"name": "L", "scope": "localhost\nhttp://localhost:32770/"}, "x"
    )
    seeds = _seed_hosts(gate)
    assert "localhost:32770" in seeds
    assert "localhost" in seeds
    # Real domains still seed; app IDs still rejected.
    gate2 = ProgramScopeGate(
        {"name": "E", "scope": "*.example.com\ncom.wolt.android"}, "example.com"
    )
    seeds2 = _seed_hosts(gate2)
    assert "example.com" in seeds2
    assert not any("wolt" in s for s in seeds2)


def test_web_scope_assets_counts_web_and_defaults_eligible():
    from oracle_hunter import _web_scope_assets

    # WEB-typed adapter output without explicit flags counts (gate parity).
    prog = {
        "structured_scopes": [{"asset_identifier": "http://h:1", "asset_type": "WEB"}]
    }
    assert len(_web_scope_assets(prog)) == 1
    # Explicitly ineligible assets never count.
    prog = {
        "structured_scopes": [
            {
                "asset_identifier": "http://h:1",
                "asset_type": "URL",
                "eligible_for_bounty": False,
            },
            {
                "asset_identifier": "http://h:2",
                "asset_type": "URL",
                "eligible_for_submission": False,
            },
        ]
    }
    assert _web_scope_assets(prog) == []
    # Non-web pointers excluded; URL/WILDCARD/DOMAIN kept.
    prog = {
        "structured_scopes": [
            {
                "asset_identifier": "https://wordpress.org/plugins/x",
                "asset_type": "URL",
            },
            {"asset_identifier": "https://github.com/org", "asset_type": "URL"},
            {"asset_identifier": "https://app.example.com", "asset_type": "DOMAIN"},
        ]
    }
    assert len(_web_scope_assets(prog)) == 1


def test_verify_seams_survives_blank_live_hosts(tmp_path):
    # Regression: a blank first line in live_hosts.txt crashed the
    # target-host fallback with IndexError (XBEN-002 blind run).
    from oracle_hunter import verify_seams

    (tmp_path / "live_hosts.txt").write_text("\n\n")
    (tmp_path / "clean_live_hosts.txt").write_text("")
    gate = ProgramScopeGate({"name": "E", "scope": "*.example.com"}, "ext.example.com")
    seams = [
        {
            "n": 1,
            "assertion_a": "a",
            "assertion_b": "b",
            "check": "curl -s http://localhost:9999/x",
            "expected": "status 200",
            "impact": "t",
            "origin": "t",
        }
    ]
    out = verify_seams(
        seams,
        "nonexistent.invalid",
        tmp_path,
        auto=True,
        scope_gate=gate,
        no_cloud=True,
    )
    assert 1 in out and out[1]["confirmed"] is False


def test_scope_gate_lab_localhost_from_scope():
    # Lab program whose SCOPE grants localhost: allowed even when the
    # program name (target fallback) is not a localhost string.
    prog = {
        "name": "xben_001_idor",
        "scope": "localhost\nhttp://localhost:32768/",
        "targets": "http://localhost:32768",
    }
    gate = ProgramScopeGate(prog, "xben_001_idor")
    ok, _ = gate.is_in_scope("http://localhost:32768/api")
    assert ok, "scope-granted localhost must be allowed"
    # Evil hosts stay blocked on the lab gate.
    ok, _ = gate.is_in_scope("http://evil.example.com/x")
    assert not ok
    # External programs without localhost scope still block it.
    ext = ProgramScopeGate({"name": "Ext", "scope": "*.bounty.com"}, "bounty.com")
    ok, reason = ext.is_in_scope("http://localhost:9999/")
    assert not ok and "localhost leak" in reason


if __name__ == "__main__":
    print("[*] Running ProgramScopeGate & Deterministic Verification Tests...")
    test_scope_gate_wildcard_matching()
    print("  ✓ Wildcard and apex domain matching")
    test_scope_gate_global_3rd_party_blocking()
    print("  ✓ Global 3rd-party CDN/analytics blocking")
    test_scope_gate_structured_scopes_with_instructions()
    print("  ✓ Structured scope and instruction extraction")
    test_scope_gate_localhost_leak_protection()
    print("  ✓ Localhost leak protection on external targets")
    test_preflight_check_validation_and_safe_mode()
    print("  ✓ Pre-flight wire validation and safe-mode downgrade")
    test_strict_evaluator_eliminates_false_positives()
    print("  ✓ Strict evaluator false-positive elimination (401/403/530/404/HTML)")
    test_distill_endpoints_strips_static_assets()
    print("  ✓ Ingress distillation strips static assets")
    test_auth_and_cookie_injection()
    print("  ✓ Auth and Cookie header injection")
    test_correlate_seams()
    print("  ✓ Multi-seam compound threat modeling & correlation")
    print("\n✅ All 9 test suites passed successfully!")


def test_scope_gate_never_raises_on_garbage():
    """Fail-closed on unparseable recon tokens (DVWA hunt-1: nuclei tag
    '[CVE-2025-49844:version]' crashed urlsplit inside is_in_scope)."""
    gate = ProgramScopeGate({}, "127.0.0.1:8080")
    for bad in (
        "[CVE-2025-49844:version]",
        "https://[CVE-2025-49844:version]/x",
        "http://[",
        "[::1",
        ":::",
        "",
    ):
        ok, reason = gate.is_in_scope(bad)
        assert ok is False, f"{bad!r} should block, got: {reason}"


# ── Phase 3: token-position-aware metachar gate ──────────────────────────
# DVWA hunt-1: all 24 authed checks BLOCKED because the injected Cookie value
# 'PHPSESSID=x; security=low' contains ';'. The blanket raw-string scan
# confused DATA (cookies, query strings, POST bodies) with CONTROL (shell
# operators). The gate must be token-position-aware: metachars in structural
# tokens stay blocked; metachars inside curl URL/value tokens reach the wire.


def _start_echo_server(capture):
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self):
            length = int(self.headers.get("Content-Length", 0))
            capture["path"] = self.path
            capture["cookie"] = self.headers.get("Cookie")
            capture["body"] = (
                self.rfile.read(length).decode("utf-8", "replace") if length else ""
            )
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._reply()

        def do_POST(self):
            self._reply()

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_cookie_with_semicolon_reaches_wire():
    """Authed Cookie 'PHPSESSID=x; security=low' must reach the wire."""
    capture = {}
    server = _start_echo_server(capture)
    try:
        port = server.server_address[1]
        rc, _out, err = _run_check(
            f'curl -s -H "Cookie: PHPSESSID=abc123; security=low"'
            f" http://127.0.0.1:{port}/"
        )
        assert "[BLOCKED]" not in err, err
        assert rc == 0, err
        assert capture.get("cookie") == "PHPSESSID=abc123; security=low"
    finally:
        server.shutdown()
        server.server_close()


def test_query_string_ampersand_reaches_wire():
    """Multi-param query strings ('?id=1&Submit=Submit') are legitimate
    URL data, not shell control operators."""
    capture = {}
    server = _start_echo_server(capture)
    try:
        port = server.server_address[1]
        rc, _out, err = _run_check(
            f"curl -s 'http://127.0.0.1:{port}/vuln/?id=1&Submit=Submit'"
        )
        assert "[BLOCKED]" not in err, err
        assert rc == 0, err
        assert capture.get("path") == "/vuln/?id=1&Submit=Submit"
    finally:
        server.shutdown()
        server.server_close()


def test_post_body_with_separators_reaches_wire_on_testnet():
    """Form bodies ('a=1&b=2;c=3') are opaque -d data on testnet."""
    capture = {}
    server = _start_echo_server(capture)
    try:
        port = server.server_address[1]
        rc, _out, err = _run_check(
            f"curl -s -X POST -d 'a=1&b=2;c=3' http://127.0.0.1:{port}/submit",
            is_testnet=True,
        )
        assert "[BLOCKED]" not in err, err
        assert rc == 0, err
        assert capture.get("body") == "a=1&b=2;c=3"
    finally:
        server.shutdown()
        server.server_close()


def test_structural_metachars_still_blocked():
    """Injection-shaped metachars in structural token position must keep
    failing closed — the fix narrows the gate, it does not remove it."""
    blocked = [
        "curl http://127.0.0.1:9/; rm -rf /",
        "curl http://127.0.0.1:9/ | tee /tmp/pwned",
        "curl http://127.0.0.1:9/ && id",
        "curl http://127.0.0.1:9/ `id`",
        "curl http://127.0.0.1:9/ $(id)",
    ]
    for command in blocked:
        rc, _out, err = _run_check(command)
        assert rc == 1, command
        assert "[BLOCKED]" in err, command


def test_non_curl_positional_metachars_still_blocked():
    """slither/forge/cast never legitimately need shell metachars in argv;
    keep the tripwire for those binaries."""
    for binary in ("slither", "forge", "cast"):
        rc, _out, err = _run_check(f"{binary} target;id")
        assert rc == 1, binary
        assert "[BLOCKED]" in err, binary


# ── Phase 3b: adversarial-review findings (runner containment) ───────────
# Independent review (gate-adversarial-review) proved these three holes
# reproduce on the pre-change baseline: the token-position-aware fix
# neither caused nor widened them, but they are real and cheap to close.


def test_data_urlencode_at_file_blocked_on_testnet():
    """Finding 1: curl's --data-urlencode interprets name@file mid-value,
    so the startswith-@ guard misses it (local file read into POST body).
    Both the space and = spellings must fail closed on testnet."""
    for cmd in (
        "curl -s -X POST --data-urlencode p@/etc/hostname http://127.0.0.1:9/x",
        "curl -s -X POST --data-urlencode=p@/etc/hostname http://127.0.0.1:9/x",
    ):
        rc, _out, err = _run_check(cmd, is_testnet=True)
        assert rc == 1, cmd
        assert "[BLOCKED]" in err, cmd


def test_plain_data_at_sign_still_allowed_on_testnet():
    """Anti-over-block guard for Finding 1: @ is literal data in plain -d
    bodies (emails). Only --data-urlencode gives @ file semantics."""
    capture = {}
    server = _start_echo_server(capture)
    try:
        port = server.server_address[1]
        rc, _out, err = _run_check(
            f"curl -s -X POST -d 'email=a@b.com' http://127.0.0.1:{port}/submit",
            is_testnet=True,
        )
        assert "[BLOCKED]" not in err, err
        assert rc == 0, err
        assert capture.get("body") == "email=a@b.com"
    finally:
        server.shutdown()
        server.server_close()


def test_clean_data_urlencode_still_allowed_on_testnet():
    """Anti-over-block guard for Finding 1: --data-urlencode without @
    is legitimate and must keep reaching the wire."""
    capture = {}
    server = _start_echo_server(capture)
    try:
        port = server.server_address[1]
        rc, _out, err = _run_check(
            f"curl -s -X POST --data-urlencode 'q=a b' http://127.0.0.1:{port}/s",
            is_testnet=True,
        )
        assert "[BLOCKED]" not in err, err
        assert rc == 0, err
        assert capture.get("body") == "q=a+b"
    finally:
        server.shutdown()
        server.server_close()


def test_secret_header_newline_blocked_before_k_file():
    """Finding 2: CR/LF in an Authorization/Cookie -H value would break
    into a new curl -K config directive (arbitrary file write). The sink
    must fail closed and no file may be created."""
    import os

    target = "/tmp/oracle_test_k_newline"
    try:
        os.unlink(target)
    except OSError:
        pass
    try:
        for nl in ("\n", "\r"):
            cmd = (
                f'curl -s -H "Authorization: Bearer x{nl}output = {target}"'
                " http://127.0.0.1:9/"
            )
            rc, _out, err = _run_check(cmd)
            assert rc == 1, repr(nl)
            assert "[BLOCKED]" in err, repr(nl)
        assert not os.path.exists(target)
    finally:
        try:
            os.unlink(target)
        except OSError:
            pass


def test_substituted_cookie_cannot_smuggle_extra_url():
    """Finding 3 (wire half): a quote in a stored session cookie must not
    break out of -H quoting post-scope-gate and fetch an unvalidated URL."""
    import http.server
    import threading

    from oracle_auth_session import (
        ACCOUNT_B_COOKIES_PLACEHOLDER,
        DualAccountHarness,
        substitute_probe_placeholders,
    )

    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        h = DualAccountHarness(
            target_domain="t.com", platform="h1", researcher_username="u"
        )
        h.account_b.token = "t"
        h.account_b.cookies = {"s": f'x" http://127.0.0.1:{port}/SMUGGLED "y'}
        base = (
            f'curl -s -H "Cookie: {ACCOUNT_B_COOKIES_PLACEHOLDER}"'
            f" http://127.0.0.1:{port}/legit"
        )
        resolved, _secrets = substitute_probe_placeholders(base, h, as_account="b")
        rc, _out, err = _run_check(resolved)
        assert rc == 0, err
        assert hits == ["/legit"], hits
    finally:
        server.shutdown()
        server.server_close()
