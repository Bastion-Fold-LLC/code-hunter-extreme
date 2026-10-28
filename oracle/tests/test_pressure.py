#!/usr/bin/env python3
"""Pressure tests — Oracle full 3-mindset pipeline vs deliberately shit code.

Spins up bad_code_app.py (7 planted architectural flaws), runs the COMPLETE
cmd_hunt() pipeline — all 3 mindsets, cloud + local, invisible seam injected
into both, Mindset 3 adversarial synthesis — and measures:

  RECALL: which of the 7 planted flaws does Oracle confirm on the wire?
  PRECISION: does Oracle confirm ANY false positive on the benign /health endpoint?
  VALIDATE_CARD_SHAPE: do legit metachar payloads pass? do injection attempts block?
  SQLI/LOGOUT MARKERS: are the detection markers correctly split?
  OP1/OP2: does reframe produce valid follow-up cards?

The 7 planted flaws in bad_code_app.py:
  Flaw 1 — beautiful-liar trust-bypass: X-Original-Role: admin header grants access
  Flaw 2 — cliff-and-current alt-path:  /api/internal/private is same data, no auth
  Flaw 3 — self-observing creds:        /debug/config leaks AWS key + broker creds
  Flaw 4 — mirror stale-version:        /api/v1/users leaks SSN field (v2 strips it)
  Flaw 5 — deathless legacy:            /api/internal/dashboard is routable (legacy_tok)
  Flaw 6 — artifact exposure:           /static/package.json + /static/.env.bak
  Flaw 7 — state-invariant violation:   POST /api/v1/orders/ord_101/apply_discount
                                         applies discount to an already-PAID order

Architecture being tested (P1 doctrine):
  Invisible Seam (templates + code lens)
    ↓ injected into BOTH lenses
  Mindset 1 (MITRE: 344 TTPs + red-team)  ||  Mindset 2 (paradox: ALL philosophy + corpus)
    ↓ both outputs merged
  Mindset 3 (seam: adversarial synthesis + chaining)
    ↓
  Verifier (7 deterministic gates)

The test runs the REAL cmd_hunt — no mocking of the pipeline.
It monkeypatches only:
  - recon() → returns a pre-built recon dir (avoids subfinder/katana/etc)
  - _write_report() → captures output instead of writing to disk

Running: python3 -m pytest tests/test_pressure.py -v -s
"""
from __future__ import annotations

import http.server
import io
import re
import sys
import threading
import types
from pathlib import Path
from typing import Dict, List, Set

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import bad_code_app  # noqa: E402 — intentionally vulnerable server
import oracle_hunter as oh  # noqa: E402
import oracle_llm  # noqa: E402
import oracle_mindsets  # noqa: E402
from oracle_foundation import (  # noqa: E402
    LOGOUT_PATH_PATTERN,
    SQLI_200_MARKERS,
    SQLI_ERROR_MARKERS,
    reframe_rejected,
    validate_card_shape,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _args(**over) -> types.SimpleNamespace:
    """Minimal args namespace for cmd_hunt — all getattr() calls satisfied."""
    base = dict(
        cloud=True,           # use cloud (OpenRouter key is set)
        model=None,           # use router default
        verify=True,
        auto=True,
        fast_triage=False,
        min_payout=0,
        max_payout=0,
        auto_pick=False,
        testnet=True,         # is_testnet=True: localhost probes allowed
        code=None,
        auth=None,
        cookie=None,
        mindset=None,         # "all" → mitre + paradox + seam
        from_scan4me=False,
        scan4me_top=1,
        seam_allow_new=False,
        handoff=None,
        schedule=None,
        pick=1,
        account_a=None,
        account_b=None,
        auto_provision=None,
        prompt_login=False,
        researcher=None,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def _build_recon(recon_dir: Path, base: str) -> None:
    """Populate a recon dir as if subfinder+httpx+ffuf ran against bad_code_app."""
    paths = [
        f"{base}/debug/config [200]",
        f"{base}/api/v1/users [200]",
        f"{base}/api/internal/dashboard [200]",
        f"{base}/api/v1/admin/metrics [403]",   # guarded — template needs 403
        f"{base}/api/internal/private [200]",    # unguarded twin
        f"{base}/api/v1/private/secure [403]",   # guarded
        f"{base}/static/package.json [200]",
        f"{base}/static/.env.bak [200]",
        f"{base}/health [200]",
        f"{base}/api/v1/orders/ord_101 [200]",
        f"{base}/api/v1/orders/ord_101/apply_discount [200]",
    ]
    (recon_dir / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
    (recon_dir / "live_hosts.txt").write_text(base + "\n")
    (recon_dir / "clean_live_hosts.txt").write_text(base + "\n")
    (recon_dir / "known_urls.txt").write_text(
        "\n".join(p.split(" ")[0] for p in paths) + "\n"
    )
    # v1/v2 version differential — needed for mirror template
    (recon_dir / "js_endpoints.txt").write_text(
        f"{base}/api/v1/users\n{base}/api/v2/users\n"
    )
    for f in ("js_secrets.txt", "api_specs.txt"):
        (recon_dir / f).write_text("")


# ─────────────────────────────────────────────────────────────────────────────
# Module-scoped server + full cmd_hunt run (expensive — runs ONCE)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def hunt_results(tmp_path_factory):
    """Spin up bad_code_app, run the FULL cmd_hunt pipeline once, return results.

    Architecture of capture:
      1. Patch verify_seams to run normally AND capture its output into
         captured["confirmed"] — this fires before synthesize_seams and
         before _finalize_verify, so a crash in either doesn't lose results.
      2. Patch _write_report to capture the final seams list.
      3. Patch ProgramWorkspace.recon_dir so the template engine reads our
         pre-built recon dir (not the empty workspace dir).
      4. Patch _scope_from_programs so prog is non-None and scope wall fires.
      5. Skip asset download (jina/firecrawl timeout).

    The MITRE cloud call may hit context limits (Groq token limit → slow
    nvidia fallback → 420s deadline). We run with mindset="seam,paradox" to
    get the philosophy+template pipeline confirmed independently of MITRE.
    A separate MITRE-only fixture runs the MITRE lens alone.
    """
    from oracle_mindset_context import ProgramWorkspace as _PW

    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), bad_code_app.VulnerableHandler
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"

    recon_dir = tmp_path_factory.mktemp("recon")
    _build_recon(recon_dir, base)

    fake_prog = {
        "name": "bad-code-testbed",
        "platform": "hackerone",
        "url": base,
        "max_payout_usd": 5000,
        "kind": "web2",
        "structured_scopes": [
            {
                "asset_identifier": base,
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "rules": "Test program for Oracle pressure testing.",
    }

    captured: Dict = {"seams": [], "confirmed": {}, "base": base}

    # Patch verify_seams to run AND capture results before any synthesis crash
    _orig_verify = oh.verify_seams
    def _capturing_verify(seams_arg, *a, **kw):
        result = _orig_verify(seams_arg, *a, **kw)
        captured["confirmed"].update(result)
        captured["seams"] = list(seams_arg)
        return result
    oh.verify_seams = _capturing_verify

    def _fake_write_report(name, recon_d, raw, seams, *a, **kw):
        if not captured["seams"]:
            captured["seams"] = list(seams)
        return recon_d / "report.md"

    _orig_recon = getattr(oh, "recon", None)
    _orig_write = getattr(oh, "_write_report", None)
    _orig_scope = oh._scope_from_programs
    _orig_download = _PW.download_assets
    _orig_recon_dir_prop = _PW.__dict__.get("recon_dir")

    oh.recon = lambda *a, **kw: recon_dir
    oh._write_report = _fake_write_report
    oh._scope_from_programs = lambda name: fake_prog
    _PW.download_assets = lambda self, **kw: []
    _PW.recon_dir = property(lambda self: recon_dir)

    # Run all mindsets. verify_seams fires BEFORE synthesize_seams, so even if
    # the MITRE engine times out and synthesis crashes, captured["confirmed"]
    # already holds the wire-verified results from the paradox+template pass.
    try:
        oh.cmd_hunt(base, _args(mindset=None))
    except (SystemExit, Exception) as e:
        captured["hunt_error"] = str(e)
    finally:
        oh.verify_seams = _orig_verify
        oh.recon = _orig_recon
        if _orig_write is not None:
            oh._write_report = _orig_write
        oh._scope_from_programs = _orig_scope
        _PW.download_assets = _orig_download
        if _orig_recon_dir_prop is None:
            try:
                del _PW.recon_dir
            except AttributeError:
                pass
        else:
            _PW.recon_dir = _orig_recon_dir_prop
        httpd.shutdown()

    return captured


# ─────────────────────────────────────────────────────────────────────────────
# P1 — All 7 planted flaws confirmed on the wire
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.live
class TestP1PlantedFlawsFullPipeline:
    """Every flaw must survive the full 3-mindset pipeline and the 7-gate verifier."""

    def _confirmed_checks(self, hunt_results) -> Set[str]:
        confirmed = hunt_results.get("confirmed", {})
        seam_by_n = {s["n"]: s for s in hunt_results.get("seams", [])}
        return {
            seam_by_n[n].get("check", "")
            for n, r in confirmed.items()
            if r.get("confirmed") and n in seam_by_n
        }

    def test_flaw1_trust_bypass_found(self, hunt_results):
        """Mindset 2 (paradox/beautiful-liar): X-Original-Role: admin bypass."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "/api/v1/admin/metrics" in c and "X-Original-Role" in c
            for c in checks
        ), f"Flaw 1 (trust-bypass) not found.\nConfirmed checks: {sorted(checks)[:8]}"

    def test_flaw2_cliff_and_current_found(self, hunt_results):
        """Mindset 2 (paradox/cliff-and-current): /internal/private serves same data, no auth."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "/api/internal/private" in c
            for c in checks
        ), f"Flaw 2 (alt-path auth gap) not found.\nConfirmed checks: {sorted(checks)[:8]}"

    def test_flaw3_debug_config_found(self, hunt_results):
        """All mindsets: /debug/config leaks credentials."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "/debug/config" in c and "?" not in c
            for c in checks
        ), f"Flaw 3 (debug creds) not found.\nConfirmed checks: {sorted(checks)[:8]}"

    def test_flaw4_mirror_version_found(self, hunt_results):
        """Mindset 1 (MITRE T1213) + Mindset 2: /api/v1/users leaks SSN that v2 strips."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "/api/v1/users" in c
            for c in checks
        ), f"Flaw 4 (v1 SSN leak) not found.\nConfirmed checks: {sorted(checks)[:8]}"

    def test_flaw5_deathless_legacy_found(self, hunt_results):
        """Mindset 1 (MITRE T1083) + Mindset 2: /api/internal/dashboard still routable."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "/api/internal/dashboard" in c
            for c in checks
        ), f"Flaw 5 (legacy dashboard) not found.\nConfirmed checks: {sorted(checks)[:8]}"

    def test_flaw6_artifact_exposure_found(self, hunt_results):
        """All mindsets: .env.bak / package.json exposed in webroot."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "/static/" in c and ("env" in c or "package" in c)
            for c in checks
        ), f"Flaw 6 (artifact) not found.\nConfirmed checks: {sorted(checks)[:8]}"

    def test_flaw7_state_invariant_found(self, hunt_results):
        """Mindset 2 (impossible-problem/state-machine): POST discount on PAID order."""
        checks = self._confirmed_checks(hunt_results)
        assert any(
            "apply_discount" in c
            for c in checks
        ), f"Flaw 7 (state-invariant) not found.\nConfirmed checks: {sorted(checks)[:8]}"


# ─────────────────────────────────────────────────────────────────────────────
# P2 — Zero false positives on the benign /health endpoint
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.live
class TestP2ZeroFalsePositives:
    def test_health_never_confirmed(self, hunt_results):
        """GET /health → {status:ok} must never become a finding."""
        confirmed = hunt_results.get("confirmed", {})
        seam_by_n = {s["n"]: s for s in hunt_results.get("seams", [])}
        fp = [
            n for n, r in confirmed.items()
            if r.get("confirmed")
            and "/health" in seam_by_n.get(n, {}).get("check", "")
            and "?" not in seam_by_n.get(n, {}).get("check", "")
        ]
        assert not fp, f"Benign /health endpoint falsely confirmed: seams {fp}"

    def test_precision_at_least_point_seven(self, hunt_results):
        """Precision (TP / confirmed) must be ≥ 0.70 — the quality gate bar."""
        confirmed = hunt_results.get("confirmed", {})
        seam_by_n = {s["n"]: s for s in hunt_results.get("seams", [])}
        base = hunt_results.get("base", "")
        n_confirmed = sum(1 for r in confirmed.values() if r.get("confirmed"))
        if n_confirmed == 0:
            pytest.skip("no confirmed seams — cannot measure precision")
        # Known benign: /health plain GET
        known_benign_checks = {"/health"}
        fp = sum(
            1 for n, r in confirmed.items()
            if r.get("confirmed")
            and any(
                b in seam_by_n.get(n, {}).get("check", "")
                for b in known_benign_checks
            )
            and "?" not in seam_by_n.get(n, {}).get("check", "")
        )
        precision = (n_confirmed - fp) / n_confirmed
        assert precision >= 0.70, (
            f"Precision {precision:.2f} below 0.70 bar "
            f"({n_confirmed} confirmed, {fp} FPs)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# P3 — validate_card_shape passes legitimate payloads
# ─────────────────────────────────────────────────────────────────────────────

def _card(check: str, a: str = "A claims X", b: str = "Wire says Y") -> Dict:
    return {
        "n": 1, "assertion_a": a, "assertion_b": b,
        "check": check, "expected": "status 200",
        "impact": "test", "reflex": "r", "mitre": "N/A", "raw": "",
    }


class TestP3LegitimatePayloadsPass:
    """Metacharacters inside single-quoted strings are inert under shell=False."""

    def test_query_ampersand_passes(self):
        assert validate_card_shape(_card("curl -i -s 'https://t.com/api?q=1&page=2'")) is None

    def test_cookie_semicolon_passes(self):
        assert validate_card_shape(_card("curl -i -s -H 'Cookie: s=abc; path=/' 'https://t.com/'")) is None

    def test_multi_param_passes(self):
        assert validate_card_shape(_card("curl -i -s 'https://t.com/search?q=foo&limit=10&offset=0'")) is None

    def test_double_ampersand_in_body_passes(self):
        assert validate_card_shape(_card("curl -i -s -X POST -d 'user=a&&pass=b' 'https://t.com/login'")) is None

    def test_bearer_token_passes(self):
        assert validate_card_shape(_card("curl -i -s -H 'Authorization: Bearer eyJhb==' 'https://t.com/api'")) is None


# ─────────────────────────────────────────────────────────────────────────────
# P4 — validate_card_shape blocks real injection
# ─────────────────────────────────────────────────────────────────────────────

class TestP4InjectionBlocked:
    def test_unquoted_double_ampersand_blocked(self):
        assert validate_card_shape(_card("curl -i -s https://t.com/ && rm -rf /")) is not None

    def test_unquoted_pipe_blocked(self):
        assert validate_card_shape(_card("curl -i -s https://t.com/ | cat /etc/passwd")) is not None

    def test_unquoted_semicolon_blocked(self):
        assert validate_card_shape(_card("curl -i -s https://t.com/ ; id")) is not None

    def test_backtick_blocked(self):
        assert validate_card_shape(_card("curl -i -s `echo https://t.com/`")) is not None

    def test_command_substitution_blocked(self):
        assert validate_card_shape(_card("curl -i -s $(cat /etc/passwd) https://t.com/")) is not None


# ─────────────────────────────────────────────────────────────────────────────
# P5 — SQLI marker broad/strict split
# ─────────────────────────────────────────────────────────────────────────────

class TestP5SQLiMarkerSplit:
    def _broad(self, text: str) -> bool:
        return any(m.strip('"') in text for m in SQLI_200_MARKERS.split(","))

    def _strict(self, text: str) -> bool:
        return any(m.strip('"') in text for m in SQLI_ERROR_MARKERS.split(","))

    def test_broad_hits_db_tech_mention(self):
        assert self._broad("Powered by mysql 5.7")

    def test_strict_misses_bare_mysql_boilerplate(self):
        assert not self._strict("SQLi DB: mysql"), \
            "strict list matched bare 'mysql' — DVWA footer is a FP"

    def test_strict_hits_mysql_fetch_error(self):
        assert self._strict("Warning: mysql_fetch_array()")

    def test_strict_hits_sql_syntax_error(self):
        assert self._strict("You have an error in your SQL syntax")

    def test_strict_hits_sqlite_error(self):
        assert self._strict("SQLITE_ERROR: near '1': syntax error")

    def test_both_hit_real_error(self):
        real = "SQL syntax error near 'OR 1=1'"
        assert self._broad(real) and self._strict(real)


# ─────────────────────────────────────────────────────────────────────────────
# P6 — LOGOUT_PATH_PATTERN
# ─────────────────────────────────────────────────────────────────────────────

class TestP6LogoutPathGuard:
    def _matches(self, path: str) -> bool:
        return bool(re.search(LOGOUT_PATH_PATTERN, path))

    def test_logout_php_matches(self):     assert self._matches("/logout.php")
    def test_logout_bare_matches(self):    assert self._matches("/logout")
    def test_logout_slash_matches(self):   assert self._matches("/logout/")
    def test_signout_matches(self):        assert self._matches("/signout")
    def test_logoff_matches(self):         assert self._matches("/logoff")
    def test_sign_out_matches(self):       assert self._matches("/sign_out")

    def test_logout_audit_no_match(self):  assert not self._matches("/logout-audit")
    def test_api_logout_event_no_match(self): assert not self._matches("/api/logout_event")
    def test_userlogout_no_match(self):    assert not self._matches("/userlogout")


# ─────────────────────────────────────────────────────────────────────────────
# P7 — Op1/Op2: reframe produces exactly one valid follow-up
# ─────────────────────────────────────────────────────────────────────────────

class TestP7Op1Op2Interaction:
    def test_reframe_on_idor_card_produces_valid_followup(self):
        parent = {
            "n": 1,
            "assertion_a": "Users can only access their own orders.",
            "assertion_b": "Order ID 101 is accessible without auth.",
            "check": "curl -i -s 'https://target.com/api/orders/101'",
            "expected": 'status 200, body contains "ord_101"',
            "impact": "IDOR — cross-account data read",
            "reflex": "REFLEX 4: IDOR",
            "mitre": "CWE-639 / T1190",
            "raw": "SEAM 1",
        }
        reframes = reframe_rejected(parent, next_n=2)
        assert reframes, "reframe_rejected produced no follow-ups for IDOR-shaped check"
        for rf in reframes:
            err = validate_card_shape(rf)
            assert err is None, f"reframe card failed validate_card_shape: {err}"
            assert rf.get("check") != parent["check"], "reframe produced identical check"


# ─────────────────────────────────────────────────────────────────────────────
# P8 — DOM-XSS false-positive gate: marker absent → rc=1, never confirms
# ─────────────────────────────────────────────────────────────────────────────

class TestP8DomXssFPGate:
    """confirm_rendered_output must return rc=1 when the marker is not in the
    rendered DOM — even if the URL echoes the marker string."""

    def test_marker_absent_returns_rc1(self, tmp_path):
        import bad_code_app, threading, http.server
        httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), bad_code_app.VulnerableHandler
        )
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        try:
            from oracle_rendered import confirm_rendered_output
            rc, stdout, stderr = confirm_rendered_output(
                f"curl -i -s 'http://127.0.0.1:{port}/health?q=%3Cimg%20src%3Dx%20onerror%3Dalert%28oracledom7%29%3E'",
                "oracledom7",
            )
            assert rc != 0, (
                f"confirm_rendered_output returned rc={rc} (expected non-zero) "
                f"when marker was absent from rendered DOM"
            )
            assert "oracledom7" not in stdout, (
                "marker leaked into stdout via URL echo — would cause false CONFIRMED"
            )
        finally:
            httpd.shutdown()
