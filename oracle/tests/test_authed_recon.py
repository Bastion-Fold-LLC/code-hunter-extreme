#!/usr/bin/env python3
"""P14: authenticated recon — login-walled surfaces must be discoverable.

Root cause (DVWA/pygoat live misses): recon ran unauthenticated while only
verify_seams injected --cookie/--auth. DVWA /vulnerabilities/* (302 to login)
and pygoat labs (302 to /login/) were structurally undiscoverable: no cards,
no confirms, recall 0 — whatever the templates could do.

Fix: recon() takes auth/cookie and attaches them (sanitized, presence-logged
only) to katana (-H), JS mining, spec discovery, and ffuf (-H).

Each test below pins one leg against a stub that 302s gated content without
the session cookie and serves it with the cookie.
"""
from __future__ import annotations

import http.server
import shutil
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_deeprecon as dr  # noqa: E402
import oracle_hunter as oh  # noqa: E402

COOKIE = "sess=abc123"
HDRS = ["Cookie: sess=abc123"]


class _Stub(http.server.BaseHTTPRequestHandler):
    def _authed(self) -> bool:
        return "sess=abc123" in (self.headers.get("Cookie") or "")

    def _send(self, code: int, body: bytes, ctype: str = "text/html") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            if self._authed():
                self._send(200, b'<html><script src="/app.js"></script></html>')
            else:
                self._send(200, b"<html>login wall</html>")
        elif path == "/open":
            self._send(200, b"public")
        elif path == "/gated":
            if self._authed():
                self._send(200, b"gated content")
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
        elif path == "/app.js":
            if self._authed():
                self._send(
                    200, b'fetch("/api/gated_endpoint");', "application/javascript"
                )
            else:
                self._send(404, b"no")
        elif path == "/openapi.json":
            if self._authed():
                self._send(
                    200,
                    b'{"openapi":"3.0.0","info":{"title":"g"},"paths":{}}',
                    "application/json",
                )
            else:
                self._send(404, b"no")
        else:
            self._send(404, b"no")

    def log_message(self, *a):  # noqa: ANN001, ANN202
        pass


class _Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


@pytest.fixture(scope="module")
def stub():
    srv = _Threaded(("127.0.0.1", 0), _Stub)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


def _gate(base: str):
    host = base.split("://", 1)[1]
    return oh.ProgramScopeGate({}, host)


def _ffuf_present() -> bool:
    p = Path.home() / "go" / "bin" / "ffuf"
    return p.exists() or shutil.which("ffuf") is not None


def test_recon_headers_builds_and_sanitizes():
    assert oh._recon_headers() == []
    assert oh._recon_headers(auth="Bearer t") == ["Authorization: Bearer t"]
    assert oh._recon_headers(cookie="a=b") == ["Cookie: a=b"]
    both = oh._recon_headers(auth="Bearer t", cookie="a=b")
    assert both == ["Authorization: Bearer t", "Cookie: a=b"]
    # CR/LF injection in --cookie must not break header framing
    evil = oh._recon_headers(cookie="a=b\r\nX-Injected: 1")
    assert evil == ["Cookie: a=bX-Injected: 1"]


def test_fuzz_finds_gated_path_only_when_authed(stub, tmp_path):
    if not _ffuf_present():
        pytest.skip("ffuf binary not installed")
    gate = _gate(stub)
    wl = tmp_path / "wl.txt"
    wl.write_text("open\ngated\n")
    out_plain = tmp_path / "plain"
    out_plain.mkdir()
    dr.fuzz_hidden_paths([stub], gate, out_plain, wordlist=wl)
    plain = (out_plain / "fuzzed_paths.txt").read_text()
    assert "/open [200]" in plain
    assert "/gated [302]" in plain, f"gated must 302 unauth, got:\n{plain}"
    assert "/gated [200]" not in plain
    out_auth = tmp_path / "auth"
    out_auth.mkdir()
    dr.fuzz_hidden_paths([stub], gate, out_auth, wordlist=wl, extra_headers=HDRS)
    authed = (out_auth / "fuzzed_paths.txt").read_text()
    assert "/gated [200]" in authed, f"gated must 200 authed, got:\n{authed}"


def test_mine_js_sees_authed_scripts_only_with_cookie(stub, tmp_path):
    gate = _gate(stub)
    out_plain = tmp_path / "plain"
    out_plain.mkdir()
    dr.mine_js([stub], gate, out_plain)
    assert "gated_endpoint" not in (out_plain / "js_endpoints.txt").read_text()
    out_auth = tmp_path / "auth"
    out_auth.mkdir()
    dr.mine_js([stub], gate, out_auth, extra_headers=HDRS)
    assert "gated_endpoint" in (out_auth / "js_endpoints.txt").read_text()


def test_discover_specs_needs_cookie(stub, tmp_path):
    gate = _gate(stub)
    out_plain = tmp_path / "plain"
    out_plain.mkdir()
    assert dr.discover_api_specs([stub], gate, out_plain) == 0
    out_auth = tmp_path / "auth"
    out_auth.mkdir()
    assert dr.discover_api_specs([stub], gate, out_auth, extra_headers=HDRS) == 1
    assert "openapi" in (out_auth / "api_specs.txt").read_text()


def test_authed_recon_still_fail_closed_without_gate(stub, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    assert dr.mine_js([stub], None, out, extra_headers=HDRS) == (0, 0)
    assert dr.discover_api_specs([stub], None, out, extra_headers=HDRS) == 0


# ── crawl.txt → template bridge (P14) ──────────────────────────────────────


def _crawl_recon(tmp_path, crawl_lines, js=(), fuzzed=()):
    recon = tmp_path / "recon"
    recon.mkdir(exist_ok=True)
    (recon / "live_hosts.txt").write_text("http://127.0.0.1:8080\n")
    (recon / "crawl.txt").write_text("\n".join(crawl_lines) + "\n")
    (recon / "js_endpoints.txt").write_text("\n".join(js) + ("\n" if js else ""))
    (recon / "fuzzed_paths.txt").write_text(
        "\n".join(fuzzed) + ("\n" if fuzzed else "")
    )
    (recon / "api_specs.txt").write_text("")
    (recon / "js_secrets.txt").write_text("")
    return recon


def test_crawled_vuln_url_gets_sqli_and_xss_cards(tmp_path):
    """DVWA shape: crawl-only /vulnerabilities/sqli/ must yield probes."""
    import oracle_seam_templates as st

    recon = _crawl_recon(tmp_path, ["http://127.0.0.1:8080/vulnerabilities/sqli/"])
    seams = st.scan_template_seams(
        recon_dir=recon,
        scope_gate=oh.ProgramScopeGate({}, target_fallback="http://127.0.0.1:8080"),
    )
    checks = [s["check"] for s in seams]
    assert any(
        "vulnerabilities/sqli" in c and ("'" in c or "%27" in c) for c in checks
    ), "no sqli probe for crawled vuln page"
    assert any(
        "vulnerabilities/sqli" in c and "onerror" in c for c in checks
    ), "no xss probe for crawled vuln page"


def test_crawl_skips_offsite_and_static(tmp_path):
    import oracle_seam_templates as st

    mat = {
        "js_endpoints": [],
        "fuzzed": [],
        "live_hosts": ["http://127.0.0.1:8080"],
        "crawled": [
            "http://127.0.0.1:8080/vulnerabilities/xss_r/",
            "https://github.com/digininja/DVWA/",
            "http://127.0.0.1:8080/dvwa/css/main.css",
            "http://127.0.0.1:8080/vulnerabilities/xss_r/",  # dup
            "not-a-url",
        ],
    }
    urls = [u for u, _s, _a in st._injection_targets(mat)]
    assert urls == ["http://127.0.0.1:8080/vulnerabilities/xss_r/"]


def test_crawl_only_recon_counts_as_web(tmp_path):
    import oracle_seam_templates as st

    recon = _crawl_recon(tmp_path, ["http://127.0.0.1:8080/index.php"])
    mat = st._build_material(recon, None)
    assert st._has_web(mat)


def test_hand_built_mats_without_crawled_key_still_work():
    """P13-era hand mats (no 'crawled') must not KeyError."""
    import oracle_seam_templates as st

    mat = {
        "js_endpoints": ["http://127.0.0.1:8765/api/res00"],
        "fuzzed": [],
        "live_hosts": ["http://127.0.0.1:8765"],
    }
    assert st._has_web(mat)
    assert any("res00" in u for u, _s, _a in st._injection_targets(mat))


def test_crawled_group_has_own_budget_at_scale(tmp_path):
    """30 crawled pages + 10 js/fuzzed: last-alpha crawled keeps probes."""
    import oracle_seam_templates as st

    base = "http://127.0.0.1:8080"
    crawled = [f"{base}/app/page{i:02d}/" for i in range(30)]
    recon = _crawl_recon(
        tmp_path,
        crawled,
        js=[f"{base}/js/route{i:02d}" for i in range(5)],
        fuzzed=[f"{base}/fuzz/route{i:02d} [200]" for i in range(5)],
    )
    seams = st.scan_template_seams(
        recon_dir=recon,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
    )
    sqli = [s for s in seams if s.get("claim_type") == "injection-sqli-probe"]
    xss = [s for s in seams if s.get("claim_type") == "injection-xss-probe"]
    last = f"{base}/app/page29/"
    assert any(
        last in s["check"] and "?id=" in s["check"] for s in sqli
    ), f"last-alpha crawled page lost its sqli primary ({len(sqli)} sqli)"
    assert any(
        last in s["check"] and "?q=" in s["check"] for s in xss
    ), f"last-alpha crawled page lost its xss primary ({len(xss)} xss)"
    # js/fuzzed groups keep their own budget (no cross-group theft)
    assert any("/js/route00" in s["check"] for s in sqli)
    assert any("/fuzz/route00" in s["check"] for s in xss)
    assert len(sqli) <= 80 and len(xss) <= 68


def test_logout_shaped_urls_never_become_probe_targets():
    """Session-suicide guard: logout endpoints are never probed.

    Fetching one with a session cookie destroys the session (DVWA
    logout.php GET → session_destroy), silently 302ing every later
    authed probe. Tight segment match — audit/log-style paths stay.
    """
    import re

    import oracle_seam_templates as st
    from oracle_foundation import LOGOUT_PATH_PATTERN

    pat = re.compile(LOGOUT_PATH_PATTERN, re.IGNORECASE)
    for hit in (
        "/logout",
        "/logout/",
        "/logout.php",
        "/auth/logout",
        "/auth/logout?next=/",
        "/app/logoff",
        "/signout",
        "/a/sign_out/",
    ):
        assert pat.search(hit), f"must match: {hit}"
    for miss in (
        "/api/logout-audit",
        "/logoutage",
        "/blog/logout-stories",
        "/login",
        "/vulnerabilities/sqli/",
    ):
        assert not pat.search(miss), f"must not match: {miss}"
    mat = {
        "js_endpoints": [],
        "fuzzed": [],
        "live_hosts": ["http://127.0.0.1:8080"],
        "crawled": [
            "http://127.0.0.1:8080/logout.php",
            "http://127.0.0.1:8080/vulnerabilities/sqli/",
            "http://127.0.0.1:8080/api/logout-audit",
        ],
    }
    urls = [u for u, _s, _a in st._injection_targets(mat)]
    assert not any("logout.php" in u for u in urls)
    assert any("vulnerabilities/sqli" in u for u in urls)
    assert any("logout-audit" in u for u in urls)


def test_injection_targets_shallow_first_within_split():
    """Shallow app routes probe before deep paths within the crawled group.

    Deepest-first was tried and REVERTED (P14): katana emits 4-7-deep
    misresolutions (/vuln/vuln/x/source/low.php, /var/www/html/...) which
    ranked ahead of the real depth-2 app routes — DVWA E2E gave all 32
    crawled sqli cards to junk, zero to /vulnerabilities/*.
    Current sort: (not is_api, has_repeated_segment, depth ASC, param_count, url).
    So /about.php (depth 1) < /vulnerabilities/sqli/ (depth 2) < /a/b/c/deep (depth 4).
    Root / is depth 0 — comes first of all.
    """
    import oracle_seam_templates as st

    mat = {
        "js_endpoints": [],
        "fuzzed": [],
        "live_hosts": ["http://127.0.0.1:8080"],
        "crawled": [
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080/about.php",
            "http://127.0.0.1:8080/vulnerabilities/sqli/",
            "http://127.0.0.1:8080/a/b/c/deep",
        ],
    }
    urls = [u for u, _s, _a in st._injection_targets(mat)]
    # Shallow-first: / (depth 0) before about.php (depth 1) before sqli (depth 2) before deep (depth 4)
    assert urls.index("http://127.0.0.1:8080/") < urls.index(
        "http://127.0.0.1:8080/about.php"
    ), "depth-0 root must rank before depth-1 page"
    assert urls.index("http://127.0.0.1:8080/about.php") < urls.index(
        "http://127.0.0.1:8080/vulnerabilities/sqli/"
    ), "depth-1 must rank before depth-2"
    assert urls.index("http://127.0.0.1:8080/vulnerabilities/sqli/") < urls.index(
        "http://127.0.0.1:8080/a/b/c/deep"
    ), "depth-2 must rank before depth-4 (deep junk last)"
