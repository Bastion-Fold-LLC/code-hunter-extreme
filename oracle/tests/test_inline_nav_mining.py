#!/usr/bin/env python3
"""P14 finisher: crawled-page mining finds inline-JS-navigated routes.

Root cause (pygoat E2E miss): /xssL is reachable ONLY via
onclick="window.location.href='/xssL'" buttons — no href, no form, no
.js reference. katana extracts href/src/action (not inline handlers)
and mine_js only fetches live-host roots, so the bar item had zero
cards unseeded. mine_crawled_pages() refetches capped crawled pages
and mines the same endpoint shapes mine_js mines.
"""
from __future__ import annotations

import http.server
import socketserver
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_deeprecon as dr  # noqa: E402
import oracle_hunter as oh  # noqa: E402

COOKIE = "sess=abc123"
HDRS = ["Cookie: sess=abc123"]
HITS: list = []


class _Stub(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "text/html") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        HITS.append(path)
        if path == "/labs":
            self._send(
                200,
                b"""<html><body>
                <button onclick="window.location.href='/xssL'">lab</button>
                <a href="/plain">plain</a>
                </body></html>""",
            )
        elif path == "/gated":
            if "sess=abc123" in (self.headers.get("Cookie") or ""):
                self._send(
                    200,
                    b"<html><body "
                    b'onclick="location.href=\'/vault\'">x</body></html>',
                )
            else:
                self._send(200, b"<html>login wall</html>")
        elif path == "/logout.php":
            self._send(200, b"logged out (session destroyed)")
        elif path == "/app.js":
            self._send(200, b'fetch("/api/thing");', "application/javascript")
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


def _recon_with_crawl(tmp_path, base: str, lines) -> Path:
    recon = tmp_path / "recon"
    recon.mkdir(exist_ok=True)
    (recon / "live_hosts.txt").write_text(base + "\n")
    (recon / "crawl.txt").write_text("\n".join(lines) + "\n")
    (recon / "js_endpoints.txt").write_text("")
    return recon


def test_onclick_window_location_mined(stub, tmp_path):
    recon = _recon_with_crawl(tmp_path, stub, [stub + "/labs"])
    n = dr.mine_crawled_pages(recon, _gate(stub))
    eps = (recon / "js_endpoints.txt").read_text()
    assert "/xssL" in eps, f"onclick route not mined:\n{eps}"
    assert n >= 1


def test_gated_inline_route_needs_cookie(stub, tmp_path):
    plain = _recon_with_crawl(tmp_path, stub, [stub + "/gated"])
    (tmp_path / "a").mkdir(exist_ok=True)
    ra = tmp_path / "a" / "recon"
    ra.mkdir(exist_ok=True)
    (ra / "crawl.txt").write_text(stub + "/gated\n")
    dr.mine_crawled_pages(ra, _gate(stub))
    ra_ep = ra / "js_endpoints.txt"
    assert "/vault" not in (ra_ep.read_text() if ra_ep.exists() else "")
    rb = tmp_path / "b" / "recon"
    rb.mkdir(parents=True, exist_ok=True)
    (rb / "crawl.txt").write_text(stub + "/gated\n")
    dr.mine_crawled_pages(rb, _gate(stub), extra_headers=HDRS)
    assert "/vault" in (rb / "js_endpoints.txt").read_text()
    assert plain.exists()


def test_logout_shaped_pages_never_fetched(stub, tmp_path):
    HITS.clear()
    recon = _recon_with_crawl(
        tmp_path, stub, [stub + "/labs", stub + "/logout.php"]
    )
    dr.mine_crawled_pages(recon, _gate(stub))
    assert "/logout.php" not in HITS, "logout page was fetched (session suicide)"
    assert "/labs" in HITS


def test_offsite_and_static_skipped(stub, tmp_path):
    HITS.clear()
    recon = _recon_with_crawl(
        tmp_path,
        stub,
        [
            stub + "/labs",
            "https://evil.example.com/x",
            stub + "/app.js",
            "not-a-url",
            stub + "/labs",  # dup
        ],
    )
    dr.mine_crawled_pages(recon, _gate(stub))
    assert HITS.count("/labs") == 1
    assert "/api/thing" not in (recon / "js_endpoints.txt").read_text()


def test_cap_bounds_fetches(stub, tmp_path):
    HITS.clear()
    recon = _recon_with_crawl(
        tmp_path, stub, [f"{stub}/p{i}" for i in range(10)]
    )
    dr.mine_crawled_pages(recon, _gate(stub), cap=3)
    assert len(HITS) <= 3


def test_missing_crawl_and_no_gate_fail_closed(stub, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert dr.mine_crawled_pages(empty, _gate(stub)) == 0
    recon = _recon_with_crawl(tmp_path, stub, [stub + "/labs"])
    assert dr.mine_crawled_pages(recon, None) == 0


def test_mined_bare_path_resolves_to_probe_target(tmp_path):
    """Bare mined paths must resolve against live hosts (template input)."""
    import oracle_seam_templates as st

    recon = tmp_path / "recon2"
    recon.mkdir(exist_ok=True)
    (recon / "live_hosts.txt").write_text("http://127.0.0.1:8000\n")
    (recon / "js_endpoints.txt").write_text("/xssL\n")
    (recon / "fuzzed_paths.txt").write_text("")
    (recon / "crawl.txt").write_text("")
    (recon / "api_specs.txt").write_text("")
    (recon / "js_secrets.txt").write_text("")
    mat = st._build_material(recon, None)
    urls = [u for u, _s, _a in st._injection_targets(mat)]
    assert any(u == "http://127.0.0.1:8000/xssL" for u in urls), urls
