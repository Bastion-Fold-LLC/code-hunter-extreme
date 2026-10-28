#!/usr/bin/env python3
"""P14: directory-listing harvest + listed-file template (juice /ftp/legal.md).

Root cause: /ftp/ serves a browsable listing linking legal.md, but no
pipeline stage parsed listings — ffuf found the dir, katana never entered
it (unlinked from the SPA), templates never saw the child. Recall miss
in juice/exposure.

Fix: harvest_listings() (deeprecon) parses fuzzed dir-like 200s for
listing-shaped bodies (>= 2 same-subtree children; no server-brand
literals) into listed_paths.txt, and the listed-file-exposure template
proves each listed document serves document bytes (text/json
content-type), not the SPA shell.
"""
from __future__ import annotations

import http.server
import re
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_deeprecon as dr  # noqa: E402
import oracle_hunter as oh  # noqa: E402
import oracle_seam_templates as st  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)


class _Stub(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/docs", "/docs/"):
            self._send(
                200,
                b"<html><title>listing directory /docs/</title>"
                b'<a href=".">.</a><a href="guide.md">guide.md</a>'
                b'<a href="data.json">data.json</a>'
                b'<a href="/outside.txt">esc</a>'
                b'<a href="?C=N;O=D">sort</a></html>',
            )
        elif path == "/docs/guide.md":
            self._send(200, b"# Guide\n", "text/markdown")
        elif path == "/docs/data.json":
            self._send(200, b'{"a": 1}', "application/json")
        elif path == "/single":
            self._send(200, b'<html><a href="/home">home</a></html>')
        elif path in ("/zzzlisting", "/zzzlisting/"):
            self._send(
                200,
                b"<html><title>listing directory /zzzlisting/</title>"
                b'<a href="a.md">a.md</a><a href="b.json">b.json</a></html>',
            )
        elif re.fullmatch(r"/f\d{3}", path):
            self._send(200, b"<html>shell</html>")
        elif path == "/app.js":
            self._send(200, b"var x = 1;", "application/javascript")
        else:
            self._send(404, b"no")

    def log_message(self, *a):  # noqa: ANN001, ANN202
        pass


class _Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _serve():
    srv = _Threaded(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _gate(base: str):
    return oh.ProgramScopeGate({}, base.split("://", 1)[1])


def test_harvest_lists_children_not_pages(tmp_path):
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        out = tmp_path / "o"
        out.mkdir()
        (out / "fuzzed_paths.txt").write_text(
            f"{base}/docs [200]\n{base}/single [200]\n{base}/app.js [200]\n"
        )
        n = dr.harvest_listings(out, _gate(base))
        listed = (out / "listed_paths.txt").read_text()
        assert n == 2, f"expected 2 children, got:\n{listed}"
        assert f"{base}/docs/guide.md" in listed
        assert f"{base}/docs/data.json" in listed
        # /single is a page (1 link), /app.js is a file — neither is a listing
        assert "/single" not in listed.replace("/docs/", "")
    finally:
        srv.shutdown()
        srv.server_close()


def test_harvest_blocks_escapes_and_sort_links(tmp_path):
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        out = tmp_path / "o"
        out.mkdir()
        (out / "fuzzed_paths.txt").write_text(f"{base}/docs [200]\n")
        dr.harvest_listings(out, _gate(base))
        listed = (out / "listed_paths.txt").read_text()
        assert "/outside.txt" not in listed
        assert "?C=" not in listed
    finally:
        srv.shutdown()
        srv.server_close()


def test_harvest_fail_closed_without_gate(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "fuzzed_paths.txt").write_text("http://127.0.0.1:9/docs [200]\n")
    assert dr.harvest_listings(out, None) == 0


def test_harvest_rarity_beats_shell_flood(tmp_path):
    """Size-rarity spends the fetch cap on outliers, not the SPA shell.

    70 same-size shell 200s sort before the alpha-last listing; alpha
    order burns the 60-dir cap on shells and never fetches it (juice
    /ftp/ ranked 260th of 739). ffuf-recorded sizes flip the order.
    """
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        out = tmp_path / "o"
        out.mkdir()
        flood = [f"{base}/f{i:03d}" for i in range(70)]
        target = f"{base}/zzzlisting"
        (out / "fuzzed_paths.txt").write_text(
            "".join(f"{u} [200]\n" for u in flood + [target])
        )
        shell_len = len(b"<html>shell</html>")
        listing_len = len(
            b"<html><title>listing directory /zzzlisting/</title>"
            b'<a href="a.md">a.md</a><a href="b.json">b.json</a></html>'
        )
        assert shell_len != listing_len
        (out / "fuzzed_sizes.txt").write_text(
            "".join(f"{u} {shell_len}\n" for u in flood) + f"{target} {listing_len}\n"
        )
        n = dr.harvest_listings(out, _gate(base))
        listed = (out / "listed_paths.txt").read_text()
        assert n == 2, f"expected 2 children, got:\\n{listed}"
        assert f"{target}/a.md" in listed
        assert f"{target}/b.json" in listed
    finally:
        srv.shutdown()
        srv.server_close()


def test_harvest_absent_sizes_falls_back_to_alpha(tmp_path):
    """No side file (old recon dirs, hand seeds): alpha order, no crash."""
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        out = tmp_path / "o"
        out.mkdir()
        (out / "fuzzed_paths.txt").write_text(
            f"{base}/docs [200]\n{base}/single [200]\n"
        )
        assert not (out / "fuzzed_sizes.txt").exists()
        n = dr.harvest_listings(out, _gate(base))
        assert n == 2, (out / "listed_paths.txt").read_text()
    finally:
        srv.shutdown()
        srv.server_close()


def test_template_cards_for_docs_not_binaries(tmp_path):
    recon = tmp_path / "r"
    recon.mkdir()
    (recon / "live_hosts.txt").write_text("http://127.0.0.1:3000\n")
    (recon / "listed_paths.txt").write_text(
        "http://127.0.0.1:3000/ftp/legal.md\n"
        "http://127.0.0.1:3000/ftp/data.json\n"
        "http://127.0.0.1:3000/ftp/logo.png\n"
        "http://127.0.0.1:3000/ftp/noext\n"
    )
    for f in (
        "js_endpoints.txt",
        "fuzzed_paths.txt",
        "api_specs.txt",
        "js_secrets.txt",
        "crawl.txt",
    ):
        (recon / f).write_text("")
    seams = st.scan_template_seams(
        recon_dir=recon,
        scope_gate=oh.ProgramScopeGate({}, target_fallback="http://127.0.0.1:3000"),
    )
    listed = [s for s in seams if s.get("claim_type") == "listed-file-exposure"]
    by_url = {s["check"].split("'")[-2]: s["expected"] for s in listed}
    assert (
        'content-type contains "text"' in by_url["http://127.0.0.1:3000/ftp/legal.md"]
    )
    assert (
        'content-type contains "json"' in by_url["http://127.0.0.1:3000/ftp/data.json"]
    )
    assert not any("logo.png" in s["check"] for s in listed)
    assert not any("noext" in s["check"] for s in listed)


def test_stub_chain_listed_doc_confirms_spa_shell_rejects(tmp_path):
    """Template->check->verify on the wire: doc bytes confirm, HTML rejects."""
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        recon = tmp_path / "r"
        recon.mkdir()
        (recon / "live_hosts.txt").write_text(base + "\n")
        (recon / "listed_paths.txt").write_text(f"{base}/docs/guide.md\n")
        for f in (
            "js_endpoints.txt",
            "fuzzed_paths.txt",
            "api_specs.txt",
            "js_secrets.txt",
            "crawl.txt",
        ):
            (recon / f).write_text("")
        cards = [
            s
            for s in st.scan_template_seams(
                recon_dir=recon,
                scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
            )
            if s.get("claim_type") == "listed-file-exposure"
        ]
        assert cards, "no listed-file card for a .md child"
        card = cards[0]
        _, out, err = oh._run_check(card["check"])
        assert "[BLOCKED]" not in err
        status = extract_status_from_curl_output(out)
        url = card["check"].split("'")[-2]
        v = verify_seam_card(card, [url], status=status, body=out)
        assert v["verdict"] == "CONFIRMED", f"doc must confirm: {v['reason']}"
        # Negative: an HTML shell served at a listed-looking URL must reject.
        html_200 = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html><body>spa shell</body></html>"
        )
        v2 = verify_seam_card(
            card,
            [url],
            status=extract_status_from_curl_output(html_200),
            body=html_200,
        )
        assert v2["verdict"] == "REJECTED", f"HTML shell: {v2['reason']}"
    finally:
        srv.shutdown()
        srv.server_close()
