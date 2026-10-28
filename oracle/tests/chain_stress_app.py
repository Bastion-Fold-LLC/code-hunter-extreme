#!/usr/bin/env python3
"""Chain-stress benchmark target — the hardest testbed for Oracle's FULL loop.

Unlike bad_code_app.py (independent flaws), this app plants a DELIBERATE
3-hop chain where each hop is unreachable without the previous hop's output.
It exists to push every stage of the pipeline — recon, both lenses, synthesis,
the 5-gate verifier, AND chain composition — not just single-bug recall.

THE CHAIN (compounds to Critical):

  Hop 1 — Exposure (Self-Observing):
    GET /.well-known/app-config.json   (unauthenticated)
    Leaks two secrets an attacker cannot otherwise know:
      - admin_path_prefix : "/internal-7f3a"   (the hidden admin mount)
      - ops_access_token  : "ops-9c2e-..."     (the operator bearer)

  Hop 2 — Auth bypass (Beautiful Liar):
    GET {admin_path_prefix}/admin/users
    Returns 401 with NO token. Accepts ONLY the leaked ops_access_token.
    Unreachable without Hop 1: you know neither the path nor the token.
    -> yields the full user id list.

  Hop 3 — PII IDOR (Cliff and the Current):
    GET {admin_path_prefix}/admin/users/{id}/ssn   (same ops token)
    Returns ANY user's SSN. Reachable only through the Hop-2 context.
    -> critical data exposure; chained severity = Critical.

Precondition wiring (what the chain engine must connect):
    Hop1.output(admin_path_prefix) -> Hop2.precondition(path)
    Hop1.output(ops_access_token)  -> Hop2/3.precondition(Authorization bearer)

Standalone bug (breadth, not part of the chain):
    GET /search?q=   reflects q unescaped (reflected XSS).

Benign controls (MUST be REJECTED — precision):
    GET /health                         -> 200 ok, nothing sensitive
    GET /status/config                  -> 200 but only non-secret build info
    GET {admin_path_prefix}/admin/users -> 401 WITHOUT the leaked token
"""

import http.server
import json
import urllib.parse

PORT = 8770

ADMIN_PREFIX = "/internal-7f3a"
OPS_TOKEN = "ops-9c2e-4d1f-a7b0"  # leaked by Hop 1; gates Hop 2 + Hop 3

USERS = [
    {"id": "u_1001", "email": "dana@corp.test", "role": "admin", "ssn": "501-22-9183"},
    {"id": "u_1002", "email": "rafe@corp.test", "role": "user", "ssn": "604-77-3310"},
    {"id": "u_1003", "email": "mina@corp.test", "role": "user", "ssn": "712-08-5529"},
]


class ChainStressHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # quiet logs for clean testing

    def _json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, status=200, content_type="text/html"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self):
        return self.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # ── Crawlable surface: homepage that references the real endpoints ────
        # A real app exposes its API through linked HTML / JS, which is how a
        # crawler (katana) discovers the surface. The hidden admin mount is NOT
        # referenced here — it is reachable only by reading the Hop-1 config
        # leak, which is the chain the pipeline must follow.
        if path == "/" or path == "/index.html":
            self._text(
                "<!doctype html><html><head><title>ledger-api</title></head><body>"
                "<h1>Ledger API</h1>"
                "<ul>"
                "<li><a href=\"/health\">health</a></li>"
                "<li><a href=\"/status/config\">status</a></li>"
                "<li><a href=\"/search?q=test\">search</a></li>"
                "</ul>"
                "<script src=\"/static/app.js\"></script>"
                "</body></html>"
            )
            return

        # app.js references the bootstrap config endpoint (Hop 1 entry point),
        # the way a SPA fetches its runtime config on load.
        if path == "/static/app.js":
            self._text(
                "// ledger-api front-end bootstrap\n"
                "fetch('/.well-known/app-config.json')"
                ".then(r => r.json()).then(cfg => window.__CFG = cfg);\n"
                "const SEARCH_API = '/search';\n",
                content_type="application/javascript",
            )
            return

        # ── Benign control: health ────────────────────────────────────────────
        if path == "/health":
            self._json({"status": "ok", "app": "ledger-api"})
            return

        # ── Benign control: build info with NOTHING secret ────────────────────
        if path == "/status/config":
            self._json({"service": "ledger-api", "version": "3.4.0", "region": "us-1"})
            return

        # ── Hop 1: Exposure — leaks the path prefix + ops token ───────────────
        if path == "/.well-known/app-config.json":
            self._json({
                "service": "ledger-api",
                "admin_path_prefix": ADMIN_PREFIX,
                "ops_access_token": OPS_TOKEN,
                "note": "internal bootstrap config — should never be public",
            })
            return

        # ── Hop 2: Auth bypass — admin user list, ONLY via leaked ops token ───
        if path == f"{ADMIN_PREFIX}/admin/users":
            if self._bearer() != OPS_TOKEN:
                self._json({"error": "unauthorized"}, 401)
                return
            self._json({"users": [{"id": u["id"], "email": u["email"]} for u in USERS]})
            return

        # ── Hop 3: PII IDOR — any user's SSN via the Hop-2 ops context ────────
        if path.startswith(f"{ADMIN_PREFIX}/admin/users/") and path.endswith("/ssn"):
            if self._bearer() != OPS_TOKEN:
                self._json({"error": "unauthorized"}, 401)
                return
            uid = path[len(f"{ADMIN_PREFIX}/admin/users/"):-len("/ssn")]
            match = next((u for u in USERS if u["id"] == uid), None)
            if not match:
                self._json({"error": "not found"}, 404)
                return
            self._json({"id": match["id"], "ssn": match["ssn"]})
            return

        # ── Standalone bug: reflected XSS ─────────────────────────────────────
        if path == "/search":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            self._text(f"<html><body>Results for: {q}</body></html>")
            return

        self._json({"error": "not found"}, 404)


def run():
    # Threaded so a slow/half-open client (e.g. a scanner that drops a
    # connection) can never wedge the single handler thread and freeze the app.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), ChainStressHandler)
    server.serve_forever()


if __name__ == "__main__":
    run()
