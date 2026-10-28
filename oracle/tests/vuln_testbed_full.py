#!/usr/bin/env python3
"""Comprehensive vulnerable testbed for Oracle Phase-A template verification.

Serves a live vulnerable route for every web2 seam template (and benign
controls that must NOT confirm), so each template can be verified both ways
on real wire behavior. Loopback only. Port 8765 (matches Work-1).
"""
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

ORDER = {"id": "ord_101", "total": 100.0, "status": "PAID", "user_id": "usr_regular"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, status=200, ctype="text/plain"):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        # ---- benign controls (must REJECT) ----
        if p == "/":
            return self._text("<html><body>Welcome</body></html>", ctype="text/html")
        if p == "/health":
            return self._json({"status": "ok", "app": "vuln_testbed"})
        # ---- self-observing (info disclosure): real internals leak ----
        if p == "/debug/config":
            return self._json(
                {
                    "service": "billing",
                    "env": "staging",
                    "debug_mode": True,
                    "aws_secret_key_mock": "AKIAIOSFODNN7EXAMPLE",
                    "internal_broker": "amqp://admin:secret@queue.internal:5672",
                }
            )
        # ---- invisible-architect + artifact: exposed infra files ----
        if p == "/package.json":
            return self._json(
                {
                    "name": "billing-ui",
                    "version": "2.3.1",
                    "dependencies": {"express": "4.18.2", "jsonwebtoken": "9.0.0"},
                }
            )
        if p == "/.env":
            return self._text(
                "DB_PASSWORD=sup3rs3cret\nAWS_SECRET_ACCESS_KEY=AKIAI\nINTERNAL_API=http://10.0.0.5\n"
            )
        # ---- spec-disclosure: openapi ----
        if p in ("/openapi.json", "/swagger.json"):
            return self._json(
                {"openapi": "3.0.0", "paths": {"/api/users": {}, "/api/admin": {}}}
            )
        # ---- observer: graphql introspection via GET ----
        if p == "/graphql":
            return self._json({"data": {"__typename": "Query"}})
        # ---- vacuum-identity TRUE positive: privileged path, NO auth, returns priv data ----
        if p == "/api/internal/dashboard":
            return self._json(
                {
                    "role": "admin",
                    "users": 9410,
                    "revenue": 1420500,
                    "internal": True,
                    "data": "sensitive",
                }
            )
        # ---- beautiful-liar: trusts client-supplied role header ----
        if p == "/api/v1/admin/metrics":
            if (
                self.headers.get("X-Original-Role") == "admin"
                or self.headers.get("Authorization") == "Bearer admin-secret-token"
            ):
                return self._json(
                    {
                        "status": "authorized",
                        "role_effective": "admin",
                        "metrics": {"total_revenue": 1420500, "user_count": 9410},
                    }
                )
            return self._json({"error": "forbidden", "required_role": "admin"}, 403)
        # ---- mirror: v1/v2 pair, old version still live ----
        if p in ("/api/v1/orders/ord_101", "/api/v2/orders/ord_101"):
            return self._json(ORDER)
        # ---- repulsive: two spellings; middleware binds one ----
        if p in ("/api/orders", "/API/orders", "/api/orders/"):
            return self._json({"id": "ord_101", "data": [ORDER], "result": "ok"})
        # ---- deathless: forgotten legacy layer still routable ----
        if p in ("/api/legacy/users", "/old/users"):
            return self._json(
                {
                    "id": 1,
                    "email": "legacy@x.com",
                    "deprecated": True,
                    "data": "still here",
                }
            )
        # ---- cliff-and-current: guarded path 403 + unguarded alternate 200 ----
        if p == "/api/v1/secrets":
            return self._json({"error": "forbidden"}, 403)
        if p == "/api/internal/secrets":
            return self._json(
                {"id": 1, "token": "s3cr3t-abc", "data": "protected", "internal": True}
            )
        # ---- single-token: unhandled input -> 500 ----
        if p == "/api/crash":
            return self._text(
                "Traceback (most recent call last): internal error", status=500
            )
        # ---- injection-sqli TRUE positive: quote breaks the backend query ----
        if p == "/api/search":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if any("'" in v for vals in qs.values() for v in vals):
                return self._text(
                    "Traceback (most recent call last): "
                    "sqlite3.OperationalError: unrecognized token",
                    status=500,
                )
            return self._json(
                {"results": [{"id": "p1", "name": "phone"}], "q": qs.get("q", [""])[0]}
            )
        # ---- injection-xss TRUE positive: reflects input unescaped ----
        if p == "/greet":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = qs.get("q", qs.get("name", qs.get("search", ["friend"])))[0]
            return self._text(
                f"<html><body><h1>Hello, {name}!</h1></body></html>",
                ctype="text/html",
            )
        # ---- open-redirect: reflects user-controlled next= into Location ----
        if p == "/redirect":
            nxt = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get(
                "next", [""]
            )[0]
            self.send_response(302)
            self.send_header("Location", nxt or "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # ---- idor TRUE positive: per-user objects with no session ----
        if p.startswith("/api/profile/"):
            uid = p.rsplit("/", 1)[-1]
            if uid.isdigit():
                return self._json(
                    {
                        "id": int(uid),
                        "username": f"user{uid}",
                        "email": f"user{uid}@example.com",
                    }
                )
            return self._json({"error": "not found"}, 404)
        # ---- Bob Work-1 routes: benign controls (must REJECT) ----
        if p == "/api/users":
            return self._json({"users": ["alice", "bob"]})
        if p.startswith("/api/users/"):
            return self._json({"id": p.rsplit("/", 1)[-1], "email": "self@x.com"})
        if p == "/upload":
            return self._text("<html>upload form</html>", ctype="text/html")
        if p.startswith("/static/"):
            return self._text("/* static asset */", ctype="text/css")
        return self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), H).serve_forever()
