#!/usr/bin/env python3
"""
Intentionally vulnerable microservice benchmark target for Oracle.
Contains deliberate architectural paradoxes ("You Never Said" flaws):

1. Identity / Proxy Seam (Beautiful Liar):
   /api/v1/admin/metrics — trusts untrusted X-Original-Role header for access control.
   You never said the server verified the role claim, only that the UI sends it.

2. Alternate-Path Auth Gap (Cliff and the Current):
   /api/v1/private/secure — enforces auth (403 without token).
   /api/internal/private — same data, different path, NO auth check.
   You never said the auth middleware binds to ALL paths, only the documented one.

3. Information / Debug Exposure (Self-Observing):
   /debug/config — unprotected internal config with credentials.

4. Stale API Version (Mirror):
   /api/v1/users and /api/v2/users — both live; v1 has weaker field filtering.

5. Legacy/Forgotten Route (Deathless):
   /api/internal/dashboard — legacy internal endpoint still routable.

6. Exposed Artifact (Invisible Architect):
   /static/package.json — dependency manifest served publicly.
   /static/.env.bak — backup env file served publicly.

7. State Invariant Violation (Single-Token / Ambiguity):
   POST /api/v1/orders/ord_101/apply_discount — coupon on already-PAID order.
"""

import http.server
import json
import urllib.parse

PORT = 8765

# In-memory mock database
# NOTE: mutated by Flaw 7 POSTs — tests hitting apply_discount must
# snapshot/restore (see test_flaw_battery) or later tests see dirty totals.
ORDERS = {
    "ord_101": {"id": "ord_101", "total": 100.0, "status": "PAID", "user_id": "usr_regular"}
}


def reset_state():
    """Restore the mutable order fixture between test suites.

    The app is intentionally stateful; a suite that POSTs a discount must
    not poison the next suite's baseline. Callers own snapshot/restore when
    they need the mutation inside one test.
    """
    ORDERS["ord_101"].update(
        {"id": "ord_101", "total": 100.0, "status": "PAID", "user_id": "usr_regular"}
    )
    ORDERS["ord_101"].pop("refund_credit_due", None)

USERS_V1 = [
    {"id": "usr_001", "email": "alice@example.com", "role": "admin", "ssn": "123-45-6789"},
    {"id": "usr_002", "email": "bob@example.com",   "role": "user",  "ssn": "987-65-4321"},
]

USERS_V2 = [
    {"id": "usr_001", "email": "alice@example.com", "role": "admin"},
    {"id": "usr_002", "email": "bob@example.com",   "role": "user"},
]

PRIVATE_DATA = {"secret": "internal-key-abc123", "users": 9410, "revenue": 1420500}


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # quiet logs for clean testing

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, status=200, content_type="text/plain"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # ── Health (benign) ───────────────────────────────────────────────────
        if path == "/health":
            self._send_json({"status": "ok", "app": "vulnerable_testbed"})
            return

        # ── Flaw 1: Beautiful Liar — trust-claim bypass ───────────────────────
        # "You never said the server validated the role claim."
        # Guarded path trusts an attacker-injectable header as the auth proof.
        if path == "/api/v1/admin/metrics":
            role = self.headers.get("X-Original-Role", "user")
            auth = self.headers.get("Authorization", "")
            if role == "admin" or auth == "Bearer admin-secret-token":
                self._send_json({
                    "status": "authorized",
                    "role_effective": role,
                    "metrics": {"total_revenue": 1420500, "user_count": 9410},
                })
            else:
                self._send_json({"error": "forbidden", "required_role": "admin"}, 403)
            return

        # ── Flaw 2: Cliff and the Current — alternate-path auth gap ──────────
        # Guarded path: /api/v1/private/secure returns 403 without real auth.
        # Alternate path: /api/internal/private has the same data, no auth check.
        if path == "/api/v1/private/secure":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer valid-user-token":
                self._send_json(PRIVATE_DATA)
            else:
                self._send_json({"error": "unauthorized"}, 403)
            return

        if path == "/api/internal/private":
            # Same data — "you never said the auth check runs on THIS path"
            self._send_json(PRIVATE_DATA)
            return

        # ── Flaw 3: Self-Observing — debug credential exposure ────────────────
        if path == "/debug/config":
            self._send_json({
                "service": "billing-engine",
                "env": "staging",
                "debug_mode": True,
                "aws_secret_key_mock": "AKIAIOSFODNN7EXAMPLE",
                "internal_broker": "amqp://admin:secret@queue.internal:5672",
            })
            return

        # ── Flaw 4: Mirror — stale API version (v1 leaks ssn, v2 does not) ───
        if path == "/api/v1/users":
            self._send_json({"users": USERS_V1})
            return

        if path == "/api/v2/users":
            self._send_json({"users": USERS_V2})
            return

        # ── Flaw 5: Deathless — legacy forgotten route ────────────────────────
        if path == "/api/internal/dashboard":
            self._send_json({
                "legacy": True,
                "data": {"revenue": 1420500, "admin_token": "legacy-tok-xyz"},
            })
            return

        # ── Flaw 6: Invisible Architect — exposed artifact ────────────────────
        if path == "/static/package.json":
            self._send_text(
                '{"name":"billing-engine","version":"2.1.0",'
                '"dependencies":{"express":"4.18.2","jsonwebtoken":"8.5.1"}}',
                content_type="application/json",
            )
            return

        if path == "/static/.env.bak":
            self._send_text(
                "DB_PASSWORD=hunter2\nSECRET_KEY=abc123\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n",
                content_type="text/plain",
            )
            return

        # ── Order read (for variant sweep tests) ─────────────────────────────
        if path == "/api/v1/orders/ord_101":
            self._send_json(ORDERS["ord_101"])
            return

        self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # ── Flaw 7: State invariant violation ─────────────────────────────────
        if path == "/api/v1/orders/ord_101/apply_discount":
            content_length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
            discount = float(payload.get("amount", 20.0))
            order = ORDERS["ord_101"]
            order["total"] = order["total"] - discount
            order["refund_credit_due"] = abs(order["total"]) if order["total"] < 0 else 0
            self._send_json({
                "status": "discount_applied",
                "order_id": order["id"],
                "new_total": order["total"],
                "refund_credit_due": order["refund_credit_due"],
                "order_status": order["status"],
            })
            return

        self._send_json({"error": "not found"}, 404)


def run():
    server = http.server.HTTPServer(("127.0.0.1", PORT), VulnerableHandler)
    server.serve_forever()


if __name__ == "__main__":
    run()
