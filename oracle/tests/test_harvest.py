"""Harvest engine: corpus extraction, login walk, data-driven reframes."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_harvest as hv  # noqa: E402

CHECK = "curl -s http://h.test/api/user/2"


def _seam(**over):
    base = {
        "n": 1,
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns other users without auth",
        "check": CHECK,
        "expected": "status 200",
    }
    base.update(over)
    return base


class _LoginStub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body="", headers=()):
        raw = body.encode()
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        self.server.hits.append(("GET", self.path))
        user_form = '<form method="POST"><input name="username"></form>'
        pass_form = '<form method="POST"><input name="password"></form>'
        if self.path == "/":
            self._send(200, user_form)
        elif self.path == "/password/test":
            self._send(200, pass_form)
        elif self.path == "/dashboard":
            self._send(200, "welcome")
        elif self.path == "/orders":
            if "session=abc123" not in self.headers.get("Cookie", ""):
                self._send(302, "", [("Location", "/")])
            else:
                self._send(200, '<a href="/order/300123/receipt">a</a>')
        elif self.path.startswith("/order/"):
            parts = self.path.strip("/").split("/")
            ident = parts[1] if len(parts) == 3 else ""
            if "session=abc123" not in self.headers.get("Cookie", ""):
                self._send(302, "", [("Location", "/")])
            elif ident in ("300123", "300401"):
                self._send(200, f"<p>Order ID: {ident}</p><p>total 5</p>")
            else:
                self._send(200, "<p>Order ID: </p>")
        elif self.path == "/evil":
            self._send(
                200,
                '<form method="POST" action="/evil-submit">'
                '<input name="username"></form>',
            )
        else:
            self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        self.server.hits.append(("POST", self.path, body))
        fields = parse_qs(body)
        path = self.path
        if path == "/" and fields.get("username") == ["test"]:
            self._send(302, "", [("Location", "/password/test")])
        elif path == "/password/test" and fields.get("password") == ["test"]:
            self._send(
                302,
                "",
                [
                    ("Location", "/dashboard"),
                    ("Set-Cookie", "session=abc123; Path=/"),
                ],
            )
        elif self.path == "/evil-submit":
            self._send(
                302,
                "",
                [
                    ("Location", "http://127.0.0.2:9/"),
                    ("Set-Cookie", "session=evil1; Path=/"),
                ],
            )
        else:
            self._send(401, "nope")


@pytest.fixture
def stub():
    server = HTTPServer(("127.0.0.1", 0), _LoginStub)
    server.hits = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield (f"http://127.0.0.1:{server.server_port}", server.hits)
    server.shutdown()
    thread.join(timeout=5)


def test_harvest_comment_creds():
    body = "<!-- TODO: Delete the testing account (test:test). -->"
    assert hv.harvest_text(body)["creds"] == [("test", "test")]
    assert hv.harvest_text("<!-- note: update later -->")["creds"] == []


def test_harvest_json_creds():
    body = '{"username": "alice", "password": "s3cret"}'
    assert hv.harvest_text(body)["creds"] == [("alice", "s3cret")]


def test_harvest_ids_cookies_tokens():
    body = (
        "GET /api/user/2 /order/99\n"
        '{"id": 7}\n'
        "Set-Cookie: session=abc; Path=/\n"
        "Set-Cookie: empty=; Path=/\n"
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJ"
    )
    got = hv.harvest_text(body)
    assert got["ids"] == ["2", "99", "7"]
    assert got["cookies"] == [("session", "abc")]
    assert len(got["tokens"]) == 1


def test_harvest_form_action_resolution():
    inner = '<input name="username"><input name="password">'
    page = "http://h.test/login"
    f = hv.harvest_text(f'<form method="POST">{inner}</form>', page)
    assert f["forms"][0]["action"] == page
    assert f["forms"][0]["user_field"] == "username"
    assert f["forms"][0]["pass_field"] == "password"
    rel = hv.harvest_text(f'<form action="go">{inner}</form>', page)
    assert rel["forms"][0]["action"] == "http://h.test/go"
    no_source = hv.harvest_text(f'<form action="go">{inner}</form>')
    assert no_source["forms"] == []
    no_fields = hv.harvest_text("<form><input name=nothing></form>", page)
    assert no_fields["forms"] == []


def test_harvest_caps_and_order():
    body = " ".join(f"/o/{i}" for i in range(30))
    ids = hv.harvest_text(body)["ids"]
    assert ids == [str(i) for i in range(20)]


def test_merge_harvest_dedups():
    a = hv.harvest_text("/o/2 /o/3")
    b = hv.harvest_text("/o/3 /o/4")
    assert hv.merge_harvest(a, b)["ids"] == ["2", "3", "4"]


def test_harvest_recon_dir_uses_manifest(tmp_path):
    recon = tmp_path / "recon"
    assets = tmp_path / "assets"
    recon.mkdir()
    assets.mkdir()
    (recon / "a.txt").write_text("/o/11")
    page_html = '<form action="/in"><input name="username"></form>'
    (assets / "p.html").write_text(page_html)
    manifest = json.dumps({"p.html": "http://h.test/p"})
    (assets / "_manifest.json").write_text(manifest)
    got = hv.harvest_recon_dir(recon)
    assert "11" in got["ids"]
    assert got["forms"][0]["action"] == "http://h.test/in"


def test_login_flow_two_step(stub):
    base, _ = stub
    cookies = hv.attempt_login_flow(base + "/", "username", "pw", "t", "t")
    assert cookies is None  # wrong creds first: proves failure path
    cookies = hv.attempt_login_flow(
        base + "/",
        "username",
        "password",
        "test",
        "test",
    )
    assert cookies == {"session": "abc123"}


def test_login_flow_offhost_redirect_not_followed(stub):
    base, hits = stub
    cookies = hv.attempt_login_flow(base + "/evil", "username", "", "u", "p")
    assert cookies == {"session": "evil1"}
    assert all("127.0.0.2" not in str(h) for h in hits)


def test_login_once_caches(stub, tmp_path):
    base, hits = stub
    form = '<form method="POST"><input name="username"></form>'
    html = form + "<!-- (test:test) -->"
    corpus = hv.merge_harvest(hv.harvest_text(html, source_url=base + "/"))
    first = hv.harvest_login_once(base + "/", corpus, tmp_path)
    posts = [h for h in hits if h[0] == "POST"]
    assert first == {"session": "abc123"}
    assert len(posts) == 2
    second = hv.harvest_login_once(base + "/", corpus, tmp_path)
    assert second == {"session": "abc123"}
    assert [h for h in hits if h[0] == "POST"] == posts
    assert (tmp_path / "harvest_login.json").stat().st_mode & 0o777 == 0o600


def test_login_once_strict_gates(stub, tmp_path):
    base, hits = stub
    form = '<form method="POST"><input name="username"></form>'
    html = form + "<!-- (test:test) -->"
    corpus = hv.harvest_text(html, source_url=base + "/")

    class _Deny:
        def is_in_scope(self, url):
            return (False, "denied")

    denied = hv.harvest_login_once(base + "/", corpus, tmp_path, _Deny())
    assert denied is None
    assert hits == []
    live = hv.harvest_login_once("http://target.test/", corpus, tmp_path)
    assert live is None
    empty = hv.harvest_login_once(base + "/", hv.harvest_text(""), tmp_path)
    assert empty is None


def _corpus(**over):
    base = {
        "creds": [("test", "test")],
        "ids": ["2", "9"],
        "cookies": [],
        "tokens": ["tok12345678"],
        "forms": [],
        "links": [],
    }
    base.update(over)
    return base


def test_reframes_shapes():
    cards = hv.harvest_reframes(
        _seam(), _corpus(), {"s": "v"}, 10, base_url="http://h.test/"
    )
    kinds = [c["reframe_transform"] for c in cards]
    assert kinds[0] == "harvest-auth"
    assert "harvest-id" in kinds
    assert "harvest-basic" in kinds
    assert "harvest-token" in kinds
    assert [c["n"] for c in cards] == list(range(10, 10 + len(cards)))
    assert all(c["reframed"] and c["origin"] == "harvest" for c in cards)
    assert "Cookie: s=v" in cards[0]["check"]
    assert "/api/user/9" in cards[1]["check"]
    assert cards[1]["check"].count("Cookie: s=v") == 1
    assert cards[1]["expected"] == 'status 200, body contains "9"'
    assert "ownership unchecked" in cards[1]["assertion_b"]


def test_reframes_cookie_host_guard():
    cards = hv.harvest_reframes(
        _seam(), _corpus(), {"s": "v"}, 5, base_url="http://other.test/"
    )
    assert all("Cookie: s=v" not in c["check"] for c in cards)
    bare = hv.harvest_reframes(_seam(), _corpus(), {"s": "v"}, 5)
    assert all("Cookie: s=v" not in c["check"] for c in bare)


def test_reframes_link_cards():
    corpus = _corpus(
        links=[
            "http://h.test/order/300123/receipt",
            "http://cdn.test/x/1",
            "http://h.test/about",
        ]
    )
    cards = hv.harvest_reframes(
        _seam(), corpus, {"s": "v"}, 5, base_url="http://h.test/"
    )
    links = [c for c in cards if c["reframe_transform"] == "harvest-link"]
    assert len(links) == 1
    assert links[0]["check"].startswith("curl -s http://h.test/order/")
    assert "Cookie: s=v" in links[0]["check"]
    assert links[0]["expected"] == 'status 200, body contains "300123"'


def test_harvest_links():
    body = (
        '<a href="/order/300123/receipt">r</a>'
        '<script src="http://cdn.test/x.js"></script>'
        '<a href="mailto:a@b.c">m</a>'
    )
    got = hv.harvest_text(body, source_url="http://h.test/orders")
    assert "http://h.test/order/300123/receipt" in got["links"]
    assert "http://cdn.test/x.js" in got["links"]
    assert not [u for u in got["links"] if u.startswith("mailto")]


def test_reframes_skip_rules():
    looped = hv.harvest_reframes(_seam(reframed=True), _corpus(), {}, 5)
    assert looped == []
    noncurl = hv.harvest_reframes(_seam(check="slither ."), _corpus(), {}, 5)
    assert noncurl == []
    cards = hv.harvest_reframes(_seam(), _corpus(), {"s": "v"}, 5, max_cards=2)
    assert len(cards) == 2
    alredy = _seam(check=CHECK + ' -H "Cookie: a=b"')
    got = hv.harvest_reframes(alredy, _corpus(), {"s": "v"}, 5)
    kinds = [c["reframe_transform"] for c in got]
    assert "harvest-auth" not in kinds


def test_followups_weak_confirmed_gets_harvest(tmp_path):
    seen = {}

    def _login(base, corpus, recon, gate, testnet):
        seen["base"] = base
        return {"s": "v"}

    cards = hv.followups_for_verdict(
        _seam(), CHECK, "/o/9", True, tmp_path, 20, login_fn=_login
    )
    assert seen["base"] == "http://h.test/api/user/2"
    assert cards and all(c["reframe_of"] == 1 for c in cards)


def test_followups_strong_confirmed_skips(tmp_path):
    called = []

    def _login(*a):
        called.append(a)
        return {}

    seam = _seam(check=CHECK + ' -H "Cookie: a=b"')
    assert (
        hv.followups_for_verdict(
            seam, seam["check"], "", True, tmp_path, 20, login_fn=_login
        )
        == []
    )
    assert called == []


def test_followups_rejected_and_reframed(tmp_path):
    calls = []

    def _login(base, corpus, recon, gate, testnet):
        calls.append(base)
        return {}

    out = hv.followups_for_verdict(
        _seam(), CHECK, "", False, tmp_path, 20, login_fn=_login
    )
    assert isinstance(out, list)
    assert calls == ["http://h.test/api/user/2"]
    assert (
        hv.followups_for_verdict(
            _seam(reframed=True),
            CHECK,
            "",
            False,
            tmp_path,
            20,
            login_fn=_login,
        )
        == []
    )
    assert calls == ["http://h.test/api/user/2"]


def test_authed_recon_harvests_gated_pages(stub, tmp_path):
    base, hits = stub
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "known_urls.txt").write_text(base + "/orders\n")
    got = hv.authed_recon({"session": "abc123"}, base + "/", recon)
    assert base + "/order/300123/receipt" in got["links"]
    assert "300123" in got["ids"]
    n = len(hits)
    again = hv.authed_recon({"session": "abc123"}, base + "/", recon)
    assert again == got
    assert len(hits) == n


def test_authed_recon_unauth_gets_no_links(stub, tmp_path):
    base, _ = stub
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "known_urls.txt").write_text(base + "/orders\n")
    got = hv.authed_recon({"session": "bogus"}, base + "/", recon)
    assert got["links"] == []


def test_fuzz_object_ids_finds_echoed(stub, tmp_path):
    base, hits = stub
    live = tmp_path / "live"
    live.mkdir()
    denied = hv.fuzz_object_ids(
        {"s": "v"},
        "http://target.test/order/300123/receipt",
        "300123",
        live,
    )
    assert denied == []
    found = hv.fuzz_object_ids(
        {"session": "abc123"},
        base + "/order/300123/receipt",
        "300123",
        tmp_path,
        span=300,
    )
    assert found == ["300401"]
    n = len(hits)
    assert hv.fuzz_object_ids(
        {"session": "abc123"},
        base + "/order/300123/receipt",
        "300123",
        tmp_path,
        span=300,
    ) == ["300401"]
    assert len(hits) == n
