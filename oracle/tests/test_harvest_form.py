#!/usr/bin/env python3
"""P14: form-gated probe replay (DVWA sqli Submit gate).

Root cause: DVWA sqli low requires $_REQUEST['Submit'] — the bare ?id=
probe never reaches the query (and the mapping's first green was a
footer-'mysql' false positive, now hardened to the true error text).

Fix (wire-guided, zero bench literals): harvest_text() extracts general
forms (action/method/named inputs) and harvest_reframes() replays the
parent probe's payload through the page's own form, gate fields
included (?id=<payload>&Submit=Submit). GET forms only in v1.
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

import oracle_harvest as hv  # noqa: E402
import oracle_hunter as oh  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)
from oracle_foundation import build_seam_card  # noqa: E402

FORM_HTML = (
    '<form action="#" method="GET">'
    'First name:<input type="text" name="id">'
    '<input type="submit" name="Submit" value="Submit">'
    "</form>"
)


def _parent(check: str, n: int = 1):
    return build_seam_card(
        n=n,
        assertion_a="endpoint handles its inputs: http://t/q",
        assertion_a_source="crawl.txt",
        assertion_b="SQLi probe leaks a database error in a 200 page",
        check=check,
        expected='status 200, body contains any of "SQL syntax","mysql"',
        impact="sqli",
        origin="seam-template",
        mindset="seam",
    )


def test_fill_forms_extracts_action_fields():
    out = hv.harvest_text(f"<html>{FORM_HTML}</html>", source_url="http://t/q")
    assert len(out["fill_forms"]) == 1
    hint = out["fill_forms"][0]
    assert hint["action"] == "http://t/q", hint
    assert hint["method"] == "GET"
    assert ("id", "text", "") in hint["fields"]
    assert ("Submit", "submit", "Submit") in hint["fields"]


def test_replay_carries_payload_through_form():
    hint = {
        "action": "http://t/q",
        "method": "GET",
        "fields": [("id", "text", ""), ("Submit", "submit", "Submit")],
    }
    built = hv._form_replay_url("curl -i -s 'http://t/q?id=%27'", hint)
    assert built == ("http://t/q?id=%27&Submit=Submit", "id")


def test_replay_fails_closed():
    hint = {
        "action": "http://t/q",
        "method": "GET",
        "fields": [("id", "text", ""), ("Submit", "submit", "Submit")],
    }
    # multi-param parent: nothing to join
    assert hv._form_replay_url("curl -i -s 'http://t/q?id=1&x=2'", hint) is None
    # param-less parent: no payload to carry
    assert hv._form_replay_url("curl -i -s 'http://t/q'", hint) is None
    # POST parent / POST form: v1 is GET-only
    assert (
        hv._form_replay_url("curl -i -s -X POST -d 'a=b' 'http://t/q?id=%27'", hint)
        is None
    )
    post = dict(hint, method="POST")
    assert hv._form_replay_url("curl -i -s 'http://t/q?id=%27'", post) is None
    # off-host action
    evil = dict(hint, action="http://evil.example/q")
    assert hv._form_replay_url("curl -i -s 'http://t/q?id=%27'", evil) is None
    # unsafe payload chars (metachars never ride unencoded)
    bad = hv._form_replay_url("curl -i -s 'http://t/q?id=a%27b;c'", hint)
    assert bad is None
    # ... while encoded payloads are fine
    ok = hv._form_replay_url("curl -i -s 'http://t/q?id=a%27b%22c'", hint)
    assert ok == ("http://t/q?id=a%27b%22c&Submit=Submit", "id")
    # single-field form replays to itself: skip
    lone = {
        "action": "http://t/q",
        "method": "GET",
        "fields": [("q", "text", "")],
    }
    assert hv._form_replay_url("curl -i -s 'http://t/q?q=%27'", lone) is None


def test_replay_renames_param_when_form_names_another():
    """Single-field replay that renames the param is discovery, not dup.

    Parent guessed ?q=; the page's only input is ?name= (nameless submit —
    browsers send the input alone). The replay carries the payload to the
    page-named input instead of echoing the parent's wrong guess.
    """
    hint = {
        "action": "http://t/q",
        "method": "GET",
        "fields": [("name", "text", "")],
    }
    built = hv._form_replay_url("curl -i -s 'http://t/q?q=%27'", hint)
    assert built == ("http://t/q?name=%27", "name")


def _form_corpus():
    corpus = hv._blank()
    corpus["fill_forms"] = [
        {
            "action": "http://t/q",
            "method": "GET",
            "fields": [("id", "text", ""), ("Submit", "submit", "Submit")],
        }
    ]
    return corpus


def test_reframe_emits_harvest_form_card():
    parent = _parent("curl -i -s 'http://t/q?id=%27'")
    cards = hv.harvest_reframes(parent, _form_corpus(), {}, 100)
    forms = [c for c in cards if c.get("reframe_transform") == "harvest-form"]
    assert len(forms) == 1
    assert "'http://t/q?id=%27&Submit=Submit'" in forms[0]["check"]
    assert "Submit" in forms[0]["assertion_b"]


def test_sqli_parent_gets_inherit_plus_bare_quote_variants():
    """Tautology replays inherit; a bare quote probes the error shape."""
    parent = _parent("curl -i -s 'http://t/q?id=%27%20OR%201%3D1'")
    parent["claim_type"] = "injection-sqli-probe"
    parent["expected"] = "status 500"
    cards = hv.harvest_reframes(parent, _form_corpus(), {}, 100)
    forms = [c for c in cards if c.get("reframe_transform") == "harvest-form"]
    assert len(forms) == 2, [c["expected"][:60] for c in cards]
    assert "'http://t/q?id=%27%20OR%201%3D1&Submit=Submit'" in forms[0]["check"]
    assert forms[0]["expected"] == "status 500"
    assert "'http://t/q?id=%27&Submit=Submit'" in forms[1]["check"]
    assert 'body contains any of "SQLITE_ERROR"' in forms[1]["expected"]


def test_errorprobe_expects_strict_markers_only():
    """Bare "mysql" matches every-page footers — the errorprobe must not.

    E2E seam 571: a TRUE "error in your SQL syntax" was demoted because the
    errorprobe inherited the broad list — the 9-fill control (footer-only,
    no error) still matched bare "mysql" and "confirmed". Strict subset:
    true error text confirms, footer boilerplate rejects (same verdict
    function the hunt uses).
    """
    parent = _parent("curl -i -s 'http://t/q?id=%27%20OR%201%3D1'")
    parent["claim_type"] = "injection-sqli-probe"
    parent["expected"] = "status 500"
    cards = hv.harvest_reframes(parent, _form_corpus(), {}, 100)
    forms = [c for c in cards if c.get("reframe_transform") == "harvest-form"]
    probe = forms[1]
    assert '"mysql"' not in probe["expected"], probe["expected"]
    assert '"mysqli"' in probe["expected"] and '"mysql_fetch"' in probe["expected"]
    error_body = (
        "Uncaught mysqli_sql_exception: You have an error in your SQL "
        "syntax; check the manual near ''''' at line 1"
    )
    verdict = verify_seam_card(
        {**probe, "n": 571}, ["http://t"], status=200, body=error_body
    )
    assert verdict["verdict"] == "CONFIRMED", verdict
    footer_body = "<html><form></form><footer>SQLi DB: mysql</footer></html>"
    verdict = verify_seam_card(
        {**probe, "n": 571}, ["http://t"], status=200, body=footer_body
    )
    assert verdict["verdict"] == "REJECTED", verdict


class _FormGateStub(http.server.BaseHTTPRequestHandler):
    """Submit-gated SQLi (DVWA shape, generic literals)."""

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query)
        idval = q.get("id", [""])[0]
        if "Submit" in q and ("'" in idval or '"' in idval):
            self._send(b"<html>You have an error in your SQL syntax;</html>")
        elif "Submit" in q:
            self._send(b"<html>ID: 1<br>First name: admin</html>")
        else:
            self._send(b"<html>" + FORM_HTML.encode() + b"<p>rowdb v1</p></html>")

    def log_message(self, *a):  # noqa: ANN001, ANN202
        pass


class _Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def test_op1_allows_ampersand_inside_quoted_url():
    """Multi-param replay checks must pass Op1 (token-position-aware).

    Prerequisite: Op1 parity with the committed Phase-3 runner gate —
    & inside a quoted URL token is query data (shell=False), while a
    bare & in structural position still fails closed.
    """
    from oracle_foundation import validate_card_shape

    ok = _parent("curl -i -s 'http://t/q?id=%27&Submit=Submit'")
    assert validate_card_shape(ok) is None
    bad = dict(ok)
    bad["check"] = "curl -i -s 'http://t/q?id=1' & curl -i -s 'http://t/x'"
    assert "metachar" in (validate_card_shape(bad) or "")


def test_stub_chain_form_replay_confirms_true_error():
    srv = _Threaded(("127.0.0.1", 0), _FormGateStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        parent = _parent(f"curl -i -s '{base}/q?id=%22%20OR%201%3D1'")
        _, out, err = oh._run_check(parent["check"], is_testnet=True)
        assert "[BLOCKED]" not in err
        status = extract_status_from_curl_output(out)
        v = verify_seam_card(parent, [base + "/q"], status=status, body=out)
        assert v["verdict"] == "REJECTED", f"bare probe: {v['reason']}"
        corpus = hv.merge_harvest(hv.harvest_text(out, source_url=base + "/q"))
        assert corpus["fill_forms"], "form not harvested from parent output"
        parent["claim_type"] = "injection-sqli-probe"
        cards = hv.harvest_reframes(parent, corpus, {}, 100)
        forms = [c for c in cards if c.get("reframe_transform") == "harvest-form"]
        assert forms, "no harvest-form replay emitted"
        assert all("&Submit=Submit" in f["check"] for f in forms)
        confirmed_true = False
        for f in forms:
            _, out2, err2 = oh._run_check(f["check"], is_testnet=True)
            assert "[BLOCKED]" not in err2
            status2 = extract_status_from_curl_output(out2)
            m = re.search(r"https?://[^\s'\"]+", f["check"])
            assert m
            v2 = verify_seam_card(f, [m.group(0)], status=status2, body=out2)
            if v2["verdict"] == "CONFIRMED" and "error in your SQL syntax" in out2:
                confirmed_true = True
        assert confirmed_true, "no replay confirmed with the TRUE error"
    finally:
        srv.shutdown()
        srv.server_close()
