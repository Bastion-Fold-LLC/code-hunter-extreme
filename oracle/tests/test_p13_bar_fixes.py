#!/usr/bin/env python3
"""P13 bar-closure regressions: structural claims need structural predictions.

Root cause (mirror + repulsive misses): the templates make STRUCTURAL
claims (stale version alive and serving API data / alternate spelling
serves live data) but predicted CONTENT-LEAK markers ("id","data",...)
that Gate 5's non-generic-marker rule can never satisfy — and that real
stale-version endpoints (domain JSON, no leak markers) never serve.
Fix: predict the API-data signal (JSON content type) instead.

Each test below pins one fix on the real template->check->verify path:
a positive case (must CONFIRM) and a negative case (must REJECT, so the
fix cannot overcorrect into confirming HTML catch-alls).
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
import oracle_seam_templates as st  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)

BASE = "http://127.0.0.1:8765"
_TESTBED = ROOT / "tests" / "vuln_testbed_full.py"


def _wait_up(timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _seed(recon: Path, routes: list[tuple[str, str]]) -> None:
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "live_hosts.txt").write_text(BASE + "\n")
    (recon / "fuzzed_paths.txt").write_text(
        "\n".join(f"{BASE}{p} [{t}]" for p, t in routes) + "\n"
    )
    (recon / "js_endpoints.txt").write_text(
        "\n".join(f"{BASE}{p}" for p, _ in routes) + "\n"
    )
    (recon / "api_specs.txt").write_text("")
    (recon / "js_secrets.txt").write_text("")


def _cards_for(recon: Path, tid_sub: str) -> list[dict]:
    seams = st.scan_template_seams(
        recon_dir=recon,
        repo_path=None,
        program=None,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
    )
    return [s for s in seams if tid_sub in s.get("claim_type", "")]


def _live_verdict(card: dict) -> dict:
    """Run the card's real check against the wire and verify."""
    check = card["check"]
    _, out, err = oh._run_check(check)
    assert "[BLOCKED]" not in err, f"check blocked: {check}"
    status = extract_status_from_curl_output(out)
    url = check.split("'")[-2] if "'" in check else check
    return verify_seam_card(card, [url], status=status, body=out)


def test_mirror_confirms_stale_json_version_live():
    """FIX-1 positive: v1 still serving domain JSON must CONFIRM."""
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(_TESTBED)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_up(10), "testbed did not come up on :8765"
    try:
        tmp = Path(tempfile.mkdtemp(prefix="p13_mirror_"))
        _seed(
            tmp,
            [
                ("/api/v1/orders/ord_101", "200"),
                ("/api/v2/orders/ord_101", "200"),
            ],
        )
        cards = _cards_for(tmp, "mirror")
        assert cards, "mirror template emitted zero cards for a v1/v2 pair"
        verdicts = [_live_verdict(c) for c in cards]
        assert any(
            v["verdict"] == "CONFIRMED" for v in verdicts
        ), "mirror miss: stale JSON version rejected: " + "; ".join(
            v["reason"] for v in verdicts
        )
    finally:
        if started:
            started.terminate()


def test_mirror_rejects_html_error_page():
    """FIX-1 negative: a 200 HTML page must NOT confirm a stale-API claim."""
    tmp = Path(tempfile.mkdtemp(prefix="p13_mirror_neg_"))
    _seed(
        tmp,
        [
            ("/api/v1/orders/ord_101", "200"),
            ("/api/v2/orders/ord_101", "200"),
        ],
    )
    cards = _cards_for(tmp, "mirror")
    assert cards, "mirror template emitted zero cards for a v1/v2 pair"
    html_200 = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<html><body><div id='app'>data result error message items</div></body></html>"
    )
    status = extract_status_from_curl_output(html_200)
    for card in cards:
        url = card["check"].split("'")[-2]
        v = verify_seam_card(card, [url], status=status, body=html_200)
        assert (
            v["verdict"] == "REJECTED"
        ), f"mirror overcorrect: HTML page confirmed: {v['reason']}"


def test_repulsive_confirms_dual_spelling_serving_json():
    """FIX-2 positive: alternate spelling serving JSON must CONFIRM."""
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(_TESTBED)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_up(10), "testbed did not come up on :8765"
    try:
        tmp = Path(tempfile.mkdtemp(prefix="p13_repulsive_"))
        _seed(tmp, [("/api/orders", "200"), ("/api/orders/", "200")])
        cards = _cards_for(tmp, "repulsive")
        assert cards, "repulsive template emitted zero cards for dual spellings"
        verdicts = [_live_verdict(c) for c in cards]
        assert any(
            v["verdict"] == "CONFIRMED" for v in verdicts
        ), "repulsive miss: JSON-serving spelling rejected: " + "; ".join(
            v["reason"] for v in verdicts
        )
    finally:
        if started:
            started.terminate()


def test_repulsive_rejects_spa_shell():
    """FIX-2 negative: a 200 SPA shell must NOT confirm a spelling claim."""
    tmp = Path(tempfile.mkdtemp(prefix="p13_repulsive_neg_"))
    _seed(tmp, [("/api/orders", "200"), ("/api/orders/", "200")])
    cards = _cards_for(tmp, "repulsive")
    assert cards, "repulsive template emitted zero cards for dual spellings"
    spa_shell = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<html><body><div id='root'>data result items message status</div></body></html>"
    )
    status = extract_status_from_curl_output(spa_shell)
    for card in cards:
        url = card["check"].split("'")[-2]
        v = verify_seam_card(card, [url], status=status, body=spa_shell)
        assert (
            v["verdict"] == "REJECTED"
        ), f"repulsive overcorrect: SPA shell confirmed: {v['reason']}"


def test_sqli_probe_confirms_on_sql_500():
    """FIX-3 positive: quote breaking the query (500) must CONFIRM."""
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(_TESTBED)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_up(10), "testbed did not come up on :8765"
    try:
        tmp = Path(tempfile.mkdtemp(prefix="p13_sqli_"))
        _seed(tmp, [("/api/search", "200")])
        cards = _cards_for(tmp, "injection-sqli")
        assert cards, "sqli template emitted zero cards for /api/search"
        verdicts = [_live_verdict(c) for c in cards]
        assert any(
            v["verdict"] == "CONFIRMED" for v in verdicts
        ), "sqli miss: SQL 500 rejected: " + "; ".join(v["reason"] for v in verdicts)
    finally:
        if started:
            started.terminate()


def test_sqli_inband_card_rejects_clean_json():
    """FIX-3 negative: 200 JSON without SQL markers must NOT confirm SQLi."""
    tmp = Path(tempfile.mkdtemp(prefix="p13_sqli_neg_"))
    _seed(tmp, [("/api/search", "200")])
    cards = [c for c in _cards_for(tmp, "injection-sqli") if "any of" in c["expected"]]
    assert cards, "sqli template emitted zero in-band marker cards"
    clean_200 = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"results": [{"id": "p1", "name": "phone"}], "q": "phone"}'
    )
    status = extract_status_from_curl_output(clean_200)
    for card in cards:
        url = card["check"].split("'")[-2]
        v = verify_seam_card(card, [url], status=status, body=clean_200)
        assert (
            v["verdict"] == "REJECTED"
        ), f"sqli overcorrect: clean JSON confirmed: {v['reason']}"


def test_sqli_probes_spread_to_last_sorting_target():
    """FIX-3b: round-robin — the last-sorting URL keeps its primary probe.

    No network: 14 API targets over the 24-card group cap. Pre-fix the
    first 6 URLs ate the whole budget (4 cards each); the tail starved.
    """
    mat = {
        "js_endpoints": [f"{BASE}/api/res{i:02d}" for i in range(14)],
        "fuzzed": [],
        "live_hosts": [BASE],
    }
    cards = st._t_sqli(mat)
    assert len(cards) == 24, f"group cap must still bind at 24, got {len(cards)}"
    probed = {c["check"].split("?")[0] for c in cards}
    assert (
        f"curl -i -s '{BASE}/api/res13" in probed
    ), "last-sorting target starved: no probe for /api/res13"
    primaries = [c for c in cards if str(c["expected"]).startswith("status 500")]
    assert (
        len(primaries) == 14
    ), f"every target must keep its primary probe, got {len(primaries)}/14"


def test_xss_probes_spread_to_last_sorting_target():
    """FIX-3b (xss): the last-sorting page keeps its reflection probe."""
    mat = {
        "js_endpoints": [],
        "fuzzed": [f"{BASE}/page{i:02d} [200]" for i in range(9)],
        "live_hosts": [BASE],
    }
    cards = st._t_xss_reflect(mat)
    probed = {c["check"].split("?")[0] for c in cards}
    assert (
        f"curl -i -s '{BASE}/page08" in probed
    ), "last-sorting page starved: no probe for /page08"


def test_xss_probe_confirms_on_reflection():
    """FIX-4 positive: unescaped reflection of the marker must CONFIRM."""
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(_TESTBED)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_up(10), "testbed did not come up on :8765"
    try:
        tmp = Path(tempfile.mkdtemp(prefix="p13_xss_"))
        _seed(tmp, [("/greet", "200")])
        cards = [
            c for c in _cards_for(tmp, "injection-xss") if "-X POST" not in c["check"]
        ]
        assert cards, "xss template emitted zero GET probes for /greet"
        verdicts = [_live_verdict(c) for c in cards]
        assert any(
            v["verdict"] == "CONFIRMED" for v in verdicts
        ), "xss miss: reflection rejected: " + "; ".join(v["reason"] for v in verdicts)
    finally:
        if started:
            started.terminate()


def test_xss_probe_rejects_non_reflecting_page():
    """FIX-4 negative: a page ignoring the probe must NOT confirm XSS."""
    tmp = Path(tempfile.mkdtemp(prefix="p13_xss_neg_"))
    _seed(tmp, [("/health", "200")])
    cards = [c for c in _cards_for(tmp, "injection-xss") if "-X POST" not in c["check"]]
    assert cards, "xss template emitted zero GET probes for /health"
    clean_200 = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"status": "ok", "app": "vuln_testbed"}'
    )
    status = extract_status_from_curl_output(clean_200)
    for card in cards:
        url = card["check"].split("'")[-2]
        v = verify_seam_card(card, [url], status=status, body=clean_200)
        assert (
            v["verdict"] == "REJECTED"
        ), f"xss overcorrect: clean page confirmed: {v['reason']}"


def test_idor_confirms_on_other_object_without_session():
    """FIX-5 positive: object 8 serving user data with no session CONFIRMs."""
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(_TESTBED)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_up(10), "testbed did not come up on :8765"
    try:
        tmp = Path(tempfile.mkdtemp(prefix="p13_idor_"))
        _seed(tmp, [("/api/profile/7", "200"), ("/api/profile/8", "200")])
        cards = _cards_for(tmp, "idor-direct-object")
        assert cards, "idor template emitted zero cards for an object-id pair"
        verdicts = [_live_verdict(c) for c in cards]
        assert any(
            v["verdict"] == "CONFIRMED" for v in verdicts
        ), "idor miss: object access rejected: " + "; ".join(
            v["reason"] for v in verdicts
        )
    finally:
        if started:
            started.terminate()


def test_idor_silent_on_lone_self_reference():
    """FIX-5 negative: a single object id never fires (benign control)."""
    tmp = Path(tempfile.mkdtemp(prefix="p13_idor_neg_"))
    _seed(tmp, [("/api/users/123", "200")])
    cards = _cards_for(tmp, "idor-direct-object")
    assert not cards, "idor overcorrect: lone self-reference fired: " + "; ".join(
        c["check"] for c in cards
    )
