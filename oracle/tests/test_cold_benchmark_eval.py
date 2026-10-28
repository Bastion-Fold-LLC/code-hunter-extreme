#!/usr/bin/env python3
"""Cold, unseeded evaluation against real benchmark repositories and live services.

Unlike tests/test_p14_bench_recall.py (which seeds recon from
benchmarks/bench_recall.json), this suite:
1. Tests repo scanning on real multi-thousand-file benchmark repositories
   (/home/phantomcore/oracle-benchmarks/{juice-shop,pygoat,dvwa}) with zero
   vendored noise from node_modules/ or vendor/ and strict sub-5s runtime.
2. Verifies that _t_sqli 500-status cards reject generic framework HTML 500
   pages (Express / Django / Apache error shells) and only confirm when
   database/driver error evidence is present.
3. Runs cold, unseeded template verification against the unseeded recon
   directory (targets/direct/http___127.0.0.1_3000/recon) when juice-shop is up,
   proving real vulnerabilities confirm without bench_recall.json hints and
   generic 500 routes (/api/Hints, /rest/admin, /rest/chat, /redirect) reject.
"""
from __future__ import annotations

import re
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_code_seam as cs  # noqa: E402
import oracle_hunter as oh  # noqa: E402
import oracle_seam_templates as st  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)

BENCH_REPOS = Path("/home/phantomcore/oracle-benchmarks")


def _up(base: str) -> bool:
    try:
        urllib.request.urlopen(base + "/", timeout=3)
        return True
    except Exception:
        return False


def test_sqli_500_rejects_generic_express_html_error():
    """Generic HTTP 500 HTML error pages must NEVER confirm as SQL injection."""
    base = "http://127.0.0.1:3000"
    mat = {
        "live_hosts": [base],
        "js_endpoints": ["/api/Hints", "/redirect"],
        "fuzzed": [],
        "crawled": [],
    }
    cards = st._t_sqli(mat)
    cards_500 = [c for c in cards if "status 500" in c.get("expected", "")]
    assert cards_500, "Expected _t_sqli to emit status-500 probe cards"

    generic_express_500 = (
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<!DOCTYPE html><html><head><title>Error</title></head>"
        "<body><pre>Error: Unrecognized target URL for redirect</pre></body></html>"
    )
    for card in cards_500:
        card_full = {
            **card,
            "n": 1,
            "assertion_a_source": card.get("source_a", "js_endpoints.txt"),
        }
        url = st._check_url(card["check"]) or base
        res = verify_seam_card(
            card_full,
            [url],
            status=500,
            body=generic_express_500,
        )
        assert res["verdict"] == "REJECTED", (
            f"Generic Express 500 HTML page falsely confirmed on {card['check']}: {res}"
        )


def test_sqli_500_confirms_real_database_error():
    """HTTP 500 with a genuine SQLite/SQL driver error must still confirm."""
    base = "http://127.0.0.1:3000"
    mat = {
        "live_hosts": [base],
        "js_endpoints": ["/rest/products/search"],
        "fuzzed": [],
        "crawled": [],
    }
    cards = st._t_sqli(mat)
    card_500 = next(c for c in cards if "status 500" in c.get("expected", ""))
    card_full = {
        **card_500,
        "n": 1,
        "assertion_a_source": card_500.get("source_a", "js_endpoints.txt"),
    }
    url = st._check_url(card_500["check"]) or base
    real_sql_500 = (
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"error":{"message":"SQLITE_ERROR: incomplete input"}}'
    )
    res = verify_seam_card(card_full, [url], status=500, body=real_sql_500)
    assert res["verdict"] == "CONFIRMED", f"Real SQLite 500 error rejected: {res}"


def test_benchmark_repo_traversal_skips_vendored_dirs_and_runs_fast():
    """Scanning juice-shop / pygoat / dvwa repos must skip node_modules/vendor and finish fast."""
    juice_repo = BENCH_REPOS / "juice-shop"
    if not juice_repo.is_dir():
        pytest.skip("juice-shop benchmark repo not present on disk")

    t0 = time.monotonic()
    files = st._iter_files(juice_repo, st._CODE_EXTS)
    elapsed_iter = time.monotonic() - t0
    assert elapsed_iter < 5.0, f"_iter_files walked vendored dirs ({elapsed_iter:.2f}s)"
    assert not any("node_modules" in p.parts for p in files), (
        "_iter_files included node_modules files"
    )

    t1 = time.monotonic()
    seams = cs.scan_repository_seams(juice_repo)
    elapsed_seam = time.monotonic() - t1
    assert elapsed_seam < 5.0, (
        f"scan_repository_seams walked node_modules ({elapsed_seam:.2f}s)"
    )
    assert not any("node_modules" in s.get("source_a", "") for s in seams)


def test_cold_source_code_bug_discovery_across_all_three_benchmarks():
    """Cold source-code scan must find real vulnerabilities in juice-shop, pygoat, and dvwa."""
    if not BENCH_REPOS.is_dir():
        pytest.skip("benchmark repos directory not present")
    gate = oh.ProgramScopeGate({}, target_fallback="http://127.0.0.1")

    juice_cards = st.scan_template_seams(
        repo_path=BENCH_REPOS / "juice-shop", scope_gate=gate
    )
    assert any("login.ts:34" in c["assertion_b"] for c in juice_cards), juice_cards
    assert any("search.ts:23" in c["assertion_b"] for c in juice_cards), juice_cards
    assert any("b2bOrder.ts:23" in c["assertion_b"] for c in juice_cards), juice_cards

    pygoat_cards = st.scan_template_seams(
        repo_path=BENCH_REPOS / "pygoat", scope_gate=gate
    )
    assert any("views.py:158" in c["assertion_b"] for c in pygoat_cards), pygoat_cards
    assert any("views.py:214" in c["assertion_b"] for c in pygoat_cards), pygoat_cards
    assert any("views.py:259" in c["assertion_b"] for c in pygoat_cards), pygoat_cards

    dvwa_cards = st.scan_template_seams(
        repo_path=BENCH_REPOS / "dvwa", scope_gate=gate
    )
    assert any(
        c["claim_type"] == "code-sqli-raw-interpolation" and "low.php:10" in c["assertion_b"]
        for c in dvwa_cards
    ), dvwa_cards
    assert any(
        c["claim_type"] == "code-cmdi-shell-exec" and "low.php:10" in c["assertion_b"]
        for c in dvwa_cards
    ), dvwa_cards


def test_cmd_audit_finds_bugs_on_benchmark_repo(monkeypatch):
    """cmd_audit on juice-shop must emit a report with the real source-code seams."""
    import types

    juice_repo = BENCH_REPOS / "juice-shop"
    if not juice_repo.is_dir():
        pytest.skip("juice-shop benchmark repo not present")
    monkeypatch.setattr(oh, "_correlate_seams", lambda *a, **k: None)
    args = types.SimpleNamespace(cloud=False)
    oh.cmd_audit(str(juice_repo), args)
    report_file = oh.REPORTS_DIR / "audit_juice-shop.md"
    assert report_file.is_file()
    txt = report_file.read_text(encoding="utf-8")
    assert "login.ts:34" in txt
    assert "search.ts:23" in txt
    assert "b2bOrder.ts:23" in txt


def test_cold_unseeded_juice_shop_live_verification():
    """Cold unseeded verification against live Juice Shop (zero bench_recall.json seeds)."""
    base = "http://127.0.0.1:3000"
    recon = ROOT / "targets" / "direct" / "http___127.0.0.1_3000" / "recon"
    if not _up(base) or not recon.is_dir():
        pytest.skip("live juice-shop container or unseeded recon dir unavailable")

    gate = oh.ProgramScopeGate({}, target_fallback=base)
    seams = st.scan_template_seams(recon_dir=recon, scope_gate=gate)
    assert len(seams) >= 100, f"Expected >=100 cold candidate cards, got {len(seams)}"

    confirmed_urls = []
    for s in seams:
        if s.get("claim_type") not in (
            "injection-sqli-probe",
            "listed-file-exposure",
            "self-observing-equation",
        ):
            continue
        _, out, err = oh._run_check(s["check"], is_testnet=True)
        if "[BLOCKED]" in err:
            continue
        status = extract_status_from_curl_output(out)
        m = re.search(r"https?://[^\s'\"]+", s["check"])
        url = m.group(0) if m else ""
        v = verify_seam_card(s, [url], status=status, body=out)
        if v["verdict"] == "CONFIRMED":
            confirmed_urls.append((s.get("claim_type"), url))

    # True positives discovered cold without bench_recall.json seeds:
    assert any(
        tid == "injection-sqli-probe" and "/rest/user/login" in u
        for tid, u in confirmed_urls
    ), f"Cold run missed /rest/user/login SQLi bypass: {confirmed_urls}"
    assert any(
        tid == "listed-file-exposure" and "/ftp/legal.md" in u
        for tid, u in confirmed_urls
    ), f"Cold run missed /ftp/legal.md exposure: {confirmed_urls}"
    assert any(
        tid == "self-observing-equation" and "/metrics" in u
        for tid, u in confirmed_urls
    ), f"Cold run missed /metrics exposure: {confirmed_urls}"

    # Generic 500 false positives must be 0:
    for false_pos_path in ("/api/Hints", "/rest/admin", "/rest/chat", "/redirect"):
        assert not any(
            tid == "injection-sqli-probe" and false_pos_path in u
            for tid, u in confirmed_urls
        ), f"Cold run falsely confirmed generic 500 on {false_pos_path}: {confirmed_urls}"
