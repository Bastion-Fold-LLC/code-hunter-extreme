#!/usr/bin/env python3
"""R1 injection templates: SQLi/XSS probes fire with gate-passable checks.

Proves the recall fix structurally (no network):
  - _t_sqli / _t_xss_reflect emit cards from API routes + live pages
  - every emitted check shlex-parses and uses only allow-listed curl flags
    (the real allow-lists imported from oracle_hunter, not copies)
  - POST JSON bodies decode to valid JSON carrying the payload
  - tags are CWE-89/CWE-79 + T1190 (no T1078 mistag at the source)

Testnet model: mutating checks (-d bodies, -X POST) pass the _run_check
gate only with is_testnet=True; GET probes pass in both modes. Bench SOP
runs hunts with --testnet, so both halves are exercised live.
"""
from __future__ import annotations

import json
import shlex
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_seam_templates as st
from oracle_deterministic import parse_expected
from oracle_hunter import (
    _ALLOWED_CHECK_BINS,
    _MUTATING_CURL_VALUE_FLAGS,
    _MUTATING_HTTP_METHODS,
    _SAFE_CURL_FLAGS,
    _SAFE_CURL_VALUE_FLAGS,
)

BASE = "http://127.0.0.1:9999"


def _seed(recon: Path) -> None:
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "live_hosts.txt").write_text(BASE + "\n")
    # NB1 seed: 10 API routes (incl. 2 login routes feeding POST cards) —
    # deliberately past every group cap, so GET-first emission would let
    # the truncation drop 100% of POST cards at production scale.
    (recon / "js_endpoints.txt").write_text(
        "\n".join(
            [
                "/api/Products",
                "/rest/user/login",
                "/rest/products/search",
                "/api/auth/login",
                "/api/Users",
                "/api/Orders",
                "/rest/basket",
                "/api/Comments",
                "/graphql",
                "/rest/user/whoami",
            ]
        )
        + "\n"
    )
    # 10 live pages: the 3 originals (incl. the ?-query strip proof) plus
    # 7 /w* pages that sort AFTER /vulnerabilities/, so the seeded
    # ?-query URL keeps its cards under the page caps.
    (recon / "fuzzed_paths.txt").write_text(
        "\n".join(
            [
                f"{BASE}/vulnerabilities/sqli/ [200]",
                f"{BASE}/.env [200]",
                f"{BASE}/vulnerabilities/xss/?q=hi [200]",
            ]
            + [f"{BASE}/wpage{i:02d} [200]" for i in range(7)]
        )
        + "\n"
    )
    # P14: 45 crawled pages — deliberately past the crawled group cap (40),
    # so the crawled group contributes exactly its cap to the pinned totals.
    # Clean depth-2 dirs (no api/login/query words: no group interference).
    (recon / "crawl.txt").write_text(
        "\n".join(f"{BASE}/cdir/page{i:02d}" for i in range(45)) + "\n"
    )


def _gate_passable(check: str, is_testnet: bool = False) -> list[str]:
    """Mirror of _run_check's curl validation, minus execution.

    Models the is_testnet gate: mutating flags (-d/--data/...) and
    mutating -X methods (POST/...) fail closed on live targets and pass
    on testnet. Safe GET probes pass in both modes.
    """
    errs: list[str] = []
    try:
        argv = shlex.split(check)
    except ValueError as e:
        return [f"shlex parse failed: {e}"]
    if not argv or argv[0] != "curl":
        return [f"not a curl command: {check!r:.80}"]
    import os

    if os.path.basename(argv[0]) not in _ALLOWED_CHECK_BINS:
        errs.append("binary not allow-listed")
    i = 1
    while i < len(argv):
        arg = argv[i]
        if (
            arg in _SAFE_CURL_FLAGS
            or arg.startswith("http://")
            or arg.startswith("https://")
        ):
            i += 1
            continue
        if arg in _SAFE_CURL_VALUE_FLAGS and i + 1 < len(argv):
            if arg in ("-X", "--request"):
                allowed = {"GET", "HEAD", "OPTIONS"}
                if is_testnet:
                    allowed |= _MUTATING_HTTP_METHODS
                if argv[i + 1].upper() not in allowed:
                    errs.append(f"unsafe HTTP method: {argv[i + 1]!r:.60}")
            i += 2
            continue
        if arg in _MUTATING_CURL_VALUE_FLAGS and i + 1 < len(argv):
            if not is_testnet:
                errs.append(f"mutating flag needs --testnet: {arg}")
            i += 2
            continue
        errs.append(f"unsafe curl argument: {arg!r:.60}")
        i += 1
    return errs


def main() -> int:
    fails: list[str] = []
    with tempfile.TemporaryDirectory(prefix="inject_tpl_") as tmp:
        recon = Path(tmp)
        _seed(recon)
        from oracle_hunter import ProgramScopeGate

        cards = st.scan_template_seams(
            recon_dir=recon,
            repo_path=None,
            program=None,
            scope_gate=ProgramScopeGate({}, target_fallback=BASE),
        )
    sqli = [c for c in cards if c["claim_type"] == "injection-sqli-probe"]
    xss = [c for c in cards if c["claim_type"] == "injection-xss-probe"]

    if not sqli:
        fails.append("injection-sqli-probe fired zero cards")
    if not xss:
        fails.append("injection-xss-probe fired zero cards")

    # P14 split-caps: every group is overfed, so totals pin at the GROUP
    # SUMS — sqli 4 POST + 24 api + 16 page + 40 crawled = 84, xss 8 + 14 +
    # 14 + 40 = 76. (NB1's truncation-pressure framing died with split-caps:
    # POSTs emit first under their own sub-cap, so truncation can no longer
    # drop them; the surviving contract is capped groups + POST survival +
    # POST-first ordering, all asserted below.)
    if len(sqli) != 84:
        fails.append(f"expected sqli group-sum pin 84, got {len(sqli)}")
    if len(xss) != 76:
        fails.append(f"expected xss group-sum pin 76, got {len(xss)}")
    # The overfed crawled group contributes exactly its cap (40 cards with
    # crawl.txt provenance) — the ordering fix below decides WHICH 40.
    n_sqli_crawl = sum(1 for c in sqli if c.get("source_a") == "crawl.txt")
    if n_sqli_crawl != 40:
        fails.append(f"sqli crawled group not capped at 40: got {n_sqli_crawl}")
    n_xss_crawl = sum(1 for c in xss if c.get("source_a") == "crawl.txt")
    if n_xss_crawl != 40:
        fails.append(f"xss crawled group not capped at 40: got {n_xss_crawl}")

    for c in sqli:
        if c["mitre"] != "CWE-89 / T1190":
            fails.append(f"sqli card {c['id']} mistagged: {c['mitre']}")
    for c in xss:
        if c["mitre"] != "CWE-79 / T1190":
            fails.append(f"xss card {c['id']} mistagged: {c['mitre']}")

    for c in sqli + xss:
        exp = parse_expected(str(c.get("expected", "")))
        if exp["status"] is None:
            fails.append(
                f"card {c['id']} expected has no status: {c['expected']!r:.60}"
            )
        is_post = "-X POST" in c["check"] or " -d " in c["check"]
        if is_post:
            # Mutating checks fail closed on live targets, pass on testnet.
            if not _gate_passable(c["check"], is_testnet=False):
                fails.append(f"card {c['id']} POST passed without --testnet")
            for e in _gate_passable(c["check"], is_testnet=True):
                fails.append(f"card {c['id']} testnet gate: {e}")
        else:
            # GET probes pass in both modes.
            for e in _gate_passable(c["check"], is_testnet=False):
                fails.append(f"card {c['id']} gate: {e}")
            for e in _gate_passable(c["check"], is_testnet=True):
                fails.append(f"card {c['id']} testnet gate: {e}")

    # Op1 (validate_card_shape) rejects & anywhere in the check: query
    # strings are stripped, never &-appended — including seeded ?-query URLs.
    for c in sqli + xss:
        if "&" in c["check"]:
            fails.append(f"card {c['id']} check contains &: {c['check']!r:.80}")

    # Query-strip proof: the seeded ?-query URL must fire with its original
    # query replaced by the probe param (never &-appended).
    seeded = [c for c in sqli + xss if "/vulnerabilities/xss/?" in c["check"]]
    if not seeded:
        fails.append("seeded ?-query URL produced no cards")
    for c in seeded:
        if "q=hi" in c["check"]:
            fails.append(f"card {c['id']} kept the original query string")

    # Dedup-proof payloads: the in-band 200+marker card must survive the
    # (tid, check) dedup — it exists only if its check differs from the
    # 500 card's (distinct single- vs double-quote payloads).
    markers = [c for c in sqli if "status 200" in str(c.get("expected", ""))]
    if not markers:
        fails.append("no in-band 200+marker SQLi card survived (dedup drop?)")

    # NB1: login/persist POSTs must survive the over-cap truncation
    # (POST-first emission) — GET-first would drop 100% of them here.
    # At least one login-bypass POST whose -d value is valid JSON with SQLi
    logins = [c for c in sqli if "-X POST" in c["check"] and "login" in c["check"]]
    if not logins:
        fails.append("no login-bypass POST card survived (want /rest/user/login)")
    for c in logins:
        argv = shlex.split(c["check"])
        body = argv[argv.index("-d") + 1]
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            fails.append(f"login card {c['id']} -d not valid JSON: {e}")
            continue
        blob = json.dumps(data)
        if "OR 1=1" not in blob:
            fails.append(f"login card {c['id']} JSON lost the SQLi payload")

    # At least one persist POST whose -d value is valid JSON with the marker
    persists = [c for c in xss if "-X POST" in c["check"]]
    if not persists:
        fails.append("no stored-XSS POST card for /api routes")
    for c in persists:
        argv = shlex.split(c["check"])
        body = argv[argv.index("-d") + 1]
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            fails.append(f"persist card {c['id']} -d not valid JSON: {e}")
            continue
        if st._XSS_MARKER not in json.dumps(data):
            fails.append(f"persist card {c['id']} JSON lost the XSS marker")

    # GET probes must carry encoded payloads (no raw quote to break shlex)
    for c in sqli + xss:
        if "-X POST" in c["check"]:
            continue
        url = st._check_url(c["check"]) or ""
        if "'" in url or '"' in url or " " in url:
            fails.append(f"card {c['id']} GET URL has raw quotable: {url!r:.80}")

    # NB3: hard caps — a pages-only mat (no API, no login, no POST cards)
    # must yield EXACTLY the page cap. A soft per-URL check overshoots:
    # xss pages emit 3 cards/URL, so per-URL capping yields 15, not 14.
    unit_mat = {
        "js_endpoints": [],
        "fuzzed": [f"{BASE}/unit/page{i:02d} [200]" for i in range(10)],
        "live_hosts": [BASE],
    }
    unit_xss = st._t_xss_reflect(unit_mat)
    if len(unit_xss) != 14:
        fails.append(f"xss pages-only mat not hard-capped at 14: got {len(unit_xss)}")
    unit_sqli = st._t_sqli(unit_mat)
    if len(unit_sqli) != 16:
        fails.append(f"sqli pages-only mat not hard-capped at 16: got {len(unit_sqli)}")

    # NB-R2-1: 40-API-route scale — POST sub-caps (<=8) must leave room
    # for GET probes under the global truncation. Pre-fix this yields
    # 40 POST + 0 GET (sqli) and 32 POST + 0 GET (xss): the mirror of NB1.
    scale_mat = {
        "js_endpoints": [f"/api/auth/login{i}" for i in range(20)]
        + [f"/api/Resource{i}" for i in range(20)],
        "fuzzed": [f"{BASE}/wpage{i:02d} [200]" for i in range(10)],
        "live_hosts": [BASE],
    }
    scale_sqli = st._t_sqli(scale_mat)
    scale_xss = st._t_xss_reflect(scale_mat)
    # P14: no crawled key in scale_mat — pins are the non-crawled group
    # sums (sqli 8 POST + 24 api + 16 page = 48, xss 8 + 14 + 14 = 36).
    if len(scale_sqli) != 48:
        fails.append(
            f"sqli scale mat not pinned at group sum 48: got {len(scale_sqli)}"
        )
    if len(scale_xss) != 36:
        fails.append(f"xss scale mat not pinned at group sum 36: got {len(scale_xss)}")
    for name, cards in (("sqli", scale_sqli), ("xss", scale_xss)):
        n_post = sum(1 for c in cards if "-X POST" in c["check"])
        n_get = len(cards) - n_post
        if n_post == 0:
            fails.append(f"{name} scale: zero POST cards survived")
        if n_get == 0:
            fails.append(
                f"{name} scale: zero GET cards survived (POSTs ate the budget)"
            )
        if n_post > 8:
            fails.append(f"{name} scale: POST sub-cap breached: {n_post} > 8")
        if cards and "-X POST" not in cards[0]["check"]:
            fails.append(f"{name} scale: POST-first ordering lost")

    # P14: crawl value-ordering — real dirs beat junk under the cap.
    # Regression: deepest-first ranked 4-7-deep katana misresolutions above
    # the real depth-2 app routes (DVWA E2E: 32/32 crawled sqli cards on
    # junk, zero on /vulnerabilities/*). Shallow-first + misresolutions-last
    # + injection-dead skips fix the starvation at the source.
    junk_mat = {
        "live_hosts": [BASE],
        "js_endpoints": [],
        "fuzzed": [],
        "crawled": (
            [f"{BASE}/vuln/vuln/mod{i}/source/low.php" for i in range(30)]
            + [f"{BASE}/var/www/html/page{i}.php" for i in range(10)]
            + [
                f"{BASE}/robots.txt",
                f"{BASE}/README.md",
                f"{BASE}/.git/HEAD",
                f"{BASE}/app/logout.php",
            ]
            + [f"{BASE}/app/dir{i:02d}/" for i in range(20)]
        ),
    }
    tgts = st._injection_targets(junk_mat)
    urls = [u for u, _, _ in tgts]
    for dead in ("robots.txt", "README.md", ".git/HEAD", "logout.php"):
        if any(dead in u for u in urls):
            fails.append(f"ordering: injection-dead survived: {dead}")
    ranks = {u: i for i, u in enumerate(urls)}
    for i in range(20):
        rank = ranks.get(f"{BASE}/app/dir{i:02d}/", 999)
        if rank >= 40:
            fails.append(f"ordering: real dir{i:02d} rank {rank} misses cap 40")
    worst_real = max(ranks.get(f"{BASE}/app/dir{i:02d}/", 999) for i in range(20))
    for u in urls:
        if "/vuln/vuln/" in u and ranks[u] < worst_real:
            fails.append(f"ordering: misresolution {u} outranks real dirs")
            break
    for u in urls:
        if "/var/www/html/" in u and ranks[u] < worst_real:
            fails.append(f"ordering: deep junk {u} outranks real dirs")
            break

    print(f"injection templates: {len(sqli)} sqli + {len(xss)} xss cards")
    if fails:
        print("RESULT: FAIL")
        print("\n".join(f"  {f}" for f in fails))
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
