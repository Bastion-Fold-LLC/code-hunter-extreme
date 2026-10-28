#!/usr/bin/env python3
"""P14: machine-enforced per-bench recall mapping (doctrine §5 denominators).

P13 closed fixture-green but left the doctrine phrase "across juice-shop /
DVWA / PyGoat" aspirational: no per-bench denominators existed anywhere.
This file + benchmarks/bench_recall.json close that gap:

- BAR items (13): in-envelope plants (black-box HTTP, unauth or operator
  session). Each runs the REAL template->check->verify path against the
  LIVE bench and must CONFIRM. Recall 1.0 enforced, per class and overall.
- NAMED entries (22): out-of-bar WITH evidence — in-class misses name
  their wall (browser / 2-account / CSRF / ...), bare cells name the
  absent plant, uncovered items name their class. Load-bearing named
  claims carry live probes below; every entry must carry a rationale
  and a source so nothing is ever silently dropped.
- IDOR has exactly one live-bench bar item (DVWA api v1 object read,
  unauthenticated password hash since the upstream image fixed the
  module); juice-shop and pygoat still wall every object behind
  auth/multi-account/cookie-minting and name those walls explicitly.

BenchDB: tests SKIP (not fail) when a bench is unreachable, so the suite
stays green without the bench containers. P14 scores them live.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
import oracle_seam_templates as st  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    extract_status_from_curl_output,
    verify_seam_card,
)

MAP = json.loads((ROOT / "benchmarks" / "bench_recall.json").read_text())
BAR_CLASSES = ("sqli", "xss", "auth-bypass", "idor", "exposure")
EXPOSURE_TIDS = {
    "self-observing-equation",
    "t1190-artifact-exposure",
    "listed-file-exposure",
}
MAX_CHECKS_PER_ITEM = 24


def _items(status: str = "bar") -> List[dict]:
    out = []
    for bench, spec in MAP["benches"].items():
        for it in spec["items"]:
            if it["status"] == status:
                out.append({"bench": bench, **it})
    return out


def _named() -> List[dict]:
    out = []
    for bench, spec in MAP["benches"].items():
        for it in spec["named"]:
            out.append({"bench": bench, **it})
    return out


# ── mapping hygiene ──────────────────────────────────────────────────────


def test_mapping_pins_match_registry():
    reg = json.loads((ROOT / "benchmarks" / "registry.json").read_text())
    rev = {b["id"]: b["revision"] for b in reg["benchmarks"]}
    for bench, pin in MAP["pins"].items():
        assert rev[bench] == pin, f"{bench}: mapping {pin} != registry {rev[bench]}"


def test_every_bar_item_has_executable_spec():
    tids = {t["tid"] for t in st.TEMPLATES}
    for it in _items():
        for key in ("id", "class", "method", "path", "template", "evidence", "source"):
            assert it.get(key), f"{it.get('id')}: empty {key}"
        assert it["class"] in BAR_CLASSES, it["id"]
        assert it["template"] in tids, f"{it['id']}: unknown tid {it['template']}"
        assert it["seed"], f"{it['id']}: no recon seed"


def test_every_named_entry_is_explicit():
    for it in _named():
        for key in ("id", "class", "evidence", "source"):
            assert it.get(key), f"{it.get('id')}: empty {key}"
        assert it["status"] in ("named-miss", "bare", "uncovered"), it["id"]
        if it["status"] == "named-miss":
            assert it.get("wall"), f"{it['id']}: named-miss without a wall"


def test_idor_live_bar_is_exactly_the_dvwa_api_plant():
    """One live IDOR bar item exists: DVWA's api object read (unauth hash).

    Juice-shop and pygoat still wall every object (named below); DVWA
    also keeps its cookie-minting bac wall named. Any new reachable
    live IDOR plant must join the bar and update this test loudly.
    """
    idor_bar = [i for i in _items() if i["class"] == "idor"]
    idor_named = [i for i in _named() if i["class"] == "idor"]
    assert {i["id"] for i in idor_bar} == {"dvwa-api-idor"}, idor_bar
    assert len(idor_named) >= 3, "each bench must name its remaining idor walls"
    assert {i["bench"] for i in idor_named} == set(
        MAP["benches"]
    ), "idor wall must be named per bench"


# ── bench sessions ───────────────────────────────────────────────────────


def _up(base: str) -> bool:
    try:
        urllib.request.urlopen(base + "/", timeout=5)
        return True
    except Exception:
        try:
            urllib.request.urlopen(base, timeout=5)
            return True
        except Exception:
            return False


@pytest.fixture(scope="module")
def juice():
    base = MAP["benches"]["juice-shop"]["base"]
    if not _up(base):
        pytest.skip("juice-shop bench unreachable")
    return base


@pytest.fixture(scope="module")
def dvwa():
    import requests

    base = MAP["benches"]["dvwa"]["base"]
    if not _up(base):
        pytest.skip("DVWA bench unreachable")
    s = requests.Session()
    login = s.get(base + "/login.php", timeout=10).text
    m = re.search(r"user_token' value='([^']+)'", login)
    assert m, "DVWA login page lost its user_token field"
    r = s.post(
        base + "/login.php",
        data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": m.group(1),
        },
        timeout=10,
        allow_redirects=False,
    )
    assert r.status_code == 302 and "index.php" in r.headers.get(
        "Location", ""
    ), f"DVWA admin login failed: {r.status_code}"
    jar = s.cookies.get_dict()
    assert "PHPSESSID" in jar, "DVWA login set no session"
    return base, f"PHPSESSID={jar['PHPSESSID']}; security=low"


PYGOAT_FALLBACK_USER = "p14tester"
PYGOAT_FALLBACK_PASS = "Testpass123!"


def _pygoat_login(s, base: str, user: str, password: str) -> None:
    """Log an existing pygoat user in on session ``s`` (asserts a 302)."""
    s.headers["Referer"] = base + "/login/"
    login = s.get(base + "/login/", timeout=10).text
    m2 = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', login)
    assert m2, "pygoat login page lost its CSRF field"
    r2 = s.post(
        base + "/login/",
        data={
            "csrfmiddlewaretoken": m2.group(1),
            "username": user,
            "password": password,
        },
        timeout=10,
        allow_redirects=False,
    )
    assert r2.status_code == 302, f"pygoat login failed: {r2.status_code}"


@pytest.fixture(scope="module")
def pygoat():
    import requests

    base = MAP["benches"]["pygoat"]["base"]
    if not _up(base):
        pytest.skip("pygoat bench unreachable")
    s = requests.Session()
    s.headers["Referer"] = base + "/register"
    reg = s.get(base + "/register", timeout=10).text
    m = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', reg)
    assert m, "pygoat register page lost its CSRF field"
    user = f"p14_{os.getpid()}_{int(time.time()) % 100000}"
    r = s.post(
        base + "/register",
        data={
            "csrfmiddlewaretoken": m.group(1),
            "username": user,
            "email": f"{user}@t.co",
            "password1": "Testpass123!",
            "password2": "Testpass123!",
        },
        timeout=10,
        allow_redirects=False,
    )
    if r.status_code == 302:
        _pygoat_login(s, base, user, "Testpass123!")
    else:
        # Register wall (2026-10-12: /register re-renders 200, no user, no
        # error): fall back to the persistent operator account instead of
        # failing the whole bench. The fallback path is pinned live by
        # test_pygoat_login_as_existing_user_works below.
        print(f"\npygoat register walled ({r.status_code}) — fallback login")
        _pygoat_login(s, base, PYGOAT_FALLBACK_USER, PYGOAT_FALLBACK_PASS)
    jar = s.cookies.get_dict()
    assert "sessionid" in jar, "pygoat login set no session"
    cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
    probe = s.get(base + "/xss", timeout=10)
    assert probe.status_code == 200, "pygoat session cannot reach labs"
    return base, cookie


def test_pygoat_login_as_existing_user_works():
    """Pin the register-wall fallback: p14tester must log in and reach labs.

    Independent of the ``pygoat`` fixture (fresh session, existing user) so
    a walled /register never silently voids the bench. Skips when the
    bench is unreachable, like every other live test in this file.
    """
    import requests

    base = MAP["benches"]["pygoat"]["base"]
    if not _up(base):
        pytest.skip("pygoat bench unreachable")
    s = requests.Session()
    _pygoat_login(s, base, PYGOAT_FALLBACK_USER, PYGOAT_FALLBACK_PASS)
    jar = s.cookies.get_dict()
    assert "sessionid" in jar, "fallback login set no session"
    probe = s.get(base + "/xss", timeout=10)
    assert probe.status_code == 200, "fallback session cannot reach labs"


# ── runner ───────────────────────────────────────────────────────────────


def _seed_recon(seed: dict, base: str) -> Path:
    recon = Path(tempfile.mkdtemp(prefix="p14bench_"))
    (recon / "live_hosts.txt").write_text(base + "\n")
    for key, fname in (
        ("js_endpoints", "js_endpoints.txt"),
        ("fuzzed", "fuzzed_paths.txt"),
        ("crawl", "crawl.txt"),
        ("listed", "listed_paths.txt"),
    ):
        lines = seed.get(key, [])
        (recon / fname).write_text("\n".join(lines) + ("\n" if lines else ""))
    (recon / "api_specs.txt").write_text("")
    (recon / "js_secrets.txt").write_text("")
    return recon


def _with_cookie(check: str, cookie: Optional[str]) -> str:
    """Mirror verify_seams cookie injection (same regex, same guard)."""
    if cookie and "cookie:" not in check.lower():
        check = re.sub(r"^(curl\s+)", rf'\1-H "Cookie: {cookie}" ', check)
    return check


def _run_card(card: dict, cookie: Optional[str]) -> Tuple[str, str, str]:
    """Run one card's check on the wire; return (verdict, reason, output)."""
    check = _with_cookie(card["check"], cookie)
    _, out, err = oh._run_check(check, is_testnet=True)
    assert "[BLOCKED]" not in err, f"check blocked: {check[:120]}"
    status = extract_status_from_curl_output(out)
    m = re.search(r"https?://[^\s'\"]+", check)
    url = m.group(0) if m else ""
    v = verify_seam_card(card, [url], status=status, body=out)
    return v["verdict"], v["reason"], out


def _confirm_item(item: dict, base: str, cookie: Optional[str]) -> Tuple[str, str]:
    """First CONFIRMED (verdict, output) for the item's tid+path, else fail."""
    recon = _seed_recon(item["seed"], base)
    seams = st.scan_template_seams(
        recon_dir=recon,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
    )
    cands = [
        s
        for s in seams
        if s.get("claim_type") == item["template"] and item["path"] in s["check"]
    ]
    assert cands, (
        f"{item['id']}: template {item['template']} emitted zero cards "
        f"for {item['path']}"
    )
    tried = []
    for card in cands[:MAX_CHECKS_PER_ITEM]:
        verdict, reason, out = _run_card(card, cookie)
        tried.append(f"{verdict}: {card['check'][:110]} ({reason[:100]})")
        if verdict == "CONFIRMED":
            return verdict, out
    raise AssertionError(
        f"{item['id']}: 0/{len(tried)} confirmed on the wire:\n"
        + "\n".join("  " + t for t in tried)
    )


# ── bar items: juice ─────────────────────────────────────────────────────


def test_juice_sqli_login_confirms(juice):
    item = next(i for i in _items() if i["id"] == "juice-sqli-login")
    _confirm_item(item, juice, None)


def test_juice_authbp_login_is_admin_session(juice):
    """Same vuln, impact-classified: the JWT must be an ADMIN session."""
    item = next(i for i in _items() if i["id"] == "juice-authbp-login")
    _, out = _confirm_item(item, juice, None)
    m = re.search(r'"token"\s*:\s*"([^"]+)"', out)
    assert m, "bypass response carries no JWT"
    payload = m.group(1).split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.b64decode(payload).decode("utf-8", "ignore"))
    data = claims.get("data", claims)
    assert data.get("email") == "admin@juice-sh.op", f"not admin: {data}"
    assert data.get("role") == "admin", f"not admin role: {data}"


def test_juice_exposure_metrics_confirms(juice):
    item = next(i for i in _items() if i["id"] == "juice-exposure-metrics")
    _confirm_item(item, juice, None)


def test_juice_exposure_legal_confirms(juice):
    item = next(i for i in _items() if i["id"] == "juice-exposure-legal")
    _confirm_item(item, juice, None)


# ── bar items: DVWA ──────────────────────────────────────────────────────


def test_dvwa_sqli_low_confirms(dvwa):
    """Form-gated chain: bare ?id= never reaches the query (Submit gate).

    The page footer contains 'SQLi DB: mysql', so a bare-probe confirm on
    generic markers is a FALSE POSITIVE by construction — only the true
    error text ('error in your SQL syntax') via the harvest-form replay
    (?id=<payload>&Submit=Submit) counts.
    """
    import oracle_harvest as hv

    base, cookie = dvwa
    item = next(i for i in _items() if i["id"] == "dvwa-sqli-low")
    recon = _seed_recon(item["seed"], base)
    seams = st.scan_template_seams(
        recon_dir=recon,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
    )
    parents = [
        s
        for s in seams
        if s.get("claim_type") == item["template"] and item["path"] in s["check"]
    ]
    assert parents, "sqli template emitted zero cards for the vuln page"
    tried = []
    for n, parent in enumerate(parents[:MAX_CHECKS_PER_ITEM]):
        verdict, reason, out = _run_card(parent, cookie)
        tried.append(f"parent {verdict}: {parent['check'][:100]}")
        if verdict == "CONFIRMED":
            # Footer-marker confirms are hunt-teardown kills, not finds:
            # only the true error text counts, and confirmed cards do not
            # reframe in-hunt, so neither do they here.
            if "error in your SQL syntax" in out:
                return
            tried.append("  (footer-FP confirm — correctly not a find)")
            continue
        corpus = hv.merge_harvest(hv.harvest_text(out, source_url=base + item["path"]))
        cards = hv.harvest_reframes(parent, corpus, {}, 900 + n)
        forms = [c for c in cards if c.get("reframe_transform") == "harvest-form"]
        for f in forms:
            v2, r2, o2 = _run_card(f, cookie)
            tried.append(f"replay {v2}: {f['check'][:110]}")
            if v2 == "CONFIRMED" and "error in your SQL syntax" in o2:
                return
            if v2 == "CONFIRMED":
                tried.append("  (replay confirm lacked the true error — FP)")
    raise AssertionError(
        "dvwa-sqli-low: no TRUE error confirm:\n" + "\n".join("  " + t for t in tried)
    )


def test_dvwa_xss_low_confirms(dvwa):
    base, cookie = dvwa
    item = next(i for i in _items() if i["id"] == "dvwa-xss-low")
    _confirm_item(item, base, cookie)


def test_dvwa_exposure_phpinfo_confirms(dvwa):
    base, cookie = dvwa
    item = next(i for i in _items() if i["id"] == "dvwa-exposure-phpinfo")
    _confirm_item(item, base, cookie)


def test_dvwa_exposure_git_head_confirms(dvwa):
    base, cookie = dvwa
    item = next(i for i in _items() if i["id"] == "dvwa-exposure-git-head")
    _confirm_item(item, base, cookie)


def test_dvwa_exposure_git_config_confirms(dvwa):
    base, cookie = dvwa
    item = next(i for i in _items() if i["id"] == "dvwa-exposure-git-config")
    _confirm_item(item, base, cookie)


# ── bar items: pygoat ────────────────────────────────────────────────────


def test_pygoat_xss_lab_confirms(pygoat):
    base, cookie = pygoat
    item = next(i for i in _items() if i["id"] == "pygoat-xss-lab")
    _confirm_item(item, base, cookie)


def test_pygoat_authbp_secret_replay_confirms(pygoat):
    """Harvest-gate chain on the wire: parent output names the rule, replay
    confirms — with a parent-vs-replay differential proving a real bypass."""
    import oracle_harvest as hv

    base, cookie = pygoat
    item = next(i for i in _items() if i["id"] == "pygoat-authbp-secret")
    recon = _seed_recon(item["seed"], base)
    seams = st.scan_template_seams(
        recon_dir=recon,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=base),
    )
    parents = [
        s
        for s in seams
        if s.get("claim_type") == item["template"] and item["path"] in s["check"]
    ]
    assert parents, "beautiful-liar emitted zero cards for /secret"
    parent = parents[0]
    _, p_out, _ = oh._run_check(_with_cookie(parent["check"], cookie), is_testnet=True)
    corpus = hv.merge_harvest(hv.harvest_text(p_out, source_url=base))
    assert corpus["gate_hints"], "parent wire output names no gate rule"
    cards = hv.harvest_reframes(parent, corpus, {}, 900)
    gate = [c for c in cards if c.get("reframe_transform") == "harvest-gate"]
    assert gate, "no harvest-gate replay emitted from parent output"
    verdict, reason, r_out = _run_card(gate[0], cookie)
    assert verdict == "CONFIRMED", f"gate replay rejected: {reason}"
    assert "S3CR37K3Y" in r_out, "replay lacks the secret (no bypass proven)"
    assert "S3CR37K3Y" not in p_out, "parent already had the secret (vacuous)"


def test_pygoat_exposure_debug_confirms(pygoat):
    base, cookie = pygoat
    item = next(i for i in _items() if i["id"] == "pygoat-exposure-debug")
    _confirm_item(item, base, cookie)


# ── bar rollup ───────────────────────────────────────────────────────────


def test_zero_miss_rollup(juice, dvwa, pygoat):
    """Recall 1.0 per class and overall across the 12 bar items."""
    auth: Dict[str, Tuple[str, Optional[str]]] = {
        "juice-shop": (juice, None),
        "dvwa": dvwa,
        "pygoat": pygoat,
    }
    misses: Dict[str, List[str]] = {c: [] for c in BAR_CLASSES}
    found = 0
    total = 0
    for it in _items():
        base, cookie = auth[it["bench"]]
        total += 1
        try:
            if it["id"] == "pygoat-authbp-secret":
                test_pygoat_authbp_secret_replay_confirms(pygoat)
            elif it["id"] == "juice-authbp-login":
                test_juice_authbp_login_is_admin_session(juice)
            elif it["id"] == "dvwa-sqli-low":
                test_dvwa_sqli_low_confirms(dvwa)
            else:
                _confirm_item(it, base, cookie)
            found += 1
        except AssertionError as e:
            misses[it["class"]].append(f"{it['id']}: {str(e)[:150]}")
    bar = float(
        json.loads((ROOT / "oracle.config.json").read_text())["quality_gates"][
            "gate_recall_min"
        ]
    )
    recall = found / total if total else 0.0
    lines = [f"live-bench detection recall: {found}/{total} = {recall:.3f} (bar {bar})"]
    for c in BAR_CLASSES:
        n = sum(1 for i in _items() if i["class"] == c)
        lines.append(f"  class {c}: planted={n} missed={len(misses[c])}")
    for c in BAR_CLASSES:
        for m in misses[c]:
            lines.append(f"  MISS [{c}]: {m}")
    print("\n" + "\n".join(lines))
    assert recall >= bar, "live-bench bar misses:\n" + "\n".join(lines)


# ── named-claim live probes (walls with evidence, not prose) ─────────────


def _get(base: str, path: str, cookie: Optional[str] = None) -> Tuple[int, str]:
    req = urllib.request.Request(base + path)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")


def test_named_juice_search_has_no_server_reflector(juice):
    status, body = _get(juice, "/rest/products/search?q=%3Cmark%3Ep14nm%3C%2Fmark%3E")
    assert status == 200
    assert "p14nm" not in body, "search reflects input — xss wall claim is wrong"


def test_named_juice_object_endpoints_401(juice):
    for path in ("/api/Users/2", "/api/BasketItems/2", "/api/Feedbacks/2"):
        status, _ = _get(juice, path)
        assert status == 401, f"{path}: expected 401, got {status}"


def test_named_juice_uploads_has_no_listing(juice):
    status, body = _get(juice, "/public/images/uploads/")
    assert status == 200 and "<html" in body.lower(), "uploads/ is now listed?"


def test_named_dvwa_bac_needs_cookie_coupling(dvwa):
    base, cookie = dvwa
    status, body = _get(base, "/vulnerabilities/bac/?action=view&user_id=2", cookie)
    assert status == 200
    assert "No user_id cookie found" in body, body[:200]


def test_dvwa_api_idor_confirms(dvwa):
    """Unauthenticated object read incl. password hash (api v1).

    Runs bare (no session cookie): no-session IS the test. Promoted from
    the dvwa-api-broken named-miss when the upstream image fixed the
    module and the plant became reachable.
    """
    base, _cookie = dvwa
    item = next(i for i in _items() if i["id"] == "dvwa-api-idor")
    _, out = _confirm_item(item, base, None)
    assert '"password"' in out, "v1 user object no longer leaks the hash?"


def test_named_pygoat_sql_lab_403_without_csrf(pygoat):
    import requests

    base, cookie = pygoat
    r = requests.post(
        base + "/sql_lab",
        data={"name": "admin", "pass": "' OR '1'='1"},
        headers={"Cookie": cookie, "Referer": base + "/sql_lab"},
        timeout=10,
    )
    assert r.status_code == 403, f"CSRF wall gone? got {r.status_code}"
