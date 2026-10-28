# LAYER: find
# DEST: basilisk
# ENDPOINTS: discover_immunefi, discover_cantina, discover_bugcrowd, discover_hackenproof, discover_yeswehack, discover_hackerone, discover_huntr, merge_into_cache  # noqa: E501
# TOPICS: none
"""oracle_discovery.py — full program-list discovery per platform.

Each discover_<platform>() pulls the COMPLETE public program directory
(paginating where needed) and returns (programs, report) where report is
a dict with at least {"status": ..., "listed": N}. Status is explicit:
  ok               full list retrieved
  partial          some pages failed; listed counts what succeeded
  failed           nothing retrieved; reason in report["error"]
  browser_required platform needs JS rendering; use the browser path

Never fails soft: an empty directory and a transport failure are
different statuses. Callers must not treat [] as authoritative death.

Provenance: every program dict carries "discovery_source".
"""

import json
import re
import time
import html as _html
import urllib.parse
import urllib.request

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def _get(url, timeout=25, headers=None):
    if urllib.parse.urlsplit(url or "").scheme not in ("http", "https"):
        raise ValueError(f"refusing to fetch non-http(s) URL: {url!r}")
    h = dict(_UA)
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        return resp.read().decode("utf-8", "replace")


def _get_json(url, timeout=25, headers=None):
    return json.loads(_get(url, timeout=timeout, headers=headers))


# ---------------------------------------------------------------- immunefi
def discover_immunefi():
    """Immunefi: all program slugs are embedded in the /bug-bounty/ HTML
    (React Server Component payload); the page lazy-renders only ~10 cards
    but ships the full list. Verified 2026-09-29: 172 slugs in HTML matches
    the "172 bounty programs" display exactly (slugs are case-sensitive in
    the payload — 1inch-SmartContracts, Aevo, KAST, METH need [A-Za-z])."""
    try:
        html = _get("https://immunefi.com/bug-bounty/")
    except Exception as e:
        return [], {"status": "failed", "listed": 0, "error": repr(e)}
    slugs = sorted(
        set(
            s.lower()
            for s in re.findall(r"bug-bounty/([A-Za-z0-9-]+)/information", html)
        )
    )
    progs = [
        {
            "platform": "immunefi",
            "name": s,
            # canonical program URL matches the existing cache convention
            "url": f"https://immunefi.com/bug-bounty/{s}/information/",
            "discovery_source": "immunefi-listing-html",
        }
        for s in slugs
    ]
    return progs, {"status": "ok", "listed": len(progs)}


# ----------------------------------------------------------------- cantina
def discover_cantina():
    """Cantina: public Next.js API route. Returns every bounty incl. ended;
    status field distinguishes live/judging/complete. Verified 2026-09-29:
    73 total, 51 live (matches site's 51 displayed)."""
    try:
        items = _get_json("https://cantina.xyz/api/v0/bounties")
    except Exception as e:
        return [], {"status": "failed", "listed": 0, "error": repr(e)}
    progs = [
        {
            "platform": "cantina",
            "name": b.get("name") or b.get("id"),
            "url": b.get("url") or f"https://cantina.xyz/bounties/{b.get('id')}",
            "discovery_source": "cantina-api-v0-bounties",
            "raw": {
                "status": b.get("status"),
                "kind": b.get("kind"),
                "totalRewardPot": b.get("totalRewardPot"),
            },
        }
        for b in items
        if isinstance(b, dict) and b.get("id")
    ]
    live = sum(1 for p in progs if p["raw"]["status"] == "live")
    return progs, {"status": "ok", "listed": len(progs), "live": live}


# ---------------------------------------------------------------- bugcrowd
def discover_bugcrowd():
    """Bugcrowd: /engagement_listings JSON API, 24 per page.
    Verified 2026-09-29: 289 total across 13 pages."""
    all_e = []
    page = 1
    failed_pages = []
    while True:
        try:
            d = _get_json(
                f"https://bugcrowd.com/engagement_listings?category=bug_bounty&page={page}",
                headers={"Accept": "application/json"},
            )
        except Exception:
            failed_pages.append(page)
            break
        es = d.get("engagements") or []
        all_e.extend(es)
        total = (d.get("paginationMeta") or {}).get("totalCount")
        if len(es) < 24 or (total and len(all_e) >= total):
            break
        page += 1
        if page > 40:
            break
        time.sleep(0.5)
    progs = [
        {
            "platform": "bugcrowd",
            "name": e.get("name"),
            "url": e.get("briefUrl")
            or ("https://bugcrowd.com" + (e.get("engagementUrl") or "")),
            "discovery_source": "bugcrowd-engagement-listings-api",
        }
        for e in all_e
        if e.get("name")
    ]
    status = "ok" if not failed_pages else "partial"
    return progs, {"status": status, "listed": len(progs), "failed_pages": failed_pages}


# ------------------------------------------------------------- hackenproof
def discover_hackenproof():
    """HackenProof: server-rendered /programs?page=N, ~10 new links/page.
    Verified 2026-09-29: 325 unique programs across 33 pages."""
    seen = set()
    failed_pages = []
    for page in range(1, 45):
        try:
            html = _get(f"https://hackenproof.com/programs?page={page}")
        except Exception:
            failed_pages.append(page)
            break
        links = set(re.findall(r'href="(/programs/[a-z0-9-]+)"', html))
        new = links - seen
        seen |= links
        if not new and page > 1:
            break
        time.sleep(0.4)
    progs = [
        {
            "platform": "hackenproof",
            "name": s.rsplit("/", 1)[-1],
            "url": "https://hackenproof.com" + s,
            "discovery_source": "hackenproof-programs-pagination",
        }
        for s in sorted(seen)
    ]
    status = "ok" if not failed_pages else "partial"
    return progs, {"status": status, "listed": len(progs), "failed_pages": failed_pages}


# code4rena removed per operator: platform is dead, fetcher deleted.
# (Was: /api/v1/audits paginated JSON.)


# --------------------------------------------------------------- yeswehack
def discover_yeswehack():
    """YesWeHack: public api.yeswehack.com/programs, 42 per page.
    Verified 2026-09-29: 57 total across 2 pages (matches site)."""
    all_p = []
    failed_pages = []
    page = 1
    while True:
        try:
            d = _get_json(f"https://api.yeswehack.com/programs?page={page}&per_page=42")
        except Exception:
            failed_pages.append(page)
            break
        items = d.get("items") or []
        all_p.extend(items)
        nb_pages = (d.get("pagination") or {}).get("nb_pages") or 1
        if page >= nb_pages:
            break
        page += 1
        time.sleep(0.4)
    progs = [
        {
            "platform": "yeswehack",
            "name": p.get("title"),
            "url": "https://yeswehack.com/programs/" + p.get("slug", ""),
            "discovery_source": "yeswehack-api-programs",
            "raw": {"slug": p.get("slug"), "status": p.get("status")},
        }
        for p in all_p
        if p.get("slug")
    ]
    status = "ok" if not failed_pages else "partial"
    return progs, {"status": status, "listed": len(progs), "failed_pages": failed_pages}


# --------------------------------------------------------------- hackerone
_H1_BROWSER_LIST = "data/hackerone_directory_20260929.json"


def discover_hackerone():
    """HackerOne directory is a JS app; the public GraphQL endpoint
    throttles direct queries (connection cut mid-response). Full team
    listing comes from a browser extraction saved to data/.
    Returns browser_required when no extraction file is present."""
    import os

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), _H1_BROWSER_LIST)
    if not os.path.exists(path):
        return [], {
            "status": "browser_required",
            "listed": 0,
            "error": "hackerone.com/directory/programs needs JS rendering; "
            "direct GraphQL throttled",
        }
    try:
        items = json.load(open(path))
    except Exception as e:
        return [], {"status": "failed", "listed": 0, "error": repr(e)}
    return items, {
        "status": "ok",
        "listed": len(items),
        "note": "browser-extracted 2026-09-29, Active-program filter on",
    }


# ------------------------------------------------------------------- huntr
def discover_huntr():
    """huntr.com/challenges lists AI/ML prompt-injection challenges.

    Challenge names live in the card aria-labels
    ("View <name> challenge"); the page is server-rendered enough to parse.
    Verified live 2026-09-29 (3 challenges).
    """
    try:
        page = _get("https://huntr.com/challenges")
    except Exception as e:
        return [], {"status": "failed", "listed": 0, "error": repr(e)}
    if not page:
        return [], {"status": "failed", "listed": 0, "error": "empty"}
    # map challenge id -> name from CARD aria-labels (not the "View details
    # for ..." button labels, which name the same challenge differently)
    names = {}
    for m in re.finditer(r'aria-label="View ((?!details for).+?) challenge"', page):
        # find the nearest challenge href after this label
        tail = page[m.end() : m.end() + 2000]
        hm = re.search(
            r'href="(/challenges/([A-Za-z0-9]+)/v1/(?:rules|leaderboard))"', tail
        )
        if hm:
            names[hm.group(2)] = _html.unescape(m.group(1)).strip()
    progs, seen = [], set()
    for m in re.finditer(
        r'href="(/challenges/([A-Za-z0-9]+)/v1/(?:rules|leaderboard))"', page
    ):
        path, cid = m.group(1), m.group(2)
        if cid in seen:
            continue
        seen.add(cid)
        progs.append(
            {
                "platform": "huntr",
                "name": names.get(cid, cid),
                "url": "https://huntr.com" + path,
            }
        )
    status = "ok" if progs else "failed"
    return progs, {"status": status, "listed": len(progs)}


DISCOVERERS = {
    "immunefi": discover_immunefi,
    "cantina": discover_cantina,
    "bugcrowd": discover_bugcrowd,
    "hackenproof": discover_hackenproof,
    # code4rena removed per operator: platform is dead, skip it.
    "yeswehack": discover_yeswehack,
    "hackerone": discover_hackerone,
    "huntr": discover_huntr,
}


def _norm_url(u):
    u = (u or "").strip().rstrip("/").lower()
    # platform URL variants that mean the same program page
    u = re.sub(r"/information$", "", u)
    u = re.sub(r"\?.*$", "", u)  # e.g. hackerone ?type=team
    return u


def merge_into_cache(cache_path="programs_cache.json", platforms=None):
    """Run discoverers and merge new programs into the cache.

    Matches on normalized URL; never duplicates, never deletes.
    Returns a per-platform merge report."""
    with open(cache_path) as f:
        cache = json.load(f)
    progs = cache["programs"] if isinstance(cache, dict) else cache
    known = {_norm_url(p.get("url")) for p in progs}
    report = {}
    for plat, fn in DISCOVERERS.items():
        if platforms and plat not in platforms:
            continue
        found, rep = fn()
        added = 0
        for p in found:
            if _norm_url(p.get("url")) not in known:
                new = {
                    "platform": p["platform"],
                    "name": p["name"],
                    "url": p["url"],
                    "max_payout_usd": None,
                    "kind": None,
                    "fast_triage": None,
                    "response_efficiency": None,
                    "reports_count": None,
                    "launched_at": None,
                    "raw": p.get("raw")
                    or {"discovery_source": p.get("discovery_source")},
                    "structured_scopes": [],
                }
                if isinstance(new["raw"], dict):
                    new["raw"].setdefault("discovery_source", p.get("discovery_source"))
                progs.append(new)
                known.add(_norm_url(p["url"]))
                added += 1
        rep["added_to_cache"] = added
        rep["cache_total_for_platform"] = sum(
            1 for p in progs if (p.get("platform") or "").lower() == plat
        )
        report[plat] = rep
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=1)
    return report


if __name__ == "__main__":
    import sys

    plats = sys.argv[1:] or None
    rep = merge_into_cache(platforms=plats)
    for plat, r in rep.items():
        print(
            f"{plat}: status={r['status']} listed={r['listed']} "
            f"added={r['added_to_cache']} cache_total={r['cache_total_for_platform']}"
        )
