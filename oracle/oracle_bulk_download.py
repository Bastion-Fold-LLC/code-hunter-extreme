#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: intake_program_scopes, run_scope_intake, download_one, main
# TOPICS: none
"""
Oracle bulk-download CLI — the operator says how many programs to pull,
the CLI downloads them across platforms into the standard intake layout.

    python3 oracle_bulk_download.py --count 20 [--kind web2] [--platform all]
    python3 oracle_bulk_download.py --count 20 --from-triage 50
    python3 oracle_bulk_download.py --slugs foo-bar,baz-qux [--force]
    python3 oracle_bulk_download.py --count 5 --dry-run
    python3 oracle_bulk_download.py --count 20 --no-cloud --no-screenshot

Selection (default): the top-N from the triage ranking (asset-count-first),
so bulk downloads feed the same targets the triage system picks.
The per-program path mirrors `oracle-hunter scan -N ... --download`:
workspace scaffold + program brief, asset download via
`download_program_assets`, then the W1b in-scope-gated repo auto-clone
(`_extract_repo_urls` / `_clone_program_repos` from oracle_hunter).

Idempotent: a program with a completed bulk manifest is skipped unless
--force. --dry-run lists exactly what would be downloaded, no network.
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
MANIFEST = ".oracle_bulk.json"


# ── GAP 1: policy extraction from downloaded program page ────────────────────


def _extract_policy_from_assets(assets_dir: Path, platform: str) -> str:
    """
    Extract program rules/policy text from downloaded program page assets.

    Looks for the plain-text CDP render of the program page and extracts
    from the first policy/rules heading through the downloaded page tail.
    Plain text does not preserve heading hierarchy, so guessing which
    later short lines are policy subheadings can silently delete rules;
    both mindsets must receive the program rules that were actually
    downloaded, and oversized prompts fail loud at model routing instead
    of being silently subset.
    Falls back gracefully if no page text found.

    Supported platforms:
      bugcrowd   — reads CDP-rendered plain text, finds 'Ratings/Rewards' section
      patchstack — reads plain text, finds 'Security Policy' section
      hackerone  — reads plain text, finds 'Program Rules' / 'Policy' section
      yeswehack  — reads plain text, finds 'Rules' section
      others     — generic: looks for any rules/policy heading
    """
    if not assets_dir or not assets_dir.exists():
        return ""

    # Platform-specific file candidates (CDP plain-text render preferred)
    platform_l = (platform or "").lower()
    candidates = []
    if platform_l == "bugcrowd":
        candidates = list(assets_dir.glob("bugcrowd.com__engagements__*.txt"))
    elif platform_l == "hackerone":
        candidates = list(assets_dir.glob("hackerone.com__*.txt"))
    elif platform_l == "patchstack":
        candidates = list(assets_dir.glob("patchstack.com__database__*.txt"))
        candidates += list(assets_dir.glob("program_page.txt"))
    elif platform_l in ("yeswehack", "intigriti"):
        candidates = list(assets_dir.glob("*.txt"))
    # always fall back to generic program_page.txt
    candidates += list(assets_dir.glob("program_page.txt"))

    # Remove duplicates, skip screenshots/binary
    seen = set()
    filtered = []
    for c in candidates:
        if c.name not in seen and c.suffix not in (".png", ".jpg", ".zip"):
            seen.add(c.name)
            filtered.append(c)

    for page_file in filtered:
        try:
            text = page_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Skip files that are raw HTML (not CDP-rendered plain text)
        if text.strip().startswith("<!DOCTYPE") or text.strip().startswith("<html"):
            continue

        # Platform-specific extraction
        if platform_l == "bugcrowd":
            policy = _extract_section(
                text,
                [
                    "Ratings/Rewards and Bounty Rules",
                    "Bounty Rules",
                    "Program Rules",
                    "Access",
                    "Credentials",
                ],
            )
        elif platform_l == "patchstack":
            policy = _extract_section(
                text,
                [
                    "Security Policy",
                    "Vulnerability Disclosure Policy",
                    "Responsible Disclosure",
                ],
            )
        elif platform_l == "hackerone":
            policy = _extract_section(
                text,
                [
                    "Program Rules",
                    "Program policy",
                    "Policy",
                    "Responsible Disclosure",
                ],
            )
        else:
            policy = _extract_section(
                text,
                [
                    "Rules",
                    "Policy",
                    "Disclosure",
                    "Guidelines",
                    "Scope Rules",
                ],
            )

        if policy and len(policy) > 40:
            return policy

    return ""


def _extract_section(text: str, headings: list, max_chars: Optional[int] = None) -> str:
    """
    Find the first matching heading and return from it through EOF by
    default. Plain-text renders do not encode heading levels, so a
    guessed next-heading stop can silently remove vulnerability-class
    policy subsections such as XSS or CSRF. ``max_chars`` remains only
    as an explicit caller override and retains the old bounded-section
    behavior. Strips excess whitespace.
    """
    import re as _re

    lower = text.lower()
    best_idx = -1
    for heading in headings:
        idx = lower.find(heading.lower())
        if idx >= 0 and (best_idx < 0 or idx < best_idx):
            best_idx = idx

    if best_idx < 0:
        return ""

    # Extract from heading forward
    chunk = (
        text[best_idx:]
        if max_chars is None
        else text[best_idx : best_idx + max_chars + 200]
    )

    # Stop at a line that looks like a new non-policy page section heading,
    # while keeping policy subheadings (Safe Harbor, Out of Scope, Rewards, etc.)
    stop_pattern = _re.compile(
        r"\n(?=(?!(?:Safe Harbor|Out of Scope|In Scope|Scope|Rewards|Bounty|"
        r"Eligibility|Disclosure|Guidelines|Rules|Testing|Legal|Allowed|"
        r"Prohibited|Qualifying|Non-Qualifying)\b)"
        r"(?:[A-Z][a-zA-Z ]{2,30}\n|[A-Z]{3,}\n))",
        _re.MULTILINE,
    )
    if max_chars is not None:
        m = stop_pattern.search(chunk, 100)
        if m:
            chunk = chunk[: m.start()]

    # Clean up
    chunk = _re.sub(r"\n{3,}", "\n\n", chunk).strip()
    return chunk if max_chars is None else chunk[:max_chars]


# ── selection (pure: no network, no directories created) ─────────────────────


def _slugify(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", (name or "unknown").lower())[:60]


def load_cache_programs(here: Path):
    cache = json.loads((here / "programs_cache.json").read_text())
    return cache.get("programs", [])


def select_candidates(args, cfg: dict, here: Path):
    """Ordered list of program dicts. Pure function — safe for --dry-run."""
    sys.path.insert(0, str(here))
    import oracle_triage as triage

    programs = load_cache_programs(here)

    kind = args.kind or cfg.get("kind", "all")
    if kind != "all":
        programs = [p for p in programs if (p.get("kind") or "") == kind]

    plat = (args.platform or "all").lower()
    if plat != "all":
        programs = [p for p in programs if (p.get("platform") or "").lower() == plat]

    if args.slugs:
        wanted = [s.strip().lower() for s in str(args.slugs).split(",") if s.strip()]
        by_key: Dict[str, Any] = {}
        for p in programs:
            by_key.setdefault(_slugify(p.get("name")), p)
            by_key.setdefault((p.get("name") or "").lower(), p)
        pool, seen = [], set()
        missing = []
        for w in wanted:
            p = by_key.get(w)
            if p is None:
                missing.append(w)
            elif id(p) not in seen:
                seen.add(id(p))
                pool.append(p)
        return pool, missing

    programs_dir = Path(cfg.get("programs_dir", "programs"))
    if not programs_dir.is_absolute():
        programs_dir = here / programs_dir
    n = args.from_triage or args.count
    rows = triage.score_programs(programs, programs_dir, cfg)
    index = {(p.get("platform"), p.get("name")): p for p in programs}
    pool = []
    for r in rows[:n]:
        p = index.get((r["platform"], r["name"]))
        if p is not None:
            pool.append(p)
    return pool, []


def asset_signal(prog: dict, here: Path, cfg: dict) -> str:
    """Short asset-count label for display, mirroring triage semantics."""
    sys.path.insert(0, str(here))
    import oracle_triage as triage

    programs_dir = Path(cfg.get("programs_dir", "programs"))
    if not programs_dir.is_absolute():
        programs_dir = here / programs_dir
    n, src = triage.asset_count(prog, programs_dir)
    if n is None:
        return "~est"
    return f"{n} (r)" if src == "reported" else str(n)


# ── download (mirrors --pick N --download-only Phase 3) ───────────────────────


def _fetch_yeswehack_scopes(prog: dict) -> list:
    """YesWeHack scope list via their public API.

    A plain page fetch of yeswehack.com/programs/<slug> returns the SPA
    homepage shell (3KB, zero program content) — the real program data loads
    in-browser. But api.yeswehack.com is public and unauthenticated: the
    per-program endpoint returns the full scope list (asset, type, value)
    plus out-of-scope entries. No rendering, no login, no API key needed.
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    import urllib.request

    slug = ""
    url = prog.get("url") or ""
    m = re.search(r"/programs/([^/?#]+)", url)
    if m:
        slug = m.group(1)
    if not slug:
        slug = _slugify(prog.get("name") or "")
    if not slug:
        return []
    try:
        req = urllib.request.Request(
            f"https://api.yeswehack.com/programs/{slug}",
            headers={
                "User-Agent": "oracle-bulk-download/1.0",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=25) as resp:  # nosec B310
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return []
    scopes = []
    for s in data.get("scopes") or []:
        ident = str(s.get("scope") or "").strip()
        if not ident:
            continue
        scopes.append(
            {
                "asset_identifier": ident,
                "asset_type": str(s.get("scope_type") or "").upper(),
                "asset_type_name": s.get("scope_type_name") or "",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "max_severity": s.get("asset_value") or "",
                "source": "yeswehack-api",
            }
        )
    for entry in data.get("out_of_scope") or []:
        text = str(entry).strip()
        if text:
            scopes.append(
                {
                    "asset_identifier": text,
                    "asset_type": "NOTE",
                    "eligible_for_bounty": False,
                    "eligible_for_submission": False,
                    "instruction": text,
                    "source": "yeswehack-api",
                }
            )
    return scopes


_H1_GRAPHQL = "https://hackerone.com/graphql"
_H1_SCOPE_QUERY = """query TeamScope($handle: String!, $cursor: String) {
  team(handle: $handle) {
    structured_scopes(first: 100, archived: false, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      edges {
        node {
          asset_identifier
          asset_type
          eligible_for_bounty
          eligible_for_submission
          instruction
          max_severity
        }
      }
    }
  }
}"""


class ProgramVanishedError(RuntimeError):
    """The platform source authoritatively says the program no longer exists."""


def _fetch_hackerone_scopes(prog: dict) -> list:
    """HackerOne scope list via Oracle's API, then public GraphQL fallback.

    When Oracle owns ``HACKERONE_USERNAME`` + a token, the authenticated
    Hacker API is the source: it is the same truth the verify pass used and
    avoids the public endpoint's aggressive throttling. Without credentials,
    public structured scopes are read via GraphQL (readable unauthenticated
    for public programs, verified live 2026-09-29). The GraphQL path paces
    itself and fails soft.
    """
    import time as _time
    import urllib.request as _urlreq

    handle = ""
    url = prog.get("url") or ""
    m = re.search(r"hackerone\.com/([A-Za-z0-9_-]+)", url)
    if m:
        handle = m.group(1)
    if not handle:
        handle = _slugify(prog.get("name") or "")
    if not handle:
        return []
    try:
        import oracle_h1_api as _h1

        if _h1.available():
            fresh = _h1.fetch_program(handle)
            if fresh is None:
                # Authoritative 404: the program is gone. Returning []
                # would read as "empty" and keep stale scope alive.
                raise ProgramVanishedError(
                    f"HackerOne program no longer exists: {handle}"
                )
            # Ineligible records ride along with their flags (as on the
            # GraphQL path) so the gate and stamps keep fresh OOS truth.
            return list(fresh.get("structured_scopes") or []) + list(
                fresh.get("out_of_scope_scopes") or []
            )
    except ImportError:
        pass
    edges = None
    cursor = None
    for attempt in range(3):
        try:
            all_edges: list = []
            while True:
                _time.sleep(
                    6
                )  # polite pacing: HackerOne throttles structured_scopes hard
                req = _urlreq.Request(
                    _H1_GRAPHQL,
                    data=json.dumps(
                        {
                            "query": _H1_SCOPE_QUERY,
                            "variables": {"handle": handle, "cursor": cursor},
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "User-Agent": "oracle-bulk-download/1.0",
                    },
                )
                with _urlreq.urlopen(req, timeout=30) as resp:  # nosec B310
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                team = (data.get("data") or {}).get("team") or {}
                conn = team.get("structured_scopes") or {}
                all_edges.extend(conn.get("edges") or [])
                page = conn.get("pageInfo") or {}
                if page.get("hasNextPage") and page.get("endCursor"):
                    cursor = page["endCursor"]
                else:
                    break
            edges = all_edges
            break
        except Exception:
            # Throttle backoff: structured_scopes is heavily rate-limited;
            # seconds don't help, minutes do.
            _time.sleep(60 if attempt == 0 else 180)
    if edges is None:
        return []
    scopes = []
    for e in edges:
        n = e.get("node") or {}
        ident = str(n.get("asset_identifier") or "").strip()
        if not ident:
            continue
        scopes.append(
            {
                "asset_identifier": ident,
                "asset_type": str(n.get("asset_type") or ""),
                "eligible_for_bounty": bool(n.get("eligible_for_bounty")),
                "eligible_for_submission": bool(n.get("eligible_for_submission")),
                "instruction": n.get("instruction") or "",
                "max_severity": n.get("max_severity") or "",
                "source": "hackerone-graphql",
            }
        )
    return scopes


def _fetch_bugcrowd_scopes(prog: dict) -> list:
    """Bugcrowd scope list — parses the already-downloaded program page asset.

    Bugcrowd blocks plain HTTP requests with 406, so we parse the program
    page text that was already fetched and saved to the workspace assets dir
    during the download phase.  Falls back to CDP and then page-text parsing.

    The page format is:
        <target name>
        In scope   |   Out of scope
        <domain or URL>
        Payment reward chart   ← signals end of target block
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"bugcrowd\.com/engagements/([A-Za-z0-9_-]+)", url)
    if not m:
        return []
    slug = m.group(1)

    # ── 1. Parse from already-downloaded workspace asset (fastest, no network) ──
    page_text = _bugcrowd_page_from_assets(prog, slug)

    # ── 2. CDP fallback if no local asset ────────────────────────────────────
    if not page_text:
        try:
            from oracle_programs import _cdp_fetch as _bc_cdp

            page_text = (
                _bc_cdp(f"https://bugcrowd.com/engagements/{slug}", wait=8) or ""
            )
        except Exception:
            pass

    if page_text and len(page_text) > 100 and "ERROR 406" not in page_text:
        scopes = _parse_bugcrowd_page_text(page_text)
        if scopes:
            return scopes

    # ── 3. target_groups JSON API (occasionally public without auth) ─────────
    try:
        req = _urlreq.Request(
            f"https://bugcrowd.com/engagements/{slug}/target_groups.json",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
                "Accept": "application/json, text/javascript, */*",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        with _urlreq.urlopen(req, timeout=20) as resp:  # nosec B310
            tg_data = json.loads(resp.read().decode("utf-8", "replace"))
        groups = tg_data.get("groups") or []
        if groups:
            return _parse_bugcrowd_groups(groups)
    except Exception:
        pass

    return []


def _bugcrowd_page_from_assets(prog: dict, slug: str) -> str:
    """Find the downloaded Bugcrowd engagement page text in the workspace assets.

    Returns plain text. If the asset is raw HTML, extracts the rendered text
    from the data-props JSON blob embedded in the React root element.
    """
    _here = Path(__file__).resolve().parent
    plat = prog.get("platform", "bugcrowd")
    name = prog.get("name", "")
    slug_raw = re.sub(r"[^\w.\-]", "_", name.lower())[:60]
    assets_dir = _here / "targets" / plat / slug_raw / "assets"
    if not assets_dir.exists():
        return ""
    # Prefer the engagement-specific text file, then program_page.txt
    candidates = []
    for pattern in [f"*engagements*{slug}*.txt", "*engagements*.txt"]:
        candidates.extend(sorted(assets_dir.glob(pattern)))
    # Always include program_page.txt if present
    pp = assets_dir / "program_page.txt"
    if pp.exists() and pp not in candidates:
        candidates.append(pp)
    for hit in candidates:
        try:
            raw = hit.read_text(encoding="utf-8", errors="replace")
            if not raw.strip():
                continue
            # If it's HTML, extract the rendered text from the React props JSON
            if raw.lstrip().startswith("<") or "data-react-class" in raw:
                extracted = _extract_bugcrowd_html_scope(raw)
                if extracted:
                    return extracted
            else:
                return raw
        except Exception:
            pass
    return ""


def _extract_bugcrowd_html_scope(html: str) -> str:
    """Pull scope text from a Bugcrowd engagement page saved as raw HTML.

    The page embeds a data-props JSON blob on the React root element.
    That JSON has a 'description' field (HTML) with the full program text,
    and a data-api-endpoints attribute with the getBriefVersionDocument path
    we can use to fetch the structured scope JSON.
    """
    import html as _html

    # Try the brief-version JSON path embedded in data-api-endpoints
    m = re.search(r'getBriefVersionDocument&quot;:&quot;(/[^&"]+)&quot;', html)
    if m:
        brief_path = _html.unescape(m.group(1))
        try:
            import urllib.request as _urlreq

            req = _urlreq.Request(
                f"https://bugcrowd.com{brief_path}.json",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
                    "Accept": "application/json",
                },
            )
            with _urlreq.urlopen(req, timeout=20) as resp:  # nosec B310
                brief = json.loads(resp.read().decode("utf-8", "replace"))
            groups = ((brief.get("data") or {}).get("scope")) or []
            if groups:
                # Return a synthetic text representation for _parse_bugcrowd_page_text
                lines = []
                for g in groups:
                    gname = str(g.get("name") or "").strip()
                    in_scope = "out of scope" not in gname.lower()
                    lines.append(gname)
                    lines.append("In scope" if in_scope else "Out of scope")
                    for t in g.get("targets") or []:
                        uri = str(t.get("uri") or t.get("name") or "").strip()
                        if uri:
                            lines.append(uri)
                    lines.append("Payment reward chart")
                return "\n".join(lines)
        except Exception:
            pass

    # Fallback: extract description HTML → strip tags → return as text
    m2 = re.search(r'"description"\s*:\s*"((?:[^"\\]|\\.)*)"', html)
    if m2:
        try:
            desc_json = m2.group(1)
            desc_html = desc_json.encode("utf-8").decode("unicode_escape")
            desc_text = re.sub(r"<[^>]+>", " ", desc_html)
            desc_text = _html.unescape(desc_text)
            return desc_text
        except Exception:
            pass
    return ""


def _parse_bugcrowd_page_text(page: str) -> list:
    """Parse scope assets from a Bugcrowd engagement page rendered as plain text.

    The page structure (after JS rendering) looks like:
        <Target Group Name>
        In scope           ← or "Out of scope"
        [description lines]
        <domain/URL>       ← the actual asset identifier
        Payment reward chart  ← marks end of this group's asset block
    """
    lines = page.splitlines()
    scopes = []
    current_in_scope = None  # True = in scope, False = out of scope

    _url_pat = re.compile(
        r"^(https?://|wss?://|\*\.|\{subdomain\}|\{[\w]+\}\.)"
        r"|^[\w][\w.-]+\.(com|net|org|io|ai|co|app|dev|cloud|xyz|gov|edu)(/|$)",
        re.IGNORECASE,
    )
    _noise = {
        "In scope",
        "Out of scope",
        "Show more",
        "Payment reward chart",
        "API Testing",
        "Website Testing",
        "Mobile Testing",
        "Penetration Testing",
        "Large Language Model",
        "In Scope",
        "Out of Scope",
    }

    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue
        if line == "In scope":
            current_in_scope = True
            continue
        if line == "Out of scope":
            current_in_scope = False
            continue
        if (
            line in _noise
            or re.match(r"^P[1-4]$", line)
            or re.match(r"^\$[\d,]+", line)
        ):
            continue
        if current_in_scope is None:
            continue

        if _url_pat.match(line) and len(line) < 200 and "\n" not in line:
            ident = line.rstrip("/")
            # Normalise {subdomain}.foo.com → *.foo.com
            ident = re.sub(r"\{[^}]+\}\.", "*.", ident)
            if not ident:
                continue
            atype = (
                "WILDCARD"
                if ident.startswith("*.")
                else ("OTHER" if ident.startswith("https://github.com") else "URL")
            )
            scopes.append(
                {
                    "asset_identifier": ident,
                    "asset_type": atype,
                    "eligible_for_bounty": current_in_scope,
                    "eligible_for_submission": current_in_scope,
                    "instruction": "",
                    "source": "bugcrowd-page-text",
                }
            )
    return scopes


def _parse_bugcrowd_groups(groups: list) -> list:
    """Shared parser for both brief-JSON and target_groups-JSON formats."""
    scopes = []
    for g in groups:
        gname = str(g.get("name") or "").strip().lower()
        in_scope = "out of scope" not in gname
        for t in g.get("targets") or []:
            uri = str(t.get("uri") or t.get("name") or "").strip()
            cat = str(t.get("category") or "").strip()
            if not uri:
                scopes.append(
                    {
                        "asset_identifier": f"[{gname or 'scope'}] unnamed target",
                        "asset_type": "NOTE",
                        "eligible_for_bounty": False,
                        "eligible_for_submission": False,
                        "instruction": "empty URI in brief",
                        "source": "bugcrowd-brief",
                    }
                )
                continue
            atype = (
                "WILDCARD"
                if re.sub(r"^https?://", "", uri).startswith("*.")
                else (cat.upper() or "URL")
            )
            scopes.append(
                {
                    "asset_identifier": uri,
                    "asset_type": atype,
                    "eligible_for_bounty": in_scope,
                    "eligible_for_submission": in_scope,
                    "instruction": t.get("description") or "",
                    "max_severity": "",
                    "source": "bugcrowd-brief",
                }
            )
    return scopes


def _fetch_patchstack_scopes(prog: dict) -> list:
    """Patchstack scope = the WordPress plugin itself.

    Patchstack is a WordPress plugin bug bounty platform. Each program is
    a single plugin. Scope is:
    - The plugin download zip from wordpress.org (free plugins) or SVN
    - A WILDCARD for the vendor's domain if discoverable from wp.org
    - The wordpress.org plugin page itself as URL asset

    For premium plugins not on wp.org (e.g. elementor-pro), falls back to
    SVN mirror at plugins.svn.wordpress.org or skips zip download.
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"/plugin/([^/]+)/", url)
    if not m:
        return []
    slug = m.group(1)

    scopes = []
    # Always add the wp.org plugin page as URL scope
    scopes.append(
        {
            "asset_identifier": f"https://wordpress.org/plugins/{slug}/",
            "asset_type": "URL",
            "eligible_for_bounty": True,
            "eligible_for_submission": True,
            "instruction": f"WordPress plugin page for {slug}",
            "source": "patchstack-derived",
        }
    )

    # Try wp.org API for download link and vendor domain
    try:
        api_url = f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"
        req = _urlreq.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
        with _urlreq.urlopen(req, timeout=15) as r:  # nosec B310
            d = json.loads(r.read().decode("utf-8", "replace"))
        dl = d.get("download_link") or ""
        if dl:
            scopes.append(
                {
                    "asset_identifier": dl,
                    "asset_type": "OTHER",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                    "instruction": f"Plugin zip download: {dl}",
                    "source": "patchstack-wporg",
                }
            )
        # Vendor homepage → add as URL scope
        homepage = d.get("homepage") or ""
        if homepage:
            vendor_host = re.sub(r"^https?://", "", homepage).split("/")[0]
            if vendor_host and "." in vendor_host:
                scopes.append(
                    {
                        "asset_identifier": f"*.{vendor_host}",
                        "asset_type": "WILDCARD",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "instruction": f"Vendor domain for {slug}",
                        "source": "patchstack-wporg",
                    }
                )
    except Exception:
        pass

    # For premium plugins not on wp.org, try SVN
    if len(scopes) == 1:
        svn_url = f"https://plugins.svn.wordpress.org/{slug}/"
        try:
            req = _urlreq.Request(svn_url, headers={"User-Agent": "Mozilla/5.0"})
            with _urlreq.urlopen(req, timeout=10) as r:  # nosec B310
                if r.status == 200:
                    scopes.append(
                        {
                            "asset_identifier": svn_url,
                            "asset_type": "OTHER",
                            "eligible_for_bounty": True,
                            "eligible_for_submission": True,
                            "instruction": f"SVN source for {slug}",
                            "source": "patchstack-svn",
                        }
                    )
        except Exception:
            pass

    return scopes


def _fetch_sherlock_scopes(prog: dict) -> list:
    """Sherlock scope list from the public bug-bounty page.

    audits.sherlock.xyz/bug-bounties/<id> is server-rendered. The
    authoritative scope is the ## Scope section (chains + named contracts).
    GitHub links under "Protocol Resources"/"Previous Audits" are REFERENCE
    material — NOT eligible scope (verified live 2026-09-29: Babylon's 10
    repos, Aave V4's 2 repos all sit under Protocol Resources; Flying
    Tulip's repo under Previous Audits). Only GitHub links INSIDE the
    ## Scope section count as eligible REPO records.
    No auth needed. Returns scope dicts in the hunter's structured_scopes
    format. Fails soft: on any error returns [].
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"sherlock\.xyz/bug-bounties/(\d+)", url)
    if not m:
        return []
    bid = m.group(1)
    try:
        req = _urlreq.Request(
            f"https://audits.sherlock.xyz/bug-bounties/{bid}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)",
                "Accept": "text/html",
            },
        )
        with _urlreq.urlopen(req, timeout=30) as resp:  # nosec B310
            page = resp.read().decode("utf-8", "replace")
    except Exception:
        return []
    scopes = []
    seen = set()

    def _add(ident, atype, eligible, instruction="", src="sherlock-page"):
        key = (atype, ident.lower()[:160])
        if key in seen:
            return
        seen.add(key)
        scopes.append(
            {
                "asset_identifier": ident[:160],
                "asset_type": atype,
                "eligible_for_bounty": eligible,
                "eligible_for_submission": eligible,
                "instruction": instruction[:500],
                "max_severity": "",
                "source": src,
            }
        )

    # 1) Authoritative scope: ## Scope section bullets.
    sc = re.search(r"## Scope(.*?)(?=(?<!#)##(?!#)|\Z)", page, re.S | re.I)
    scope_body = ""
    if sc:
        scope_body = sc.group(1).replace("\\n", "\n")
        # GitHub links inside ## Scope are eligible repos.
        for org, repo in re.findall(
            r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", scope_body
        ):
            _add(
                f"https://github.com/{org}/{repo}",
                "REPO",
                True,
                "GitHub repo listed in ## Scope",
            )
        # Named contracts / chains bullets.
        for raw in scope_body.split("\n"):
            line = raw.strip()
            if not line.startswith("-"):
                continue
            line = line.lstrip("-").strip()
            clean = re.sub(r"[*_`]", "", line).strip()
            if len(clean) < 2 or len(clean) > 80 or clean.startswith("#"):
                continue
            if "github.com" in clean.lower():
                continue  # already captured above
            atype = "CONTRACT" if re.fullmatch(r"[A-Za-z0-9_.*]+", clean) else "OTHER"
            _add(clean, atype, True, line)
    # 2) GitHub links OUTSIDE ## Scope (Protocol Resources, Previous
    # Audits) are reference material — recorded, NOT eligible scope.
    for org, repo in re.findall(
        r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", page
    ):
        url = f"https://github.com/{org}/{repo}"
        if url.lower() not in scope_body.lower():
            _add(
                url,
                "REFERENCE",
                False,
                "GitHub link outside ## Scope (Protocol Resources / Previous Audits) — reference only",
            )
    # Out-of-scope bullets -> excluded notes (case-insensitive heading).
    oos = re.search(r"## Out of [Ss]cope(.*?)(?=(?<!#)##(?!#)|\Z)", page, re.S)
    if oos:
        body = oos.group(1).replace("\\n", "\n")
        for raw in body.split("\n"):
            line = raw.strip()
            if not line.startswith("-"):
                continue
            line = line.lstrip("-").strip()
            if len(line) > 20 and not line.startswith("#"):
                scopes.append(
                    {
                        "asset_identifier": line[:160],
                        "asset_type": "NOTE",
                        "eligible_for_bounty": False,
                        "eligible_for_submission": False,
                        "instruction": line[:500],
                        "max_severity": "",
                        "source": "sherlock-page",
                    }
                )
    return scopes


def _fetch_codehawks_scopes(prog: dict) -> list:
    """CodeHawks scope from the public contest page.

    codehawks.cyfrin.io/c/<slug> is server-rendered (SvelteKit) with the
    contest repo in githubUrl. For audit contests the repo IS the scope.
    No auth needed — verified live 2026-09-29.
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"codehawks\.cyfrin\.io/c/([A-Za-z0-9_-]+)", url)
    if not m:
        return []
    slug = m.group(1)
    try:
        req = _urlreq.Request(
            f"https://codehawks.cyfrin.io/c/{slug}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)",
                "Accept": "text/html",
            },
        )
        with _urlreq.urlopen(req, timeout=30) as resp:  # nosec B310
            page = resp.read().decode("utf-8", "replace")
    except Exception:
        return []
    gm = re.search(r'githubUrl\s*:\s*"([^"]+)"', page)
    if not gm:
        # fallback: any CodeHawks-Contests repo link
        gm = re.search(r'"(https://github\.com/CodeHawks-Contests/[^"]+)"', page)
    if not gm:
        return []
    repo_url = gm.group(1).rstrip("/")
    return [
        {
            "asset_identifier": repo_url,
            "asset_type": "REPO",
            "eligible_for_bounty": True,
            "eligible_for_submission": True,
            "instruction": "",
            "max_severity": "",
            "source": "codehawks-page",
        }
    ]


def _fetch_cantina_scopes(prog: dict) -> list:
    """Cantina scope from the public bounty page.

    cantina.xyz/bounties/<uuid> is server-rendered (Next.js flight data)
    with a structured "assets" array: name, description (repo URL or
    contract addresses), hidden flag. No auth needed — verified live
    2026-09-29 (Uniswap: 13 assets).
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"cantina\.xyz/bounties/([0-9a-f-]{36})", url)
    if not m:
        return []
    bid = m.group(1)
    try:
        req = _urlreq.Request(
            f"https://cantina.xyz/bounties/{bid}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)",
                "Accept": "text/html",
            },
        )
        with _urlreq.urlopen(req, timeout=30) as resp:  # nosec B310
            page = resp.read().decode("utf-8", "replace")
    except Exception:
        return []
    i = page.find('\\"assets\\":[{')
    assets = []
    if i >= 0:
        start = page.find("[", i)
        depth, k, instr = 0, start, False
        while k < len(page):
            c = page[k]
            if c == "\\":
                k += 2
                continue
            if c == '"':
                instr = not instr
            elif not instr:
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                    if depth == 0:
                        break
            k += 1
        try:
            assets = json.loads(
                page[start : k + 1].replace('\\"', '"').replace("\\\\", "\\")
            )
        except Exception:
            assets = []
    if not assets:
        # Fallback: bounties without the assets array render scope content.
        # Two variants seen live: a "Scope" section with explorer links, or a
        # "Smart Contracts in Scope" table (name + address).
        seg = ""
        for marker in (">Scope<", "in Scope</h", "in scope</h", "In Scope</h"):
            si = page.find(marker)
            if si >= 0:
                seg = page[si : si + 30000]
                break
        if not seg:
            seg = page  # last resort: whole page
        for m in re.finditer(r"<tr[^>]*>(.*?)</tr>", seg, re.S):
            row = m.group(1)
            addrs = re.findall(r"0x[0-9a-fA-F]{40}", row)
            if not addrs:
                continue
            name = re.sub(r"<[^>]+>", " ", row).strip().split("0x")[0].strip()[:80]
            for addr in sorted(set(addrs)):
                assets.append(
                    {"name": name or addr, "description": addr, "hidden": False}
                )
        if not assets:
            for addr in sorted(set(re.findall(r"0x[0-9a-fA-F]{40}", seg))):
                assets.append({"name": addr, "description": addr, "hidden": False})
        for org, repo in sorted(
            set(re.findall(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", seg))
        ):
            if org.lower() not in ("cantina",):
                assets.append(
                    {
                        "name": f"{org}/{repo}",
                        "description": f"https://github.com/{org}/{repo}",
                        "hidden": False,
                    }
                )
    scopes = []
    for a in assets:
        name = str(a.get("name") or "").strip()
        desc = str(a.get("description") or "").strip()
        hidden = bool(a.get("hidden"))
        eligible = not hidden
        gm = re.search(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", desc)
        cm = re.search(r"0x[0-9a-fA-F]{40}", desc)
        if gm:
            ident = f"https://github.com/{gm.group(1)}/{gm.group(2)}"
            atype = "REPO"
        elif cm:
            ident = cm.group(0)
            atype = "CONTRACT"
        else:
            ident = name or desc[:80]
            atype = "OTHER"
        scopes.append(
            {
                "asset_identifier": ident,
                "asset_type": atype,
                "eligible_for_bounty": eligible,
                "eligible_for_submission": eligible,
                "instruction": (name + ": " + desc)[:300] if not gm else name,
                "max_severity": "",
                "source": "cantina-page",
            }
        )
    return scopes


def _fetch_hackenproof_scopes(prog: dict) -> list:
    """HackenProof scope from the public program page.

    hackenproof.com/programs/<slug> renders an "In scope" table
    (Target | Type | Severity). No auth needed — verified live 2026-09-29
    (starknet-staking: 18 rows, starknet-blockchain: 37 rows).
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"hackenproof\.com/programs/([A-Za-z0-9_.-]+)", url)
    if not m:
        return []
    slug = m.group(1)
    try:
        req = _urlreq.Request(
            f"https://hackenproof.com/programs/{slug}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)",
                "Accept": "text/html",
            },
        )
        with _urlreq.urlopen(req, timeout=30) as resp:  # nosec B310
            page = resp.read().decode("utf-8", "replace")
    except Exception:
        return []
    scopes = []
    i = page.find("In scope")
    if i >= 0:
        j = page.find("</table>", i)
        tbl = page[i : j if j > 0 else i + 20000]
        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", tbl, re.S)
        for r in rows[1:]:  # skip header
            cells = [
                re.sub(r"<[^>]+>", "", c).strip()
                for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", r, re.S)
            ]
            cells = [c for c in cells if c]
            if not cells:
                continue
            target = cells[0]
            atype = cells[1] if len(cells) > 1 else ""
            sev = cells[2] if len(cells) > 2 else ""
            scopes.append(
                {
                    "asset_identifier": target,
                    "asset_type": atype.upper().replace(" ", "_") or "OTHER",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                    "instruction": "",
                    "max_severity": sev.lower(),
                    "source": "hackenproof-page",
                }
            )
    # Out-of-scope table, if present.
    oi = page.find("Out of scope")
    if oi >= 0:
        oj = page.find("</table>", oi)
        otbl = page[oi : oj if oj > 0 else oi + 20000]
        for r in re.findall(r"<tr[^>]*>(.*?)</tr>", otbl, re.S)[1:]:
            cells = [
                re.sub(r"<[^>]+>", "", c).strip()
                for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", r, re.S)
            ]
            cells = [c for c in cells if c]
            if not cells:
                continue
            scopes.append(
                {
                    "asset_identifier": cells[0][:160],
                    "asset_type": "NOTE",
                    "eligible_for_bounty": False,
                    "eligible_for_submission": False,
                    "instruction": " | ".join(cells)[:300],
                    "max_severity": "",
                    "source": "hackenproof-page",
                }
            )
    return scopes


def _fetch_immunefi_scopes(prog: dict) -> list:
    """Immunefi scope from the public bug-bounty page.

    immunefi.com/bug-bounty/<slug>/ carries a structured "assets" array
    (url, type, description) in Next.js flight data. No auth needed —
    verified live 2026-09-29 (Cosmos).
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = re.search(r"immunefi\.com/bug-bounty/([A-Za-z0-9_.-]+)", url)
    if not m:
        return []
    slug = m.group(1)
    try:
        req = _urlreq.Request(
            f"https://immunefi.com/bug-bounty/{slug}/information/",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)",
                "Accept": "text/html",
            },
        )
        with _urlreq.urlopen(req, timeout=30) as resp:  # nosec B310
            page = resp.read().decode("utf-8", "replace")
    except Exception:
        return []
    i = page.find('\\"assets\\":[{')
    if i < 0:
        return []
    start = page.find("[", i)
    depth, k, instr = 0, start, False
    while k < len(page):
        c = page[k]
        if c == "\\":
            k += 2
            continue
        if c == '"':
            instr = not instr
        elif not instr:
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    break
        k += 1
    try:
        assets = json.loads(
            page[start : k + 1].replace('\\"', '"').replace("\\\\", "\\")
        )
    except Exception:
        return []
    scopes = []
    for a in assets:
        aurl = str(a.get("url") or "").strip()
        if not aurl:
            continue
        scopes.append(
            {
                "asset_identifier": aurl,
                "asset_type": str(a.get("type") or "OTHER").upper(),
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": str(a.get("description") or "")[:300],
                "max_severity": "",
                "source": "immunefi-page",
            }
        )
    om = re.search(r'\\"outOfScopeAndRules\\":(null|\\"((?:[^"\\]|\\.)*)\\")', page)
    if om and om.group(1) != "null":
        txt = om.group(2).replace("\\n", "\n").replace('\\"', '"')[:500]
        if len(txt.strip()) > 20:
            scopes.append(
                {
                    "asset_identifier": txt[:160],
                    "asset_type": "NOTE",
                    "eligible_for_bounty": False,
                    "eligible_for_submission": False,
                    "instruction": txt,
                    "max_severity": "",
                    "source": "immunefi-page",
                }
            )
    return scopes


def _fetch_huntr_scopes(prog: dict) -> list:
    """huntr.com challenges are AI prompt-injection targets.

    The challenge card on /challenges carries the name (aria-label) and
    description; the challenge URL itself is the in-scope asset (a WEB
    target — the AI agent interface). Verified live 2026-09-29.
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    import re as _re
    import html as _html
    import urllib.request as _urlreq

    url = prog.get("url") or ""
    m = _re.search(r"/challenges/([A-Za-z0-9]+)", url)
    if not m:
        return []
    cid = m.group(1)
    try:
        req = _urlreq.Request(
            "https://huntr.com/challenges",
            headers={"User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)"},
        )
        with _urlreq.urlopen(req, timeout=25) as r:  # nosec B310
            if r.status != 200:
                return []
            page = r.read().decode("utf-8", "replace")
    except Exception:
        return []
    name, desc = "", ""
    for lm in _re.finditer(r'aria-label="View (.+?) challenge"', page):
        tail = page[lm.end() : lm.end() + 3000]
        if cid in tail[:1500] and _re.search(r"/challenges/" + cid + r"/", tail):
            name = _html.unescape(lm.group(1)).strip()
            # description sits between the card link and the button
            txt = _re.sub(r"<[^>]+>", " ", tail[:1500])
            txt = _html.unescape(_re.sub(r"\s+", " ", txt)).strip()
            desc = txt[:400]
            break
    challenge_url = f"https://huntr.com/challenges/{cid}"
    return [
        {
            "asset_identifier": challenge_url,
            "asset_type": "WEB",
            "eligible_for_bounty": True,
            "eligible_for_submission": True,
            "instruction": (
                f"huntr AI challenge: {name}. {desc}"
                if name
                else f"huntr AI challenge {cid}"
            )[:500],
            "max_severity": "",
            "source": "huntr-challenges",
        }
    ]


_INTIGRITI_ID_MAP: Optional[Dict[str, Any]] = None


def _fetch_intigriti_scopes(prog: dict) -> list:
    """Intigriti structured scope list via the researcher REST API v1.0.

    Calls GET /external/researcher/v1/programs/{programId} with the
    Intigriti Bearer token (INTIGRITI_TOKEN / INTIGRITI_JWT).
    Extracts domains (wildcards, URLs, apps, etc.) and tier/bounty eligibility.
    Also extracts policy description into prog['policy_text'] if present.
    Returns scope dicts in the hunter's structured_scopes format.
    Fails soft: on any error returns [] and the download proceeds as before.
    """
    global _INTIGRITI_ID_MAP
    import requests
    from oracle_programs import _key, _UA

    token = _key("INTIGRITI_TOKEN") or _key("INTIGRITI_JWT")
    if not token:
        return []

    prog_id = prog.get("id") or prog.get("program_id") or ""
    if not prog_id and isinstance(prog.get("raw"), dict):
        prog_id = prog["raw"].get("id", "")

    if not prog_id:
        if _INTIGRITI_ID_MAP is None:
            _INTIGRITI_ID_MAP = {}
            try:
                hdr = {
                    "User-Agent": _UA,
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                }
                r = requests.get(
                    "https://api.intigriti.com/external/researcher/v1/programs?limit=500",
                    headers=hdr,
                    timeout=20,
                )
                if r.ok:
                    for p in r.json().get("records", []):
                        if p.get("handle"):
                            _INTIGRITI_ID_MAP[str(p["handle"]).lower()] = p["id"]
                        if p.get("name"):
                            _INTIGRITI_ID_MAP[str(p["name"]).lower()] = p["id"]
            except Exception:
                pass

        handle = prog.get("handle") or ""
        name = prog.get("name") or ""
        if not handle and prog.get("url"):
            m = re.search(r"/programs/([^/?#]+)", prog["url"])
            if m:
                handle = m.group(1)
        if handle and handle.lower() in _INTIGRITI_ID_MAP:
            prog_id = _INTIGRITI_ID_MAP[handle.lower()]
        elif name and name.lower() in _INTIGRITI_ID_MAP:
            prog_id = _INTIGRITI_ID_MAP[name.lower()]

    if not prog_id:
        return []

    headers = {
        "User-Agent": _UA,
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        r = requests.get(
            f"https://api.intigriti.com/external/researcher/v1/programs/{prog_id}",
            headers=headers,
            timeout=20,
        )
        if not r.ok:
            return []
        data = r.json()
    except Exception:
        return []

    # Optional policy extraction if available in rulesOfEngagement
    roe = data.get("rulesOfEngagement")
    if isinstance(roe, dict):
        roe_content = roe.get("content")
        if isinstance(roe_content, dict):
            pdesc = roe_content.get("description")
            if pdesc and not prog.get("policy_text"):
                prog["policy_text"] = pdesc

    domains = data.get("domains")
    items = domains.get("content", []) if isinstance(domains, dict) else []
    scopes = []
    for d in items:
        endpoint = str(d.get("endpoint") or "").strip()
        if not endpoint:
            continue
        type_val = d.get("type", {})
        atype = str(
            type_val.get("value") if isinstance(type_val, dict) else type_val or "OTHER"
        ).upper()
        tier_val = d.get("tier", {})
        tier_name = str(
            tier_val.get("value") if isinstance(tier_val, dict) else tier_val or ""
        )
        bounty_eligible = tier_name.lower() != "no bounty"
        desc = str(d.get("description") or "").strip()
        scopes.append(
            {
                "asset_identifier": endpoint,
                "asset_type": atype,
                "eligible_for_bounty": bounty_eligible,
                "eligible_for_submission": True,
                "instruction": desc if desc else "",
                "max_severity": tier_name,
                "source": "intigriti-api",
            }
        )

    return scopes


# ── Scope intake registry ─────────────────────────────────────────────────
# Single source of truth for "which adapter fetches scopes for a platform".
# Adapters return a list of scope dicts, or None when the page is
# client-rendered (JS-only scope data — not a failure, needs browser path).

_SCOPE_ADAPTERS = {
    "yeswehack": _fetch_yeswehack_scopes,
    "hackerone": _fetch_hackerone_scopes,
    "bugcrowd": _fetch_bugcrowd_scopes,
    "sherlock": _fetch_sherlock_scopes,
    "codehawks": _fetch_codehawks_scopes,
    "cantina": _fetch_cantina_scopes,
    "hackenproof": _fetch_hackenproof_scopes,
    "immunefi": _fetch_immunefi_scopes,
    # code4rena removed per operator: platform is dead, skip it.
    "huntr": _fetch_huntr_scopes,
    "patchstack": _fetch_patchstack_scopes,
    "intigriti": _fetch_intigriti_scopes,
}


def _looks_client_rendered(url: str) -> bool:
    """Heuristic: page is the new JS-only UI (scope loads via token API)."""
    if urllib.parse.urlsplit(url or "").scheme not in ("http", "https"):
        return False
    try:
        req = urllib.request.Request(url or "", headers={"User-Agent": "Mozilla/5.0"})
        raw = urllib.request.urlopen(req, timeout=20)  # nosec B310
        page = raw.read().decode("utf-8", "replace")
        return (
            "bug-bounties" in page
            and "self.__next_f" in page
            and "Bug Bounty - Sherlock" in page
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def _scope_key(scope: dict) -> str:
    """Stable identity for one scope record across intake runs.

    Normalized so cosmetic differences (case, trailing slash) don't fake
    a "new asset".
    """
    atype = (scope.get("asset_type") or "").strip().upper()
    ident = (scope.get("asset_identifier") or "").strip().lower().rstrip("/")
    return f"{atype}|{ident}"


def _stamp_scope_times(existing: list, fresh: list, now: str) -> tuple:
    """Replace current scopes with a successful fresh intake, stamping time.

    Returns ``(current, new_count, removed)``.
    - first_seen: when Oracle first observed the asset. None = unknown
      (baseline: the program's first-ever intake can't know when the
      platform added the asset, so we don't pretend).
    - last_seen: last intake run where the asset was observed.
    - Assets absent from a successful non-empty fetch are NOT current
      scope. They move to ``removed`` history with ``removed_at``. Keeping
      them in ``structured_scopes`` made a revoked asset probe-eligible
      forever; a failed/empty intake is handled by the caller and still
      preserves the last known current set.
    """
    if not isinstance(existing, list):
        existing = []
    if not isinstance(fresh, list):
        fresh = []
    by_key: Dict[str, Any] = {}
    for s in existing:
        if isinstance(s, dict):
            by_key.setdefault(_scope_key(s), s)
        # non-dict records can't be keyed; drop them rather than crash
    baseline = not by_key  # first-ever intake: age unknown, don't fake it
    current = []
    new_count = 0
    fresh_keys = set()
    for s in fresh:
        if not isinstance(s, dict):
            continue  # corrupt adapter output: skip, don't crash
        ident = (s.get("asset_identifier") or "").strip()
        key = _scope_key(s)
        if not ident:
            # Unidentifiable: can't establish identity, so can't claim
            # newness either. Always appended, age honestly unknown.
            rec = dict(s)
            rec["first_seen"] = None
            rec["last_seen"] = now
            current.append(rec)
            continue
        if key in fresh_keys:
            continue  # duplicate inside this fetch: keep first
        fresh_keys.add(key)
        old = by_key.get(key)
        rec = dict(s)
        if old is not None:
            rec["first_seen"] = old.get("first_seen")
            rec["last_seen"] = now
        elif baseline:
            rec["first_seen"] = None
            rec["last_seen"] = now
        else:
            rec["first_seen"] = now
            rec["last_seen"] = now
            new_count += 1
        current.append(rec)
    removed = []
    for key, old in by_key.items():
        if key not in fresh_keys:
            rec = dict(old)
            rec["removed_at"] = now
            removed.append(rec)
    return current, new_count, removed


def intake_program_scopes(prog: dict) -> tuple:
    """Run the platform scope adapter for one program.

    Returns (scopes, status) where status is one of:
      ok               scopes retrieved (may be non-empty)
      empty            adapter succeeded, program genuinely has no scopes
      client-rendered  JS-only page; needs the browser path
      no-adapter       no scope adapter for this platform
      vanished         platform authoritatively says the program is gone
      auth-error       platform rejected Oracle's credentials (permanent
                       until fixed; not a transient transport failure)
      error            transport/parse failure (NOT authoritative empty)
    """
    plat = (prog.get("platform") or "").lower()
    fn = _SCOPE_ADAPTERS.get(plat)
    if fn is None:
        return [], "no-adapter"
    try:
        scopes = fn(prog)
    except ProgramVanishedError:
        return [], "vanished"
    except Exception as exc:
        if type(exc).__name__ == "H1AuthError":
            return [], "auth-error"
        return [], "error"
    if scopes is None:
        return [], "client-rendered"
    if (
        not scopes
        and plat == "sherlock"
        and _looks_client_rendered(prog.get("url") or "")
    ):
        return [], "client-rendered"
    if not scopes:
        return [], "empty"
    return scopes, "ok"


def refresh_program_scopes(prog: dict) -> dict:
    """Return a prog copy refreshed against the platform source.

    Always runs the adapter (Oracle re-scans with its own platform
    credentials; handoff/DB scopes may be stale). A successful non-empty
    fetch is authoritative: current scopes are replaced and revoked
    assets move to removed history. An authoritative vanish clears
    current scope entirely. Only an empty/failed intake keeps the last
    known set, stamped unverified. Never mutates prog.
    """
    _now = datetime.now(timezone.utc).isoformat()
    api_scopes, _istatus = intake_program_scopes(prog)
    out = dict(prog)
    out["scope_intake_status"] = _istatus
    out["scope_intake_at"] = _now
    if _istatus == "vanished":
        _existing = out.get("structured_scopes")
        _existing = _existing if isinstance(_existing, list) else []
        _current, _new, removed = _stamp_scope_times(_existing, [], _now)
        out["structured_scopes"] = _current
        out["scope_intake_new"] = _new
        if removed:
            out["scope_intake_removed"] = removed
        out["scope_intake_missing"] = len(removed)
        out["scope_intake_fresh"] = 0
        return out
    if api_scopes:
        _existing = out.get("structured_scopes")
        _existing = _existing if isinstance(_existing, list) else []
        current, _new, removed = _stamp_scope_times(_existing, api_scopes, _now)
        out["structured_scopes"] = current
        out["scope_intake_new"] = _new
        if removed:
            out["scope_intake_removed"] = removed
        # The source's current list is authoritative after a successful
        # non-empty fetch. Removed assets live in history only.
        out["scope_intake_missing"] = len(removed)
        out["scope_intake_fresh"] = len(api_scopes)
    return out


def run_scope_intake(
    cache_path: str = "programs_cache.json",
    platforms: str = "all",
    force: bool = False,
    limit: int = 0,
) -> dict:
    """Fetch scopes for cache programs missing them and persist to cache.

    Only touches programs with no structured_scopes unless force=True.
    Records per-program intake_status + intake_at. Returns summary.
    """
    with open(cache_path) as f:
        cache = json.load(f)
    progs = cache["programs"] if isinstance(cache, dict) else cache
    plats = None if platforms == "all" else set(platforms.split(","))
    targets = [
        p
        for p in progs
        if (plats is None or (p.get("platform") or "").lower() in plats)
        and (force or not (p.get("structured_scopes") or []))
    ]
    if limit:
        targets = targets[:limit]
    summary = {
        "targets": len(targets),
        "ok": 0,
        "empty": 0,
        "client_rendered": 0,
        "no_adapter": 0,
        "vanished": 0,
        "error": 0,
        "scopes_added": 0,
        "scopes_new": 0,
    }
    from datetime import datetime, timezone

    for n, prog in enumerate(targets):
        scopes, status = intake_program_scopes(prog)
        now = datetime.now(timezone.utc).isoformat()
        if status == "ok":
            current, new_count, removed = _stamp_scope_times(
                prog.get("structured_scopes") or [], scopes, now
            )
            prog["structured_scopes"] = current
            if removed:
                prog["scope_intake_removed"] = removed
            summary["ok"] += 1
            summary["scopes_added"] += len(scopes)
            summary["scopes_new"] += new_count
        elif status == "vanished":
            current, _new_count, removed = _stamp_scope_times(
                prog.get("structured_scopes") or [], [], now
            )
            prog["structured_scopes"] = current
            if removed:
                prog["scope_intake_removed"] = removed
            summary["vanished"] += 1
        elif status == "empty":
            summary["empty"] += 1
        elif status == "client-rendered":
            summary["client_rendered"] += 1
        elif status == "no-adapter":
            summary["no_adapter"] += 1
        else:
            summary["error"] += 1
        raw = prog.get("raw")
        if not isinstance(raw, dict):
            raw = {}
            prog["raw"] = raw
        raw["intake_status"] = status
        raw["intake_at"] = now
        if (n + 1) % 25 == 0:
            with open(cache_path, "w") as f:
                json.dump(cache, f, indent=1)
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=1)
    return summary


def workspace_base_for(prog: dict):
    from oracle_hunter import TARGETS_DIR

    return (
        TARGETS_DIR
        / (prog.get("platform") or "unknown")
        / _slugify(prog.get("name") or "unknown")
    )


def already_downloaded(prog: dict) -> bool:
    return (workspace_base_for(prog) / MANIFEST).exists()


def download_one(prog: dict, *, cdp_port: int, take_screenshot: bool) -> dict:
    """Run the full intake for one program. Returns a status dict."""
    from oracle_mindset_context import ProgramWorkspace, OracleMindsetContext
    from oracle_hunter import TARGETS_DIR, _extract_repo_urls, _clone_program_repos
    from oracle_scan import download_program_assets

    # Scope intake via the platform adapters (API keys where the
    # adapter uses them, signed-in/public paths otherwise). Always
    # refresh against the source: handoff scopes came from the local
    # DB and may be stale. A successful intake is authoritative
    # (revoked assets leave current scope); only an empty/failed
    # intake keeps the last known set.
    prog = refresh_program_scopes(prog)

    ws = ProgramWorkspace(prog, base=TARGETS_DIR)

    # Asset download first — we need program_page.txt on disk before extracting policy
    saved, dl_info = download_program_assets(
        prog,
        ws.base,
        cdp_port=cdp_port,
        take_screenshot=take_screenshot,
        clone_repos=False,
    )

    # GAP 1 fix: extract policy/rules from the downloaded program page text
    # and patch prog before saving program.json so it lands in the scope wall
    prog = dict(prog)
    _policy = _extract_policy_from_assets(ws.assets_dir, prog.get("platform", ""))
    if _policy:
        prog["policy_text"] = _policy

    ws.save_program_json()
    ctx = OracleMindsetContext(prog, voice=True)
    ws.save_program_brief(ctx)

    # W1b repo auto-clone: extract repo URLs from program + downloaded
    # assets, shallow-clone only the in-scope ones into repos/.
    cloned = []
    repo_urls = _extract_repo_urls(prog, ws.assets_dir)
    if repo_urls:
        cloned = [
            str(p)
            for p in _clone_program_repos(repo_urls, ws.base / "repos", prog=prog)
        ]

    assets = [s for s in saved if not s.startswith("repo:")]
    manifest = {
        "program": prog.get("name"),
        "platform": prog.get("platform"),
        "slug": _slugify(prog.get("name") or "unknown"),
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "assets": assets,
        "asset_count": len(assets),
        "page_source": dl_info.get("page_source"),
        "auth_session": dl_info.get("auth_session"),
        "structured_scopes": len(prog.get("structured_scopes") or []),
        "repos": cloned,
        "repo_count": len(cloned),
        "by": "oracle_bulk_download.py",
    }
    (ws.base / MANIFEST).write_text(json.dumps(manifest, indent=2))

    if assets or cloned:
        return {
            "status": "downloaded",
            "detail": f"{len(assets)} asset(s), {len(cloned)} repo(s)",
            "manifest": manifest,
        }
    return {
        "status": "empty",
        "detail": "no downloadable assets or in-scope repos found",
        "manifest": manifest,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Oracle bulk download: pull N programs' assets across platforms."
    )
    ap.add_argument(
        "--count",
        type=int,
        default=10,
        help="how many programs to download (default: 10)",
    )
    ap.add_argument(
        "--from-triage",
        type=int,
        default=None,
        help="candidate pool = top-N of triage ranking (default: --count)",
    )
    ap.add_argument(
        "--slugs",
        default=None,
        help="explicit program slugs/names, comma-separated (overrides triage; downloads all listed)",
    )
    ap.add_argument(
        "--platform", default="all", help="restrict to one platform (default: all)"
    )
    ap.add_argument(
        "--kind",
        default=None,
        choices=["web2", "web3", "ai", "all"],
        help="program kind filter (default: from triage.yaml)",
    )
    ap.add_argument(
        "--triage-config",
        default="triage.yaml",
        help="triage config file (default: triage.yaml)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="list what WOULD be downloaded; no network, no directories",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="re-download even if a bulk manifest already exists",
    )
    ap.add_argument(
        "--no-cloud",
        action="store_true",
        help="disable cloud fetch paths (Firecrawl); plain GET only",
    )
    ap.add_argument("--no-screenshot", action="store_true", help="skip CDP screenshots")
    ap.add_argument("--cdp-port", type=int, default=9227)
    ap.add_argument(
        "--intake-scopes",
        action="store_true",
        help="scope-intake mode: fetch scopes for cache programs "
        "missing them and persist to programs_cache.json; "
        "no asset download",
    )
    ap.add_argument(
        "--intake-limit",
        type=int,
        default=0,
        help="with --intake-scopes: max programs to process (0 = all)",
    )
    args = ap.parse_args(argv)

    if args.intake_scopes:
        summary = run_scope_intake(
            platforms=args.platform, force=args.force, limit=args.intake_limit
        )
        print(
            f"scope intake: {summary['targets']} targeted, "
            f"{summary['ok']} ok ({summary['scopes_added']} scopes, "
            f"{summary['scopes_new']} new), "
            f"{summary['empty']} empty, "
            f"{summary['client_rendered']} client-rendered, "
            f"{summary['no_adapter']} no-adapter, "
            f"{summary['error']} error"
        )
        return 0

    if args.count < 1 and not args.slugs:
        print("error: --count must be >= 1", file=sys.stderr)
        return 2

    sys.path.insert(0, str(HERE))
    import oracle_triage as triage

    cfg_path = Path(args.triage_config)
    if not cfg_path.is_absolute():
        cfg_path = HERE / cfg_path
    cfg = triage.load_config(cfg_path)

    if args.no_cloud:
        import oracle_programs

        oracle_programs.NO_CLOUD = True
        print("[no-cloud] Firecrawl/cloud fetch disabled — plain GET only.")

    pool, missing = select_candidates(args, cfg, HERE)
    for m in missing:
        print(f"[warn] slug not found in cache: {m}")

    # The operator's count is the contract.
    want = len(pool) if args.slugs else args.count
    if not pool:
        print("Nothing selected. Done.")
        return 0
    if len(pool) < want:
        print(f"[warn] pool exhausted: requested {want}, {len(pool)} available.")

    if args.dry_run:
        print(f"DRY RUN — would download up to {want} program(s):")
        hdr = f"  {'#':>3}  {'program':<38} {'platform':<11} {'kind':<5} {'assets':>8}"
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        for i, prog in enumerate(pool[:want], 1):
            sig = asset_signal(prog, HERE, cfg)
            print(
                f"  {i:>3}  {(prog.get('name') or '?')[:38]:<38} "
                f"{(prog.get('platform') or '?'):<11} {(prog.get('kind') or '?'):<5} {sig:>8}"
            )
        print(
            f"\n{min(want, len(pool))} program(s) would be downloaded. No network touched, no directories created."
        )
        return 0

    # Live run.
    take_screenshot = not args.no_screenshot
    results = []  # (prog, status, detail)
    attempted = 0
    total = min(want, len(pool))
    t0 = time.time()
    for prog in pool:
        if attempted >= want:
            break
        name = prog.get("name") or "?"
        plat = prog.get("platform") or "?"
        tag = f"[{attempted + 1}/{total}] {plat} / {name}"
        if already_downloaded(prog) and not args.force:
            print(f"{tag}\n  ↷ skipped: already downloaded (use --force to redo)")
            results.append((prog, "skipped", "already downloaded"))
            continue
        attempted += 1
        print(f"{tag} …")
        try:
            st = download_one(
                prog, cdp_port=args.cdp_port, take_screenshot=take_screenshot
            )
            mark = "✓" if st["status"] == "downloaded" else "○"
            print(f"  {mark} {st['status']}: {st['detail']}")
            results.append((prog, st["status"], st["detail"]))
        except KeyboardInterrupt:
            print("\nInterrupted by operator.")
            break
        except Exception as e:  # per-program failure must not kill the batch
            detail = f"{type(e).__name__}: {e}"
            print(f"  ✗ failed: {detail}")
            results.append((prog, "failed", detail))

    # Summary — the count contract, reported cleanly.
    from collections import Counter

    counts = Counter(s for _, s, _ in results)
    dt = time.time() - t0
    print(
        f"\n{'=' * 60}\nBulk download summary ({dt:.1f}s): "
        f"{counts.get('downloaded', 0)} downloaded, "
        f"{counts.get('empty', 0)} empty, "
        f"{counts.get('skipped', 0)} skipped, "
        f"{counts.get('failed', 0)} failed."
    )
    bad = [(p, d) for p, s, d in results if s in ("failed", "empty")]
    if bad:
        print("Needs attention:")
        for p, d in bad:
            state = next(s for q, s, _ in results if q is p)
            print(
                f"  [{state}] {(p.get('platform') or '?')}/{(p.get('name') or '?')}: {d}"
            )
    return 0 if not counts.get("failed") else 1


if __name__ == "__main__":
    sys.exit(main())
