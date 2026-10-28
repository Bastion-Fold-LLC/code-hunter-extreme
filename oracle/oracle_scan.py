#!/usr/bin/env python3
# LAYER: seal
# DEST: vortex
# ENDPOINTS: load_config, scan_platforms, pick_per_platform, download_program_assets, hunt_program, main  # noqa: E501
# TOPICS: none
"""
oracle_scan.py — retired one-button CLI; helper functions retained.
════════════════════════════════════════════════════════════════════
This file used to be a second, unverified pipeline: it picked programs from
the unauthenticated local cache, wrote program.json before a real prescan,
and could launch hunts without the Scan4Me→Oracle handoff. That entry point
is retired.

The supported pipeline is:
    oracle-hunter prescan --sync
    oracle-hunter scan -N 1 --download
    oracle-hunter queue --execute

Helpers in this module are still imported by the P11 download path and its
tests (notably download_program_assets, scan_platforms and the CDP page
reader). They are not a CLI contract and are not a substitute for the
verified pipeline above.
"""

import json
from datetime import datetime, timezone
import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
_CONFIG_PATH = _HERE / "oracle.config.json"

# ── Optional rich ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]


def _p(msg: str, style: str = ""):
    if RICH:
        console.print(f"[{style}]{msg}[/{style}]" if style else msg)
    else:
        print(msg)


def _banner(msg: str):
    if RICH:
        console.rule(f"[bold cyan]{msg}[/bold cyan]")
    else:
        print(f"\n{'─'*60}\n{msg}\n{'─'*60}")


# ── Config loader ──────────────────────────────────────────────────────────────


def load_config(path: Optional[Path] = None) -> Dict:
    p = path or _CONFIG_PATH
    if not p.exists():
        _p(f"[yellow]No config at {p} — using defaults[/yellow]")
        return _default_config()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        # Strip _comment keys
        return {k: v for k, v in raw.items() if not k.startswith("_")}
    except json.JSONDecodeError as e:
        _p(f"[red]Bad JSON in {p}: {e}[/red]")
        sys.exit(1)


def _default_config() -> Dict:
    return {
        "scan": {"platforms": "all", "refresh_cache": False, "cdp_port": 9227},
        "filter": {
            "min_payout_usd": 500,
            "max_payout_usd": 0,
            "max_resolved_reports": 500,
            "fast_triage_only": False,
            "new_programs_only": False,
            "new_program_days": 90,
            "web2": True,
            "web3": False,
            "top_n": 25,
            "pick_per_platform": 5,
        },
        "hunt": {
            "auto": False,
            "verify": True,
            "cloud": True,
            "testnet": False,
            "download_assets": True,
            "screenshot": True,
            "code_lens": True,
        },
        "researcher": {"handle": "codehunterextreme"},
    }


# ── Platform scan ──────────────────────────────────────────────────────────────


def scan_platforms(
    cfg: Dict,
    force_refresh: bool = False,
    kind: Optional[str] = None,
    platform: Optional[str] = None,
) -> List[Dict]:
    """
    Fetch programs from every configured platform using API keys where available,
    falling back to CDP session cookies for the rest.
    Returns the full merged + scored list.
    kind:     optional override of the config's web2/web3 filter —
              one of "web2", "web3", "ai", "all". None = use oracle.config.json.
    platform: comma-separated list of platforms to restrict to, e.g. "patchstack,hackerone"
    """
    from oracle_programs import (
        fetch_all_programs,
        filter_programs,
        _load_cache,
        _save_cache,
    )
    from oracle_triage import load_config as load_triage_config, score_programs

    scan_cfg = cfg.get("scan", {})
    filter_cfg = cfg.get("filter", {})
    configured_platforms = scan_cfg.get("platforms", "all")
    if configured_platforms in (None, "", "all", ["all"]):
        platforms = None
    elif isinstance(configured_platforms, str):
        platforms = [p.strip() for p in configured_platforms.split(",") if p.strip()]
    elif isinstance(configured_platforms, list):
        platforms = configured_platforms
    else:
        raise ValueError(
            "scan.platforms must be 'all', a comma-separated string, or a list"
        )
    refresh = force_refresh or scan_cfg.get("refresh_cache", False)

    programs = None
    if not refresh:
        programs = _load_cache()
        if programs:
            _p(
                f"[dim]Cache: {len(programs)} programs loaded (use --refresh to update)[/dim]"
            )

    if not programs:
        _p("[cyan]Scanning platforms…[/cyan]")
        programs, fetch_errors = fetch_all_programs(platforms, return_errors=True)
        if platforms:
            _p(
                "[yellow]Filtered refresh fetched "
                f"{len(programs)} program(s) — shared cache left untouched[/yellow]"
            )
        else:
            _save_cache(programs, errors=fetch_errors)
        _p(
            f"[green]✓[/green] {len(programs)} programs fetched across {len(set(p['platform'] for p in programs))} platforms"  # noqa: E501
        )
        for err in fetch_errors:
            _p(f"[red]Platform failure: {err}[/red]")

    # Apply config filters (CLI --kind overrides the config's web2/web3 flags)
    _kind = (kind or "").strip().lower() or None
    if _kind == "all":
        web2, web3 = True, True
    elif _kind in ("web2", "web3", "ai"):
        web2, web3 = (_kind == "web2"), (_kind == "web3")
    else:
        web2 = filter_cfg.get("web2", True)
        web3 = filter_cfg.get("web3", True)
    filtered = filter_programs(
        programs,
        min_payout=filter_cfg.get("min_payout_usd", 0),
        max_payout=filter_cfg.get("max_payout_usd", 0),
        fast_triage=filter_cfg.get("fast_triage_only", False),
        web2=web2,
        web3=web3,
        max_reports=filter_cfg.get("max_resolved_reports") or None,
        new_programs_only=filter_cfg.get("new_programs_only", False),
        new_program_days=filter_cfg.get("new_program_days", 90),
        recently_added_assets=filter_cfg.get("recently_added_assets_only", False),
    )
    if _kind == "ai":
        # filter_programs only expresses web2/web3; narrow to ai here (order preserved)
        filtered = [p for p in filtered if p.get("kind") == "ai"]

    # --platform filter: restrict to one or more platforms
    if platform:
        plats = {p.strip().lower() for p in platform.split(",")}
        filtered = [p for p in filtered if (p.get("platform") or "").lower() in plats]

    # The scan picker and oracle_triage must use one source of truth.  The
    # triage config gives new assets and verified fast triage their intended
    # weight instead of falling back to the legacy payout-dominated score.
    triage_cfg = load_triage_config(_HERE / "triage.yaml")
    filtered = score_programs(filtered, _HERE / "programs", triage_cfg)

    per_platform_n = filter_cfg.get("pick_per_platform")
    if per_platform_n:
        return pick_per_platform(filtered, int(per_platform_n))

    top_n = filter_cfg.get("top_n", 50)
    return filtered[:top_n]


def pick_per_platform(programs: List[Dict], count_per_plat: int) -> List[Dict]:
    """Pick up to N top programs for each distinct platform."""
    by_plat: Dict[str, List[Dict]] = {}
    for p in programs:
        by_plat.setdefault(p.get("platform", "unknown"), []).append(p)
    picked = []
    for plat in sorted(by_plat.keys()):
        picked.extend(by_plat[plat][:count_per_plat])
    return picked


# ── Display ranked list ────────────────────────────────────────────────────────


def display_programs(programs: List[Dict]):
    if not programs:
        _p("[yellow]No programs match your filters. Loosen oracle.config.json[/yellow]")
        return

    _banner(f"Ranked Programs — top {len(programs)} by hunt value")

    if RICH:
        tbl = Table(show_header=True, show_lines=True)
        tbl.add_column("#", style="bold dim", no_wrap=True)
        tbl.add_column("Platform", style="cyan", no_wrap=True)
        tbl.add_column("Program", style="bold white")
        tbl.add_column("Score", justify="right", style="bright_cyan")
        tbl.add_column("Payout", justify="right", style="green")
        tbl.add_column("Reports", justify="right", style="magenta")
        tbl.add_column("Kind", style="yellow", no_wrap=True)
        tbl.add_column("Fast ✓", justify="center")
        for i, p in enumerate(programs, 1):
            payout = f"${p['max_payout_usd']:,}" if p.get("max_payout_usd") else "—"
            reps = (
                str(p["reports_count"]) if p.get("reports_count") is not None else "—"
            )
            ft = "✓" if p.get("fast_triage") else ""
            score = f"{p.get('score', 0):.0f}"
            tbl.add_row(
                str(i),
                p["platform"],
                p["name"][:42],
                score,
                payout,
                reps,
                p.get("kind", "?"),
                ft,
            )
        console.print(tbl)
    else:
        hdr = f"{'#':<4} {'Platform':<14} {'Program':<38} {'Score':>7} {'Payout':>10} {'Reports':>8} {'Kind':<6} {'Fast'}"  # noqa: E501
        print(hdr)
        print("─" * len(hdr))
        for i, p in enumerate(programs, 1):
            payout = f"${p['max_payout_usd']:,}" if p.get("max_payout_usd") else "—"
            reps = (
                str(p.get("reports_count"))
                if p.get("reports_count") is not None
                else "—"
            )
            ft = "✓" if p.get("fast_triage") else " "
            score = f"{p.get('score', 0):.0f}"
            print(
                f"{i:<4} {p['platform']:<14} {p['name'][:36]:<38} {score:>7} {payout:>10} {reps:>8} {p.get('kind', '?'):<6} {ft}"  # noqa: E501
            )

    print()
    _p("[dim]Pick a number, a range (1-5), or 'all' to queue them.  q to quit.[/dim]")


# ── Authenticated page fetch via the logged-in CDP session ───────────────────
#
# Pipeline rule (Alex): program pages on bounty platforms are ALWAYS fetched
# through the operator's logged-in Chromium session via CDP. There is NO
# anonymous fallback for platform pages — an unauthenticated fetch returns
# SPA shells / login walls and reports "success" on garbage. If no
# authenticated session is reachable, the fetch fails LOUDLY (returns None)
# so the caller records it instead of pretending.
# Target-domain recon assets (robots.txt, openapi.json on the hunt target's
# own domains) are NOT platform pages and stay on plain fetch.


def _cdp_page_text(url: str, cdp_port: int = 9227, wait: int = 8):
    """
    Render url in the operator's logged-in Chromium (CDP) and return the
    rendered page text. Opens a fresh tab so the operator's own tabs are
    never hijacked, closes it afterwards.
    Returns the text on success, None when no authenticated session is
    reachable or the render fails. Never falls back to anonymous fetch.
    """
    try:
        import urllib.request as _ur
        import urllib.parse as _up
        import json as _jj
        import time as _t
        import websocket  # type: ignore

        base = f"http://localhost:{cdp_port}"
        # fresh tab (never touch the operator's open tabs). Chrome
        # >= 111 requires PUT here; GET answers 405 and the render
        # silently died as CDP_RENDER_FAILED in live hunts.
        req = _ur.Request(
            f"{base}/json/new?about:blank",
            headers={"User-Agent": "oracle/1.0"},
            method="PUT",
        )
        tab = _jj.loads(_ur.urlopen(req, timeout=5).read())  # nosec B310
        ws_url = tab.get("webSocketDebuggerUrl")
        tab_id = tab.get("id")
        if not ws_url:
            return None
        ws = websocket.create_connection(ws_url, timeout=15)

        def _send(method, params=None, mid=1):
            ws.send(_jj.dumps({"id": mid, "method": method, "params": params or {}}))
            while True:
                msg = _jj.loads(ws.recv())
                if msg.get("id") == mid:
                    return msg.get("result", {})

        try:
            _send("Page.navigate", {"url": url}, 1)
            _t.sleep(wait)
            ev = _send(
                "Runtime.evaluate",
                {
                    "expression": "document.documentElement ? document.documentElement.innerText : ''",
                    "returnByValue": True,
                },
                2,
            )
            text = ((ev.get("result") or {}).get("value")) or ""
        finally:
            try:
                ws.close()
            except Exception:
                pass
            if tab_id:
                try:
                    _ur.urlopen(  # nosec B310
                        f"{base}/json/close/{_up.quote(str(tab_id))}", timeout=5
                    ).read()
                except Exception:
                    pass
        text = text.strip()
        return text if len(text) > 50 else None
    except Exception as e:
        # Fail loud with the reason: a silent None here presents as
        # CDP_RENDER_FAILED with no diagnosis (405 tab creation hid
        # exactly this way through a whole live hunt).
        _p(f"  [dim]cdp_page_text failed: {type(e).__name__}: {e}[/dim]")
        return None


def _cdp_available(cdp_port: int = 9227) -> bool:
    """True when the operator's logged-in Chromium answers on cdp_port."""
    try:
        import urllib.request as _ur
        import json as _jj

        tabs = _jj.loads(
            _ur.urlopen(
                f"http://localhost:{cdp_port}/json", timeout=3
            ).read()  # nosec B310
        )
        return isinstance(tabs, list)
    except Exception:
        return False


# ── Screenshot via CDP ────────────────────────────────────────────────────────


def _screenshot(url: str, out_path: Path, cdp_port: int = 9227, wait: int = 4) -> bool:
    """
    Take a full-page screenshot of url using the logged-in Chromium CDP session.
    Saves as PNG to out_path.  Returns True on success.
    """
    try:
        import urllib.request as _ur
        import json as _jj
        import time as _t
        import websocket  # type: ignore

        tabs = _jj.loads(
            _ur.urlopen(
                f"http://localhost:{cdp_port}/json", timeout=3
            ).read()  # nosec B310
        )
        tab = next((t for t in tabs if t.get("type") == "page"), None)
        if not tab or not tab.get("webSocketDebuggerUrl"):
            return False

        ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=12)

        def _send(method, params=None, mid=1):
            ws.send(_jj.dumps({"id": mid, "method": method, "params": params or {}}))
            while True:
                msg = _jj.loads(ws.recv())
                if msg.get("id") == mid:
                    return msg.get("result", {})

        _send("Page.navigate", {"url": url}, 1)
        _t.sleep(wait)
        result = _send("Page.captureScreenshot", {"format": "png", "fullPage": True}, 2)
        ws.close()

        data = result.get("data")
        if not data:
            return False
        import base64

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(base64.b64decode(data))
        return True
    except Exception:
        return False


# ── Asset download (enhanced) ─────────────────────────────────────────────────

CODE_FORGES = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "sourceforge.net",
    "raw.githubusercontent.com",
)

WEB_ASSET_TYPES = (
    "URL",
    "DOMAIN",
    "WILDCARD",
    "WEB",
    "WEB_APPLICATION",
    "API",
    "WEBSITE",
    "HOST",
    "SUBDOMAIN",
)


def _route_scope_records(prog: Dict) -> Dict:
    """Route every structured scope record to its intake lane.

    Lanes: web_hosts (fetched by the downloader), wildcards (parent domain
    fetched now; full expansion happens in recon), repos (cloned, never
    fetched as web hosts), contracts (0x addresses, never fetched as web),
    mobile (app-store IDs, skipped by the web downloader), notes (non-web
    text), excluded (not eligible for bounty/submission), other (eligible
    but unclassifiable — surfaced, never silently dropped).

    A REPO record like https://github.com/aave/aave-v4 must NEVER become
    a web target of github.com — that was the misclassification bug.
    """
    m = re.search(r"https?://([\w.\-]+)", prog.get("url") or "")
    platform_host = m.group(1).lower() if m else ""
    lanes: Dict[str, List[str]] = {
        "web_hosts": [],
        "wildcards": [],
        "repos": [],
        "contracts": [],
        "mobile": [],
        "notes": [],
        "excluded": [],
        "other": [],
    }
    for s in prog.get("structured_scopes", []):
        if not (
            s.get("eligible_for_bounty", True)
            and s.get("eligible_for_submission", True)
        ):
            lanes["excluded"].append(s.get("asset_identifier", ""))
            continue
        ident = (s.get("asset_identifier", "") or "").strip()
        atype = (s.get("asset_type", "") or "").upper()
        if atype in ("NOTE", "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"):
            lanes["mobile" if "APP_ID" in atype else "notes"].append(ident)
            continue
        body = ident.split("://", 1)[1] if "://" in ident else ident
        host = body.split("/")[0].split(":")[0].strip().lower()
        bare = host.lstrip("*.")
        # Contract addresses are not web hosts.
        if re.fullmatch(r"0x[0-9a-fA-F]{40}", ident.strip()) or atype == "CONTRACT":
            lanes["contracts"].append(ident)
            continue
        # Code forges are repos, never web targets.
        if host in CODE_FORGES or atype == "REPO":
            lanes["repos"].append(ident if "://" in ident else f"https://{ident}")
            continue
        if not bare or "." not in bare or " " in bare:
            lanes["other"].append(ident)
            continue
        if platform_host and (
            bare == platform_host or bare.endswith("." + platform_host)
        ):
            lanes["excluded"].append(ident)  # platform's own docs
            continue
        if atype == "WILDCARD" or host.startswith("*."):
            if bare not in lanes["wildcards"]:
                lanes["wildcards"].append(bare)
        elif atype in WEB_ASSET_TYPES or "://" in ident or "." in host:
            if bare not in lanes["web_hosts"]:
                lanes["web_hosts"].append(bare)
        else:
            lanes["other"].append(ident)
    return lanes


def _collect_asset_urls(prog: Dict) -> List[Tuple[str, str]]:
    """Build the (filename, url) fetch list for a program's assets.

    Every input — structured_scopes AND legacy flat scope/targets text —
    goes through _route_scope_records. No lane bypass: a legacy flat line
    like https://github.com/foo/bar is classified REPO and never fetched
    as a web host.
    For each in-scope web host: the homepage plus standard recon paths
    (openapi/swagger/api-docs/robots/security). The platform's own docs are
    never counted as target assets.
    """
    # Convert legacy flat http lines into pseudo scope records so they are
    # routed by the same classifier as structured records.
    extra: List[Dict] = []
    for field in ("scope", "targets"):
        val = prog.get(field, "")
        if isinstance(val, str):
            for line in val.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    atype = (
                        "REPO"
                        if re.search(
                            r"github\.com|gitlab\.com|bitbucket\.org|sourceforge\.net",
                            line,
                            re.I,
                        )
                        else "URL"
                    )
                    extra.append(
                        {
                            "asset_identifier": line,
                            "asset_type": atype,
                            "eligible_for_bounty": True,
                            "eligible_for_submission": True,
                            "instruction": "",
                            "max_severity": "",
                        }
                    )
    routed_prog = dict(prog)
    routed_prog["structured_scopes"] = list(prog.get("structured_scopes", [])) + extra

    # In-scope web hosts from the scope router: web lane + wildcard parent
    # domains. Repos, contracts, mobile IDs, notes never become web targets.
    routes = _route_scope_records(routed_prog)
    domains: List[str] = list(routes["web_hosts"])
    for w in routes["wildcards"]:
        if w not in domains:
            domains.append(w)

    urls_to_fetch: List[Tuple[str, str]] = []
    # Exact legacy URLs that routed to the web lane are fetched as-is once
    # (they may be deep links the standard paths don't cover). Only if their
    # domain survived routing (platform-owned/excluded domains stay out).
    web_domains = set(domains)
    for s in extra:
        if s["asset_type"] != "URL":
            continue
        u = s["asset_identifier"]
        dm = re.search(r"https?://([\w.\-]+)", u)
        if dm and dm.group(1).lower().lstrip("*.") in web_domains:
            fn = re.sub(
                r"[^\w.\-]", "_", u.replace("https://", "").replace("http://", "")
            )[:60]
            urls_to_fetch.append((f"scope_{fn}.txt", u))
    for domain in domains[:12]:
        for path, fname in [
            ("/openapi.json", "openapi.json"),
            ("/swagger.json", "swagger.json"),
            ("/api-docs", "api_docs.html"),
            ("/api/openapi.json", "api_openapi.json"),
            ("/v1/openapi.json", "v1_openapi.json"),
            ("/robots.txt", "robots.txt"),
            ("/.well-known/security.txt", "security.txt"),
        ]:
            urls_to_fetch.append((f"{domain}__{fname}", f"https://{domain}{path}"))

    # Homepage for EVERY in-scope web host (cheap, one request each) — the
    # 12-host cap above covers recon paths only, so no host is dropped.
    for domain in domains:
        urls_to_fetch.append((f"{domain}__homepage.html", f"https://{domain}/"))

    # Dedupe on filename, keep first occurrence
    seen, deduped = set(), []
    for fname, url in urls_to_fetch:
        if fname not in seen:
            seen.add(fname)
            deduped.append((fname, url))
    return deduped


def _clone_repos_gated(git_repo_urls, workspace_root: Path, prog: Dict):
    """Clone candidate repos ONLY through the hunter's in-scope gate.

    Candidate URLs come from untrusted program text, so this module must
    never run its own ``git clone``: the single gated path validates the
    URL shape, requires program-token overlap, and passes ``--`` before
    the URL. Returns ``repo:<dirname>`` saved markers.
    """
    from oracle_hunter import _clone_program_repos

    candidates = sorted(
        {str(u).split()[0].rstrip("/.,") for u in git_repo_urls if str(u).strip()}
    )
    if not candidates:
        return []
    cloned = _clone_program_repos(
        candidates, workspace_root / "repos", prog=prog
    )
    return [f"repo:{dest.name}" for dest in cloned]


def _cascade_fetch(url: str, timeout: int = 45) -> str:
    """Second, independent fetch path (Crawl4AI -> Jina -> Firecrawl ->
    plain GET via oracle_programs._fetch). CDP is excluded so this path
    never borrows the saved session: agreement between this render and
    the authenticated one is genuine cross-source corroboration.
    Fail-soft: any error returns "".
    """
    try:
        from oracle_programs import _fetch

        return _fetch(url, timeout=timeout, use_cdp=False) or ""
    except Exception:
        return ""


def _corroboration_metrics(prog: Dict, text: str) -> Dict:
    """Cheap agreement checks between an independent render and the
    program identity/scope we already hold: does the render name the
    program, and which in-scope hosts does it mention?"""
    low = (text or "").lower()
    name = str(prog.get("name") or "").lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", name) if len(t) >= 4]
    hosts = []
    for s in prog.get("structured_scopes") or []:
        if not isinstance(s, dict):
            continue
        ident = str(s.get("asset_identifier") or "").strip().lower()
        ident = re.sub(r"^https?://", "", ident).lstrip("*.").split("/")[0]
        if ident and ident in low and ident not in hosts:
            hosts.append(ident)
    return {
        "fetched": bool(text),
        "bytes": len(text or ""),
        "name_match": bool(tokens) and any(t in low for t in tokens),
        "scope_hits": hosts[:20],
        "scope_hit_count": len(hosts),
    }


def download_program_assets(
    prog: Dict,
    workspace_base: Path,
    cdp_port: int = 9227,
    take_screenshot: bool = True,
    clone_repos: bool = True,
):
    """
    Download every useful asset for a program:
      1. Git repositories for Web3 / smart contracts or open-source targets
         (skipped when clone_repos=False — callers may use the in-scope-gated
         _clone_program_repos from oracle_hunter instead)
      2. The program listing page (rendered text via the operator's LOGGED-IN
         Chromium session over CDP — see PLATFORM RULE below)
      3. Screenshot of the program page (CDP, logged-in session)
      4. Every in-scope URL in the program brief
      5. Common API doc endpoints on each in-scope domain (/openapi.json, /swagger.json)
      6. robots.txt and security.txt for each domain

    PLATFORM RULE (Alex): the program listing page is fetched ONLY through
    the operator's authenticated browser session. There is NO anonymous
    fallback for platform pages — a plain fetch returns SPA shells and login
    walls while reporting success. When no authenticated session is
    reachable, the page fetch fails LOUDLY (page_source recorded, nothing
    written) instead of pretending. Target-domain recon assets (steps 4-6)
    are the hunt target's own infrastructure, not platform pages, and stay
    on plain fetch.

    Returns (saved, info): saved is the filename list as before; info carries
    page_source ("cdp-authenticated" | "cached" | "NO_AUTH_SESSION" |
    "CDP_RENDER_FAILED") and auth_session (bool).
    """
    if workspace_base.name == "assets":
        workspace_assets = workspace_base
        workspace_root = workspace_base.parent
    else:
        workspace_root = workspace_base
        workspace_assets = workspace_base / "assets"

    workspace_assets.mkdir(parents=True, exist_ok=True)
    workspace_root.mkdir(parents=True, exist_ok=True)
    saved = []

    # 1. Check for Git Repositories (Web3 / open source targets)
    # (skipped when clone_repos=False — the caller handles repo intake,
    # e.g. the in-scope-gated _clone_program_repos in oracle_hunter)
    git_repo_urls = set()
    if clone_repos:
        if prog.get("repo_url"):
            git_repo_urls.add(prog["repo_url"])
        for s in prog.get("structured_scopes", []):
            ident = s.get("asset_identifier", "").strip()
            if "github.com/" in ident or "gitlab.com/" in ident:
                git_repo_urls.add(ident)
        for field in ("scope", "targets"):
            val = prog.get(field, "")
            if isinstance(val, str):
                for line in val.splitlines():
                    line = line.strip()
                    if (
                        "github.com/" in line or "gitlab.com/" in line
                    ) and " " not in line:
                        git_repo_urls.add(line)

    if git_repo_urls:
        saved.extend(_clone_repos_gated(git_repo_urls, workspace_root, prog))

    # Collect target URLs from the program dict
    urls_to_fetch = []

    # 2. Program listing page — AUTHENTICATED ONLY. The operator's logged-in
    # Chromium session renders the page (JS SPAs included) with their
    # platform logins. No anonymous fallback: plain fetches return shells.
    page_source = "none"
    page_corroboration: Dict[str, Any] = {"fetched": False, "bytes": 0,
                                          "name_match": False,
                                          "scope_hits": [], "scope_hit_count": 0}
    auth_session = _cdp_available(cdp_port)
    if prog.get("url"):
        out = workspace_assets / "program_page.txt"
        if out.exists():
            saved.append("program_page.txt")
            page_source = "cached"
        else:
            text = (
                _cdp_page_text(prog["url"], cdp_port=cdp_port) if auth_session else None
            )
            if text:
                out.write_text(text[:300_000], encoding="utf-8", errors="replace")
                saved.append("program_page.txt")
                page_source = "cdp-authenticated"
                _p("  [dim]↓ program_page.txt (authenticated session)[/dim]")
            else:
                page_source = "CDP_RENDER_FAILED" if auth_session else "NO_AUTH_SESSION"
                _p(
                    f"  [red]✗ program page: {page_source} — no anonymous fallback; "
                    f"start the logged-in Chromium with --remote-debugging-port={cdp_port}[/red]"
                )

        # Independent corroboration render (Crawl4AI/Jina/Firecrawl/GET,
        # never the saved session). It can cross-check the authenticated
        # page, but it NEVER substitutes for it: page_source above stays
        # authoritative and a login-wall corroboration proves nothing.
        corr_out = workspace_assets / "program_page_corroboration.txt"
        if corr_out.exists():
            corr_text = corr_out.read_text(encoding="utf-8", errors="replace")
            saved.append("program_page_corroboration.txt")
        else:
            corr_text = _cascade_fetch(prog["url"])
            if corr_text:
                corr_out.write_text(
                    corr_text[:300_000], encoding="utf-8", errors="replace"
                )
                saved.append("program_page_corroboration.txt")
        page_corroboration = _corroboration_metrics(prog, corr_text)
        _p(
            "  [dim]page corroboration: "
            f"fetched={page_corroboration['fetched']} "
            f"name_match={page_corroboration['name_match']} "
            f"scope_hits={page_corroboration['scope_hit_count']}[/dim]"
        )

    # 3-5. Asset URLs from every scope format (bare domains, wildcards,
    # typed assets — not just URL/WILDCARD http idents). Platform's own
    # domain is excluded: its docs are not target assets.
    urls_to_fetch = _collect_asset_urls(prog)

    # Fetch each URL — every attempt is recorded so the download is
    # verifiable: expected (from scope) vs fetched, with status/error.
    import requests as _req

    fetch_results: List[Dict[str, Any]] = []
    for fname, url in urls_to_fetch[
        :160
    ]:  # raised cap: homepages for all hosts + 12x7 recon paths
        out = workspace_assets / fname
        if out.exists():
            saved.append(fname)
            fetch_results.append(
                {"file": fname, "url": url, "status": "cached", "via": "cached"}
            )
            continue
        plain_error = ""
        plain_status: Any = "fetch-failed"
        try:
            r = _req.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OracleScan/1.0)"},
                timeout=10,
                allow_redirects=True,
            )
            plain_status = r.status_code
            if r.ok and len(r.text) > 50:
                out.write_text(r.text[:300_000], encoding="utf-8", errors="replace")
                saved.append(fname)
                fetch_results.append(
                    {
                        "file": fname,
                        "url": url,
                        "status": r.status_code,
                        "via": "plain-get",
                        "bytes": len(r.text),
                    }
                )
                _p(f"  [dim]↓ {fname}[/dim]")
                continue
            plain_error = "empty-or-not-ok"
        except Exception as e:
            plain_error = f"{type(e).__name__}: {str(e)[:80]}"

        # Second path for renderable assets (homepages / HTML / text):
        # the shared cascade can render JS pages plain GET cannot. Its
        # content is saved for analysis but counted separately
        # ("cascade" is not a verified 2xx fetch) so multi-path data
        # never inflates the verified-download counts.
        cascade_text = ""
        if fname.endswith((".html", ".txt")):
            cascade_text = _cascade_fetch(url)
        if cascade_text and len(cascade_text) > 50:
            out.write_text(
                cascade_text[:300_000], encoding="utf-8", errors="replace"
            )
            saved.append(fname)
            fetch_results.append(
                {
                    "file": fname,
                    "url": url,
                    "status": "cascade",
                    "via": "cascade",
                    "bytes": len(cascade_text),
                    "plain_status": plain_status,
                    "plain_error": plain_error,
                }
            )
            _p(f"  [dim]↓ {fname} (cascade)[/dim]")
        else:
            fetch_results.append(
                {
                    "file": fname,
                    "url": url,
                    "status": plain_status,
                    "via": "plain-get",
                    "error": plain_error,
                }
            )

    # Download verification report: what the scope said vs what we got.
    # Only 2xx HTTP (or a cache hit) counts as fetched-ok; non-2xx int
    # statuses are failures, not successes.
    def _ok(r):
        st = r["status"]
        return st == "cached" or (isinstance(st, int) and 200 <= st < 300)

    fetched_ok = sum(1 for r in fetch_results if _ok(r))
    fetched_fail = sum(1 for r in fetch_results if not _ok(r))
    attempted = len(fetch_results)
    unattempted = max(0, len(urls_to_fetch) - attempted)
    scope_recs = prog.get("structured_scopes", [])
    scope_eligible = sum(
        1
        for s in scope_recs
        if s.get("eligible_for_bounty", True) and s.get("eligible_for_submission", True)
    )
    routes = _route_scope_records(prog)
    host_results: Dict[str, Dict[str, int]] = {}
    for rec in fetch_results:
        host = re.search(r"https?://([\w.\-]+)", rec["url"])
        hostname = host.group(1) if host else "?"
        hr = host_results.setdefault(hostname, {"fetched": 0, "failed": 0, "cached": 0})
        if rec["status"] == "cached":
            hr["cached"] += 1
        elif _ok(rec):
            hr["fetched"] += 1
        else:
            hr["failed"] += 1
    report = {
        "program": prog.get("name"),
        "platform": prog.get("platform"),
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "scope_expected": len(scope_recs),
        "scope_eligible": scope_eligible,
        "scope_excluded": len(scope_recs) - scope_eligible,
        "routing": {lane: len(v) for lane, v in routes.items()},
        "expected_urls": len(urls_to_fetch),
        "attempted_urls": attempted,
        "unattempted_urls": unattempted,
        "fetched_ok": fetched_ok,
        "fetched_fail": fetched_fail,
        "cached": sum(1 for r in fetch_results if r["status"] == "cached"),
        "hosts": host_results,
        "results": fetch_results,
        "page_source": page_source,
        "auth_session": auth_session,
        "page_corroboration": page_corroboration,
        "cascade_fetched": sum(
            1 for r in fetch_results if r.get("via") == "cascade"
        ),
    }
    (workspace_root / "download_report.json").write_text(json.dumps(report, indent=1))
    _p(
        f"  [dim]download_report.json: {fetched_ok} ok / {fetched_fail} failed / "
        f"{len(host_results)} hosts[/dim]"
    )

    # Screenshot
    if take_screenshot and prog.get("url"):
        ss_path = workspace_assets / "screenshot.png"
        if not ss_path.exists():
            ok = _screenshot(prog["url"], ss_path, cdp_port=cdp_port)
            if ok:
                _p("  [dim]📸 screenshot.png[/dim]")
                saved.append("screenshot.png")

    return saved, {
        "page_source": page_source,
        "auth_session": auth_session,
        "page_corroboration": page_corroboration,
    }


# ── Hunt one program ───────────────────────────────────────────────────────────


def hunt_program(prog: Dict, cfg: Dict, args):
    """
    Run the full Oracle hunt on a single program using cmd_hunt from oracle_hunter.
    Applies all config settings as if they were CLI flags.
    """
    from oracle_hunter import cmd_hunt

    hunt_cfg = cfg.get("hunt", {})
    filter_cfg = cfg.get("filter", {})
    researcher = cfg.get("researcher", {}).get("handle", "")

    # ── Inline scope intake ──────────────────────────────────────────────────
    # Run the platform scope adapter and persist the result to program.json so
    # cmd_hunt → _scope_from_programs picks up real scope (not the empty cache).
    if not (prog.get("structured_scopes") or []):
        try:
            from oracle_bulk_download import intake_program_scopes

            scopes, status = intake_program_scopes(prog)
            if scopes:
                prog["structured_scopes"] = scopes
                prog["scope_status"] = "scope-fetched"
                prog["intake_status"] = "scope-fetched"
                _p(
                    f"[green]✓[/green] Scope intake: {len(scopes)} asset(s) → [bold]{prog.get('name')}[/bold]"
                )
            else:
                prog["scope_status"] = {
                    "empty": "no-scope",
                    "client-rendered": "scope-needs-browser",
                    "no-adapter": "scope-unsupported",
                    "error": "scope-intake-failed",
                }.get(status, "scope-intake-failed")
                prog["intake_status"] = prog["scope_status"]
                _p(
                    f"[yellow]⚠[/yellow] Scope intake: {status} for [bold]{prog.get('name')}[/bold]"
                )
        except Exception as _se:
            _p(f"[yellow]⚠[/yellow] Scope intake: {_se}")

    # Persist prog (with structured_scopes) to the workspace program.json so
    # cmd_hunt's _scope_from_programs() reads real scope from disk — not cache.
    try:
        from oracle_mindset_context import ProgramWorkspace
        from oracle_hunter import TARGETS_DIR

        _ws = ProgramWorkspace(prog, base=TARGETS_DIR)
        _ws.save_program_json()
    except Exception as _we:
        _p(f"[yellow]⚠[/yellow] Could not persist program.json: {_we}")

    # Build a minimal args namespace — use SimpleNamespace to avoid class-body scoping issues
    import types

    _cloud = hunt_cfg.get("cloud", True)
    _a = types.SimpleNamespace(
        cloud=_cloud,
        no_cloud=not _cloud,
        model=__import__("oracle_llm").load_backend_config()["local_model"],
        verify=hunt_cfg.get("verify", True),
        auto=hunt_cfg.get("auto", False),
        testnet=hunt_cfg.get("testnet", False),
        code=None,
        auth=None,
        cookie=None,
        account_a=None,
        account_b=None,
        prompt_login=False,
        fast_triage=filter_cfg.get("fast_triage_only", False),
        min_payout=filter_cfg.get("min_payout_usd", 0),
        max_payout=filter_cfg.get("max_payout_usd", 0),
        auto_pick=False,
        researcher=researcher,
    )

    # Override from CLI args if provided
    for attr in (
        "cloud",
        "verify",
        "auto",
        "testnet",
        "code",
        "auth",
        "cookie",
        "model",
    ):
        if hasattr(args, attr) and getattr(args, attr) is not None:
            setattr(_a, attr, getattr(args, attr))

    name = prog.get("name", "")
    _banner(f"Hunting: {prog['platform']} / {name}")
    cmd_hunt(name, _a)


# ── Status check ──────────────────────────────────────────────────────────────


def cmd_status(cfg: Dict):
    from oracle_hunter import cmd_status as _hs

    _hs()

    _banner("oracle_scan config summary")
    scan_cfg = cfg.get("scan", {})
    filter_cfg = cfg.get("filter", {})
    hunt_cfg = cfg.get("hunt", {})
    configured_platforms = scan_cfg.get("platforms", "all")
    platforms_label = (
        "all"
        if configured_platforms in (None, "", "all", ["all"])
        else (
            ", ".join(configured_platforms)
            if isinstance(configured_platforms, list)
            else str(configured_platforms)
        )
    )
    print(f"  platforms : {platforms_label}")
    print(f"  min_payout: ${filter_cfg.get('min_payout_usd', 0):,}")
    print(f"  max_reports:{filter_cfg.get('max_resolved_reports', '—')}")
    print(f"  fast_triage:{filter_cfg.get('fast_triage_only', False)}")
    print(
        f"  web2/web3  : {filter_cfg.get('web2', '?')} / {filter_cfg.get('web3', '?')}"
    )
    print(f"  top_n      : {filter_cfg.get('top_n', 25)}")
    print(f"  verify     : {hunt_cfg.get('verify', True)}")
    print(f"  cloud      : {hunt_cfg.get('cloud', True)}")
    print(f"  screenshot : {hunt_cfg.get('screenshot', True)}")

    # Invisible seam check
    try:
        from oracle_code_seam import _INVISIBLE_SEAM_AVAILABLE

        if _INVISIBLE_SEAM_AVAILABLE:
            _p("  [green]✓ invisible_seam[/green]: available (Type-1 engine live)")
        else:
            _p(
                "  [yellow]✗ invisible_seam[/yellow]: not importable (Type-1 engine will be skipped)"
            )
    except Exception:
        _p("  [yellow]? invisible_seam[/yellow]: unknown state")


# ── Interactive picker ────────────────────────────────────────────────────────


def interactive_pick(programs: List[Dict]) -> List[Dict]:
    """Show the list and ask which programs to hunt. Returns chosen programs."""
    display_programs(programs)
    if not programs:
        return []

    while True:
        try:
            raw = (
                input(
                    "\nPick [1-N / 1-5 / per:N (e.g. per:3 for 3 per platform) / all / q]: "
                )
                .strip()
                .lower()
            )
        except (EOFError, KeyboardInterrupt):
            return []

        if raw in ("q", "quit", "exit", ""):
            return []
        if raw == "all":
            return list(programs)

        # per-platform syntax: "per:3", "p:3", "per 3"
        m_per = re.match(r"^(?:per|p|each)[:\s]+(\d+)$", raw)
        if m_per:
            n = int(m_per.group(1))
            picked = pick_per_platform(programs, n)
            _p(
                f"[green]Selected {len(picked)} program(s) (top {n} per platform)[/green]"
            )
            return picked

        # Single number
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(programs):
                return [programs[idx]]
            _p(f"[red]Out of range (1–{len(programs)})[/red]")
            continue

        # Range: "1-5"
        m = re.match(r"^(\d+)\s*[-,]\s*(\d+)$", raw)
        if m:
            lo, hi = int(m.group(1)) - 1, int(m.group(2)) - 1
            lo, hi = max(0, lo), min(len(programs) - 1, hi)
            return programs[lo : hi + 1]

        _p(
            "[yellow]Enter a number (1), a range (1-5), 'per:N' (e.g. per:3), 'all', or 'q'[/yellow]"
        )


def display_assets_report(chosen: List[Dict], download_results: Dict[str, Dict]):
    """Display the Asset Intake Report showing all downloaded companies and their folders."""
    _banner(f"Asset Intake Complete — {len(chosen)} Target(s) Ready")

    if RICH:
        tbl = Table(show_header=True, show_lines=True)
        tbl.add_column("#", style="bold dim", no_wrap=True)
        tbl.add_column("Platform", style="cyan", no_wrap=True)
        tbl.add_column("Program / Company", style="bold white")
        tbl.add_column("Target Workspace Folder", style="yellow")
        tbl.add_column("Assets Acquired", style="green")
        tbl.add_column("Readiness", justify="center", style="bold green")

        for i, p in enumerate(chosen, 1):
            name = p.get("name", "unknown")
            res = download_results.get(name, {})
            folder_str = str(
                res.get("rel_folder", f"targets/{p.get('platform')}/{name}")
            )
            assets_summary = res.get("summary", f"{res.get('count', 0)} asset(s)")
            tbl.add_row(
                str(i),
                p.get("platform", ""),
                name[:36],
                folder_str,
                assets_summary,
                "✓ READY",
            )
        console.print(tbl)
    else:
        hdr = f"{'#':<3} {'Platform':<12} {'Company':<28} {'Folder':<35} {'Assets':<20} {'Status'}"
        print(hdr)
        print("─" * len(hdr))
        for i, p in enumerate(chosen, 1):
            name = p.get("name", "unknown")
            res = download_results.get(name, {})
            folder_str = str(
                res.get("rel_folder", f"targets/{p.get('platform')}/{name}")
            )[:34]
            assets_summary = res.get("summary", f"{res.get('count', 0)} asset(s)")[:19]
            print(
                f"{i:<3} {p.get('platform', ''):<12} {name[:26]:<28} {folder_str:<35} {assets_summary:<20} READY"
            )
    print()


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    """Retired CLI entry point.

    The helpers in this module remain importable for the P11 download path
    and tests, but this file is no longer a pipeline entry point. Any caller
    reaching here previously bypassed the authenticated Scan4Me prescan and
    the Oracle verify/handoff step.
    """
    print(
        "oracle_scan.py is retired — it bypasses the verified pipeline.\n"
        "\n"
        "Use:\n"
        "  oracle-hunter prescan --sync\n"
        "  oracle-hunter scan -N 1 --download\n"
        "  oracle-hunter queue --execute\n"
        "\n"
        "Helpers in oracle_scan remain importable for P11 downloads and tests.\n"
        "Run logs: reports/runs/latest.json\n",
        file=sys.stderr,
    )
    raise SystemExit(2)

if __name__ == "__main__":
    main()
