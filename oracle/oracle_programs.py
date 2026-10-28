#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: fetch_all_programs, filter_programs, normalize_program_record, save_session_cookies, main  # noqa: E501
# TOPICS: none
"""
Oracle Programs — Bug Bounty Program Discovery
───────────────────────────────────────────────
Logs into your bug bounty accounts, crawls all program listings,
filters by your criteria (min payout, triage speed, scope type),
and outputs a ranked list of programs worth hunting.

Platforms supported:
  HackerOne     — API key (preferred) or browser scrape
  Bugcrowd      — browser scrape (logged-in)
  Intigriti     — browser scrape (logged-in)
  HackenProof   — API key (preferred) or browser scrape
  Immunefi      — public API / scrape (no login needed)
  Bugbase       — browser scrape

Additional platforms (open to more):
  YesWeHack     — browser scrape
  HatsFinance   — public scrape

Usage:
    python3 oracle_programs.py list                       # list all programs (cached or fresh)
    python3 oracle_programs.py list --refresh             # force fresh scrape
    python3 oracle_programs.py list --min-payout 500      # filter: $500+ critical
    python3 oracle_programs.py list --platform hackerone  # one platform only
    python3 oracle_programs.py list --fast-triage         # fast-triage programs only
    python3 oracle_programs.py list --web2 --web3         # filter by scope type
    python3 oracle_programs.py list --top 20              # top 20 by payout
    python3 oracle_programs.py save <program_name>        # save a program's full scope to disk
    python3 oracle_programs.py check-keys                 # show which API keys are configured
"""

import os
import re
import sys
import json
import math
import time
import argparse
import subprocess
import logging
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, List, Dict, Any, Tuple
from urllib.parse import urljoin

log = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.table import Table

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
CACHE_FILE = _HERE / "programs_cache.json"
ENV_FILE = _HERE / ".env"
ORACLE_KEYS_FILE = _HERE / "ORACLE_KEYS.env"
TRIO_KEYS_FILE = Path.home() / ".config" / "trio" / "keys.env"
_CREDENTIAL_SUFFIXES = ("_API_KEY", "_API_TOKEN", "_TOKEN", "_JWT", "_SECRET")

# ── Chromium Code profile (logged-in sessions for all bounty platforms) ────────
CHROMIUM_USER_DATA = Path(
    os.environ.get(
        "CHROMIUM_USER_DATA", str(Path.home() / "snap/chromium/common/chromium")
    )
)
CHROMIUM_PROFILE = "Profile 2"  # "Code" — has sessions for all platforms
CHROMIUM_CDP_PORT = 9227  # separate port so it never clashes with oracle_email

# ── Platform definitions ───────────────────────────────────────────────────────
PLATFORMS = {
    "hackerone": {
        "label": "HackerOne",
        "kind": "web2",
        "url": "https://hackerone.com/opportunities/all",
        "api": True,
    },
    "bugcrowd": {
        "label": "Bugcrowd",
        "kind": "web2",
        "url": "https://bugcrowd.com/engagements",
        "api": False,
    },
    "intigriti": {
        "label": "Intigriti",
        "kind": "web2",
        "url": "https://app.intigriti.com/researcher/programs",
        "api": False,
    },
    "hackenproof": {
        "label": "HackenProof",
        "kind": "web3",
        "url": "https://hackenproof.com/programs",
        "api": True,
    },
    "immunefi": {
        "label": "Immunefi",
        "kind": "web3",
        "url": "https://immunefi.com/explore/",
        "api": True,
    },
    "bugbase": {
        "label": "Bugbase",
        "kind": "web2",
        "url": "https://bugbase.in/programs",
        "api": False,
    },
    "yeswehack": {
        "label": "YesWeHack",
        "kind": "web2",
        "url": "https://yeswehack.com/programs",
        "api": False,
    },
    "hatsfinance": {
        "label": "Hats Finance",
        "kind": "web3",
        "url": "https://app.hats.finance/bug-bounties",
        "api": False,
    },
    "cantina": {
        "label": "Cantina",
        "kind": "web3",
        "url": "https://cantina.xyz/opportunities",
        "api": False,
    },
    "sherlock": {
        "label": "Sherlock",
        "kind": "web3",
        "url": "https://audits.sherlock.xyz/bug-bounties",
        "api": False,
    },
    "codehawks": {
        "label": "CodeHawks",
        "kind": "web3",
        "url": "https://codehawks.cyfrin.io/contests",
        "api": False,
    },
    "patchstack": {
        "label": "Patchstack",
        "kind": "web2",
        "url": "https://patchstack.com/database/vdp",
        "api": False,
    },
    "huntr": {
        "label": "Huntr",
        "kind": "ai",
        "url": "https://huntr.com/challenges",
        "api": False,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# .env loader
# ─────────────────────────────────────────────────────────────────────────────


def _load_env() -> Dict[str, str]:
    # Same layering as oracle_hunter._load_env: ORACLE_KEYS.env holds
    # platform keys absent from .env; repo .env overrides it; empty
    # placeholders never clobber a real key.
    store: Dict[str, str] = {}
    for env_file in (TRIO_KEYS_FILE, ORACLE_KEYS_FILE, ENV_FILE):
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    v = v.strip().strip('"').strip("'")
                    if v and not (
                        k.strip().endswith(_CREDENTIAL_SUFFIXES)
                        and any(c.isspace() for c in v)
                    ):
                        store[k.strip()] = v
    # Process environment wins — same precedence as oracle_hunter._load_env.
    # Empty process values never clobber a real file key.
    store.update({k: v for k, v in os.environ.items() if v})
    for k in [k for k in store if k.endswith(_CREDENTIAL_SUFFIXES)]:
        if any(c.isspace() for c in store[k]):
            del store[k]
    return store


def _key(name: str) -> Optional[str]:
    value = _load_env().get(name) or None
    if value and any(c.isspace() for c in value):
        return None  # placeholder sentence, not a credential
    return value


# ── --no-cloud enforcement ──────────────────────────────────────────────────
# When True, _fetch() skips the Firecrawl cloud scrape step (api.firecrawl.dev)
# and falls back to CDP / plain GET. Set from oracle_hunter when --no-cloud
# is passed. Plain GETs to bounty platforms/targets are the hunt itself and
# are NOT gated — only the third-party cloud scrape service is.
NO_CLOUD = False


# ─────────────────────────────────────────────────────────────────────────────
# CDP helpers — logged-in Chromium Code profile
# ─────────────────────────────────────────────────────────────────────────────


def _tabs_list(port: int = CHROMIUM_CDP_PORT) -> Optional[list]:
    import urllib.request
    import json as _json

    try:
        with urllib.request.urlopen(
            f"http://localhost:{port}/json", timeout=3
        ) as r:  # nosec B310
            return _json.loads(r.read())
    except Exception:
        return None


# Cookie snapshot: saved by save_session_cookies() from the warm visible browser,
# restored into headless by _restore_session_cookies() after Chrome starts.
_COOKIE_SNAPSHOT = CHROMIUM_USER_DATA / CHROMIUM_PROFILE / "oracle_session_cookies.json"

_BOUNTY_HOSTS = [
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
    "hackenproof.com",
    "immunefi.com",
    "cantina.xyz",
    "codehawks.cyfrin.io",
    "sherlock.xyz",
    "bugbase.ai",
    "hckrt.com",
    "bugbop.com",
    "huntr.com",
]


def save_session_cookies(port: int = CHROMIUM_CDP_PORT) -> int:
    """Snapshot all bounty-platform cookies from the warm browser to disk.

    Call this while Chrome is running visibly (logged-in sessions alive).
    The snapshot is restored automatically the next time headless Chrome starts.
    Returns the number of cookies saved.
    """
    if _tabs_list(port) is None:
        log.warning("save_session_cookies: no browser on port %d", port)
        return 0
    try:
        import websocket as _ws

        with urllib.request.urlopen(  # nosec B310
            f"http://localhost:{port}/json/version", timeout=5
        ) as r:
            info = json.loads(r.read())
        ws_url = info.get("webSocketDebuggerUrl")
        if not ws_url:
            return 0
        ws = _ws.create_connection(ws_url, timeout=10)
        ws.send(json.dumps({"id": 1, "method": "Storage.getCookies", "params": {}}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == 1:
                break
        ws.close()
        all_cookies = msg.get("result", {}).get("cookies", [])
        bounty_cookies = [
            c
            for c in all_cookies
            if any(h in c.get("domain", "") for h in _BOUNTY_HOSTS)
        ]
        # Credential-at-rest: these are live platform auth cookies. Write
        # owner-only (0600) atomically, and enforce 0600 on any pre-existing
        # snapshot — default write_text() leaves it group/world-readable.
        _fd = os.open(_COOKIE_SNAPSHOT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as _f:
            json.dump(bounty_cookies, _f, indent=2)
        os.chmod(_COOKIE_SNAPSHOT, 0o600)
        log.info(
            "save_session_cookies: %d cookies saved to %s",
            len(bounty_cookies),
            _COOKIE_SNAPSHOT,
        )
        return len(bounty_cookies)
    except Exception as e:
        log.warning("save_session_cookies failed: %s", e)
        return 0


def _restore_session_cookies(port: int = CHROMIUM_CDP_PORT) -> int:
    """Restore the saved cookie snapshot into the running headless browser.

    Called automatically by _ensure_chromium_cdp after headless starts.
    Returns the number of cookies restored.
    """
    if not _COOKIE_SNAPSHOT.exists():
        return 0
    try:
        cookies = json.loads(_COOKIE_SNAPSHOT.read_text(encoding="utf-8"))
        if not cookies:
            return 0
        import websocket as _ws

        with urllib.request.urlopen(  # nosec B310
            f"http://localhost:{port}/json/version", timeout=5
        ) as r:
            info = json.loads(r.read())
        ws_url = info.get("webSocketDebuggerUrl")
        if not ws_url:
            return 0
        ws = _ws.create_connection(ws_url, timeout=10)
        restored = 0
        for i, c in enumerate(cookies):
            # Strip fields Chrome won't accept back
            payload = {
                k: v
                for k, v in c.items()
                if k
                in (
                    "name",
                    "value",
                    "domain",
                    "path",
                    "secure",
                    "httpOnly",
                    "sameSite",
                    "expires",
                )
            }
            ws.send(
                json.dumps(
                    {"id": i + 100, "method": "Storage.setCookie", "params": payload}
                )
            )
            result = json.loads(ws.recv())
            if result.get("result", {}).get("success"):
                restored += 1
        ws.close()
        log.info(
            "_restore_session_cookies: %d/%d cookies restored", restored, len(cookies)
        )
        return restored
    except Exception as e:
        log.warning("_restore_session_cookies failed: %s", e)
        return 0


def _ensure_chromium_cdp(port: int = CHROMIUM_CDP_PORT) -> bool:
    """Ensure Chromium Code profile is up and listening on the CDP port.

    If a warm browser is already running on the port, reuse it (cookies intact).
    If not, launch headless and restore the saved cookie snapshot so scrapers
    get the same logged-in sessions without requiring a visible browser.
    """
    if _tabs_list(port) is not None:
        return True  # already running — cookies are live, nothing to do
    try:
        subprocess.Popen(
            [
                "/snap/bin/chromium",
                f"--remote-debugging-port={port}",
                "--remote-allow-origins=*",
                f"--user-data-dir={CHROMIUM_USER_DATA}",
                f"--profile-directory={CHROMIUM_PROFILE}",
                "--headless=new",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-gpu",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(20):
            time.sleep(0.5)
            if _tabs_list(port) is not None:
                # Restore saved sessions into the fresh headless instance
                _restore_session_cookies(port)
                return True
        log.warning("cdp: chromium did not come up on port %d", port)
        return False
    except Exception as e:
        log.warning("cdp: launch failed: %s", e)
        return False


def _cdp_fetch(url: str, wait: int = 6, port: int = CHROMIUM_CDP_PORT) -> Optional[str]:
    """
    Navigate to url in the logged-in Chromium Code profile via CDP and return
    the rendered page text.  Launches Chromium headless if not already running
    on the given port.  Returns None on any failure.
    """
    import json as _json
    import time as _time

    if not _ensure_chromium_cdp(port):
        return None

    tabs = _tabs_list(port)
    if not tabs:
        return None

    # Find an existing page tab or use the first one
    tab = next((t for t in tabs if t.get("type") == "page"), tabs[0])
    ws_url = tab.get("webSocketDebuggerUrl")
    if not ws_url:
        return None

    try:
        import websocket  # websocket-client
    except ImportError:
        log.warning(
            "cdp_fetch: websocket-client not installed — pip install websocket-client"
        )
        return None

    try:
        ws = websocket.create_connection(ws_url, timeout=15)

        def _send(method: str, params: Optional[dict] = None, msg_id: int = 1) -> dict:
            ws.send(
                _json.dumps({"id": msg_id, "method": method, "params": params or {}})
            )
            while True:
                msg = _json.loads(ws.recv())
                if msg.get("id") == msg_id:
                    return msg.get("result", {})

        _send("Page.navigate", {"url": url}, 1)
        _time.sleep(wait)
        result = _send(
            "Runtime.evaluate",
            {
                "expression": "document.body.innerText",
                "returnByValue": True,
            },
            2,
        )
        ws.close()
        return result.get("result", {}).get("value")
    except Exception as e:
        log.warning("cdp_fetch %s failed: %s", url, e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────


def _get(
    url: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
    redirect_validator: Optional[Callable[[str], bool]] = None,
) -> Optional[str]:
    """Fetch an HTTP URL, validating every redirect destination when supplied."""
    try:
        import requests

        current = url
        request_headers = headers or {
            "User-Agent": "Mozilla/5.0 (compatible; OracleBounty/1.0)"
        }
        for _ in range(6):
            if redirect_validator and not redirect_validator(current):
                log.warning("blocked out-of-scope redirect target: %s", current)
                return None
            r = requests.get(
                current,
                headers=request_headers,
                timeout=timeout,
                allow_redirects=False,
            )
            if not r.is_redirect and not r.is_permanent_redirect:
                return r.text if r.ok else None
            location = r.headers.get("Location")
            if not location:
                return None
            current = urljoin(current, location)
        log.warning("GET %s exceeded redirect limit", url)
        return None
    except Exception as e:
        log.warning("GET %s failed: %s", url, e)
        return None


def _jina_reader(
    url: str, api_key: Optional[str] = None, timeout: int = 30
) -> Optional[str]:
    """Fetch clean content via Jina Reader (r.jina.ai) — zero-cost cloud LLM markdown scraper."""
    try:
        import urllib.request

        jina_url = f"https://r.jina.ai/{url}"
        headers = {
            "User-Agent": "Oracle-Security-Engine/1.0",
            "X-Return-Format": "markdown",
        }
        key = api_key or _key("JINA_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(jina_url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            content = resp.read().decode("utf-8", errors="ignore")
            if content and len(content) > 100:
                return content
    except Exception as e:
        log.warning("jina reader %s failed: %s", url, e)
    return None


def _ensure_playwright_browsers() -> Optional[str]:
    """Pin Playwright browser resolution so Crawl4AI works no matter which HOME
    launched this process. Sandboxed launchers override HOME to dirs without
    browsers; in that case fall back to the passwd-entry home of this uid.
    Returns the browsers dir in effect, or None when no chromium build exists
    anywhere (caller must log loudly — never silently degrade)."""
    import glob

    def _has_chromium(d):
        return bool(d) and bool(glob.glob(os.path.join(d, "chromium*")))

    explicit = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if _has_chromium(explicit):
        return explicit
    home_cache = os.path.join(os.path.expanduser("~"), ".cache", "ms-playwright")
    if _has_chromium(home_cache):
        return home_cache
    try:
        import pwd

        real_home = pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        real_home = None
    real_cache = (
        os.path.join(real_home, ".cache", "ms-playwright") if real_home else None
    )
    if _has_chromium(real_cache):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = real_cache
        log.warning(
            "PLAYWRIGHT_BROWSERS_PATH pinned to %s (HOME=%s has no browsers)",
            real_cache,
            os.environ.get("HOME"),
        )
        return real_cache
    return None


def _crawl4ai(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch JS-rendered page via local Crawl4AI (runs locally, zero cloud credits)."""
    if _ensure_playwright_browsers() is None:
        log.warning(
            "crawl4ai %s skipped: no Playwright chromium under HOME=%s; "
            "launcher must run `playwright install`",
            url,
            os.environ.get("HOME"),
        )
        return None
    try:
        import asyncio
        from crawl4ai import AsyncWebCrawler

        async def _run():
            async with AsyncWebCrawler() as crawler:
                res = await crawler.arun(url=url)
                return res.html or res.markdown or None

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(asyncio.run, _run()).result(timeout=timeout)
            else:
                return loop.run_until_complete(_run())
        except RuntimeError:
            return asyncio.run(_run())
    except Exception as e:
        log.warning("crawl4ai %s failed: %s", url, e)
    return None


def _firecrawl(url: str, api_key: str, timeout: int = 60) -> Optional[str]:
    """JS-rendered scrape via Firecrawl — needed for React/Next.js program pages."""
    try:
        import requests

        r = requests.post(
            "https://api.firecrawl.dev/v1/scrape",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={"url": url, "formats": ["rawHtml"]},
            timeout=timeout,
        )
        if r.ok:
            data = r.json().get("data") or {}
            return data.get("rawHtml") or data.get("html") or None
        log.warning("firecrawl %s failed: HTTP %s", url, r.status_code)
    except Exception as e:
        log.warning("firecrawl %s failed: %s", url, e)
    return None


def _fetch(
    url: str,
    firecrawl_key: Optional[str] = None,
    timeout: int = 60,
    use_cdp: bool = True,
    redirect_validator: Optional[Callable[[str], bool]] = None,
) -> str:
    """Cascade:
    1. CDP (logged-in Chromium)
    2. Crawl4AI (local Playwright headless, $0, handles --no-cloud)
    3. Jina Reader (cloud markdown, 10M tokens free)
    4. Firecrawl (cloud fallback)
    5. Plain HTTP GET
    Never crashes."""
    if "://" not in url:
        # Schemeless input (bare host from recon): curl-consistent default.
        # HTTPS redirect targets are followed by every cascade stage.
        url = "http://" + url.lstrip("/")
    if redirect_validator:
        # Browser and cloud renderers cannot expose every redirect hop to this
        # policy boundary, so scoped asset retrieval uses the local HTTP path.
        return _get(
            url, timeout=timeout, redirect_validator=redirect_validator
        ) or ""
    if use_cdp:
        html = _cdp_fetch(url)
        if html and len(html) > 200:
            return html

    # Local JS rendering (works even in --no-cloud mode)
    c4ai_res = _crawl4ai(url, timeout=min(timeout, 25))
    if c4ai_res and len(c4ai_res) > 200:
        return c4ai_res

    # Cloud renderers (skipped with --no-cloud)
    if not NO_CLOUD:
        jina_res = _jina_reader(url, timeout=min(timeout, 25))
        if jina_res and len(jina_res) > 200:
            return jina_res

        fc_key = firecrawl_key or _key("FIRECRAWL_API_KEY")
        if fc_key:
            html = _firecrawl(url, fc_key, timeout)
            if html:
                return html
    elif firecrawl_key or _key("FIRECRAWL_API_KEY"):
        log.warning(
            "--no-cloud: skipping cloud scrape for %s (local Crawl4AI / plain GET only)",
            url,
        )

    return _get(url, timeout=timeout) or ""


# ─────────────────────────────────────────────────────────────────────────────
# Per-platform scrapers
# ─────────────────────────────────────────────────────────────────────────────


def _cdp_get_cookies(host: str) -> Dict[str, str]:
    """Pull cookies for a given host using the browser-level CDP endpoint."""
    _ensure_chromium_cdp(CHROMIUM_CDP_PORT)
    try:
        import websocket

        # Use /json/version to get the browser websocket URL (works even with no page tabs)
        with urllib.request.urlopen(  # nosec B310
            f"http://localhost:{CHROMIUM_CDP_PORT}/json/version", timeout=5
        ) as r:
            info = json.loads(r.read())
        ws_url = info.get("webSocketDebuggerUrl")
        if not ws_url:
            return {}
        ws = websocket.create_connection(ws_url, timeout=10)
        ws.send(json.dumps({"id": 1, "method": "Storage.getCookies", "params": {}}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == 1:
                break
        ws.close()
        all_cookies = msg.get("result", {}).get("cookies", [])

        # Match cookies whose domain is a suffix of the requested host
        # e.g. domain=".bugcrowd.com" matches host="bugcrowd.com" or "app.bugcrowd.com"
        def _matches(cookie_domain: str, req_host: str) -> bool:
            cd = cookie_domain.lstrip(".")
            return (
                req_host == cd
                or req_host.endswith("." + cd)
                or cd.endswith("." + req_host.lstrip("."))
            )

        matching = [c for c in all_cookies if _matches(c.get("domain", ""), host)]
        return {c["name"]: c["value"] for c in matching}
    except Exception as e:
        log.warning("cdp_get_cookies(%s) failed: %s", host, e)
        return {}


_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"


def _session_get(
    url: str, host: str, extra_headers: Optional[Dict] = None, timeout: int = 30
) -> Optional[str]:
    """GET using live CDP session cookies for the given host."""
    try:
        import requests

        cookies = _cdp_get_cookies(host)
        headers = {"User-Agent": _UA, "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        r = requests.get(url, headers=headers, cookies=cookies, timeout=timeout)
        return r.text if r.ok else None
    except Exception as e:
        log.warning("session_get %s failed: %s", url, e)
        return None


def _session_post(
    url: str,
    host: str,
    body: Dict,
    extra_headers: Optional[Dict] = None,
    timeout: int = 30,
) -> Optional[str]:
    """POST using live CDP session cookies + CSRF for the given host."""
    try:
        import requests

        cookies = _cdp_get_cookies(host)
        headers = {
            "User-Agent": _UA,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)
        r = requests.post(
            url, headers=headers, cookies=cookies, json=body, timeout=timeout
        )
        return r.text if r.ok else None
    except Exception as e:
        log.warning("session_post %s failed: %s", url, e)
        return None


def _get_csrf_from_page(url: str, meta_name: str = "csrf-token") -> Optional[str]:
    """Navigate to a page via CDP and extract a CSRF meta tag."""
    try:
        import websocket

        req = urllib.request.Request(
            f"http://localhost:{CHROMIUM_CDP_PORT}/json/new", method="PUT"
        )
        with urllib.request.urlopen(req, timeout=5) as r:  # nosec B310
            tab = json.loads(r.read())
        ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=15)
        ws.send(
            json.dumps({"id": 1, "method": "Page.navigate", "params": {"url": url}})
        )
        import time as _t

        _t.sleep(5)
        ws.send(
            json.dumps(
                {
                    "id": 2,
                    "method": "Runtime.evaluate",
                    "params": {
                        "expression": f'document.querySelector("meta[name={meta_name}]")?.content || ""'
                    },
                }
            )
        )
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == 2:
                break
        ws.close()
        # Close the tab
        with urllib.request.urlopen(  # nosec B310
            urllib.request.Request(
                f"http://localhost:{CHROMIUM_CDP_PORT}/json/close/{tab['id']}",
                method="GET",
            ),
            timeout=5,
        ) as _:
            pass
        return msg.get("result", {}).get("result", {}).get("value") or None
    except Exception as e:
        log.warning("_get_csrf_from_page failed: %s", e)
        return None


def _csrf_from_open_tab(host: str, port: int = CHROMIUM_CDP_PORT) -> str:
    """
    Pull the CSRF token from an already-open tab matching `host`.
    Zero navigation cost — reads from the DOM of a tab that is already loaded
    and authenticated.  Returns empty string if no matching tab found.
    """
    try:
        import websocket as _ws

        tabs = _tabs_list(port) or []
        tab = next(
            (
                t
                for t in tabs
                if host in t.get("url", "")
                and t.get("type") == "page"
                and t.get("webSocketDebuggerUrl")
            ),
            None,
        )
        if not tab:
            return ""
        ws = _ws.create_connection(tab["webSocketDebuggerUrl"], timeout=8)
        ws.send(
            json.dumps(
                {
                    "id": 1,
                    "method": "Runtime.evaluate",
                    "params": {
                        "expression": (
                            "document.querySelector('meta[name=\"csrf-token\"]')?.content"
                            " || document.querySelector('meta[name=\"csrf-param\"]')?.content"
                            ' || ""'
                        ),
                        "returnByValue": True,
                    },
                }
            )
        )
        import time as _t

        _t.sleep(0.3)
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == 1:
                break
        ws.close()
        return msg.get("result", {}).get("result", {}).get("value", "") or ""
    except Exception as e:
        log.debug("_csrf_from_open_tab(%s) failed: %s", host, e)
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Shared payout parsing (K/M/B suffixes; None = unknown, never silently wrong)
# ─────────────────────────────────────────────────────────────────────────────
_K_MULTIPLIERS = {"K": 1_000, "M": 1_000_000, "B": 1_000_000_000}


def parse_payout(value: object, require_symbol: bool = False) -> Optional[int]:
    """Parse a money string/number → int USD. None when unparseable.

    Handles 500, "$5,000", "$500K", "$1.5M". Negative/garbage → None.
    "KB" is kilobytes, not money (→ plain-number fallback).
    require_symbol: only match $-prefixed amounts (for full-card prose text).
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return None
        return int(value) if value >= 0 else None
    text = str(value).strip()
    if not text:
        return None
    sym = r"[$£€]\s*" if require_symbol else ""
    m = re.search(rf"{sym}([\d,]+(?:\.\d+)?)\s*([KMB])\b", text, re.I)
    if m:
        try:
            return int(
                float(m.group(1).replace(",", "")) * _K_MULTIPLIERS[m.group(2).upper()]
            )
        except (ValueError, KeyError):
            return None
    m = re.search(rf"{sym}([\d,]+(?:\.\d+)?)", text)
    if m:
        try:
            return int(float(m.group(1).replace(",", "")))
        except ValueError:
            return None
    return None


def _parse_codehawks_payout(text: str) -> Tuple[Optional[int], Optional[str]]:
    """CodeHawks card text → (payout_usd, raw_text). ETH/OP stay None (volatile)."""
    m = re.search(r"([\d,]+(?:\.\d+)?)\s*([KMB])?\s*(USDC|USD|ETH|OP|DAI)", text, re.I)
    unit_regex = True
    if not m:
        m = re.search(r"\$([\d,]+(?:\.\d+)?)\s*([KMB])?\b", text, re.I)
        unit_regex = False
    if not m:
        return None, None
    try:
        raw = m.group(0).strip()
        val = float(m.group(1).replace(",", ""))
        suffix = m.group(2) if m.lastindex and m.lastindex >= 2 else None
        unit = m.group(3).upper() if unit_regex else "USD"
        if suffix:
            val *= _K_MULTIPLIERS[suffix.upper()]
        if unit in ("USD", "USDC", "DAI"):
            return int(val), raw
        return None, raw
    except (ValueError, TypeError, IndexError, KeyError):
        return None, None


def _scrape_hackerone() -> List[Dict]:
    """
    HackerOne — three-tier auth cascade:
      1. API key (fast, but may be expired — validated first with a quick probe)
      2. Playwright CDP GraphQL (full browser auth, navigates the opportunities page)
      3. Raw requests with CSRF pulled from the already-open H1 tab (zero navigation cost)

    The raw-requests path is tried FIRST when an H1 tab is already open and loaded,
    because it is cheaper and more reliable than Playwright startup.
    """
    programs: List[Dict] = []

    # ── Fast path: CSRF from already-open H1 tab ─────────────────────────────
    csrf = _csrf_from_open_tab("hackerone.com")
    if csrf:
        log.info("hackerone: using CSRF from open tab (zero-nav path)")
        import requests as _req

        cookies = _cdp_get_cookies("hackerone.com")
        GQL = "https://hackerone.com/graphql"
        headers = {
            "User-Agent": _UA,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-csrf-token": csrf,
        }
        cursor = None
        page_count = 0
        while page_count < 20 and len(programs) < 1000:
            page_count += 1
            after = f', after: "{cursor}"' if cursor else ""
            q = (
                f"{{teams(first:100{after}){{"
                f"pageInfo{{hasNextPage endCursor}}"
                f"edges{{node{{"
                f"handle name offers_bounties submission_state "
                f"triage_active triage_plus "
                f"top_bounty_lower_amount top_bounty_upper_amount "
                f"minimum_bounty response_efficiency_percentage "
                f"resolved_report_count launched_at"
                f"}}}}}}}}"
            )
            try:
                r = _req.post(
                    GQL, headers=headers, cookies=cookies, json={"query": q}, timeout=30
                )
                if not r.ok:
                    log.warning("hackerone GQL %s: %s", r.status_code, r.text[:120])
                    break
                data = r.json().get("data", {}).get("teams", {})
            except Exception as e:
                log.warning("hackerone GQL failed: %s", e)
                break
            edges = data.get("edges", [])
            for edge in edges:
                node = edge.get("node", {})
                if (
                    not node.get("offers_bounties")
                    or node.get("submission_state") != "open"
                ):
                    continue
                payout = 0
                try:
                    payout = int(
                        float(
                            str(
                                node.get("top_bounty_upper_amount")
                                or node.get("top_bounty_lower_amount")
                                or 0
                            )
                        )
                    )
                except (ValueError, TypeError):
                    pass
                reports = None
                try:
                    rc = node.get("resolved_report_count")
                    reports = int(rc) if rc is not None else None
                except (ValueError, TypeError):
                    pass
                programs.append(
                    {
                        "platform": "hackerone",
                        "name": node.get("handle", ""),
                        "url": f"https://hackerone.com/{node.get('handle', '')}",
                        "max_payout_usd": payout,
                        "kind": "web2",
                        "fast_triage": bool(
                            node.get("triage_active") or node.get("triage_plus")
                        ),
                        "response_efficiency": node.get(
                            "response_efficiency_percentage"
                        ),
                        "reports_count": reports,
                        "launched_at": node.get("launched_at"),
                        "raw": node,
                    }
                )
            page_info = data.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            time.sleep(0.2)
        if programs:
            log.info("hackerone: %d programs via open-tab CSRF path", len(programs))
            return programs
        log.warning(
            "hackerone: open-tab CSRF path returned 0 programs — falling through"
        )

    # ── API key path (validates before using) ────────────────────────────────
    api_key = _key("HACKERONE_API_KEY")
    if api_key:
        import requests as _req

        try:
            h1_user = _key("HACKERONE_USERNAME") or "api"
            probe = _req.get(
                "https://api.hackerone.com/v1/hackers/programs?page[number]=1&page[size]=1",
                auth=(h1_user, api_key),
                timeout=5,
            )
            if probe.ok:
                page = 1
                while True:
                    r = _req.get(
                        f"https://api.hackerone.com/v1/hackers/programs?page[number]={page}&page[size]=100",
                        auth=(h1_user, api_key),
                        timeout=10,
                    )
                    if not r.ok:
                        break
                    data = r.json()
                    items = data.get("data", [])
                    if not items:
                        break
                    for item in items:
                        attr = item.get("attributes", {})
                        name = attr.get("handle", "")
                        payout = 0
                        if attr.get("offers_bounties"):
                            try:
                                payout = int(float(str(attr.get("top_bounty") or 0)))
                            except (ValueError, TypeError):
                                pass
                        reports = None
                        try:
                            rc = attr.get("number_of_valid_reports_for_user")
                            reports = int(rc) if rc is not None else None
                        except (ValueError, TypeError):
                            pass
                        programs.append(
                            {
                                "platform": "hackerone",
                                "name": name,
                                "url": f"https://hackerone.com/{name}",
                                "max_payout_usd": payout,
                                "kind": "web2",
                                "fast_triage": bool(attr.get("triage_active")),
                                "response_efficiency": attr.get(
                                    "response_efficiency_percentage"
                                ),
                                "reports_count": reports,
                                "launched_at": attr.get("started_accepting_at"),
                                "raw": attr,
                            }
                        )
                    if len(items) < 100:
                        break
                    page += 1
                    time.sleep(0.3)
                if programs:
                    return programs
            else:
                log.warning(
                    "hackerone API key rejected (%s) — key may be expired",
                    probe.status_code,
                )
        except Exception as e:
            log.warning("hackerone API key probe failed: %s", e)

    # Use Playwright over CDP to run in-page GraphQL with full browser auth/cookies
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch_h1_gql():
            h1_progs = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                await page.goto(
                    "https://hackerone.com/opportunities/all",
                    wait_until="domcontentloaded",
                    timeout=15000,
                )

                cursor = None
                page_count = 0
                while page_count < 5 and len(h1_progs) < 200:
                    page_count += 1
                    after_clause = f', after: "{cursor}"' if cursor else ""
                    query = f"""{{teams(first:100{after_clause}){{
                        pageInfo{{hasNextPage endCursor}}
                        edges{{node{{
                          handle name offers_bounties submission_state
                          triage_active triage_plus
                          top_bounty_lower_amount top_bounty_upper_amount
                          minimum_bounty response_efficiency_percentage
                          resolved_report_count launched_at
                        }}}}}}}}"""
                    res = await page.evaluate(
                        """async (q) => {
                        const csrf = document.querySelector('meta[name="csrf-token"]')?.content
                                  || document.querySelector('meta[name="csrf-param"]')?.content
                                  || '';
                        const r = await fetch('https://hackerone.com/graphql', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json', 'x-csrf-token': csrf},
                            body: JSON.stringify({query: q})
                        });
                        return await r.json();
                    }""",
                        query,
                    )
                    teams_data = (res.get("data") or {}).get("teams") or {}
                    edges = teams_data.get("edges") or []
                    if not edges:
                        break
                    for edge in edges:
                        node = edge.get("node") or {}
                        if (
                            not node.get("offers_bounties")
                            or node.get("submission_state") != "open"
                        ):
                            continue
                        payout = 0
                        try:
                            payout = int(
                                float(
                                    str(
                                        node.get("top_bounty_upper_amount")
                                        or node.get("top_bounty_lower_amount")
                                        or 0
                                    )
                                )
                            )
                        except (ValueError, TypeError):
                            pass
                        reports = node.get("resolved_report_count")
                        try:
                            reports = int(reports) if reports is not None else None
                        except (ValueError, TypeError):
                            reports = None
                        h1_progs.append(
                            {
                                "platform": "hackerone",
                                "name": node.get("handle", ""),
                                "url": f"https://hackerone.com/{node.get('handle', '')}",
                                "max_payout_usd": payout,
                                "kind": "web2",
                                "fast_triage": bool(
                                    node.get("triage_active") or node.get("triage_plus")
                                ),
                                "response_efficiency": node.get(
                                    "response_efficiency_percentage"
                                ),
                                "reports_count": reports,
                                "launched_at": node.get("launched_at"),
                                "raw": node,
                            }
                        )
                    page_info = teams_data.get("pageInfo") or {}
                    if not page_info.get("hasNextPage"):
                        break
                    cursor = page_info.get("endCursor")
                    if not cursor:
                        break
                await page.close()
            return h1_progs

        programs = asyncio.run(_fetch_h1_gql())
        if programs:
            return programs
    except Exception as e:
        log.warning("hackerone playwright CDP GraphQL failed: %s", e)

    # Fallback: raw requests with session cookie + CSRF from page
    import requests

    csrf = _get_csrf_from_page("https://hackerone.com/opportunities/all") or ""
    if not csrf:
        log.warning("hackerone: could not get CSRF token")
        return programs
    cookies = _cdp_get_cookies("hackerone.com")
    GQL = "https://hackerone.com/graphql"
    headers = {
        "User-Agent": _UA,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-csrf-token": csrf,
    }
    cursor = None
    while True:
        after = f', after: "{cursor}"' if cursor else ""
        q = f"""{{teams(first:100{after}){{
          pageInfo{{hasNextPage endCursor}}
          edges{{node{{
            handle name offers_bounties submission_state
            triage_active triage_plus
            top_bounty_lower_amount top_bounty_upper_amount
            minimum_bounty response_efficiency_percentage
          }}}}}}}}"""
        try:
            r = requests.post(
                GQL, headers=headers, cookies=cookies, json={"query": q}, timeout=30
            )
            data = r.json().get("data", {}).get("teams", {})
        except Exception as e:
            log.warning("hackerone graphql failed: %s", e)
            break
        edges = data.get("edges", [])
        for edge in edges:
            node = edge.get("node", {})
            if (
                not node.get("offers_bounties")
                or node.get("submission_state") != "open"
            ):
                continue
            payout = 0
            try:
                payout = int(
                    float(
                        str(
                            node.get("top_bounty_upper_amount")
                            or node.get("top_bounty_lower_amount")
                            or 0
                        )
                    )
                )
            except (ValueError, TypeError):
                pass
            programs.append(
                {
                    "platform": "hackerone",
                    "name": node.get("handle", ""),
                    "url": f"https://hackerone.com/{node.get('handle', '')}",
                    "max_payout_usd": payout,
                    "kind": "web2",
                    "fast_triage": bool(
                        node.get("triage_active") or node.get("triage_plus")
                    ),
                    "response_efficiency": node.get("response_efficiency_percentage"),
                    "raw": node,
                }
            )
        page_info = data.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        time.sleep(0.3)
    return programs


def _scrape_immunefi() -> List[Dict]:
    """Immunefi public directory — all programs with payout caps."""
    programs: List[Dict[str, Any]] = []

    # Scrape via Playwright CDP explore page
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch_im():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                await page.goto(
                    "https://immunefi.com/bug-bounty/",
                    wait_until="domcontentloaded",
                    timeout=20000,
                )
                await page.wait_for_timeout(3000)
                cards = await page.evaluate(
                    """() => {
                    const results = [];
                    const links = Array.from(document.querySelectorAll('a[href*="/bug-bounty/"]'));
                    const seen = new Set();
                    for (const a of links) {
                        const href = a.href;
                        if (href.endsWith('/bug-bounty/') || href.endsWith('/explore/')) continue;
                        let p = a.parentElement;
                        while (p && p.tagName !== 'TR' && !p.className?.includes('card') && p !== document.body) {
                            p = p.parentElement;
                        }
                        const text = (p || a).innerText.split(String.fromCharCode(10)).join(' | ');
                        const name = a.innerText.split(String.fromCharCode(10))[0].trim()
                            || href.split('/bug-bounty/')[1]?.split('/')[0] || '';
                        if (!name || seen.has(name) || name.toLowerCase().includes('view bounty')) continue;
                        seen.add(name);
                        results.push({name, href, text});
                    }
                    return results;
                }"""
                )
                for c in cards:
                    text = c.get("text", "")
                    payout = 0
                    parsed = parse_payout(text, require_symbol=True)
                    if parsed is not None:
                        payout = parsed
                    items.append(
                        {
                            "platform": "immunefi",
                            "name": c.get("name"),
                            "url": c.get("href"),
                            "max_payout_usd": payout,
                            "kind": "web3",
                            "fast_triage": False,
                            "raw": {"card_text": text},
                        }
                    )
                await page.close()
            return items

        im_progs = asyncio.run(_fetch_im())
        if im_progs:
            return im_progs
    except Exception as e:
        log.warning("immunefi playwright CDP scrape failed: %s", e)

    return programs


def _scrape_hackenproof() -> List[Dict]:
    """HackenProof — API if key present, else public scrape."""
    programs = []
    api_key = _key("HACKENPROOF_API_KEY")

    if api_key:
        try:
            import requests

            r = requests.get(
                "https://hackenproof.com/api/v1/programs",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                },
                timeout=30,
            )
            if r.ok:
                for item in r.json().get("data", []):
                    max_p = 0
                    try:
                        max_p = int(
                            float(str(item.get("max_bounty", 0)).replace(",", ""))
                        )
                    except (ValueError, TypeError):
                        pass
                    programs.append(
                        {
                            "platform": "hackenproof",
                            "name": item.get("name", ""),
                            "url": item.get("url", ""),
                            "max_payout_usd": max_p,
                            "kind": "web3",
                            "fast_triage": bool(
                                item.get("is_managed") or item.get("triage_active")
                            ),
                            "raw": item,
                        }
                    )
                return programs
        except Exception as e:
            log.warning("hackenproof API failed: %s", e)

    # Scrape via Playwright CDP session
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch_hp():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                # Reuse the already-open hackenproof.com tab if present
                existing = next(
                    (pg for pg in context.pages if "hackenproof.com" in pg.url), None
                )
                page = existing or await context.new_page()
                if not existing:
                    await page.goto(
                        "https://hackenproof.com/programs",
                        wait_until="domcontentloaded",
                        timeout=20000,
                    )
                await page.wait_for_timeout(4000)
                cards = await page.evaluate(
                    """() => {
                    const els = Array.from(document.querySelectorAll('a[href*="/programs/"]'));
                    return els.map(e => {
                        let p = e.parentElement;
                        while (p && p.tagName !== 'TR' && !p.className?.includes('card') && p !== document.body) {
                            p = p.parentElement;
                        }
                        return {
                            name: e.innerText.split(String.fromCharCode(10))[0].trim(),
                            href: e.href,
                            text: (p || e).innerText.split(String.fromCharCode(10)).join(' | ')
                        };
                    });
                }"""
                )
                seen = set()
                for c in cards:
                    name = c.get("name")
                    if not name or name in seen or len(name) < 2:
                        continue
                    seen.add(name)
                    text = c.get("text", "")
                    payout = 0
                    m = re.search(r"UP TO\s*\|\s*\$([\d,]+)", text, re.I) or re.search(
                        r"PAID\s*\|\s*\$([\d,]+)", text, re.I
                    )
                    if m:
                        payout = int(m.group(1).replace(",", ""))
                    fast_triage = "TRIAGED BY HACKENPROOF" in text.upper()
                    items.append(
                        {
                            "platform": "hackenproof",
                            "name": name,
                            "url": c.get("href"),
                            "max_payout_usd": payout,
                            "kind": "web3",
                            "fast_triage": fast_triage,
                            "raw": {"card_text": text},
                        }
                    )
                await page.close()
            return items

        hp_progs = asyncio.run(_fetch_hp())
        if hp_progs:
            return hp_progs
    except Exception as e:
        log.warning("hackenproof playwright CDP scrape failed: %s", e)

    return programs


def _scrape_intigriti() -> List[Dict]:
    """
    Intigriti — three-tier cascade:
      1. JWT Bearer token → REST API (fast path, valid until 2026-09-30)
      2. CDP cookies → REST API (uses active session from any logged-in tab)
      3. Playwright CDP → navigate to app.intigriti.com/researcher/programs and
         scrape the program cards from the rendered page
    """
    programs: List[Dict] = []

    # ── Tier 1 & 2: REST API with JWT or session cookies ─────────────────────
    import requests

    token = _key("INTIGRITI_TOKEN") or _key("INTIGRITI_JWT")
    if token:
        try:
            headers = {
                "User-Agent": _UA,
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
            offset = 0
            limit = 100
            while True:
                url = f"https://api.intigriti.com/external/researcher/v1/programs?limit={limit}&offset={offset}"
                r = requests.get(url, headers=headers, timeout=20)
                if not r.ok:
                    break
                data = r.json()
                records = data.get("records", [])
                if not records:
                    break
                for item in records:
                    payout = 0
                    try:
                        bounty = item.get("maxBounty")
                        if isinstance(bounty, dict):
                            bounty = bounty.get("value", 0)
                        payout = int(float(str(bounty or 0)))
                    except (ValueError, TypeError):
                        pass
                    handle = item.get("handle") or item.get("id") or ""
                    prog_id = item.get("id") or ""
                    name = item.get("name") or handle
                    detail_url = ""
                    if isinstance(item.get("webLinks"), dict):
                        detail_url = item["webLinks"].get("detail", "")
                    if not detail_url:
                        detail_url = f"https://app.intigriti.com/researcher/programs/{handle}/detail"
                    programs.append(
                        {
                            "platform": "intigriti",
                            "name": name,
                            "handle": handle,
                            "id": prog_id,
                            "program_id": prog_id,
                            "url": detail_url,
                            "max_payout_usd": payout,
                            "kind": "web2",
                            "fast_triage": False,
                            "raw": item,
                        }
                    )
                offset += len(records)
                max_count = data.get("maxCount", 0)
                if offset >= max_count or len(records) < limit:
                    break
            if programs:
                log.info("intigriti: %d programs via REST API", len(programs))
                return programs
        except Exception as e:
            log.debug("intigriti official REST API failed: %s", e)

    # ── Tier 2: CDP cookies → fallback REST API ──────────────────────────────
    # Ensure the headless browser has a live Intigriti session by navigating
    # to the app first — this causes the browser to refresh its auth cookies.
    try:
        import websocket as _ws2

        _tabs = _tabs_list() or []
        _inti = next(
            (
                t
                for t in _tabs
                if "intigriti" in t.get("url", "").lower()
                and t.get("webSocketDebuggerUrl")
            ),
            None,
        )
        if not _inti:
            import urllib.request as _ur2

            req2 = _ur2.Request(
                f"http://localhost:{CHROMIUM_CDP_PORT}/json/new", method="PUT"
            )
            _inti = json.loads(_ur2.urlopen(req2, timeout=5).read())  # nosec B310
        _ws3 = _ws2.create_connection(_inti["webSocketDebuggerUrl"], timeout=10)
        _ws3.send(
            json.dumps(
                {
                    "id": 1,
                    "method": "Page.navigate",
                    "params": {"url": "https://app.intigriti.com/researcher/programs"},
                }
            )
        )
        import time as _t2

        _t2.sleep(5)
        _ws3.close()
    except Exception as _e2:
        log.debug("intigriti pre-nav failed: %s", _e2)

    cookies = _cdp_get_cookies("app.intigriti.com")
    headers = {"User-Agent": _UA, "Accept": "application/json"}

    api_endpoints = [
        "https://api.intigriti.com/external/researcher/v1/programs?limit=100&offset=0",
        "https://api.intigriti.com/external/researcher/programs?pgSize=200&pgNumber=1",
        "https://api.intigriti.com/core/researcher/programs?limit=200",
        "https://api.intigriti.com/v2/researcher/programs",
    ]
    for url in api_endpoints:
        try:
            r = requests.get(url, headers=headers, cookies=cookies, timeout=20)
            if not r.ok:
                continue
            data = r.json()
            items = (
                data
                if isinstance(data, list)
                else data.get("records", data.get("data", data.get("results", [])))
            )
            if not items:
                continue
            for item in items:
                payout = 0
                try:
                    bounty = item.get("maxBounty") or item.get("maxBountyValue") or 0
                    if isinstance(bounty, dict):
                        bounty = bounty.get("value", 0)
                    payout = int(float(str(bounty)))
                except (ValueError, TypeError):
                    pass
                handle = (
                    item.get("handle") or item.get("programId") or item.get("id") or ""
                )
                prog_id = item.get("id") or ""
                name = item.get("name") or item.get("companyHandle") or handle
                detail_url = ""
                if isinstance(item.get("webLinks"), dict):
                    detail_url = item["webLinks"].get("detail", "")
                if not detail_url:
                    detail_url = (
                        f"https://app.intigriti.com/researcher/programs/{handle}/detail"
                    )
                programs.append(
                    {
                        "platform": "intigriti",
                        "name": name,
                        "handle": handle,
                        "id": prog_id,
                        "program_id": prog_id,
                        "url": detail_url,
                        "max_payout_usd": payout,
                        "kind": "web2",
                        "fast_triage": item.get("fastTriage", False)
                        or item.get("managedTriage", False),
                        "raw": item,
                    }
                )
            if programs:
                log.info("intigriti: %d programs via REST API", len(programs))
                return programs
        except Exception as e:
            log.debug("intigriti REST %s failed: %s", url, e)

    # ── Tier 3: Playwright CDP — navigate to the programs page ───────────────
    log.info("intigriti: REST API returned 0 — trying Playwright CDP scrape")
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch_intigriti():
            items = []
            async with async_playwright() as pw:
                browser = await pw.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                # /overview shows all programs the researcher has access to
                await page.goto(
                    "https://app.intigriti.com/researcher/programs/overview",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
                # Wait for program cards to render
                try:
                    await page.wait_for_selector(
                        'a[href*="program-redirect"]', timeout=10000
                    )
                except Exception:
                    pass
                await page.wait_for_timeout(2000)
                # Scroll to load all lazy-loaded programs
                for _ in range(10):
                    await page.evaluate(
                        "window.scrollTo(0, document.body.scrollHeight)"
                    )
                    await page.wait_for_timeout(1500)
                # Extract program cards — Intigriti uses anchor elements linking to program detail
                cards = await page.evaluate(
                    r"""() => {
                    const results = [];
                    const seen = new Set();
                    // Try JSON embedded in __NEXT_DATA__ first (Next.js SSR)
                    const nd = document.getElementById('__NEXT_DATA__');
                    if (nd) {
                        try {
                            const data = JSON.parse(nd.textContent);
                            const progs = (data?.props?.pageProps?.programs)
                                        || (data?.props?.pageProps?.initialPrograms)
                                        || [];
                            for (const p of progs) {
                                const handle = p.handle || p.programId || p.id || '';
                                results.push({
                                    name: p.name || p.companyHandle || handle,
                                    handle: handle,
                                    payout: p.maxBounty || p.maxBountyValue || 0,
                                    source: 'ssr',
                                });
                            }
                            if (results.length > 0) return results;
                        } catch(e) {}
                    }
                    // Fallback: DOM scrape — Intigriti uses program-redirect links
                    const anchors = Array.from(document.querySelectorAll('a[href*="program-redirect"]'));
                    for (const a of anchors) {
                        const href = a.href || '';
                        if (seen.has(href)) continue;
                        seen.add(href);
                        const parts = href.split('/program-redirect/');
                        const handle = parts[1] ? parts[1].split('/').pop() : '';
                        const companyId = parts[1] ? parts[1].split('/')[0] : '';
                        const lines = a.innerText.split("\\n").map(s => s.trim()).filter(Boolean);
                        const name = lines[0] || handle;
                        if (!name || name.length < 2) continue;
                        const text = lines.join(' ');
                        const em = text.match(/[€$£]([\d,]+)/);
                        const payout = em ? parseInt(em[1].replace(/,/g,''), 10) : 0;
                        const isBounty = !/disclosure|VDP/i.test(text);
                        results.push({name, handle, companyId, payout, isBounty, source: 'dom'});
                    }
                    return results;
                }"""
                )
                await page.close()
                for c in cards:
                    handle = c.get("handle", "")
                    payout = 0
                    try:
                        payout = int(float(str(c.get("payout") or 0)))
                    except (ValueError, TypeError):
                        pass
                    items.append(
                        {
                            "platform": "intigriti",
                            "name": c.get("name") or handle,
                            "url": f"https://app.intigriti.com/researcher/programs/{handle}/detail",
                            "max_payout_usd": payout,
                            "kind": "web2",
                            "fast_triage": bool(
                                c.get("fastTriage") or c.get("managedTriage")
                            ),
                            "raw": c,
                        }
                    )
            return items

        progs = asyncio.run(_fetch_intigriti())
        if progs:
            log.info("intigriti: %d programs via Playwright CDP", len(progs))
            return progs
    except Exception as e:
        log.warning("intigriti playwright CDP scrape failed: %s", e)

    log.warning(
        "intigriti: all tiers returned 0 programs — "
        "log in to app.intigriti.com in Chromium Profile 2, then run --refresh"
    )
    return programs


def _scrape_bugcrowd() -> List[Dict]:
    """Bugcrowd — authenticated session via cookies."""
    programs = []
    page = 1
    while True:
        try:
            raw = _session_get(
                f"https://bugcrowd.com/engagements.json?sort[]=promoted-desc&page[number]={page}&page[size]=100",
                host="bugcrowd.com",
                extra_headers={
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                },
            )
            if not raw:
                break
            data = json.loads(raw)
        except Exception as e:
            log.warning("bugcrowd scrape failed: %s", e)
            break
        items = data.get("engagements", [])
        if not items:
            break
        for item in items:
            payout = 0
            rew = item.get("rewardSummary") or {}
            max_str = (
                rew.get("maxReward")
                or rew.get("compensationSummary")
                or (item.get("rewards") or {}).get("max")
                or item.get("max_payout")
            )
            parsed = parse_payout(max_str)
            if parsed is not None:
                payout = parsed
            name = item.get("code") or item.get("name") or ""
            brief = item.get("briefUrl", f"/{name}").lstrip("/")
            programs.append(
                {
                    "platform": "bugcrowd",
                    "name": name,
                    "url": f"https://bugcrowd.com/{brief}",
                    "max_payout_usd": payout,
                    "kind": "web2",
                    "fast_triage": bool(
                        item.get("managed_services")
                        or item.get("serviceLevel")
                        in ("Priority Triage", "P1 24/7", "Managed")
                    ),
                    "raw": item,
                }
            )
        if len(items) < 100:
            break
        page += 1
        time.sleep(0.3)
    return programs


def _scrape_yeswehack() -> List[Dict]:
    """YesWeHack — public API."""
    programs: List[Dict[str, Any]] = []
    page = 1
    while page <= 20:  # hard cap: API reports no total page count
        try:
            raw = _get(
                f"https://api.yeswehack.com/programs?page={page}&resultsPerPage=100",
                timeout=20,
            )
            if not raw:
                break
            data = json.loads(raw)
        except Exception as e:
            log.warning("yeswehack scrape failed: %s", e)
            break
        items = data.get("items", data.get("results", []))
        if not items:
            break
        for item in items:
            payout = 0
            try:
                payout = int(
                    float(
                        str(
                            item.get("max_bounty")
                            or item.get("bounty_reward_range", {}).get("max")
                            or 0
                        )
                    )
                )
            except (ValueError, TypeError):
                pass
            name = item.get("slug") or item.get("name") or ""
            rc = item.get("reports_count")
            reports = int(rc) if rc is not None else None
            resp_time = item.get("average_first_response_time")
            programs.append(
                {
                    "platform": "yeswehack",
                    "name": name,
                    "url": f"https://yeswehack.com/programs/{name}",
                    "max_payout_usd": payout,
                    "kind": "web2",
                    "fast_triage": bool(
                        item.get("managed")
                        or (resp_time is not None and resp_time <= 3)
                    ),
                    "reports_count": reports,
                    "raw": item,
                }
            )
        if len(items) < 100:
            break
        page += 1
        time.sleep(0.3)
    return programs


def _scrape_generic_platform(platform: str) -> List[Dict]:
    """Fallback generic scraper for Bugbase, Hats Finance."""
    cfg: Dict[str, Any] = PLATFORMS[platform]
    raw = _fetch(cfg["url"])
    programs: List[Dict[str, Any]] = []
    if not raw:
        return programs
    link_patterns = {
        "bugbase": r'href="(/programs/[^"]+)"',
        "hatsfinance": r'href="(https://app\.hats\.finance/bug-bounties/[^"]+)"',
    }
    pat = link_patterns.get(platform, r'href="(/programs/[^"]+)"')
    base = re.sub(r"/[^/]*$", "", cfg["url"].rstrip("/"))
    seen = set()
    for m in re.finditer(pat, raw, re.IGNORECASE):
        path = m.group(1)
        name = path.split("/")[-1].replace("-", " ").title()
        url = path if path.startswith("http") else base + path
        key = url.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        programs.append(
            {
                "platform": platform,
                "name": name,
                "url": url,
                "max_payout_usd": None,
                "kind": cfg["kind"],
                "fast_triage": False,
                "raw": {},
            }
        )
    return programs


def _scrape_cantina() -> List[Dict]:
    """Cantina — scrape opportunities / bounties via CDP."""
    programs: List[Dict[str, Any]] = []
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                await page.goto(
                    "https://cantina.xyz/opportunities",
                    wait_until="domcontentloaded",
                    timeout=15000,
                )
                await page.wait_for_timeout(3000)
                for _ in range(5):
                    await page.mouse.wheel(0, 1500)
                    await page.wait_for_timeout(500)

                cards = await page.evaluate(
                    """() => {
                    const results = [];
                    const anchors = Array.from(document.querySelectorAll(
                        'a[href*="/bounties/"], a[href*="/competitions/"]'));
                    const seen = new Set();
                    for (const a of anchors) {
                        const href = a.href;
                        if (seen.has(href) || href.endsWith('/bounties') || href.endsWith('/competitions')) continue;
                        seen.add(href);
                        const lines = a.innerText.split(String.fromCharCode(10)).map(s => s.trim()).filter(Boolean);
                        results.push({href, lines});
                    }
                    return results;
                }"""
                )
                for c in cards:
                    lines = c.get("lines", [])
                    if not lines:
                        continue
                    name = lines[0]
                    text = " ".join(lines)
                    payout = 0
                    m = re.search(r"\$([\d,]+(?:\.\d+)?)", text)
                    if not m:
                        m = re.search(
                            r"([\d,]+(?:\.\d+)?)\s*(?:in\s+USDC|USDC)", text, re.I
                        )
                    if m:
                        try:
                            payout = int(float(m.group(1).replace(",", "")))
                        except (ValueError, TypeError):
                            pass
                    fast_triage = True if "Cantina-Triaged" in text else None
                    items.append(
                        {
                            "platform": "cantina",
                            "name": name,
                            "url": c.get("href"),
                            "max_payout_usd": payout,
                            "kind": "web3",
                            "fast_triage": fast_triage,
                            "reports_count": None,
                            "raw": {"lines": lines},
                        }
                    )
                await page.close()
            return items

        progs = asyncio.run(_fetch())
        if progs:
            return progs
    except Exception as e:
        log.warning("cantina scrape failed: %s", e)
    return programs


def _scrape_sherlock() -> List[Dict]:
    """Sherlock — Web3 bug bounties and audit contests via Chromium CDP."""
    programs: List[Dict[str, Any]] = []
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()

                # 1. Fetch Bug Bounties
                await page.goto(
                    "https://audits.sherlock.xyz/bug-bounties",
                    wait_until="networkidle",
                    timeout=20000,
                )
                await page.wait_for_timeout(3000)
                bb_links = await page.evaluate(
                    """() => {
                    const anchors = Array.from(document.querySelectorAll('a[href*="/bug-bounties/"]'));
                    const seen = new Set();
                    const results = [];
                    for (const a of anchors) {
                        const href = a.href;
                        if (seen.has(href)) continue;
                        seen.add(href);
                        results.push({href: href, text: a.innerText});
                    }
                    return results;
                }"""
                )
                for b in bb_links:
                    lines = [
                        raw_line.strip()
                        for raw_line in b["text"].split("\n")
                        if raw_line.strip()
                    ]
                    if not lines:
                        continue
                    name = lines[0]
                    text = " ".join(lines)
                    payout = 0
                    m = re.search(r"([\d,]+(?:\.\d+)?)\s*(?:USDC|USD)", text, re.I)
                    if not m:
                        m = re.search(r"\$([\d,]+(?:\.\d+)?)", text)
                    if m:
                        try:
                            payout = int(float(m.group(1).replace(",", "")))
                        except (ValueError, TypeError):
                            pass
                    items.append(
                        {
                            "platform": "sherlock",
                            "name": name,
                            "url": b.get("href"),
                            "max_payout_usd": payout,
                            "kind": "web3",
                            "fast_triage": None,
                            "reports_count": None,
                            "raw": {"type": "bug-bounty", "lines": lines},
                        }
                    )

                # 2. Fetch Contests
                await page.goto(
                    "https://audits.sherlock.xyz/contests",
                    wait_until="networkidle",
                    timeout=20000,
                )
                await page.wait_for_timeout(2000)
                c_links = await page.evaluate(
                    """() => {
                    const anchors = Array.from(document.querySelectorAll('a[href*="/contests/"]'));
                    const seen = new Set();
                    const results = [];
                    for (const a of anchors) {
                        const href = a.href;
                        if (seen.has(href)) continue;
                        seen.add(href);
                        results.push({href: href, text: a.innerText});
                    }
                    return results;
                }"""
                )
                for c in c_links:
                    lines = [
                        raw_line.strip()
                        for raw_line in c["text"].split("\n")
                        if raw_line.strip()
                    ]
                    if not lines:
                        continue
                    name = lines[0]
                    text = " ".join(lines)
                    payout = 0
                    m = re.search(r"([\d,]+(?:\.\d+)?)\s*(?:USDC|USD)", text, re.I)
                    if m:
                        try:
                            payout = int(float(m.group(1).replace(",", "")))
                        except (ValueError, TypeError):
                            pass
                    items.append(
                        {
                            "platform": "sherlock",
                            "name": f"[Contest] {name}",
                            "url": c.get("href"),
                            "max_payout_usd": payout,
                            "kind": "web3",
                            "fast_triage": None,
                            "reports_count": None,
                            "raw": {"type": "contest", "lines": lines},
                        }
                    )
                await page.close()
            return items

        progs = asyncio.run(_fetch())
        if progs:
            return progs
    except Exception as e:
        log.warning("sherlock scrape failed: %s", e)
    return programs


def _scrape_codehawks() -> List[Dict]:
    """Cyfrin CodeHawks — competitive smart contract audits via Chromium CDP."""
    programs: List[Dict[str, Any]] = []
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                await page.goto(
                    "https://codehawks.cyfrin.io/contests",
                    wait_until="networkidle",
                    timeout=20000,
                )
                await page.wait_for_timeout(3000)

                cards = await page.evaluate(
                    """() => {
                    const results = [];
                    const anchors = Array.from(document.querySelectorAll('a[href*="/c/"]'));
                    const seen = new Set();
                    for (const a of anchors) {
                        const href = a.href;
                        if (seen.has(href)) continue;
                        seen.add(href);
                        let parent = a.closest('div[class*="card"], div[class*="border"], div[class*="rounded"]') || a;
                        results.push({href: href, text: (parent.innerText || a.innerText).trim()});
                    }
                    return results;
                }"""
                )
                for c in cards:
                    lines = [
                        raw_line.strip()
                        for raw_line in c["text"].split("\n")
                        if raw_line.strip()
                    ]
                    if not lines:
                        continue
                    name = (
                        lines[1]
                        if (
                            len(lines) > 1
                            and lines[0] in ("KYC Rewards", "Quick actions")
                        )
                        else lines[0]
                    )
                    text = " ".join(lines)
                    payout, raw_payout = _parse_codehawks_payout(text)
                    items.append(
                        {
                            "platform": "codehawks",
                            "name": name,
                            "url": c.get("href"),
                            "max_payout_usd": payout,
                            "kind": "web3",
                            "fast_triage": None,
                            "reports_count": None,
                            "raw": {"lines": lines, "payout_text": raw_payout},
                        }
                    )
                await page.close()
            return items

        progs = asyncio.run(_fetch())
        if progs:
            return progs
    except Exception as e:
        log.warning("codehawks scrape failed: %s", e)
    return programs


def _scrape_patchstack() -> List[Dict]:
    """Patchstack — WordPress VDPs and community bounty program via Chromium CDP."""
    programs: List[Dict[str, Any]] = []
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                await page.goto(
                    "https://patchstack.com/database/vdp",
                    wait_until="networkidle",
                    timeout=20000,
                )
                await page.wait_for_timeout(3000)

                vdps = await page.evaluate(
                    r"""() => {
                    const anchors = Array.from(document.querySelectorAll('a[href*="/database/wordpress/"]'));
                    const seen = new Set();
                    const results = [];
                    for (const a of anchors) {
                        const href = a.href;
                        if (seen.has(href)) continue;
                        seen.add(href);
                        // Derive a clean name from the URL slug — the innerText says "Plugin"
                        const slug = href.replace(/\/vulnerabilities\/?$/, '').split('/').pop() || '';
                        const name = slug.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                        results.push({href: href, name: name || 'Patchstack VDP'});
                    }
                    return results;
                }"""
                )
                for v in vdps:
                    name = v.get("name") or "Patchstack VDP"
                    if not name or name in ("N/A", "Read more.", "Patchstack Vdp"):
                        continue
                    items.append(
                        {
                            "platform": "patchstack",
                            "name": name,
                            "url": v.get("href"),
                            "max_payout_usd": None,
                            "kind": "web2",
                            "fast_triage": None,
                            "reports_count": None,
                            "raw": {"href": v.get("href")},
                        }
                    )
                await page.close()
            return items

        progs = asyncio.run(_fetch())
        if progs:
            return progs
    except Exception as e:
        log.warning("patchstack scrape failed: %s", e)
    return programs


def _scrape_huntr() -> List[Dict]:
    """Huntr — AI/ML bug bounty platform challenges via Chromium CDP."""
    programs: List[Dict[str, Any]] = []
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _fetch():
            items = []
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(
                    f"http://localhost:{CHROMIUM_CDP_PORT}"
                )
                context = (
                    browser.contexts[0]
                    if browser.contexts
                    else await browser.new_context()
                )
                page = await context.new_page()
                await page.goto(
                    "https://huntr.com/challenges",
                    wait_until="networkidle",
                    timeout=20000,
                )
                await page.wait_for_timeout(3000)

                challenges = await page.evaluate(
                    """() => {
                    const anchors = Array.from(document.querySelectorAll('a[href*="/challenges/"]'));
                    const seen = new Set();
                    const results = [];
                    for (const a of anchors) {
                        const href = a.href;
                        if (seen.has(href)) continue;
                        seen.add(href);
                        let parent = a.closest('div[class*="card"], div[class*="border"]') || a;
                        results.push({href: href, text: (parent.innerText || a.innerText).trim()});
                    }
                    return results;
                }"""
                )
                for c in challenges:
                    lines = [
                        raw_line.strip()
                        for raw_line in c["text"].split("\n")
                        if raw_line.strip()
                    ]
                    if not lines:
                        continue
                    name = lines[0]
                    text = " ".join(lines)
                    payout = 0
                    m = re.search(r"\$([\d,]+(?:\.\d+)?)", text)
                    if m:
                        try:
                            payout = int(float(m.group(1).replace(",", "")))
                        except (ValueError, TypeError):
                            pass
                    items.append(
                        {
                            "platform": "huntr",
                            "name": name,
                            "url": c.get("href"),
                            "max_payout_usd": payout,
                            "kind": "ai",
                            "fast_triage": None,
                            "reports_count": None,
                            "raw": {"lines": lines},
                        }
                    )
                await page.close()
            return items

        progs = asyncio.run(_fetch())
        if progs:
            return progs
    except Exception as e:
        log.warning("huntr scrape failed: %s", e)
    return programs


# ─────────────────────────────────────────────────────────────────────────────
# Main fetch dispatcher
# ─────────────────────────────────────────────────────────────────────────────

SCRAPERS = {
    "hackerone": _scrape_hackerone,
    "immunefi": _scrape_immunefi,
    "hackenproof": _scrape_hackenproof,
    "bugcrowd": _scrape_bugcrowd,
    "cantina": _scrape_cantina,
    # code4rena removed per operator: platform is dead, skip it.
    "sherlock": _scrape_sherlock,
    "codehawks": _scrape_codehawks,
    "patchstack": _scrape_patchstack,
    "huntr": _scrape_huntr,
    "intigriti": _scrape_intigriti,
    "yeswehack": _scrape_yeswehack,
    "bugbase": lambda: _scrape_generic_platform("bugbase"),
    "hatsfinance": lambda: _scrape_generic_platform("hatsfinance"),
}


def normalize_program_record(
    record: Dict[str, Any], platform: str
) -> Optional[Dict[str, Any]]:
    """Return one honest, portable program record or reject malformed output.

    Listing pages are discovery evidence, not authority for scope or missing
    ranking metadata. Every adapter passes this boundary before scan/ranking
    so downstream code can distinguish an unavailable field from a favorable
    zero/false value.
    """
    if not isinstance(record, dict):
        return None
    name = str(record.get("name") or "").strip()
    url = str(record.get("url") or "").strip()
    if not name or not url.startswith(("https://", "http://")):
        return None

    normalized = dict(record)
    normalized["platform"] = platform
    normalized["name"] = name
    normalized["url"] = url
    normalized["kind"] = normalized.get("kind") or PLATFORMS[platform]["kind"]
    for field in ("max_payout_usd", "fast_triage", "reports_count", "launched_at"):
        normalized.setdefault(field, None)
    if normalized.get("max_payout_usd") == 0:
        # 0 is adapters' "unknown" default, not observed money (None = unknown).
        normalized["max_payout_usd"] = None
    normalized.setdefault("structured_scopes", [])
    normalized.setdefault("scope_status", "not-fetched")
    normalized.setdefault("intake_status", "discovered")
    return normalized


def fetch_all_programs(
    platforms: Optional[List[str]] = None,
    return_errors: bool = False,
):
    """Scrape all (or given) platforms. Returns merged list.

    With return_errors=True, returns (programs, errors) where errors names
    every platform that failed or was unknown — partial results must never
    be cached as complete.
    """
    targets = platforms or list(SCRAPERS.keys())
    all_programs = []
    errors: List[str] = []
    for plat in targets:
        if plat not in SCRAPERS:
            _warn(f"Unknown platform: {plat}")
            errors.append(f"{plat}: unknown platform")
            continue
        _info(f"  → Fetching {PLATFORMS[plat]['label']}…")
        try:
            found = SCRAPERS[plat]()
            normalized = [
                program
                for record in found
                if (program := normalize_program_record(record, plat)) is not None
            ]
            rejected = len(found) - len(normalized)
            _info(
                f"    {len(normalized)} programs"
                + (f" ({rejected} malformed records rejected)" if rejected else "")
            )
            all_programs.extend(normalized)
        except Exception as e:
            _warn(f"    Failed ({plat}): {e}")
            errors.append(f"{plat}: {e}")
    if return_errors:
        return all_programs, errors
    return all_programs


# ─────────────────────────────────────────────────────────────────────────────
# Cache
# ─────────────────────────────────────────────────────────────────────────────


def _save_cache(
    programs: List[Dict],
    cache_file: Optional[Path] = None,
    errors: Optional[List[str]] = None,
) -> bool:
    target = cache_file or CACHE_FILE
    if not programs:
        _warn("Refusing to save empty program cache — existing cache preserved")
        return False
    if target.is_file():
        try:
            existing = json.loads(target.read_text())
            existing_count = (
                existing.get("count", 0)
                if isinstance(existing, dict)
                else len(existing)
            )
            if existing_count > 0 and len(programs) == 0:
                _warn(
                    f"Refusing to overwrite populated cache ({existing_count} programs) with empty list"
                )
                return False
        except Exception:
            pass
    fetch_errors = list(errors or [])
    if fetch_errors:
        _warn(
            f"Cache is PARTIAL ({len(fetch_errors)} platform(s) failed) — "
            "recorded in envelope, not presented as complete"
        )
    payload = json.dumps(
        {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "count": len(programs),
            "complete": not fetch_errors,
            "fetch_errors": fetch_errors,
            "programs": programs,
        },
        indent=2,
    )
    # Atomic write: a killed process must never leave a half-written cache
    # behind (the corruption _load_cache now guards against).
    tmp_path = target.with_name(target.name + ".tmp")
    tmp_path.write_text(payload)
    try:
        os.replace(tmp_path, target)
    except BaseException:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    return True


def _load_cache(cache_file: Optional[Path] = None) -> Optional[List[Dict]]:
    target = cache_file or CACHE_FILE
    if not target.is_file():
        return None
    try:
        data = json.loads(target.read_text())
    except Exception:
        _warn("Cache file is corrupt JSON — ignoring, will refetch")
        return None
    if not isinstance(data, dict):
        _warn("Cache file has wrong shape — ignoring, will refetch")
        return None
    try:
        # stale after 24 hours — programs change daily, not hourly
        fetched = datetime.fromisoformat(
            data.get("fetched_at", "2000-01-01T00:00:00+00:00")
        )
        age_h = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
    except Exception:
        _warn("Cache timestamp unreadable — ignoring, will refetch")
        return None
    if age_h > 24:
        return None
    programs = data.get("programs", [])
    if not isinstance(programs, list):
        _warn("Cache programs field corrupt — ignoring, will refetch")
        return None
    return programs


# ─────────────────────────────────────────────────────────────────────────────
# Filtering & ranking
# ─────────────────────────────────────────────────────────────────────────────

# Ranking weights. Methodology knobs, not data: they shape the money-first
# EV proxy but never substitute for an observed field. Unknown fields always
# resolve to the pessimistic branch (see _program_score).
SCORE_REPORT_CLAMP = 100.0
SCORE_FAST_TRIAGE_MULT = 1.5
SCORE_RECENCY_MULT = 1.3
SCORE_RECENCY_DAYS = 90


def _program_score(p: Dict) -> float:
    """
    Composite hunt-value score.

    score = payout / sqrt(effective_reports + 1) * fast_triage_bonus * recency_bonus

    Rationale:
    - High payout matters, but only if the program isn't already saturated.
    - Low report count = less noise = better odds of a first-find.
    - Report penalty is clamped at 100 to avoid severely under-scoring high-paying enterprise programs.
    - Fast triage = faster payout cycle; 1.5x multiplier.
    - Recency: program launched in the last 90 days = 1.3x multiplier
      (fresh programs with less historical hunting = more uncovered surface).

    Unknown-field policy (fail-closed):
    - Unknown payout (None) scores 0 — no observed money, no rank.
    - Unknown reports_count (None) assumes saturation (clamp). Unknown
      crowdedness must never outrank observed freshness.
    - Unknown fast_triage (None) earns no multiplier — only boolean True,
      matching the strict filter gate.
    - Unknown launch date earns no recency bonus.
    """
    import math
    import datetime

    payout = p.get("max_payout_usd")
    payout_value = float(payout) if payout is not None else 0.0
    reports = p.get("reports_count")
    if reports is None:
        effective_reports = SCORE_REPORT_CLAMP
    else:
        effective_reports = min(float(reports), SCORE_REPORT_CLAMP)
    score = payout_value / math.sqrt(effective_reports + 1)
    if p.get("fast_triage") is True:
        score *= SCORE_FAST_TRIAGE_MULT
    # Recency bonus
    launched = p.get("launched_at") or p.get("created_at") or ""
    if launched:
        try:
            dt = datetime.datetime.fromisoformat(launched.replace("Z", "+00:00"))
            age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
            if age_days < SCORE_RECENCY_DAYS:
                score *= SCORE_RECENCY_MULT
        except Exception:
            pass
    return round(score, 2)


def filter_programs(
    programs: List[Dict],
    min_payout: int = 0,
    max_payout: int = 0,
    platform: Optional[str] = None,
    fast_triage: bool = False,
    web2: bool = False,
    web3: bool = False,
    max_reports: Optional[int] = None,
    web2_only: bool = False,
    web3_only: bool = False,
    new_programs_only: bool = False,
    new_program_days: int = 90,
    recently_added_assets: bool = False,
    include_variable: bool = False,
) -> List[Dict]:
    out = programs
    if platform:
        out = [p for p in out if p["platform"] == platform]
    if min_payout > 0:
        # This is an explicit pay gate. When include_variable is True, programs
        # that offer bounties but have unparsed/variable max payout tiers are kept.
        if include_variable:
            out = [
                p
                for p in out
                if (p.get("max_payout_usd") or 0) >= min_payout
                or (bool(p.get("offers_bounties")) and p.get("max_payout_usd") is None)
            ]
        else:
            out = [p for p in out if (p.get("max_payout_usd") or 0) >= min_payout]
    if max_payout > 0:
        # A maximum-payout gate also requires a known value. Treating unknown
        # as zero would silently admit programs the operator explicitly capped.
        out = [
            p
            for p in out
            if p.get("max_payout_usd") is not None and p["max_payout_usd"] <= max_payout
        ]
    if fast_triage:
        # A fast-triage gate means verified fast triage, not unknown metadata.
        out = [
            p
            for p in out
            if p.get("fast_triage") is True or p.get("managed_triage") is True
        ]
    # Accept either web2=True or web2_only=True for the same filter
    _web2 = web2 or web2_only
    _web3 = web3 or web3_only
    if _web2 and not _web3:
        out = [p for p in out if (p.get("kind") or p.get("program_kind")) == "web2"]
    elif _web3 and not _web2:
        out = [p for p in out if (p.get("kind") or p.get("program_kind")) == "web3"]
    if max_reports is not None:
        # Do not drop platforms that don't report count (None); only drop if count is known and exceeds limit
        out = [
            p
            for p in out
            if p.get("reports_count") is None or p["reports_count"] <= max_reports
        ]

    # New programs filter
    if new_programs_only:
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        fresh = []
        for p in out:
            launched = p.get("launched_at") or p.get("created_at") or ""
            if launched:
                try:
                    dt = datetime.datetime.fromisoformat(
                        launched.replace("Z", "+00:00")
                    )
                    if (now - dt).days <= new_program_days:
                        fresh.append(p)
                except Exception:
                    pass
        out = fresh

    # Recently added assets filter
    if recently_added_assets:
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        recent_assets = []
        for p in out:
            if p.get("new_assets") or p.get("has_new_scopes"):
                recent_assets.append(p)
                continue
            for scope in p.get("structured_scopes") or []:
                if not isinstance(scope, dict):
                    continue
                val = scope.get("first_seen") or ""
                try:
                    dt = datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    continue
                if (now - dt).days <= 60:
                    recent_assets.append(p)
                    break
        out = recent_assets

    # Compute composite score and sort descending
    for p in out:
        p["score"] = _program_score(p)
    out.sort(key=lambda p: -p["score"])
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────


def cmd_list(args):
    programs = None
    if not args.refresh:
        cached = _load_cache()
        if cached:
            programs = cached
            _info(f"[cache] {len(programs)} programs loaded (use --refresh to update)")
    if not programs:
        _info("Fetching programs…")
        platforms = [args.platform] if args.platform else None
        programs, fetch_errors = fetch_all_programs(platforms, return_errors=True)
        if platforms:
            _warn(
                "Filtered refresh (--platform) fetched "
                f"{len(programs)} program(s) — shared cache left untouched"
            )
        else:
            _save_cache(programs, errors=fetch_errors)

    max_rep = getattr(args, "max_reports", None)
    filtered = filter_programs(
        programs,
        min_payout=args.min_payout or 0,
        platform=args.platform,
        fast_triage=args.fast_triage,
        web2=args.web2,
        web3=args.web3,
        max_reports=max_rep,
        include_variable=getattr(args, "include_variable", False),
    )

    top = filtered[: args.top] if args.top else filtered

    if not top:
        _info("No programs match your filters.")
        return

    if RICH:
        tbl = Table(title=f"🎯 Bug Bounty Programs ({len(top)} shown)", show_lines=True)
        tbl.add_column("#", style="dim", no_wrap=True)
        tbl.add_column("Platform", style="cyan", no_wrap=True)
        tbl.add_column("Program", style="bold")
        tbl.add_column("Score", justify="right", style="bright_cyan")
        tbl.add_column("Max Payout", justify="right", style="green")
        tbl.add_column("Reports", justify="right", style="magenta")
        tbl.add_column("Kind", style="yellow", no_wrap=True)
        tbl.add_column("Fast Triage", justify="center")
        tbl.add_column("URL", style="dim", no_wrap=True)
        for i, p in enumerate(top, 1):
            payout = f"${p['max_payout_usd']:,}" if p.get("max_payout_usd") else "—"
            reps = (
                str(p["reports_count"]) if p.get("reports_count") is not None else "—"
            )
            ft = "✓" if p.get("fast_triage") else ""
            score = f"{p.get('score', 0):.0f}"
            tbl.add_row(
                str(i),
                p["platform"],
                p["name"],
                score,
                payout,
                reps,
                p.get("kind", "?"),
                ft,
                p["url"],
            )
        console.print(tbl)
    else:
        print(
            f"\n{'#':<4} {'Platform':<12} {'Program':<30} {'Score':>8} {'Max Payout':>12} {'Reports':>8} {'Kind':<6} {'Fast':<5} {'URL'}"  # noqa: E501
        )
        print("-" * 125)
        for i, p in enumerate(top, 1):
            payout = f"${p['max_payout_usd']:,}" if p.get("max_payout_usd") else "—"
            reps = (
                str(p.get("reports_count"))
                if p.get("reports_count") is not None
                else "—"
            )
            ft = "✓" if p.get("fast_triage") else ""
            score = f"{p.get('score', 0):.0f}"
            print(
                f"{i:<4} {p['platform']:<12} {p['name'][:28]:<30} {score:>8} {payout:>12} {reps:>8} {p.get('kind', '?'):<6} {ft:<5} {p['url']}"  # noqa: E501
            )
    print()


def cmd_save(args):
    """Save a specific program's scope to disk (for oracle-hunter to consume)."""
    name = args.program_name
    programs = _load_cache()
    if not programs:
        _info("No cache — fetching first…")
        programs, fetch_errors = fetch_all_programs(return_errors=True)
        _save_cache(programs, errors=fetch_errors)

    match = next((p for p in programs if p["name"].lower() == name.lower()), None)
    if not match:
        # fuzzy
        hits = [p for p in programs if name.lower() in p["name"].lower()]
        if not hits:
            _die(f"Program not found: {name}")
        if len(hits) == 1:
            match = hits[0]
            _info(f"Matched: {match['name']} ({match['platform']})")
        else:
            _die(
                f"Multiple matches: {[p['name'] for p in hits[:5]]}. Be more specific."
            )

    if match.get("platform") == "hackerone":
        try:
            import asyncio
            from playwright.async_api import async_playwright

            async def _fetch_scopes(handle):
                async with async_playwright() as p:
                    browser = await p.chromium.connect_over_cdp(
                        f"http://localhost:{CHROMIUM_CDP_PORT}"
                    )
                    context = (
                        browser.contexts[0]
                        if browser.contexts
                        else await browser.new_context()
                    )
                    page = await context.new_page()
                    try:
                        await page.goto(
                            f"https://hackerone.com/{handle}",
                            wait_until="domcontentloaded",
                            timeout=15000,
                        )
                        await page.wait_for_timeout(2000)
                        res = await page.evaluate(
                            """async (h) => {
                            const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
                            const query = `query TeamScope($handle: String!) {
                                team(handle: $handle) {
                                    structured_scopes(first: 100, archived: false) {
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
                            }`;
                            const r = await fetch('https://hackerone.com/graphql', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json', 'x-csrf-token': csrf},
                                body: JSON.stringify({query: query, variables: {handle: h}})
                            });
                            return await r.json();
                        }""",
                            handle,
                        )
                        return (
                            (res.get("data") or {})
                            .get("team", {})
                            .get("structured_scopes", {})
                            .get("edges", [])
                        )
                    finally:
                        await page.close()

            edges = asyncio.run(_fetch_scopes(match["name"]))
            if edges:
                in_scope = []
                out_of_scope = []
                for edge in edges:
                    n = edge.get("node", {})
                    if n.get("eligible_for_submission") or n.get("eligible_for_bounty"):
                        in_scope.append(n.get("asset_identifier"))
                    else:
                        out_of_scope.append(n.get("asset_identifier"))
                match["structured_scopes"] = [e.get("node") for e in edges]
                match["scope"] = "\n".join(in_scope)
                match["out_of_scope"] = "\n".join(out_of_scope)
                _info(
                    f"   Scope: {len(in_scope)} in-scope assets, {len(out_of_scope)} out-of-scope assets"
                )
        except Exception as e:
            log.warning("failed to fetch structured scopes: %s", e)

    out_dir = (
        _HERE
        / "programs"
        / match["platform"]
        / re.sub(r"[^\w-]", "_", match["name"].lower())
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "program.json").write_text(json.dumps(match, indent=2))
    _info(f"✅ Saved: {out_dir}/program.json")
    _info(f"   Run: oracle-hunter {match['platform']} \"{match['name']}\" to hunt it.")


def cmd_check_keys():
    env = _load_env()
    keys = [
        ("HACKERONE_API_KEY", "HackerOne API — full program list with payouts"),
        ("HACKENPROOF_API_KEY", "HackenProof API — full program list"),
        (
            "JINA_API_KEY",
            "Jina Reader — zero-cost cloud LLM markdown scraper (r.jina.ai)",
        ),
        ("FIRECRAWL_API_KEY", "Firecrawl — JS-rendered scrape (all platforms)"),
        ("TAVILY_API_KEY", "Tavily — web search fallback for unknown programs"),
        ("INTIGRITI_TOKEN", "Intigriti API — official researcher v1 REST API token"),
        ("GROQ_API_KEY", "Groq LPU — ultra-fast sub-second LLM reasoning"),
        ("CLOUDFLARE_API_TOKEN", "Cloudflare Workers AI — edge LLM inference token"),
        ("CLOUDFLARE_ACCOUNT_ID", "Cloudflare Account ID — account-scoped AI endpoint"),
        ("BYNARA_API_KEY", "Bynara — multi-model reasoning gateway"),
        ("NVIDIA_API_KEY", "NVIDIA NIM — high-speed code reasoning"),
        ("OPENROUTER_API_KEY", "OpenRouter — free open-source model fleet"),
    ]
    if RICH:
        tbl = Table(title="🔑 API Key Status", show_lines=True)
        tbl.add_column("Key", style="bold")
        tbl.add_column("Status")
        tbl.add_column("Purpose")
        for k, desc in keys:
            ok = bool(env.get(k))
            status = "[green]✓ set[/green]" if ok else "[red]✗ missing[/red]"
            tbl.add_row(k, status, desc)
        console.print(tbl)
    else:
        for k, desc in keys:
            ok = "✓" if env.get(k) else "✗"
            print(f"  {ok} {k:<28} {desc}")
    print()
    print(f"  Add keys to: {ENV_FILE}")
    print("  Format:  KEY=value  (one per line)")


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────────────────


def _info(msg):
    print(msg)


def _warn(msg):
    print(f"[!] {msg}", file=sys.stderr)


def _die(msg):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


def cmd_platforms(args):
    """List all registered bug bounty and VDP platforms from the global registry."""
    reg_file = _HERE / "platforms_registry.json"
    if not reg_file.is_file():
        _die("platforms_registry.json not found")
    data = json.loads(reg_file.read_text(encoding="utf-8"))
    cat = getattr(args, "category", None)
    if cat and cat != "all":
        data = [p for p in data if p.get("category") == cat]

    if RICH:
        tbl = Table(
            title=f"🌐 Global Bug Bounty & VDP Platforms ({len(data)} platforms)",
            show_lines=True,
        )
        tbl.add_column("#", style="dim", no_wrap=True)
        tbl.add_column("Platform Name", style="bold cyan")
        tbl.add_column("Category", style="yellow")
        tbl.add_column("Region", style="green")
        tbl.add_column("Type", style="magenta")
        tbl.add_column("URL", style="dim")
        for i, p in enumerate(data, 1):
            tbl.add_row(
                str(i),
                p["name"],
                p["category"].upper(),
                p.get("region", "Global"),
                p.get("type", "public"),
                p["url"],
            )
        console.print(tbl)
    else:
        print(f"\n{'#':<4} {'Platform':<32} {'Category':<14} {'Region':<16} {'URL'}")
        print("-" * 90)
        for i, p in enumerate(data, 1):
            print(
                f"{i:<4} {p['name']:<32} {p['category'].upper():<14} {p.get('region', 'Global'):<16} {p['url']}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Oracle Programs — bug bounty program discovery across all platforms"
    )
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="List programs (filtered)")
    p_list.add_argument(
        "--refresh", action="store_true", help="Force fresh scrape (ignore cache)"
    )
    p_list.add_argument(
        "--platform", choices=list(SCRAPERS.keys()), help="One platform only"
    )
    p_list.add_argument(
        "--min-payout",
        type=int,
        default=0,
        metavar="USD",
        help="Minimum max payout in USD (e.g. 500)",
    )
    p_list.add_argument(
        "--fast-triage", action="store_true", help="Fast-triage programs only"
    )
    p_list.add_argument(
        "--max-reports",
        type=int,
        default=None,
        metavar="N",
        help="Filter for programs with <= N reports (low competition)",
    )
    p_list.add_argument("--web2", action="store_true", help="Web2 programs only")
    p_list.add_argument("--web3", action="store_true", help="Web3/DeFi programs only")
    p_list.add_argument(
        "--include-variable",
        action="store_true",
        help="Include programs offering bounties with variable or unparsed payout tiers",
    )
    p_list.add_argument("--top", type=int, metavar="N", help="Show top N results")

    p_save = sub.add_parser(
        "save", help="Save a program's data to disk for oracle-hunter"
    )
    p_save.add_argument("program_name", help="Program name (from the list)")

    sub.add_parser("check-keys", help="Show which API keys are configured")

    sub.add_parser(
        "save-cookies",
        help="Snapshot logged-in bounty-platform cookies from the warm browser to disk "
        "(run while Chrome is visible and you are logged in)",
    )

    p_platforms = sub.add_parser(
        "platforms", help="List all registered global platforms across categories"
    )
    p_platforms.add_argument(
        "--category",
        choices=[
            "government",
            "web3",
            "ai",
            "acquisition",
            "ecosystem",
            "crowdsourced",
            "all",
        ],
        default="all",
        help="Filter by platform category",
    )

    args = parser.parse_args()

    if args.command == "list":
        cmd_list(args)
    elif args.command == "save":
        cmd_save(args)
    elif args.command == "check-keys":
        cmd_check_keys()
    elif args.command == "platforms":
        cmd_platforms(args)
    elif args.command == "save-cookies":
        n = save_session_cookies()
        print(f"✓ {n} cookies saved → {_COOKIE_SNAPSHOT}")
        print("  Headless Chrome will restore these automatically on next startup.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
