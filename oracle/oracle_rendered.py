#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: rendered_reflection, confirm_rendered_output, close_browser
# TOPICS: none
"""oracle_rendered.py — DOM XSS rendered differential (wall gap 4.1).

Raw-response checks cannot see script probes that execute only after the
browser runs the page's JavaScript (juice XSS x9). This module renders the
probe URL in headless Chromium (Playwright) and compares the marker in
the RAW body vs the RENDERED DOM:

  raw miss + rendered hit  → DOM XSS (the gap this closes)
  raw hit  + rendered hit  → classic reflected XSS (also a hit)
  no rendered hit          → not vulnerable to this probe

Output is shaped like ``curl -i`` text (status line + excerpt) so the
existing verify gates (status extraction, body-contains matching,
grounding, SPA control) apply unchanged. The browser fetches ONLY the
probe URL already approved by the scope gate — no crawling, no
form-filling, no credentialed navigation beyond headers already in the
check. One browser is reused per process (close_browser() at hunt end).
"""

from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

DOM_MARKER = "oracledom7"
DOM_PAYLOAD = "%3Cimg%20src%3Dx%20onerror%3Dalert%28" + DOM_MARKER + "%29%3E"

_CLAIM = "dom-xss-rendered-differential"

_lock = threading.Lock()
_browser = None
_pw = None


def _headers_from_check(check: str) -> Dict[str, str]:
    """Authorization/Cookie headers already approved in the check string."""
    headers: Dict[str, str] = {}
    for name, value in re.findall(
        r"-H\s+[\"']([^\"':]+):\s*([^\"']+)[\"']", check or ""
    ):
        if name.strip().lower() in ("authorization", "cookie"):
            headers[name.strip()] = value.strip()
    return headers


def _url_from_check(check: str) -> str:
    m = re.search(r"https?://[^\s'\"<>`]+", check or "")
    return m.group(0) if m else ""


def _same_origin(left: str, right: str) -> bool:
    """Return whether two HTTP URLs share scheme, host, and effective port."""
    try:
        a, b = urlsplit(left), urlsplit(right)
        return (
            a.scheme.lower(),
            a.hostname.lower() if a.hostname else "",
            a.port or (443 if a.scheme.lower() == "https" else 80),
        ) == (
            b.scheme.lower(),
            b.hostname.lower() if b.hostname else "",
            b.port or (443 if b.scheme.lower() == "https" else 80),
        )
    except ValueError:
        return False


def rendered_available() -> bool:
    """True when the playwright package is importable (browser launch is
    attempted lazily by _ensure_browser and fails loud there)."""
    import importlib.util

    try:
        return importlib.util.find_spec("playwright.sync_api") is not None
    except (ImportError, ValueError):
        return False


def _ensure_browser():
    """Process-shared headless Chromium (launch once, reuse per card)."""
    global _browser, _pw
    with _lock:
        if _browser is not None:
            try:
                if _browser.is_connected():
                    return _browser
            except Exception:
                _browser = None
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise RuntimeError(
                "playwright is not installed — rendered differential unavailable"
            ) from e
        try:
            # Sanctioned resolver: pins PLAYWRIGHT_BROWSERS_PATH to the
            # real chromium build even when HOME is sandboxed/polluted.
            # A set-but-bogus pin (leaked tmp dir) is dropped first: the
            # resolver trusts an explicit value only when it holds a
            # chromium build, and so do we.
            import glob
            import os

            _explicit = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
            if _explicit and not glob.glob(os.path.join(_explicit, "chromium*")):
                os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
            from oracle_programs import _ensure_playwright_browsers

            _ensure_playwright_browsers()
        except Exception:
            pass
        _pw = sync_playwright().start()
        _browser = _pw.chromium.launch()
        return _browser


def close_browser() -> None:
    """Release the shared browser (hunt end; tests)."""
    global _browser, _pw
    with _lock:
        try:
            if _browser is not None:
                _browser.close()
        except Exception:
            pass
        try:
            if _pw is not None:
                _pw.stop()
        except Exception:
            pass
        _browser = None
        _pw = None


def rendered_reflection(
    url: str,
    marker: str = DOM_MARKER,
    timeout_ms: int = 15000,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Render one URL headless; report marker in raw vs rendered body.

    Returns {url, status, raw_hit, rendered_hit, raw_len, rendered_len,
    excerpt, error}. Raises RuntimeError when playwright is unavailable.
    Credential-bearing checks are rejected because browser navigation cannot
    guarantee header isolation across every redirect and subresource request.
    """
    if not url or not urlsplit(url).netloc:
        return {
            "url": url,
            "status": None,
            "raw_hit": False,
            "rendered_hit": False,
            "error": "no URL to render",
        }
    if headers:
        return {
            "url": url,
            "status": None,
            "raw_hit": False,
            "rendered_hit": False,
            "error": "credentialed rendered navigation is disabled",
        }
    browser = _ensure_browser()
    page = browser.new_page()
    try:
        resp = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        status = resp.status if resp else None
        rendered = page.content() or ""
    except Exception as e:
        return {
            "url": url,
            "status": None,
            "raw_hit": False,
            "rendered_hit": False,
            "error": f"render failed: {e}",
        }
    finally:
        try:
            page.close()
        except Exception:
            pass
    # Raw leg: the unrendered bytes, fetched without JS (urllib, no browser).
    raw = ""
    try:
        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": "oracle-rendered/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000.0) as r:  # nosec B310
            raw = r.read().decode("utf-8", "replace")
    except Exception as e:
        raw = f"[raw fetch failed: {e}]"
    rendered_hit = marker in rendered
    excerpt = ""
    if rendered_hit:
        i = rendered.find(marker)
        excerpt = rendered[max(0, i - 200) : i + 200]
    return {
        "url": url,
        "status": status or 200,
        "raw_hit": marker in raw,
        "rendered_hit": rendered_hit,
        "raw_len": len(raw),
        "rendered_len": len(rendered),
        "excerpt": excerpt,
        "error": "",
    }


def confirm_rendered_output(
    check: str, marker: Optional[str] = None, timeout_ms: int = 15000
) -> Tuple[int, str, str]:
    """Execute the rendered differential for a dom-xss card's check.

    Returns (rc, stdout, stderr) shaped like ``curl -i`` output so the
    downstream verify gates apply unchanged. rc=0 with the marker in
    stdout iff the rendered DOM contains the marker.
    """
    url = _url_from_check(check)
    mark = (marker or DOM_MARKER).strip() or DOM_MARKER
    if not url:
        return 1, "", "[RENDERED] no URL in check — cannot confirm"
    try:
        obs = rendered_reflection(url, mark, timeout_ms, _headers_from_check(check))
    except RuntimeError as e:
        return 2, "", f"[RENDERED] {e} — inconclusive, never executed"
    if obs.get("error"):
        return 1, "", f"[RENDERED] {obs['error']}"
    status = obs.get("status") or 200
    # Build output lines. The URL line intentionally omits the marker value
    # so it cannot be matched by body_contains checks in verify_seam_card —
    # only genuine DOM reflection should ever carry the marker text.
    lines: List[str] = [
        f"HTTP/1.1 {status} OK",
        "Content-Type: text/html",
        "",
        "[RENDERED] confirmed via rendered DOM",
        f"[RENDERED] raw_hit={obs['raw_hit']}"
        f" rendered_hit={obs['rendered_hit']}",
    ]
    if obs["rendered_hit"]:
        lines.append(obs["excerpt"])
        return 0, "\n".join(lines), ""
    else:
        # rc=1: DOM did not contain the marker → not confirmed.
        # Never return rc=0 here — that would make verify_seam_card
        # confirm on the HTTP 200 status alone, ignoring DOM reflection.
        lines.append("[RENDERED] marker absent from rendered DOM")
        return 1, "\n".join(lines), ""
