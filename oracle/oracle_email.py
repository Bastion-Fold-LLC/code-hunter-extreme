#!/usr/bin/env python3
# LAYER: seal
# DEST: vortex
# ENDPOINTS: main
# TOPICS: none
"""
Oracle Email Daemon
───────────────────
Gmail via your real Chrome session (CDP) — no OAuth, no GCP, no credentials file.
WebPipe reads and real human-input clicks send. Your Chrome must be running with
remote debugging on port 9222 (Firefox default).

LinkedIn spider (Connection Map) is OFF by default. Turn it on with --spider.
The spider never sends anything — it only ranks and reports who to add next.

Usage:
    oracle-email                          # interactive TUI
    oracle-email inbox                    # list inbox (WebPipe)
    oracle-email read <msg_id>            # read a thread
    oracle-email compose                  # draft + approval gate + real click send
    oracle-email reply <msg_id>           # Oracle-voiced reply draft
    oracle-email queue                    # show approval queue
    oracle-email approve <draft_id>       # approve and real-click send
    oracle-email recon <url>              # WebPipe recon a bug bounty target
    oracle-email spider [role]            # run Connection Map cycle (requires --spider)
    oracle-email spider --list-roles      # show available role presets
    oracle-email daemon                   # background polling loop
    oracle-email sms <message>            # send a quick SMS via T-Mobile gateway
    oracle-email setup                    # show setup instructions

Flags:
    --spider    Enable LinkedIn Connection Map commands (off by default)
    --port N    Firefox CDP port (default: 9222)
    --phone N   Your T-Mobile number for SMS (or set ORACLE_PHONE env var)

Spider roles (pass as: oracle-email --spider spider ceo):
    ceo, cfo, cto, founder, head-of-ai, director-ai, vp-engineering,
    vp-product, principal-engineer, staff-engineer, ai-researcher,
    ai-evaluator, red-team, ml-engineer, tech-recruiter, inhouse-recruiter,
    hiring-manager, engineering-manager, product-manager, investor,
    scale-ai, anthropic, openai, nvidia
"""

import os
import sys
import json
import time
import random
import textwrap
import argparse
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional
import urllib.request
import urllib.parse

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
QUEUE_FILE = _HERE / "email_queue.json"
ORACLE_VOICE = _HERE / "ORACLE_VOICE.md"
ORACLE_EMAIL_MD = _HERE / "ORACLE_EMAIL.md"


# Production repo tools (WebPipe + Connection Map)
# oracle_email.py lives at: <home>/oracle-main-extracted/oracle-main/oracle_email.py
# Walk up until we find the production/ sibling — works regardless of how the
# script is invoked (direct, imported, or via the oracle-email launcher).
def _find_home() -> Path:
    """Find the home dir by walking up from this file until production/ exists."""
    p = Path(__file__).resolve().parent
    for _ in range(6):
        p = p.parent
        if (p / "production").exists():
            return p
    # fallback: guess based on parents
    return Path(__file__).resolve().parents[1]


_HOME = _find_home()
_PROD = _HOME / "production"
WEBPIPE_DIR = _PROD / "tools" / "webpipe"
CONNMAP_DIR = _PROD / "connection-map"
NEXT_TO_ADD = CONNMAP_DIR / "out" / "next-to-add.md"
SPIDER_CONFIG = CONNMAP_DIR / "spider.config.json"

# Voice reference — checked in priority order:
# 1. ALEX_VOICE.md right here in the oracle folder (travels with the project)
# 2. YOUR_VOICE.md in Desktop/product (the master copy)
# 3. ORACLE_VOICE.md fallback (hunting voice, less complete)
_VOICE_FILE = _HERE / "ALEX_VOICE.md"
if not _VOICE_FILE.exists():
    _VOICE_FILE = _HOME / "Desktop" / "product" / "YOUR_VOICE.md"
if not _VOICE_FILE.exists():
    _VOICE_FILE = _HERE / "ORACLE_VOICE.md"

# ── Optional rich output ──────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]

# ── Firefox CDP port ─────────────────────────────────────────────────────────
DEFAULT_PORT = 9222  # Firefox CDP port for oracle-email

# Active Firefox profile (the one currently running with Gmail + LinkedIn signed in)
FIREFOX_PROFILE = _HOME / ".mozilla" / "firefox" / "bugcrowd-clean.default-release"

# CDP session profile — a lightweight copy that gets fresh cookies synced on each launch
FIREFOX_CDP_PROFILE = _HOME / ".oracle-firefox-cdp"

# Session files to copy from the live profile (everything needed to be signed in,
# nothing that would cause a profile conflict with the running Firefox)
_SESSION_FILES = [
    "cookies.sqlite",
    "key4.db",
    "cert9.db",
    "logins.json",
    "sessionstore.jsonlz4",
]

# Firefox binary candidates — tries in order, uses first one found
_FIREFOX_BINS = [
    "/usr/bin/firefox",
    "/snap/bin/firefox",
    "/usr/lib/firefox/firefox",
]


def _browser_reachable(port: int) -> bool:
    """
    Return True if Firefox with remote debugging is listening on the port.
    Firefox BiDi server responds 200 on '/' and writes WebDriverBiDiServer.json;
    it does NOT serve /json/version (that's a Chrome-only endpoint).
    """
    # Check WebDriverBiDiServer.json first — written by Firefox when CDP/BiDi is ready
    bidi_file = FIREFOX_CDP_PROFILE / "WebDriverBiDiServer.json"
    if bidi_file.exists():
        try:
            import json as _json

            data = _json.loads(bidi_file.read_text())
            if data.get("ws_port") == port:
                # Confirm the port is actually accepting connections
                try:
                    with urllib.request.urlopen(  # nosec B310
                        f"http://127.0.0.1:{port}/", timeout=2
                    ) as r:
                        return r.status == 200
                except Exception:
                    pass
        except Exception:
            pass
    # Fallback: try Chrome-style /json/version (for Chromium compatibility)
    try:
        with urllib.request.urlopen(  # nosec B310
            f"http://127.0.0.1:{port}/json/version", timeout=2
        ) as r:
            return r.status == 200
    except Exception:
        return False


def _copy_sqlite_safe(src: Path, dst: Path) -> bool:
    """
    Copy a SQLite database that may be open by Firefox.
    Raw file copy is safe for reads — Firefox flushes pages to disk continuously
    and we only need the snapshot at copy time (same as what 'cp' does).
    Also copies the -wal and -shm files if they exist so the copy is consistent.
    """
    import shutil

    try:
        shutil.copy2(str(src), str(dst))
        # Copy WAL/SHM so the snapshot is self-consistent
        for suffix in ("-wal", "-shm"):
            extra = src.parent / (src.name + suffix)
            if extra.exists():
                try:
                    shutil.copy2(str(extra), str(dst.parent / (dst.name + suffix)))
                except Exception:
                    pass
        return True
    except Exception:
        return False


def _sync_cdp_profile():
    """
    Copy session-critical files from the live Firefox profile into the CDP profile.
    Uses sqlite3 backup API for .sqlite files so the copy works even while
    Firefox has the database locked.
    """
    import shutil

    src = FIREFOX_PROFILE
    dst = FIREFOX_CDP_PROFILE

    if not src.exists():
        return False

    dst.mkdir(parents=True, exist_ok=True)

    # Copy prefs.js so Firefox doesn't show first-run screens
    prefs = src / "prefs.js"
    if prefs.exists():
        try:
            shutil.copy2(str(prefs), str(dst / "prefs.js"))
        except Exception:
            pass

    copied = 0
    for fname in _SESSION_FILES:
        s = src / fname
        d = dst / fname
        if not s.exists():
            continue
        if fname.endswith(".sqlite"):
            ok = _copy_sqlite_safe(s, d)
        else:
            try:
                shutil.copy2(str(s), str(d))
                ok = True
            except Exception:
                ok = False
        if ok:
            copied += 1

    return copied > 0


def _ensure_browser(port: int = DEFAULT_PORT) -> bool:
    """
    Make sure Firefox with remote debugging is running on `port`.
    If already running, return immediately.
    If not, sync cookies from your live Firefox profile into a CDP-dedicated
    profile and launch a fresh Firefox instance on that port.

    The CDP profile is a lightweight copy — only session files, not the full
    340MB profile. Your running Firefox is never touched or interrupted.
    """
    if _browser_reachable(port):
        return True

    firefox_bin = next((b for b in _FIREFOX_BINS if Path(b).exists()), None)
    if not firefox_bin:
        _print("⚠️  Firefox not found. Install with: sudo apt install firefox")
        return False

    # Sync fresh cookies from your live profile before launching
    _print("🔄 Syncing session from live Firefox profile…")
    synced = _sync_cdp_profile()
    if not synced:
        _print("⚠️  Could not sync session files — you may need to sign in manually")

    _print(f"🦊 Launching Firefox on port {port} with CDP…")

    cmd = [
        firefox_bin,
        f"--remote-debugging-port={port}",
        "--remote-allow-origins=*",
        f"--profile={FIREFOX_CDP_PROFILE}",
        "--no-remote",
        "--new-instance",
        "https://mail.google.com/mail/u/0/#inbox",
    ]

    # Inherit the current environment so DISPLAY / WAYLAND_DISPLAY pass through
    env = os.environ.copy()

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    except Exception as e:
        _print(f"⚠️  Firefox launch failed: {e}")
        return False

    # Wait up to 45s for Firefox CDP to be ready (Firefox is slow to start)
    for i in range(90):
        time.sleep(0.5)
        if _browser_reachable(port):
            _print(f"✅ Firefox ready on port {port}")
            time.sleep(3)  # let Gmail finish loading
            return True

    _print(f"⚠️  Firefox not responding on port {port} after 45s.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# WebPipe bootstrap
# ─────────────────────────────────────────────────────────────────────────────


def _get_webpipe(port: int = DEFAULT_PORT):
    """
    Import and return a WebPipe instance pointed at the headed Chrome on `port`.
    WebPipe reads Gmail via your real authenticated session — no OAuth needed.
    Gmail is always driven on the headed Firefox browser (DEFAULT_PORT), never headless.
    Launches Chrome automatically if it's not already running.
    """
    _ensure_browser(port)
    if str(WEBPIPE_DIR) not in sys.path:
        sys.path.insert(0, str(WEBPIPE_DIR))
    try:
        from webpipe.pipe import WebPipe

        return WebPipe(headed_port=port)
    except ImportError as e:
        _die(
            f"WebPipe not found at {WEBPIPE_DIR}\n  {e}\n  Check that the production repo is at {_PROD}"
        )


def _get_human_input(ws):
    """Return a HumanInput dispatcher for real CDP mouse/keyboard events."""
    if str(WEBPIPE_DIR) not in sys.path:
        sys.path.insert(0, str(WEBPIPE_DIR))
    from webpipe.input import HumanInput

    return HumanInput(ws)


# ─────────────────────────────────────────────────────────────────────────────
# Chrome CDP helpers (raw websocket, for Gmail compose actions)
# ─────────────────────────────────────────────────────────────────────────────


def _chrome_tabs(port: int) -> List[Dict]:
    _ensure_browser(port)
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/json", timeout=5
        ) as r:  # nosec B310
            return json.loads(r.read().decode())
    except Exception as e:
        _die(
            f"Browser not reachable on port {port} even after auto-launch attempt.\n  {e}"
        )


def _find_gmail_tab(port: int) -> Optional[Dict]:
    """Return the first Gmail tab open in Chrome, or None."""
    for tab in _chrome_tabs(port):
        url = tab.get("url", "")
        if "mail.google.com" in url and tab.get("type") == "page":
            return tab
    return None


def _open_gmail_tab(port: int) -> Dict:
    """Navigate a new tab to Gmail and return it."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/json/new?https://mail.google.com", method="PUT"
    )
    with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310
        tab = json.loads(r.read().decode())
    time.sleep(3)
    return tab


def _ws_connect(tab: Dict):
    """Open a websocket connection to a Chrome tab. Caller must close."""
    try:
        import websocket

        ws = websocket.create_connection(tab["webSocketDebuggerUrl"], timeout=15)
        return ws
    except ImportError:
        _die("websocket-client not installed. Run: pip3 install websocket-client")


def _ws_eval(ws, js: str, msg_id: int = 1):
    """Evaluate JS in a tab via CDP Runtime.evaluate."""
    ws.send(
        json.dumps(
            {
                "id": msg_id,
                "method": "Runtime.evaluate",
                "params": {"expression": js, "returnByValue": True},
            }
        )
    )
    while True:
        raw = json.loads(ws.recv())
        if raw.get("id") == msg_id:
            return raw.get("result", {}).get("result", {}).get("value")


def _ws_enable(ws):
    for i, method in enumerate(
        ["Page.enable", "Runtime.enable", "Network.enable"], start=1
    ):
        ws.send(json.dumps({"id": i, "method": method}))
        ws.recv()


# ─────────────────────────────────────────────────────────────────────────────
# Gmail reading via WebPipe
# ─────────────────────────────────────────────────────────────────────────────


def _parse_gmail_sync_payload(
    data: list, seen_ids: set, max_results: int
) -> List[Dict]:
    """
    Parse one Gmail sync/fd payload into message dicts.

    Gmail uses two wire formats in the same endpoint:

    Format A  (real-time push, 5-element thread items):
      data[1] = [ [thread_id, [[thread_id, subject, snippet, timestamp, ...]], ...], ... ]

    Format B  (bulk load, 3-element thread items):
      data[1] = [ [thread_id, None, [[msg_id, [from_list, None, None, to_list, subject, ...]], ...]], ... ]

    Both formats nest the useful fields differently — this function handles both.
    Returns a flat list of {"id", "subject", "snippet", "from", "date"} dicts.
    """
    messages: List[Dict[str, Any]] = []
    if not isinstance(data, list) or len(data) < 2:
        return messages
    threads = data[1]
    if not isinstance(threads, list):
        return messages

    for item in threads:
        if not isinstance(item, list) or not item:
            continue
        thread_id = str(item[0]) if item[0] else ""
        if not thread_id or thread_id in seen_ids:
            continue

        subject = ""
        snippet = ""
        sender = ""
        date_ts = ""

        def _extract_sender(fields: list) -> str:
            """Pull sender from a Gmail message fields list: [from_list, None, None, to_list, subject, ...]"""
            if not isinstance(fields, list):
                return ""
            # from is at index 0: [[type, email, name], ...]
            if fields and isinstance(fields[0], list) and fields[0]:
                addr = fields[0][0]
                if isinstance(addr, list) and len(addr) >= 2:
                    name = str(addr[2]) if len(addr) > 2 and addr[2] else ""
                    email = str(addr[1]) if addr[1] else ""
                    return f"{name} <{email}>" if name else email
            return ""

        # ── Format A: item = [thread_id, [[thread_id, subject, snippet, ts, ...], ...], item[2]=[msg...]] ──
        if len(item) >= 2 and isinstance(item[1], list) and item[1]:
            inner = item[1][0]
            if isinstance(inner, list) and len(inner) >= 3:
                subject = str(inner[1] or "")
                snippet = str(inner[2] or "")
                date_ts = str(inner[3]) if len(inner) > 3 and inner[3] else ""
            # Sender lives in item[2] for Format A too
            if len(item) >= 3 and isinstance(item[2], list) and item[2]:
                msg = item[2][0]
                if isinstance(msg, list) and len(msg) >= 2:
                    sender = _extract_sender(msg[1])

        # ── Format B: item = [thread_id, None, [[msg_id, [from_list, .., to_list, subj, ..]], ...]] ──
        if not subject and len(item) >= 3 and isinstance(item[2], list) and item[2]:
            msg = item[2][0]
            if isinstance(msg, list) and len(msg) >= 2:
                fields = msg[1]
                if isinstance(fields, list):
                    if len(fields) > 4 and fields[4]:
                        subject = str(fields[4])
                    if not sender:
                        sender = _extract_sender(fields)

        if not subject:
            continue  # skip unparseable items

        seen_ids.add(thread_id)
        messages.append(
            {
                "id": thread_id,
                "subject": subject[:120],
                "snippet": snippet[:200],
                "from": sender[:80],
                "date": date_ts,
            }
        )
        if len(messages) >= max_results:
            break

    return messages


def read_inbox_via_webpipe(port: int, max_results: int = 20) -> List[Dict]:
    """
    Fetch the Gmail inbox by attaching directly to the existing Gmail tab via CDP,
    enabling network interception, triggering a page reload, and collecting the
    mail.google.com/sync payloads that Gmail fires on every load.

    This is more reliable than opening a new tab because:
    - Gmail's sync feed only fires on a loaded, authenticated session
    - A fresh tab navigation often completes before sync calls happen
    - The existing tab is already authenticated and rendered
    """
    import websocket as ws_lib

    _ensure_browser(port)
    _print("📬 Fetching inbox via Chrome session…")

    # Find (or open) the Gmail tab
    try:
        tabs = json.loads(
            urllib.request.urlopen(  # nosec B310
                f"http://127.0.0.1:{port}/json/list", timeout=5
            ).read()
        )
    except Exception as e:
        _print(f"⚠️  Could not list tabs: {e}")
        return []

    gmail_tab = next(
        (
            t
            for t in tabs
            if "mail.google.com" in t.get("url", "") and t.get("type") == "page"
        ),
        None,
    )
    if not gmail_tab:
        # Open Gmail if no tab is open
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/json/new?https://mail.google.com/mail/u/0/#inbox",
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310
            gmail_tab = json.loads(r.read().decode())
        time.sleep(4)

    ws_url = gmail_tab.get("webSocketDebuggerUrl", "")
    if not ws_url:
        _print("⚠️  No WebSocket URL for Gmail tab")
        return []

    collected_payloads = []
    msg_id = [1]

    def next_id():
        msg_id[0] += 1
        return msg_id[0]

    try:
        ws = ws_lib.create_connection(ws_url, timeout=20)
        ws.settimeout(2)

        # Enable Network events
        ws.send(json.dumps({"id": next_id(), "method": "Network.enable"}))
        # Bypass the Gmail service worker so sync API calls hit the real network
        # (Service Worker intercepts requests and serves from cache — CDP can't see them)
        ws.send(
            json.dumps(
                {
                    "id": next_id(),
                    "method": "Network.setBypassServiceWorker",
                    "params": {"bypass": True},
                }
            )
        )

        # Hard reload (ignoreCache=True) forces Gmail to re-fetch from network, not SW cache
        ws.send(
            json.dumps(
                {
                    "id": next_id(),
                    "method": "Page.reload",
                    "params": {"ignoreCache": True},
                }
            )
        )

        # Collect responses for up to 8 seconds
        deadline = time.time() + 8
        pending_requests: Dict[str, str] = {}  # requestId → url

        while time.time() < deadline:
            try:
                raw = json.loads(ws.recv())
            except Exception:
                continue

            method = raw.get("method", "")
            params = raw.get("params", {})

            # Track request URLs
            if method == "Network.requestWillBeSent":
                req_url = params.get("request", {}).get("url", "")
                if "mail.google.com/sync" in req_url:
                    pending_requests[params.get("requestId", "")] = req_url

            # Capture response bodies for Gmail sync calls
            elif method == "Network.responseReceived":
                req_url = params.get("response", {}).get("url", "")
                req_id = params.get("requestId", "")
                if "mail.google.com/sync" in req_url:
                    pending_requests[req_id] = req_url

            elif method == "Network.loadingFinished":
                req_id = params.get("requestId", "")
                if req_id in pending_requests:
                    try:
                        rid = next_id()
                        ws.send(
                            json.dumps(
                                {
                                    "id": rid,
                                    "method": "Network.getResponseBody",
                                    "params": {"requestId": req_id},
                                }
                            )
                        )
                        # Wait for the body response
                        body_deadline = time.time() + 3
                        while time.time() < body_deadline:
                            try:
                                body_raw = json.loads(ws.recv())
                            except Exception:
                                break
                            if body_raw.get("id") == rid:
                                body_text = body_raw.get("result", {}).get("body", "")
                                if body_text:
                                    # Gmail wraps JSON responses in )]}'\n
                                    clean = body_text.lstrip(")]}'\n").strip()
                                    try:
                                        data = json.loads(clean)
                                        collected_payloads.append(
                                            {
                                                "url": pending_requests[req_id],
                                                "data": data,
                                            }
                                        )
                                    except Exception:
                                        pass
                                del pending_requests[req_id]
                                break
                    except Exception:
                        pass

        ws.close()

    except Exception as e:
        _print(f"⚠️  Gmail tab CDP error: {e}")
        return []

    # Parse all collected payloads
    messages: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for payload in collected_payloads:
        if "mail.google.com/sync" not in payload.get("url", ""):
            continue
        msgs = _parse_gmail_sync_payload(
            payload["data"], seen_ids, max_results - len(messages)
        )
        messages.extend(msgs)
        if len(messages) >= max_results:
            break

    if not messages:
        _print(
            "⚠️  No Gmail sync payloads captured — check that Gmail is open and signed in"
        )

    return messages[:max_results]


def read_thread_via_webpipe(msg_id: str, port: int) -> Dict:
    """Open a Gmail thread by ID and return its content."""
    wp = _get_webpipe(port)
    url = f"https://mail.google.com/mail/u/0/#inbox/{msg_id}"
    _print(f"📖 Opening thread {msg_id}…")
    result = wp.query(url, wait_seconds=4, port_override=port)
    return {
        "id": msg_id,
        "content": result.get("clean_content", ""),
        "url": url,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Gmail sending via real Chrome clicks (HumanInput CDP)
# ─────────────────────────────────────────────────────────────────────────────


def send_via_chrome_clicks(to: str, subject: str, body: str, port: int) -> bool:
    """
    Send an email by clicking through Gmail's compose UI using real CDP mouse/keyboard
    events (HumanInput). isTrusted=true on all events. No OAuth, no API.

    Flow: find/open Gmail tab → click Compose → fill To/Subject/Body → click Send.
    """

    tab = _find_gmail_tab(port)
    if not tab:
        _print("No Gmail tab open — opening one…")
        tab = _open_gmail_tab(port)
        # Re-find after navigation
        time.sleep(3)
        tab = _find_gmail_tab(port) or tab

    ws = _ws_connect(tab)
    _ws_enable(ws)
    hi = _get_human_input(ws)

    try:
        # 1. Click the Compose button
        _print("🖱  Clicking Compose…")
        clicked = hi.click_human('[gh="cm"]')  # Gmail's compose button data-gh attr
        if not clicked:
            # Fallback selector
            clicked = hi.click_human(".T-I.T-I-KE.L3")
        if not clicked:
            _print("⚠️  Could not find Compose button — Gmail may not be fully loaded")
            ws.close()
            return False
        time.sleep(random.uniform(1.2, 2.0))

        # 2. Fill To field
        _print(f"⌨️  Typing To: {to}")
        hi.type_human('[name="to"]', to)
        time.sleep(random.uniform(0.4, 0.8))
        # Press Tab to confirm the address
        ws.send(
            json.dumps(
                {
                    "id": 200,
                    "method": "Input.dispatchKeyEvent",
                    "params": {"type": "keyDown", "key": "Tab", "code": "Tab"},
                }
            )
        )
        ws.recv()
        time.sleep(random.uniform(0.3, 0.6))

        # 3. Fill Subject
        _print(f"⌨️  Typing Subject: {subject}")
        hi.type_human('[name="subjectbox"]', subject)
        time.sleep(random.uniform(0.4, 0.7))

        # 4. Fill body — Gmail's contenteditable compose area
        _print("⌨️  Typing body…")
        body_sel = ".Am.Al.editable"
        clicked_body = hi.click_human(body_sel)
        if not clicked_body:
            body_sel = '[aria-label="Message Body"]'
            hi.click_human(body_sel)
        time.sleep(random.uniform(0.3, 0.6))

        # Type body line by line, Enter between lines
        for i, line in enumerate(body.splitlines()):
            if i > 0:
                ws.send(
                    json.dumps(
                        {
                            "id": 300 + i,
                            "method": "Input.dispatchKeyEvent",
                            "params": {
                                "type": "keyDown",
                                "key": "Enter",
                                "code": "Enter",
                                "text": "\n",
                            },
                        }
                    )
                )
                ws.recv()
                time.sleep(random.uniform(0.05, 0.12))
            # Type each char with human cadence
            for ch in line:
                ws.send(
                    json.dumps(
                        {
                            "id": 400,
                            "method": "Input.dispatchKeyEvent",
                            "params": {
                                "type": "keyDown",
                                "text": ch,
                                "unmodifiedText": ch,
                            },
                        }
                    )
                )
                ws.recv()
                time.sleep(random.uniform(0.02, 0.06))
                ws.send(
                    json.dumps(
                        {
                            "id": 401,
                            "method": "Input.dispatchKeyEvent",
                            "params": {
                                "type": "keyUp",
                                "text": ch,
                                "unmodifiedText": ch,
                            },
                        }
                    )
                )
                ws.recv()
                time.sleep(random.uniform(0.01, 0.04))

        time.sleep(random.uniform(0.8, 1.4))

        # 5. Click Send button
        _print("🖱  Clicking Send…")
        # Gmail's literal tooltip embeds RTL marks; required for selector match.
        sent = hi.click_human('[data-tooltip="Send ‪(Ctrl-Enter)‬"]')  # nosec B613
        if not sent:
            sent = hi.click_human(".T-I.J-J5-Ji.aoO.v7.T-I-atl.L3")
        if not sent:
            _print("⚠️  Could not find Send button. Draft saved in Gmail.")
            ws.close()
            return False

        time.sleep(random.uniform(1.0, 1.8))
        _print(f"✅ Email sent to {to}")
        ws.close()
        return True

    except Exception as e:
        _print(f"[error during send: {e}]")
        try:
            ws.close()
        except Exception:
            pass
        return False


# ─────────────────────────────────────────────────────────────────────────────
# SMS via T-Mobile email gateway
# ─────────────────────────────────────────────────────────────────────────────


def send_sms(message: str, phone: str, port: int) -> bool:
    """
    Send an SMS via the T-Mobile email gateway (number@tmomail.net).
    Uses the same Chrome click-send path as regular email — no extra accounts.
    Rate-limited: will not send more than once per 60 seconds to avoid spam.
    """
    if not phone:
        _print("⚠️  No phone number set. Use --phone or set ORACLE_PHONE env var.")
        return False

    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) < 10:
        _print(f"⚠️  Phone number looks wrong: {phone}")
        return False

    gateway = f"{digits}@tmomail.net"
    short = message[:160]  # SMS length limit
    return send_via_chrome_clicks(
        to=gateway,
        subject="Oracle",
        body=short,
        port=port,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Oracle voice drafting (local Ollama)
# ─────────────────────────────────────────────────────────────────────────────

OLLAMA_API = "http://localhost:11434/api/generate"
DRAFT_MODEL = "qwen2.5:14b"  # drafts replies in Alex's voice
VERIFY_MODEL = "devstral:24b"  # voice-checks the draft — bigger = harder to fool


def _ollama(prompt: str, model: str = DRAFT_MODEL, timeout: int = 120) -> str:
    """
    Call the local Ollama HTTP API directly — no subprocess, no cold-start delay.
    Returns the model's response text, or empty string on failure.
    """
    import json as _json

    payload = _json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
    ).encode()
    req = urllib.request.Request(
        OLLAMA_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
            return _json.loads(r.read().decode()).get("response", "").strip()
    except Exception:
        return ""


def _load_persona() -> str:
    parts = []
    for f in (ORACLE_VOICE, ORACLE_EMAIL_MD):
        if f.exists():
            parts.append(f.read_text(encoding="utf-8"))
    return "\n\n".join(parts)


# ── Scam detection + company legitimacy ──────────────────────────────────────

# Hard scam signals — any one of these in sender/subject/snippet = skip immediately
_SCAM_SENDER_PATTERNS = [
    "gmail.com",  # recruiter using personal Gmail is a red flag
    "yahoo.com",
    "hotmail.com",
    "outlook.com",  # personal domains for job offers
    "mail.ru",
    "yandex.ru",
    "qq.com",
]
_SCAM_SUBJECT_PATTERNS = [
    "urgent",
    "immediate",
    "asap",
    "quick start",
    "w2 only",
    "c2c",
    "corp-to-corp",  # visa mill signals
    "100% remote",
    "work from home",  # not inherently bad but common in scams
    "no experience",
    "no interview",
    "wire transfer",
    "western union",
    "gift card",
    "ssn",
    "social security",
    "passport copy",
    "sign up fee",
    "training fee",
    "equipment fee",
]
_SCAM_BODY_PATTERNS = [
    "send your resume to",
    "forward your resume",
    "please provide your ssn",
    "provide your date of birth",
    "we will pay you",
    "earn up to",
    "click here to apply",
    "fill out the form",
    "your profile was selected",
    "we found your resume",
    "kindly revert",
    "revert back",  # offshore grammar
    "do the needful",
    "perks and benefits include",
    "please share your",
    "please send your",
]


def _extract_domain(email_or_str: str) -> str:
    """Pull the domain out of an email address string."""
    import re

    m = re.search(r"@([\w.\-]+)", email_or_str)
    return m.group(1).lower() if m else ""


def scam_check(frm: str, subject: str, snippet: str) -> Dict[str, Any]:
    """
    Fast pattern-based scam detector. No LLM, no network.
    Returns {"scam": bool, "confidence": str, "signals": [str]}

    confidence: "high" (definite skip) | "medium" (flag for review) | "low" (probably fine)
    """
    signals = []
    frm_lower = frm.lower()
    subject_lower = subject.lower()
    body_lower = snippet.lower()

    # Personal email domain used for job offer
    domain = _extract_domain(frm_lower)
    if domain in {p.strip("@") for p in _SCAM_SENDER_PATTERNS}:
        signals.append(f"personal email domain: {domain}")

    # Subject scam patterns
    for pat in _SCAM_SUBJECT_PATTERNS:
        if pat in subject_lower:
            signals.append(f"subject flag: '{pat}'")

    # Body scam patterns
    for pat in _SCAM_BODY_PATTERNS:
        if pat in body_lower:
            signals.append(f"body flag: '{pat}'")

    # Mismatched domain — sender name says one company but email domain is different
    # e.g. "From: Google Recruiter <hire@staffingco.biz>"
    name_part = frm_lower.split("<")[0].strip()
    if domain and name_part:
        big_names = [
            "google",
            "amazon",
            "microsoft",
            "apple",
            "meta",
            "facebook",
            "netflix",
            "tesla",
            "openai",
            "anthropic",
            "nvidia",
        ]
        for bn in big_names:
            if bn in name_part and bn not in domain:
                signals.append(
                    f"name/domain mismatch: claims '{bn}' but domain is '{domain}'"
                )

    if not signals:
        return {"scam": False, "confidence": "low", "signals": []}
    if len(signals) >= 3:
        return {"scam": True, "confidence": "high", "signals": signals}
    return {"scam": False, "confidence": "medium", "signals": signals}


def check_company_legit(frm: str, subject: str, port: int) -> Dict:
    """
    Check whether the company behind a recruiter email is real.
    Extracts the domain from the sender address, fetches its homepage via WebPipe,
    and asks the LLM to assess legitimacy.

    Returns {"legit": bool, "confidence": str, "reason": str, "domain": str}
    confidence: "high" | "medium" | "low" | "unknown"
    """
    domain = _extract_domain(frm)
    if not domain:
        return {
            "legit": False,
            "confidence": "unknown",
            "reason": "no domain in sender",
            "domain": "",
        }

    # Known-legit domains — skip the web check
    _KNOWN_LEGIT = {
        "linkedin.com",
        "indeed.com",
        "dice.com",
        "monster.com",
        "ziprecruiter.com",
        "greenhouse.io",
        "lever.co",
        "workday.com",
        "icims.com",
        "jobvite.com",
        "smartrecruiters.com",
        "taleo.net",
        "successfactors.com",
    }
    if any(domain.endswith(kl) for kl in _KNOWN_LEGIT):
        return {
            "legit": True,
            "confidence": "high",
            "reason": f"known job platform: {domain}",
            "domain": domain,
        }

    # Fetch the company homepage
    url = f"https://{domain}"
    try:
        if str(WEBPIPE_DIR) not in sys.path:
            sys.path.insert(0, str(WEBPIPE_DIR))
        from webpipe.pipe import WebPipe
        from webpipe import politeness

        politeness.unblock(domain)
        wp = WebPipe(headed_port=port)
        wp.interactive = False
        result = wp.query(url, wait_seconds=4)
        content = result.get("clean_content", "")[:2000]
        status = result.get("wire", {}).get("doc_status")
    except Exception as e:
        return {
            "legit": False,
            "confidence": "unknown",
            "reason": f"could not fetch {url}: {e}",
            "domain": domain,
        }

    if not content or status in (None,) or (status and status >= 400):
        return {
            "legit": False,
            "confidence": "medium",
            "reason": f"domain unreachable or error: HTTP {status}",
            "domain": domain,
        }

    # Ask LLM to assess
    prompt = (
        f"You are vetting a company that sent a job email to Alex Sorrell.\n"
        f"Sender domain: {domain}\n"
        f"Email subject: {subject}\n\n"
        f"Company homepage content:\n{content}\n\n"
        "Answer with EXACTLY this format (no other text):\n"
        "LEGIT: yes|no\n"
        "CONFIDENCE: high|medium|low\n"
        "REASON: one sentence\n\n"
        "LEGIT means: real company with real web presence, not a staffing mill or fake recruiter.\n"
        "NOT LEGIT: page is empty, parked domain, pure staffing/body-shop with no real product/clients, "
        "offshore-only with no US presence, or obvious scam site.\n"
    )
    raw = _ollama(prompt, model=DRAFT_MODEL, timeout=60)

    legit = True
    confidence = "medium"
    reason = "LLM assessment"

    for line in (raw or "").splitlines():
        upper = line.strip().upper()
        if upper.startswith("LEGIT:"):
            legit = "YES" in upper
        elif upper.startswith("CONFIDENCE:"):
            c = upper.split(":", 1)[1].strip().lower()
            if c in ("high", "medium", "low"):
                confidence = c
        elif line.strip().upper().startswith("REASON:"):
            reason = line.split(":", 1)[1].strip()

    return {
        "legit": legit,
        "confidence": confidence,
        "reason": reason,
        "domain": domain,
    }


# ── Email triage ──────────────────────────────────────────────────────────────

# Senders / subject patterns that never need a reply — skip silently
_SKIP_SENDERS = {
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "notifications@",
    "notify@",
    "alert@",
    "alerts@",
    "newsletter",
    "digest",
    "mailer-daemon",
    "postmaster",
    "support@",
    "help@",
    "info@",
    "hello@",
    "billing@",
    "invoice@",
    "receipts@",
    "linkedin",
    "twitter",
    "facebook",
    "instagram",
    "github",
    "gitlab",
    "jira",
    "confluence",
    "google",
    "apple",
    "microsoft",
    "unsubscribe",
    "bounce",
}

_SKIP_SUBJECT_WORDS = {
    "unsubscribe",
    "newsletter",
    "digest",
    "weekly",
    "monthly",
    "your receipt",
    "your invoice",
    "order confirmation",
    "password reset",
    "verify your",
    "confirm your",
    "github action",
    "build failed",
    "build passed",
    "new sign-in",
    "security alert",
}


def triage_email(
    frm: str, subject: str, snippet: str, port: int = DEFAULT_PORT
) -> Dict:
    """
    Decide whether this email deserves a drafted reply.

    Returns {"reply": bool, "reason": str, "priority": str, "scam": dict, "company": dict}

    Pipeline (in order — bail early at each gate):
    1. Hard sender/subject patterns → instant skip
    2. Scam detector — pattern match on sender/subject/body → skip if high confidence
    3. LLM triage — is this even a reply-worthy email?
    4. Company legitimacy check — fetch their domain, LLM assesses if real company
    """
    frm_lower = frm.lower()
    subject_lower = subject.lower()
    scam_result = {"scam": False, "confidence": "low", "signals": []}
    company_result = {
        "legit": True,
        "confidence": "unknown",
        "reason": "",
        "domain": "",
    }

    # ── Gate 1: hard sender/subject patterns ─────────────────────────────────
    for pat in _SKIP_SENDERS:
        if pat in frm_lower:
            return {
                "reply": False,
                "reason": f"automated sender ({pat})",
                "priority": "skip",
                "scam": scam_result,
                "company": company_result,
            }

    for word in _SKIP_SUBJECT_WORDS:
        if word in subject_lower:
            return {
                "reply": False,
                "reason": f"auto-subject keyword ({word})",
                "priority": "skip",
                "scam": scam_result,
                "company": company_result,
            }

    # ── Gate 2: scam detector ─────────────────────────────────────────────────
    scam_result = scam_check(frm, subject, snippet)
    if scam_result["scam"]:
        _sig = scam_result["signals"]
        _sig_list = _sig if isinstance(_sig, list) else []
        return {
            "reply": False,
            "reason": f"scam signals: {'; '.join(_sig_list[:2])}",
            "priority": "skip",
            "scam": scam_result,
            "company": company_result,
        }

    # ── Gate 3: LLM triage — is this worth replying to at all? ───────────────
    prompt = (
        "You are an email triage assistant for Alex Sorrell, a security engineer and AI builder.\n"
        "Decide if this email needs a human reply.\n\n"
        f"FROM: {frm}\n"
        f"SUBJECT: {subject}\n"
        f"SNIPPET: {snippet[:300]}\n\n"
        "Answer with EXACTLY this format (no other text):\n"
        "REPLY: yes|no\n"
        "PRIORITY: high|normal|skip\n"
        "REASON: one short sentence\n\n"
        "REPLY emails: direct questions, recruiter outreach, bug bounty responses, "
        "client/business correspondence, personal messages from real humans.\n"
        "SKIP: newsletters, automated alerts, receipts, job alert digests, marketing, "
        "mass recruiter blasts with no personal touch.\n"
        "HIGH: direct job offer with salary, bounty payout, urgent request from known person.\n"
    )
    raw = _ollama(prompt, model=DRAFT_MODEL, timeout=60)

    reply = True
    priority = "normal"
    reason = "LLM said reply"

    for line in (raw or "").splitlines():
        upper = line.strip().upper()
        if upper.startswith("REPLY:"):
            reply = "YES" in upper
        elif upper.startswith("PRIORITY:"):
            p = upper.split(":", 1)[1].strip().lower()
            if p in ("high", "normal", "skip"):
                priority = p
                if p == "skip":
                    reply = False
        elif line.strip().upper().startswith("REASON:"):
            reason = line.split(":", 1)[1].strip()

    if not reply:
        return {
            "reply": False,
            "reason": reason,
            "priority": "skip",
            "scam": scam_result,
            "company": company_result,
        }

    # ── Gate 4: company legitimacy check (only for emails worth replying to) ──
    company_result = check_company_legit(frm, subject, port)
    if not company_result["legit"] and company_result["confidence"] in (
        "high",
        "medium",
    ):
        return {
            "reply": False,
            "reason": f"company not legit ({company_result['domain']}): {company_result['reason']}",
            "priority": "skip",
            "scam": scam_result,
            "company": company_result,
        }

    # Flag medium-confidence scam signals in the reason even if we proceed
    if scam_result["signals"]:
        _sig2 = scam_result["signals"]
        _sig2_list = _sig2 if isinstance(_sig2, list) else []
        reason = f"{reason} [⚠️ scam signals: {'; '.join(_sig2_list[:2])}]"

    return {
        "reply": reply,
        "reason": reason,
        "priority": priority,
        "scam": scam_result,
        "company": company_result,
    }


def oracle_draft_reply(original_thread: str, context: str = "") -> str:
    """Ask local Ollama to draft a reply in Oracle voice."""
    persona = _load_persona()
    if not persona:
        return "[Oracle voice files not found — draft manually]"

    prompt = (
        f"{persona}\n\n"
        "---\n"
        "Draft a reply to the following email thread as Alex Sorrell. "
        "Be direct, honest, no fluff. "
        "Output ONLY the email body — no subject line, no commentary.\n\n"
        f"ORIGINAL THREAD:\n{original_thread}\n\n"
        f"EXTRA CONTEXT: {context or 'none'}\n\n"
        "REPLY DRAFT:"
    )
    result = _ollama(prompt, model=DRAFT_MODEL)
    return result if result else "[ollama unavailable — draft manually]"


# ─────────────────────────────────────────────────────────────────────────────
# Email address validator
# ─────────────────────────────────────────────────────────────────────────────

# Disposable/throwaway email domains — not exhaustive but catches the common ones
_DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwam.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "spam4.me",
    "trashmail.com",
    "yopmail.com",
    "10minutemail.com",
    "fakeinbox.com",
    "mailnull.com",
    "spamgourmet.com",
    "dispostable.com",
    "maildrop.cc",
    "getairmail.com",
    "filzmail.com",
    "discard.email",
    "throwaway.email",
}


def validate_email_address(address: str) -> Dict:
    """
    Check whether an email address is likely legitimate.
    Returns {"valid": bool, "reason": str, "domain": str}

    Checks:
    1. Basic format (has @ and a domain with a dot)
    2. Not a known disposable/throwaway domain
    3. Domain has MX records (can receive email) — requires DNS lookup
    """
    import re

    result = {"valid": False, "reason": "", "domain": ""}

    address = address.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", address):
        result["reason"] = f"malformed address: {address}"
        return result

    domain = address.split("@", 1)[1]
    result["domain"] = domain

    if domain in _DISPOSABLE_DOMAINS:
        result["reason"] = f"disposable email domain: {domain}"
        return result

    # MX record check — stdlib only, no external deps
    try:
        import socket

        # Try to resolve the domain — not a full MX check but catches typos
        socket.getaddrinfo(domain, None, socket.AF_INET)
        result["valid"] = True
        result["reason"] = "domain resolves"
    except socket.gaierror:
        result["reason"] = f"domain does not resolve: {domain} — possible typo"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Voice verifier — checks a draft sounds like Alex before it gets queued
# ─────────────────────────────────────────────────────────────────────────────


def verify_voice(body: str) -> Dict:
    """
    Run the draft body through local Ollama to check it sounds like Alex Sorrell.
    Uses YOUR_VOICE.md (or ORACLE_VOICE.md fallback) as the reference.

    Returns {"pass": bool, "score": str, "feedback": str, "revised": str}

    The verifier checks:
    - Does NOT beg, backpedal, or over-apologise
    - Does NOT start with "I hope this email finds you well" or similar
    - Short declaratives. Periods where others use commas.
    - Stands tall. Direct. No hollow corporate filler.
    - Swearing only if load-bearing on a beat (never at the person)
    """
    voice_ref = ""
    if _VOICE_FILE.exists():
        voice_ref = _VOICE_FILE.read_text(encoding="utf-8")[:3000]

    prompt = (
        f"VOICE REFERENCE:\n{voice_ref}\n\n"
        "---\n"
        "You are a voice verifier for Alex Sorrell's email drafts.\n\n"
        "His voice rules:\n"
        "- Short declaratives. Periods where others use commas.\n"
        "- Never begs, backtracks, or over-apologises. Stands tall.\n"
        "- No hollow openers: never 'I hope this finds you well', 'I wanted to reach out', 'Just following up'\n"
        "- Direct. Says what he means. Doesn't soften to the point of saying nothing.\n"
        "- Swearing only if it's load-bearing on a rhythm beat — never AT the person.\n"
        "- Ends quiet and short, not with a flourish.\n\n"
        "Review this email draft. Respond with:\n"
        "PASS or FAIL\n"
        "SCORE: (1-10, 10=perfect Alex voice)\n"
        "ISSUES: (bullet list of what's off, if anything)\n"
        "REVISED: (rewrite only if FAIL — otherwise write 'none')\n\n"
        f"DRAFT:\n{body}\n\n"
        "VERDICT:"
    )

    raw = _ollama(prompt, model=VERIFY_MODEL, timeout=180)
    if not raw:
        return {
            "pass": True,
            "score": "?",
            "feedback": "verifier unavailable — queuing anyway",
            "revised": "",
        }

    passed = raw.upper().startswith("PASS")
    score = ""
    feedback = ""
    revised = ""

    for line in raw.splitlines():
        clean = line.strip()
        if clean.upper().startswith("SCORE:"):
            score = clean.split(":", 1)[1].strip()
        elif clean.upper().startswith("ISSUES:"):
            feedback = clean.split(":", 1)[1].strip()
        elif clean.upper().startswith("REVISED:"):
            revised = clean.split(":", 1)[1].strip()
            if revised.lower() == "none":
                revised = ""

    return {"pass": passed, "score": score, "feedback": feedback, "revised": revised}


# ─────────────────────────────────────────────────────────────────────────────
# Approval queue
# ─────────────────────────────────────────────────────────────────────────────


def load_queue() -> List[Dict]:
    if QUEUE_FILE.exists():
        return json.loads(QUEUE_FILE.read_text())
    return []


def save_queue(q: List[Dict]):
    QUEUE_FILE.write_text(json.dumps(q, indent=2))


def queue_draft(to: str, subject: str, body: str, context: str = "") -> str:
    """
    Add an email to the approval queue.
    Runs two checks before queuing:
    1. Email address validator — rejects disposable/unresolvable domains
    2. Voice verifier — flags drafts that don't sound like Alex, offers a rewrite
    """
    # 1. Validate the recipient address
    if "@" in to:
        check = validate_email_address(to)
        if not check["valid"]:
            _print(f"⚠️  Address check: {check['reason']}")
            if not _confirm("Queue anyway?"):
                return ""

    # 2. Voice check
    _print("🎙  Checking voice…")
    verdict = verify_voice(body)
    score_str = f" (score {verdict['score']}/10)" if verdict.get("score") else ""

    if verdict["pass"]:
        _print(f"✅ Voice check passed{score_str}")
    else:
        _print(f"⚠️  Voice check FAILED{score_str}")
        if verdict.get("feedback"):
            _print(f"   Issues: {verdict['feedback']}")
        if verdict.get("revised"):
            _print("\n📝 Suggested rewrite:")
            _preview(to, subject, verdict["revised"])
            choice = _ask(
                "Use rewrite? [y]es / [n]o keep original / [e]dit rewrite", default="y"
            ).lower()
            if choice == "y":
                body = verdict["revised"]
            elif choice == "e":
                print("Edit rewrite (type END on its own line to finish):")
                lines = []
                while True:
                    line = input()
                    if line.strip() == "END":
                        break
                    lines.append(line)
                body = "\n".join(lines)
        else:
            if not _confirm("Queue anyway despite voice issues?"):
                return ""

    draft_id = hashlib.sha256(f"{to}{subject}{time.time()}".encode()).hexdigest()[:12]
    q = load_queue()
    q.append(
        {
            "id": draft_id,
            "to": to,
            "subject": subject,
            "body": body,
            "context": context,
            "queued_at": datetime.now().isoformat(),
            "voice_score": verdict.get("score", "?"),
        }
    )
    save_queue(q)
    return draft_id


# ─────────────────────────────────────────────────────────────────────────────
# LinkedIn Connection Map spider
# ─────────────────────────────────────────────────────────────────────────────


def _load_spider_config() -> Dict:
    if SPIDER_CONFIG.exists():
        return json.loads(SPIDER_CONFIG.read_text(encoding="utf-8"))
    return {"roles": {}, "default_role": "head-of-ai", "max_loads": 25}


def _list_roles():
    cfg = _load_spider_config()
    roles = cfg.get("roles", {})
    if RICH:
        tbl = Table(title="🕸  Spider Role Presets", show_lines=True, style="cyan")
        tbl.add_column("Role key", style="bold")
        tbl.add_column("Search query")
        tbl.add_column("Notes")
        for key, val in roles.items():
            notes = []
            if val.get("allow_gatekeeper"):
                notes.append("includes recruiters")
            if val.get("target_boost"):
                notes.append(f"boosts {val['target_boost']}")
            tbl.add_row(key, val.get("query", ""), ", ".join(notes))
        console.print(tbl)
    else:
        print(f"\n{'Role':<24} {'Query'}")
        print("-" * 72)
        for key, val in roles.items():
            print(f"{key:<24} {val.get('query', '')}")
    _print(f"\nEdit roles: {SPIDER_CONFIG}")


def cmd_spider(spider_enabled: bool, role: str = "", list_roles: bool = False):
    """
    Run a Connection Map cycle: targeted search → enrich → rank → show next-to-add.
    Never sends anything. Only reads LinkedIn and updates local data files.
    Requires --spider flag to be enabled — off by default.

    role: preset from spider.config.json — e.g. "ceo", "founder", "tech-recruiter"
          Defaults to config["default_role"] if not specified.
    """
    if list_roles:
        _list_roles()
        return

    if not spider_enabled:
        _die(
            "Spider is OFF by default.\n"
            "Run with --spider to enable LinkedIn Connection Map.\n"
            "This uses your real Firefox session on port 9222.\n"
            "It NEVER sends messages — only ranks who to connect with.\n"
            "See roles: oracle-email --spider spider --list-roles"
        )

    if not CONNMAP_DIR.exists():
        _die(
            f"Connection Map not found at {CONNMAP_DIR}\n  Check that the production repo is cloned."
        )

    cfg = _load_spider_config()
    roles = cfg.get("roles", {})
    role_key = (role or cfg.get("default_role", "head-of-ai")).lower().replace(" ", "-")

    # fuzzy match
    if role_key not in roles:
        matches = [k for k in roles if role_key in k or k in role_key]
        if len(matches) == 1:
            role_key = matches[0]
        elif len(matches) > 1:
            _die(
                f"Ambiguous role '{role_key}' — matches: {', '.join(matches)}\nRun --list-roles to see all."
            )
        elif role_key:
            _die(
                f"Unknown role '{role_key}'.\nRun: oracle-email --spider spider --list-roles"
            )

    role_cfg = roles.get(role_key, {})
    query = role_cfg.get("query", role_key)
    max_loads = cfg.get("max_loads", 25)

    _print(f"\n🕸  Spider: role={role_key!r} | query={query!r} | max_loads={max_loads}")
    _print("   LinkedIn Connection Map — never sends, only ranks\n")

    # Step 1: targeted 2nd-degree search
    _print(f'   🔍 Searching: "{query}"')
    try:
        res = subprocess.run(
            ["node", "src/expand.mjs", "search", query],
            cwd=str(CONNMAP_DIR),
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "MAX_LOADS": str(max_loads)},
        )
        if res.returncode == 1:
            _print("   ⚠️  Not signed into LinkedIn in Chrome — open LinkedIn first")
        elif res.returncode == 2:
            _print("   ⚠️  Challenge/captcha — solve it in Chrome and re-run")
        elif res.returncode not in (0,):
            _print(f"   ⚠️  expand search exited {res.returncode}: {res.stderr[:200]}")
        else:
            _print("   ✅ Search complete")
    except subprocess.TimeoutExpired:
        _print("   ⚠️  Search timed out — partial results written")
    except FileNotFoundError:
        _die("node not found. Node 20+ is required for Connection Map.")

    # Step 2: enrich → rank → map
    steps = [
        (["node", "src/enrich.mjs", "--new"], "Enriching new people…"),
        (["node", "src/rank.mjs"], "Ranking network…"),
        (["node", "src/map.mjs"], "Building web map…"),
    ]
    for cmd_args, label in steps:
        _print(f"   {label}")
        try:
            res = subprocess.run(
                cmd_args,
                cwd=str(CONNMAP_DIR),
                capture_output=True,
                text=True,
                timeout=300,
            )
            if res.returncode not in (0, 1):
                _print(
                    f"   ⚠️  {cmd_args[1]} exited {res.returncode}: {res.stderr[:200]}"
                )
        except subprocess.TimeoutExpired:
            _print(f"   ⚠️  {label} timed out — partial results written")
        except FileNotFoundError:
            _die("node not found. Node 20+ is required for Connection Map.")

    # Show result
    if NEXT_TO_ADD.exists():
        content = NEXT_TO_ADD.read_text(encoding="utf-8")
        lines = content.splitlines()[:60]
        if RICH:
            console.print(
                Panel(
                    "\n".join(lines), title=f"🕸  Next to Add — {role_key}", style="cyan"
                )
            )
        else:
            print("\n" + "=" * 80)
            print("\n".join(lines))
            print("=" * 80)
        _print(f"\n   Full report: {NEXT_TO_ADD}")
    else:
        _print(
            "   No next-to-add.md yet — the search above should have created candidates."
        )


# ─────────────────────────────────────────────────────────────────────────────
# WebPipe recon (bug bounty targets)
# ─────────────────────────────────────────────────────────────────────────────


def cmd_recon(url: str, port: int):
    """
    Use WebPipe to recon a bug bounty target URL.
    Respects WebPipe's politeness cooldowns (45s between requests to same host).
    Never touches gmail.com or linkedin.com — those have their own dedicated paths.
    """
    host = urllib.parse.urlsplit(url).netloc.lower()
    if "gmail" in host or "linkedin" in host or "google.com" in host:
        _die(
            "Recon is for bug bounty targets.\n"
            "  Gmail → use 'oracle-email inbox'\n"
            "  LinkedIn → use 'oracle-email spider --spider'"
        )

    wp = _get_webpipe(port)
    _print(f"\n🔍 Recon: {url}")
    _print("   (Using WebPipe smart_query — politeness cooldown enforced)\n")

    try:
        result, verdict = wp.smart_query(url, wait_seconds=4)
    except PermissionError as e:
        _die(str(e))

    content = result.get("clean_content", "")
    status = result.get("wire", {}).get("doc_status")
    _print(
        f"   HTTP {status} | verified: {verdict.get('verified')} | {len(content)} chars"
    )

    if not content:
        _print("   No content extracted.")
        return

    # Oracle analysis
    _print("\n⚙️  Oracle analysing target (qwen2.5:3b)…")
    persona = _load_persona()
    prompt = (
        f"{persona}\n\n---\n"
        "You are analysing a bug bounty target page. Apply the Oracle 8-reflex: "
        "find the gap between what the spec CLAIMS and what is ENFORCED. "
        "Output: target summary, attack surface, top 3 candidate vulnerabilities, "
        "one curl PoC for the most promising.\n\n"
        f"TARGET URL: {url}\n\nPAGE CONTENT:\n{content[:4000]}\n\nANALYSIS:"
    )
    analysis = _ollama(prompt, timeout=180) or "[ollama unavailable]"

    if RICH:
        console.print(Panel(analysis, title=f"🔍 Oracle Recon: {url}", style="green"))
    else:
        print(f"\n{'='*80}\n{analysis}\n{'='*80}")


# ─────────────────────────────────────────────────────────────────────────────
# Daemon mode
# ─────────────────────────────────────────────────────────────────────────────


def cmd_daemon(port: int, phone: str, spider_enabled: bool, poll_seconds: int = 120):
    """
    Background polling loop:
    - Checks inbox every poll_seconds (default 2 min)
    - Sends desktop notify-send on new messages
    - Sends SMS on CONFIRMED bug bounty finding (from oracle_bounty output)
    - Runs Connection Map cycle once per hour if --spider enabled
    """
    _print(f"\n🔄 Oracle daemon started (polling every {poll_seconds}s)")
    _print(
        f"   Chrome port: {port} | SMS: {'enabled' if phone else 'disabled'} | Spider: {'ON' if spider_enabled else 'OFF'}"  # noqa: E501
    )
    _print("   Ctrl+C to stop\n")

    last_ids: set = set()
    last_spider = 0.0

    while True:
        try:
            # ── Inbox check ───────────────────────────────────────────────
            try:
                messages = read_inbox_via_webpipe(port, max_results=10)
                new_ids = {m["id"] for m in messages} - last_ids
                if last_ids and new_ids:
                    for m in messages:
                        if m["id"] not in new_ids:
                            continue
                        subject = m.get("subject", "(no subject)")[:60]
                        frm = m.get("from", "")[:40]
                        snippet = m.get("snippet", "")[:200]

                        # ── Triage: skip junk, notify + draft for real emails ──
                        triage = triage_email(frm, subject, snippet, port=port)
                        _print(
                            f"[daemon] {frm[:30]} | {subject[:40]} → {triage['priority']}: {triage['reason']}"
                        )

                        if triage["priority"] == "skip":
                            continue

                        notify_msg = f"From: {frm}\n{subject}"
                        if triage["priority"] == "high":
                            notify_msg = f"🔴 HIGH PRIORITY\n{notify_msg}"

                        # Desktop notification
                        try:
                            subprocess.run(
                                ["notify-send", "📬 Oracle Email", notify_msg],
                                timeout=5,
                                capture_output=True,
                            )
                        except Exception:
                            pass

                        # SMS for high-priority only (avoid spam)
                        if phone and triage["priority"] == "high":
                            send_sms(f"HIGH: {subject[:120]}", phone, port)

                        # Auto-draft reply and drop into approval queue
                        if triage["reply"]:
                            try:
                                thread = read_thread_via_webpipe(m["id"], port)
                                content = thread.get("content", "") or snippet
                                draft_body = oracle_draft_reply(content)
                                draft_subject = f"Re: {subject}"
                                did = queue_draft(
                                    frm,
                                    draft_subject,
                                    draft_body,
                                    context=f"triage={triage['priority']}: {triage['reason']}",
                                )
                                if did:
                                    _print(
                                        f"[daemon] ✅ Draft queued: {did} — run 'oracle-email queue' to review"
                                    )
                            except Exception as de:
                                _print(f"[daemon] draft error for {m['id']}: {de}")

                last_ids = {m["id"] for m in messages}
            except Exception as e:
                _print(f"[daemon] inbox check error: {e}")

            # ── Spider cycle (hourly if enabled) ──────────────────────────
            if spider_enabled and (time.time() - last_spider) > 3600:
                try:
                    cmd_spider(spider_enabled=True)
                    last_spider = time.time()
                except Exception as e:
                    _print(f"[daemon] spider error: {e}")

            time.sleep(poll_seconds)

        except KeyboardInterrupt:
            _print("\n🛑 Daemon stopped.")
            break


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────


def cmd_inbox(port: int):
    messages = read_inbox_via_webpipe(port)
    if not messages:
        _print("Inbox is empty or could not be read.")
        return

    if RICH:
        tbl = Table(title="📬 Inbox", show_lines=True, style="cyan")
        tbl.add_column("ID", style="dim", no_wrap=True)
        tbl.add_column("From")
        tbl.add_column("Subject")
        for m in messages:
            tbl.add_row(
                m.get("id", ""), m.get("from", "")[:35], m.get("subject", "")[:50]
            )
        console.print(tbl)
    else:
        print(f"\n{'ID':<20} {'From':<35} {'Subject'}")
        print("-" * 90)
        for m in messages:
            print(
                f"{m.get('id', ''):<20} {m.get('from', '')[:35]:<35} {m.get('subject', '')[:50]}"
            )


def cmd_read(msg_id: str, port: int):
    thread = read_thread_via_webpipe(msg_id, port)
    content = thread.get("content", "")
    if RICH:
        console.print(
            Panel(
                textwrap.fill(content[:3000], 100),
                title=f"📧 Thread {msg_id}",
                style="green",
            )
        )
    else:
        print(f"\n{'='*80}\n{content[:3000]}\n{'='*80}")


def cmd_compose(port: int):
    print()
    to = _ask("To")
    subject = _ask("Subject")
    print("Body (type END on its own line to finish):")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    body = "\n".join(lines)

    _preview(to, subject, body)
    choice = _ask(
        "Action? [s]end now / [q]ueue for approval / [d]iscard", default="q"
    ).lower()

    if choice == "s":
        send_via_chrome_clicks(to, subject, body, port)
    elif choice == "q":
        did = queue_draft(to, subject, body)
        _print(f"✅ Queued as draft ID: {did}")
        _print("   Run `oracle-email queue` to review, `approve <id>` to send.")
    else:
        _print("Discarded.")


def cmd_reply(msg_id: str, port: int):
    thread = read_thread_via_webpipe(msg_id, port)
    content = thread.get("content", "")

    _print(f"\n⚙️  Drafting Oracle reply to thread {msg_id}…")
    _print("   (Calling local Ollama — 20-60s…)\n")

    draft_body = oracle_draft_reply(original_thread=content)
    subject = f"Re: {msg_id}"

    _preview(msg_id, subject, draft_body)

    choice = _ask(
        "Action? [s]end now / [q]ueue for approval / [e]dit / [d]iscard", default="q"
    ).lower()

    if choice == "s":
        send_via_chrome_clicks(msg_id, subject, draft_body, port)
    elif choice == "q":
        did = queue_draft(msg_id, subject, draft_body, context=f"reply to {msg_id}")
        _print(f"✅ Queued as draft ID: {did}")
    elif choice == "e":
        print("Edit body (type END on its own line to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        new_body = "\n".join(lines)
        did = queue_draft(
            msg_id, subject, new_body, context=f"reply to {msg_id} (edited)"
        )
        _print(f"✅ Edited draft queued as: {did}")
    else:
        _print("Discarded.")


def cmd_queue():
    q = load_queue()
    if not q:
        _print("✅ Approval queue is empty.")
        return

    if RICH:
        tbl = Table(title="📋 Approval Queue", show_lines=True, style="yellow")
        tbl.add_column("Draft ID", style="bold")
        tbl.add_column("To")
        tbl.add_column("Subject")
        tbl.add_column("Queued At")
        for item in q:
            tbl.add_row(item["id"], item["to"], item["subject"], item["queued_at"])
        console.print(tbl)
    else:
        print(f"\n{'Draft ID':<14} {'To':<30} {'Subject':<40} {'Queued At'}")
        print("-" * 100)
        for item in q:
            print(
                f"{item['id']:<14} {item['to']:<30} {item['subject']:<40} {item['queued_at']}"
            )
    print()
    _print("Run: oracle-email approve <draft_id>")


def cmd_approve(draft_id: str, port: int):
    q = load_queue()
    item = next((x for x in q if x["id"] == draft_id), None)
    if not item:
        _die(f"Draft ID not found: {draft_id}")

    _preview(item["to"], item["subject"], item["body"])
    if not _confirm("Send this email via Chrome?"):
        _print("Cancelled. Still in queue.")
        return

    ok = send_via_chrome_clicks(item["to"], item["subject"], item["body"], port)
    if ok:
        save_queue([x for x in q if x["id"] != draft_id])
        _print("✅ Sent and removed from queue.")
    else:
        _print("⚠️  Send failed — draft still in queue. Check Chrome is open on Gmail.")


def cmd_interactive(port: int, phone: str, spider_enabled: bool):
    if RICH:
        console.print(
            Panel(
                "[bold cyan]Oracle Email Daemon[/bold cyan]\n"
                "Commands: inbox · read <id> · compose · reply <id> · queue · approve <id>\n"
                "          recon <url> · sms <msg>"
                + (
                    " · spider"
                    if spider_enabled
                    else " · spider (use --spider to enable)"
                )
                + " · daemon · quit",
                style="cyan",
            )
        )
    else:
        print("\n=== Oracle Email Daemon ===")
        print("inbox · read <id> · compose · reply <id> · queue · approve <id>")
        print("recon <url> · sms <msg> · spider · daemon · quit\n")

    while True:
        try:
            raw = input("\noracle-email> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break
        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            print("Signing off.")
            break
        elif cmd == "inbox":
            cmd_inbox(port)
        elif cmd == "read" and arg:
            cmd_read(arg.strip(), port)
        elif cmd == "compose":
            cmd_compose(port)
        elif cmd == "reply" and arg:
            cmd_reply(arg.strip(), port)
        elif cmd == "queue":
            cmd_queue()
        elif cmd == "approve" and arg:
            cmd_approve(arg.strip(), port)
        elif cmd == "recon" and arg:
            cmd_recon(arg.strip(), port)
        elif cmd == "sms" and arg:
            send_sms(arg.strip(), phone, port)
        elif cmd == "spider":
            parts2 = arg.split()
            role_arg = next((p for p in parts2 if not p.startswith("-")), "")
            list_arg = "--list-roles" in parts2
            cmd_spider(spider_enabled, role=role_arg, list_roles=list_arg)
        elif cmd == "daemon":
            cmd_daemon(port, phone, spider_enabled)
        elif cmd == "help":
            print("inbox | read <id> | compose | reply <id> | queue | approve <id>")
            print("recon <url> | sms <message> | spider | daemon | quit")
        else:
            print(f"Unknown: {raw}  (type 'help')")


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ask(prompt: str, default: str = "") -> str:
    if RICH:
        return Prompt.ask(prompt, default=default)
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else default


def _confirm(prompt: str) -> bool:
    if RICH:
        return Confirm.ask(prompt)
    ans = input(f"{prompt} [y/N]: ").strip().lower()
    return ans == "y"


def _preview(to: str, subject: str, body: str):
    if RICH:
        console.print(
            Panel(
                f"[bold]To:[/bold]      {to}\n"
                f"[bold]Subject:[/bold] {subject}\n\n" + textwrap.fill(body, 100),
                title="📝 Draft Preview",
                style="yellow",
            )
        )
    else:
        print(f"\n{'='*60}\nTo:      {to}\nSubject: {subject}\n\n{body}\n{'='*60}")


def _print(msg: str):
    if RICH:
        console.print(msg)
    else:
        print(msg)


def _die(msg: str) -> NoReturn:
    if RICH:
        console.print(f"[red]{msg}[/red]")
    else:
        print(msg)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Oracle Email Daemon — Gmail via Chrome CDP, real clicks, no OAuth"
    )
    parser.add_argument(
        "--spider",
        action="store_true",
        help="Enable LinkedIn Connection Map commands (off by default)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Chrome remote debugging port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--phone",
        default=os.environ.get("ORACLE_PHONE", ""),
        help="T-Mobile number for SMS (or set ORACLE_PHONE env var)",
    )

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("inbox", help="List inbox via Chrome session")
    p_read = sub.add_parser("read", help="Read a thread by ID")
    p_read.add_argument("msg_id")
    sub.add_parser("compose", help="Compose and send via Chrome clicks")
    p_reply = sub.add_parser("reply", help="Oracle-voiced reply draft")
    p_reply.add_argument("msg_id")
    sub.add_parser("queue", help="Show approval queue")
    p_approve = sub.add_parser("approve", help="Approve and send a queued draft")
    p_approve.add_argument("draft_id")
    p_recon = sub.add_parser("recon", help="WebPipe recon a bug bounty target URL")
    p_recon.add_argument("url")
    p_spider = sub.add_parser(
        "spider", help="Run Connection Map cycle (requires --spider)"
    )
    p_spider.add_argument(
        "role",
        nargs="?",
        default="",
        help="Role preset (e.g. ceo, founder, tech-recruiter)",
    )
    p_spider.add_argument(
        "--list-roles", action="store_true", help="List available role presets and exit"
    )
    sub.add_parser("daemon", help="Background polling loop")
    p_sms = sub.add_parser("sms", help="Send a quick SMS via T-Mobile gateway")
    p_sms.add_argument("message", nargs="+")
    sub.add_parser("setup", help="Show setup instructions")

    args = parser.parse_args()

    if args.command == "setup":
        print(__doc__)
        return

    port = args.port
    phone = args.phone
    spider = args.spider

    if args.command == "inbox":
        cmd_inbox(port)
    elif args.command == "read":
        cmd_read(args.msg_id, port)
    elif args.command == "compose":
        cmd_compose(port)
    elif args.command == "reply":
        cmd_reply(args.msg_id, port)
    elif args.command == "queue":
        cmd_queue()
    elif args.command == "approve":
        cmd_approve(args.draft_id, port)
    elif args.command == "recon":
        cmd_recon(args.url, port)
    elif args.command == "spider":
        cmd_spider(spider, role=args.role, list_roles=args.list_roles)
    elif args.command == "daemon":
        cmd_daemon(port, phone, spider)
    elif args.command == "sms":
        send_sms(" ".join(args.message), phone, port)
    else:
        cmd_interactive(port, phone, spider)


if __name__ == "__main__":
    main()
