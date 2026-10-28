#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: credentials, available, fetch_program, H1APIError, H1AuthError
# TOPICS: none
"""Oracle's own HackerOne Hacker API re-scan.

Scan4Me is the ranked feed, but Oracle must not trust Scan4Me's scope copy
for the verification pass. This module fetches the program's structured
scopes directly from api.hackerone.com with Oracle's own credentials
(``HACKERONE_USERNAME`` + ``HACKERONE_API_TOKEN``/``HACKERONE_API_KEY``).

The result is shaped like the Scan4Me bridge's program dict so the same
verify legs run unchanged. No token is ever printed or written to a report;
provenance carries only the username and counts.

No credentials or network use at import time. Missing/rejected credentials
raise ``H1AuthError``; a 404 (program gone) returns ``None`` so the caller
can render a vanished program as unverified, not silently re-use stale scope.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

API_BASE = "https://api.hackerone.com/v1"
API_HOST = "api.hackerone.com"
DEFAULT_TIMEOUT = 15.0
MAX_PAGES = 20
_HERE = Path(__file__).resolve().parent
# Same layered key files (and precedence) as oracle_hunter._load_env:
# trio central < ORACLE_KEYS.env < repo .env < system environment.
_ENV_FILES = (
    Path.home() / ".config" / "trio" / "keys.env",
    _HERE / "ORACLE_KEYS.env",
    _HERE / ".env",
)


class H1APIError(RuntimeError):
    """The Oracle HackerOne re-scan could not establish truth."""


class H1AuthError(H1APIError):
    """Oracle's HackerOne credentials are missing or rejected."""


def _env_value(name: str) -> str:
    """Resolve one variable through the layered key files, then os.environ."""
    value = ""
    for path in _ENV_FILES:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw = line.split("=", 1)
            if key.strip() != name:
                continue
            candidate = raw.strip().strip('"').strip("'")
            # Empty values and multi-word placeholder notes never clobber
            # a real key from a lower layer (oracle_hunter._load_env rule).
            if candidate and not any(c.isspace() for c in candidate):
                value = candidate
    return (os.environ.get(name) or value or "").strip()


def credentials() -> Tuple[str, str]:
    """Return ``(username, token)`` from Oracle-owned env/file layers only."""
    username = _env_value("HACKERONE_USERNAME")
    token = _env_value("HACKERONE_API_TOKEN") or _env_value("HACKERONE_API_KEY")
    return username, token


def available() -> bool:
    username, token = credentials()
    return bool(username and token)


def _auth_header(username: str, token: str) -> str:
    raw = f"{username}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: the default handler forwards Authorization cross-host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request_json(
    path_or_url: str,
    *,
    username: str,
    token: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[Dict[str, Any]]:
    """GET one HackerOne API resource. 404 -> None; auth/transport -> error."""
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        url = path_or_url
    else:
        url = API_BASE + (
            path_or_url if path_or_url.startswith("/") else "/" + path_or_url
        )
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != API_HOST:
        raise H1APIError(f"refusing non-HackerOne API URL: {url[:120]}")
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "Authorization": _auth_header(username, token),
            "User-Agent": "oracle-h1-rescan/1.0",
        },
    )
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (401, 403):
            raise H1AuthError(
                f"HackerOne API rejected Oracle credentials (HTTP {exc.code})"
            ) from exc
        raise H1APIError(f"HackerOne API HTTP {exc.code} for {url}") from exc
    except urllib.error.URLError as exc:
        raise H1APIError(f"HackerOne API transport failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise H1APIError("HackerOne API timed out") from exc
    try:
        payload = json.loads(body)
    except (TypeError, ValueError) as exc:
        raise H1APIError("HackerOne API returned non-JSON") from exc
    if not isinstance(payload, dict):
        raise H1APIError("HackerOne API returned a non-object payload")
    return payload


def _next_url(payload: Dict[str, Any]) -> Optional[str]:
    links = payload.get("links")
    if not isinstance(links, dict):
        return None
    nxt = links.get("next")
    if not isinstance(nxt, str) or not nxt.strip():
        return None
    return urllib.parse.urljoin(API_BASE + "/", nxt.strip())


def _scope_record(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    attrs = item.get("attributes") if isinstance(item, dict) else None
    if not isinstance(attrs, dict):
        return None
    ident = str(attrs.get("asset_identifier") or "").strip()
    if not ident:
        return None
    try:
        from oracle_scan4me import canon_asset_type
    except Exception:
        canon_asset_type = lambda raw: str(raw or "OTHER").upper()  # noqa: E731

    return {
        "asset_identifier": ident,
        "asset_type": canon_asset_type(attrs.get("asset_type")),
        "is_wildcard": "*" in ident
        or str(attrs.get("asset_type") or "").upper() == "WILDCARD",
        # Missing eligibility is malformed truth: fail closed to ineligible
        # (the public GraphQL path defaults the same way).
        "eligible_for_bounty": attrs.get("eligible_for_bounty") is True,
        "eligible_for_submission": attrs.get("eligible_for_submission") is True,
        "instruction": str(attrs.get("instruction") or ""),
        "max_severity": str(attrs.get("max_severity") or ""),
    }


def fetch_program(
    handle: str, *, timeout: float = DEFAULT_TIMEOUT
) -> Optional[Dict[str, Any]]:
    """Fetch a program's current structured scopes with Oracle credentials.

    Returns a Scan4Me-shaped program dict with ``_oracle_rescan`` provenance,
    or ``None`` when HackerOne says the program no longer exists.
    """
    handle = (handle or "").strip().strip("/").lower()
    if not handle:
        raise ValueError("HackerOne handle is required")
    username, token = credentials()
    if not username or not token:
        raise H1AuthError(
            "Oracle HackerOne credentials missing: set HACKERONE_USERNAME and "
            "HACKERONE_API_TOKEN (or HACKERONE_API_KEY) before scan"
        )
    fetched_at = datetime.now(timezone.utc).isoformat()
    quoted = urllib.parse.quote(handle, safe="")
    program_payload = _request_json(
        f"/hackers/programs/{quoted}", username=username, token=token, timeout=timeout
    )
    scopes_payload = _request_json(
        f"/hackers/programs/{quoted}/structured_scopes?page%5Bsize%5D=100",
        username=username,
        token=token,
        timeout=timeout,
    )
    if program_payload is None:
        # A 404 on the program itself is authoritative: it is gone. Never let
        # a stale scopes response keep a revoked program alive.
        return None
    if scopes_payload is None:
        raise H1APIError(
            "HackerOne structured_scopes returned 404 for an existing program; "
            "refusing an empty/partial scope list"
        )

    scopes: List[Dict[str, Any]] = []
    out_of_scope: List[str] = []
    out_of_scope_records: List[Dict[str, Any]] = []
    pages = 0
    payload: Optional[Dict[str, Any]] = scopes_payload or {"data": []}
    while isinstance(payload, dict):
        if pages >= MAX_PAGES:
            # The last allowed page still has a next link: refuse a partial
            # scope list. Do not fetch an extra page just to discover that.
            if _next_url(payload):
                raise H1APIError(
                    f"HackerOne structured_scopes exceeded {MAX_PAGES} pages; "
                    "refusing a partial scope list"
                )
            break
        pages += 1
        data = payload.get("data")
        if not isinstance(data, list):
            raise H1APIError("HackerOne structured_scopes payload has no data list")
        for item in data:
            rec = _scope_record(item)
            if rec is None:
                continue
            if (
                rec["eligible_for_submission"] is False
                or rec["eligible_for_bounty"] is False
            ):
                out_of_scope.append(rec["asset_identifier"])
                out_of_scope_records.append(rec)
            else:
                scopes.append(rec)
        nxt = _next_url(payload)
        if not nxt:
            break
        if pages >= MAX_PAGES:
            raise H1APIError(
                f"HackerOne structured_scopes exceeded {MAX_PAGES} pages; "
                "refusing a partial scope list"
            )
        payload = _request_json(nxt, username=username, token=token, timeout=timeout)
        if payload is None:
            raise H1APIError("HackerOne pagination returned 404")

    attrs: Dict[str, Any] = {}
    if isinstance(program_payload, dict):
        maybe = program_payload.get("data")
        if isinstance(maybe, dict):
            attrs = maybe.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
    policy = str(attrs.get("policy") or "")
    return {
        "name": str(attrs.get("name") or handle),
        "handle": str(attrs.get("handle") or handle),
        "platform": "HackerOne",
        "url": f"https://hackerone.com/{handle}",
        "website": "",
        "max_payout_usd": None,
        "currency": "USD",
        "safe_harbor": "",
        "managed_triage": bool(attrs.get("triage_active", False)),
        "program_kind": "web2",
        "structured_scopes": scopes,
        "out_of_scope": sorted(set(out_of_scope)),
        "out_of_scope_scopes": out_of_scope_records,
        "rules_text": policy,
        "policy": policy,
        "_oracle_rescan": {
            "source": "hackerone-api-authenticated",
            "independent": True,
            "found": True,
            "api": "v1",
            "username": username,
            "handle": handle,
            "fetched_at": fetched_at,
            "scope_count": len(scopes),
            "out_of_scope_count": len(out_of_scope),
            "scope_pages": pages,
            "program_metadata": bool(attrs),
        },
    }
