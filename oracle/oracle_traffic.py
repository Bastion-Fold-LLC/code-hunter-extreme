# LAYER: find
# DEST: basilisk
# ENDPOINTS: import_har
# TOPICS: none
"""Safe, scope-gated traffic evidence ingestion for website-only hunts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}


def _redacted_url(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode(
        [
            (key, "<redacted>")
            for key, _ in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _header_names(headers: Any) -> list[str]:
    return sorted(
        {
            str(header.get("name", "")).lower()
            for header in headers
            if isinstance(header, dict)
            and str(header.get("name", "")).lower() not in _SENSITIVE_HEADERS
        }
    )


def _body_field_names(post_data: Any) -> list[str]:
    if not isinstance(post_data, dict):
        return []
    params = post_data.get("params")
    if isinstance(params, list):
        return sorted(
            {
                str(param.get("name", ""))
                for param in params
                if isinstance(param, dict) and param.get("name")
            }
        )
    return []


def import_har(
    har_path: Path,
    recon_dir: Path,
    scope_gate: Optional[Any] = None,
) -> Dict[str, int]:
    """Import redacted, in-scope HAR request metadata into recon evidence.

    Cookies, authorization values, response bodies, and request values are
    deliberately never persisted. A scope gate is required so a browser export
    cannot smuggle third-party traffic into a target's research context.
    """
    if scope_gate is None:
        raise ValueError("HAR import requires a program scope gate")
    try:
        document = json.loads(har_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read HAR file {har_path}: {exc}") from exc

    entries = document.get("log", {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("HAR file has no log.entries array")

    recon_dir.mkdir(parents=True, exist_ok=True)
    output = recon_dir / "traffic_evidence.jsonl"
    accepted: list[Dict[str, Any]] = []
    rejected = malformed = 0

    for entry in entries:
        request = entry.get("request") if isinstance(entry, dict) else None
        response = entry.get("response") if isinstance(entry, dict) else None
        if not isinstance(request, dict) or not isinstance(response, dict):
            malformed += 1
            continue
        url = request.get("url")
        if not isinstance(url, str) or not url:
            malformed += 1
            continue
        allowed, _reason = scope_gate.is_in_scope(url)
        if not allowed:
            rejected += 1
            continue
        raw_content = response.get("content")
        content = raw_content if isinstance(raw_content, dict) else {}
        accepted.append(
            {
                "source": "har",
                "method": str(request.get("method", "GET")).upper(),
                "url": _redacted_url(url),
                "status": int(response.get("status", 0) or 0),
                "request_header_names": _header_names(request.get("headers", [])),
                "request_body_fields": _body_field_names(request.get("postData")),
                "response_mime_type": str(content.get("mimeType", "")),
            }
        )

    with output.open("w", encoding="utf-8") as handle:
        for record in accepted:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    return {
        "accepted": len(accepted),
        "rejected_out_of_scope": rejected,
        "malformed": malformed,
    }
