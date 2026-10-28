#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: verify_seam_card, run_deterministic, render_findings_block, parse_expected, check_security_headers, check_cors, extract_js_secrets, check_response_secrets, extract_js_endpoints, check_verbose_errors, check_open_api, extract_status_from_curl_output, extract_check_url  # noqa: E501
# TOPICS: none
"""Oracle deterministic engine — rule-based web-surface checks.

Pure code, no LLM. Every finding carries three things Alex demanded:
  1. MITRE ATT&CK technique code(s) drawn from the fused TTP library
     (oracle_ttps_fused.json) — the same language the reflexes speak.
  2. A scope verdict from the bounty program's ProgramScopeGate —
     out-of-scope findings are dropped, never emitted.
  3. A paradox lens — a "you never said" inversion prompt in the Oracle
     voice, so the reflexes know WHERE to aim, not just WHAT was found.

Integration: run_reflexes() calls run_deterministic() after recon and
injects render_findings_block() into the reflex task as
--- DETERMINISTIC FINDINGS ---. Additive only; existing blocks untouched.
"""
from __future__ import annotations

import json
import re
import shlex
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from oracle_foundation import generate_proof_packet

_HERE = Path(__file__).resolve().parent
_TTPS_FUSED = _HERE / "oracle_ttps_fused.json"

# ---------------------------------------------------------------------------
# MITRE code registry (validated against the fused library at import)
# ---------------------------------------------------------------------------

_MITRE_REGISTRY: Dict[str, str] = {
    "T1595": "Active Scanning",
    "T1590": "Gather Victim Network Information",
    "T1592": "Gather Victim Host Information",
    "T1593": "Search Open Websites/Domains",
    "T1594": "Search Victim-Owned Websites",
    "T1190": "Exploit Public Facing Application",
    "T1552": "Unsecured Credentials",
    "T1539": "Steal Web Session Cookie",
    "T1557": "Adversary In The Middle",
    "T1606": "Forge Web Credentials",
    "T1078": "Valid Accounts",
    "T1213": "Data from Information Repositories",
}


def _validate_mitre() -> None:
    """Fail fast if a registry code is missing from the fused library."""
    if not _TTPS_FUSED.exists():
        raise FileNotFoundError(
            f"deterministic engine: fused library not found: {_TTPS_FUSED}"
        )
    try:
        known = {
            t.get("code") for t in json.loads(_TTPS_FUSED.read_text(encoding="utf-8"))
        }
    except Exception as e:
        raise RuntimeError(
            f"deterministic engine: failed to parse fused library {_TTPS_FUSED}: {e}"
        ) from e
    missing = [c for c in _MITRE_REGISTRY if c not in known]
    if missing:
        raise RuntimeError(
            f"deterministic engine: MITRE codes missing from fused library: {missing}"
        )


_validate_mitre()

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

Finding = Dict[str, object]


def _finding(
    check: str,
    asset: str,
    severity: str,
    evidence: str,
    mitre: List[str],
    paradox: str,
    repro: str,
) -> Finding:
    for code in mitre:
        if code not in _MITRE_REGISTRY:
            raise ValueError(f"unknown MITRE code in finding: {code}")
    return {
        "check": check,
        "asset": asset,
        "severity": severity,
        "evidence": evidence,
        "mitre": mitre,
        "mitre_names": [_MITRE_REGISTRY[c] for c in mitre],
        "paradox": paradox,
        "repro": repro,
    }


# ---------------------------------------------------------------------------
# Check 1: security headers
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS = {
    "content-security-policy": (
        "medium",
        "Missing Content-Security-Policy — XSS has no browser-level backstop.",
    ),
    "strict-transport-security": (
        "medium",
        "Missing Strict-Transport-Security — TLS can be stripped.",
    ),
    "x-frame-options": ("low", "Missing X-Frame-Options — clickjacking surface open."),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options — MIME-sniffing attacks possible.",
    ),
    "referrer-policy": (
        "low",
        "Missing Referrer-Policy — full URLs (tokens?) leak in Referer headers.",
    ),
}


def check_security_headers(url: str, headers: Dict[str, str]) -> List[Finding]:
    lowered = {k.lower(): v for k, v in headers.items()}
    out = []
    for h, (sev, why) in _REQUIRED_HEADERS.items():
        if h not in lowered:
            # R4: a missing hardening header is scanner-observed surface
            # (T1595), not an exploited weakness (T1190). HSTS keeps T1557
            # (TLS stripping is the adversary-in-the-middle it enables).
            mitre_tags = ["T1557"] if h == "strict-transport-security" else ["T1595"]
            out.append(
                _finding(
                    check="missing_security_header",
                    asset=url,
                    severity=sev,
                    evidence=f"Response headers lack {h}. {why}",
                    mitre=mitre_tags,
                    paradox=(
                        "You claimed the app is hardened. You never said WHERE the hardening lives. "
                        "No header, no enforcement — find what the missing policy was supposed to stop."
                    ),
                    repro=f"curl -i -s {url} | head -30",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Check 2: CORS misconfiguration
# ---------------------------------------------------------------------------


def check_cors(url: str, headers: Dict[str, str]) -> List[Finding]:
    lowered = {k.lower(): v for k, v in headers.items()}
    acao = lowered.get("access-control-allow-origin", "")
    acac = lowered.get("access-control-allow-credentials", "").lower() == "true"
    out = []
    if acao == "*" and acac:
        out.append(
            _finding(
                check="cors_wildcard_credentials",
                asset=url,
                severity="high",
                evidence="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — "
                "any origin reads credentialed responses.",
                mitre=["T1539", "T1557"],
                paradox=(
                    "You claimed cross-origin data is protected. You never said WHICH origins. "
                    "The answer is 'all of them' — find what an attacker's page can now read."
                ),
                repro=f"curl -i -s -H 'Origin: https://evil.example' {url}",
            )
        )
    elif acao == "*":
        out.append(
            _finding(
                check="cors_wildcard",
                asset=url,
                severity="low",
                evidence="Access-Control-Allow-Origin: * — any origin can read non-credentialed responses (standard on public APIs).",  # noqa: E501
                mitre=["T1213"],
                paradox=(
                    "You claimed the API is same-origin. You never said the server agrees. "
                    "It answers everyone — find what public data becomes an attacker's data."
                ),
                repro=f"curl -i -s -H 'Origin: https://evil.example' {url}",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Check 3: secrets in JavaScript
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "generic_api_key",
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    ),
    ("bearer_token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("google_api", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("stripe", re.compile(r"s[kr]_(live|test)_[0-9A-Za-z]{16,}")),
]


def extract_js_secrets(js_url: str, js_text: str) -> List[Finding]:
    out = []
    for name, rx in _SECRET_PATTERNS:
        m = rx.search(js_text)
        if m:
            out.append(
                _finding(
                    check="js_secret_exposed",
                    asset=js_url,
                    severity="high",
                    evidence=f"Pattern '{name}' matched in shipped JavaScript: {m.group(0)[:40]}...",
                    mitre=["T1552", "T1594"],
                    paradox=(
                        "You claimed secrets live server-side. You never said the bundle agrees. "
                        "It ships to every visitor — find what this key unlocks."
                    ),
                    repro=f"curl -s {js_url} | grep -o -E '.{{0,20}}{re.escape(m.group(0)[:12])}.{{0,20}}'",
                )
            )
    return out


def check_response_secrets(url: str, body: str) -> List[Finding]:
    """Scan ANY response body (HTML/JSON/API) for leaked secrets — not just JS
    bundles. A credential returned in an endpoint's response (e.g. a /debug or
    /config route) is the leak itself, and extract_js_secrets only ever saw .js.
    First match per pattern, high severity."""
    out = []
    for name, rx in _SECRET_PATTERNS:
        m = rx.search(body or "")
        if m:
            out.append(
                _finding(
                    check="response_secret_exposed",
                    asset=url,
                    severity="high",
                    evidence=f"Pattern '{name}' matched in the response body: {m.group(0)[:40]}...",
                    mitre=["T1552", "T1594"],
                    paradox=(
                        "You claimed secrets stay internal. You never said this endpoint agrees. "
                        "It handed one back in its response — find what this credential unlocks."
                    ),
                    repro=f"curl -s {url} | grep -o -E '.{{0,20}}{re.escape(m.group(0)[:12])}.{{0,20}}'",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Check 4: API endpoints in JavaScript
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/[a-zA-Z0-9_\-/{}:.]{3,}?)["\']'),
    re.compile(r'["\'](https?://[a-zA-Z0-9_\-./:{}?=&%]{8,}?)["\']'),
]


def extract_js_endpoints(
    js_url: str, js_text: str, max_endpoints: int = 40
) -> List[Finding]:
    seen: List[str] = []
    for rx in _ENDPOINT_PATTERNS:
        for m in rx.finditer(js_text):
            ep = m.group(1)
            if ep not in seen and any(
                k in ep
                for k in (
                    "/api",
                    "/v1",
                    "/v2",
                    "/graphql",
                    "/rest",
                    "auth",
                    "token",
                    "admin",
                )
            ):
                seen.append(ep)
            if len(seen) >= max_endpoints:
                break
    if not seen:
        return []
    return [
        _finding(
            check="js_api_surface",
            asset=js_url,
            severity="low",
            evidence=f"{len(seen)} API-ish endpoints referenced in shipped JS: {', '.join(seen[:8])}"
            + ("..." if len(seen) > 8 else ""),
            mitre=["T1594", "T1590"],
            paradox=(
                "You claimed the API surface is documented. You never said the docs are complete. "
                "The bundle lists endpoints nobody announced — probe the undocumented ones first."
            ),
            repro=f"curl -s {js_url} | grep -o -E '\"/[a-z0-9/_-]{{3,}}\"' | sort -u",
        )
    ]


# ---------------------------------------------------------------------------
# Check 5: verbose errors / stack traces
# ---------------------------------------------------------------------------

_ERROR_PATTERNS = [
    (
        "stack_trace",
        re.compile(r"(?i)(stack trace|at [a-zA-Z_$][\w$.]+\s*\([^)]*:\d+:\d+\))"),
    ),
    (
        "debug_page",
        re.compile(r"(?i)(debug\s*mode|django|laravel|rails).{0,80}(version|error)"),
    ),
    (
        "sql_error",
        re.compile(r"(?i)(sql syntax|mysql|pg_query|ORA-|sqlite3?\.|psycopg2)"),
    ),
]


def check_verbose_errors(url: str, body: str) -> List[Finding]:
    out = []
    for name, rx in _ERROR_PATTERNS:
        m = rx.search(body or "")
        if m:
            out.append(
                _finding(
                    check="verbose_error",
                    asset=url,
                    severity="medium",
                    evidence=f"Error disclosure '{name}': {m.group(0)[:80]}...",
                    mitre=["T1592", "T1595"],
                    paradox=(
                        "You claimed errors are sanitized. You never said the edge cases are. "
                        "One malformed input made the server confess — find what else it will admit."
                    ),
                    repro=f"curl -s '{url}' | head -c 2000",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Check 6: unauthenticated API surface (200 on api-ish path, no auth challenge)
# ---------------------------------------------------------------------------


def check_open_api(
    url: str, status: int, headers: Dict[str, str], body: str
) -> List[Finding]:
    path = urlparse(url).path.lower()
    if status != 200 or not any(
        k in path for k in ("/api", "/v1", "/v2", "/graphql", "/rest", "/internal")
    ):
        return []
    lowered = {k.lower(): v for k, v in headers.items()}
    if "www-authenticate" in lowered:
        return []
    return [
        _finding(
            check="open_api_surface",
            asset=url,
            severity="high",
            evidence="API-ish path returns 200 with no auth challenge.",
            # Dual tag is deliberate: a 200 with no auth challenge on an
            # API path is an exploitable misconfiguration (T1190 — the
            # endpoint serves data to unauthenticated callers), not mere
            # observation; T1595 covers the active-probing discovery side.
            mitre=["T1190", "T1595"],
            paradox=(
                "You claimed the API requires authentication. You never said this endpoint got the memo. "
                "It answered 200 to nobody — find what data it hands out."
            ),
            repro=f"curl -i -s {url} | head -20",
        )
    ]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_fetcher(
    url: str, scope_gate=None
) -> Tuple[int, Dict[str, str], str, List[str]]:
    """Fetch a URL. Returns (status, headers, body, js_urls_found)."""
    opener = urllib.request.build_opener(_NoRedirect)
    current = url
    for _ in range(3):
        if scope_gate is not None and not scope_gate.is_in_scope(current)[0]:
            return 0, {}, "", []
        req = urllib.request.Request(
            current, headers={"User-Agent": "OracleDeterministic/1.0"}
        )
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        except Exception:
            return 0, {}, "", []
        status = response.status
        headers = dict(response.headers.items())
        if status in (301, 302, 303, 307, 308):
            location = headers.get("Location")
            if not location:
                return 0, {}, "", []
            from urllib.parse import urljoin

            current = urljoin(current, location)
            continue
        try:
            with response:
                body = response.read(500_000).decode("utf-8", errors="replace")
        except Exception:
            return 0, {}, "", []
        break
    else:
        return 0, {}, "", []
    js_urls: List[str] = []
    if "text/html" in headers.get("Content-Type", ""):
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body):
            src = m.group(1)
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("/"):
                p = urlparse(current)
                js_urls.append(f"{p.scheme}://{p.netloc}{src}")
    return status, headers, body, js_urls[:10]


def run_deterministic(
    live_hosts: List[str],
    scope_gate=None,
    fetcher: Optional[
        Callable[[str], Tuple[int, Dict[str, str], str, List[str]]]
    ] = None,
    max_hosts: int = 25,
) -> List[Finding]:
    """Run all deterministic checks against live hosts.

    live_hosts: URLs from clean_live_hosts.txt.
    scope_gate: ProgramScopeGate or None (None = no scope filtering).
    fetcher: injectable for tests; defaults to a real HTTP fetch.
    Returns findings sorted high > medium > low, in-scope only.
    """
    fetch = fetcher or (lambda url: _default_fetcher(url, scope_gate))
    findings: List[Finding] = []
    seen_js: set = set()

    for raw in live_hosts[:max_hosts]:
        url = raw.strip().split()[0]
        if not url.startswith("http"):
            url = "https://" + url
        if scope_gate is not None:
            ok, _reason = scope_gate.is_in_scope(url)
            if not ok:
                continue
        status, headers, body, js_urls = fetch(url)
        if status == 0:
            continue
        findings += check_security_headers(url, headers)
        findings += check_cors(url, headers)
        findings += check_verbose_errors(url, body)
        findings += check_open_api(url, status, headers, body)
        findings += check_response_secrets(url, body)
        for js_url in js_urls:
            if js_url in seen_js:
                continue
            seen_js.add(js_url)
            if scope_gate is not None:
                ok, _ = scope_gate.is_in_scope(js_url)
                if not ok:
                    continue
            jstatus, _jh, jbody, _ = fetch(js_url)
            if jstatus == 0:
                continue
            findings += extract_js_secrets(js_url, jbody)
            findings += extract_js_endpoints(js_url, jbody)

    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: rank.get(str(f["severity"]), 3))
    return findings


def render_findings_block(findings: List[Finding]) -> str:
    """Render findings as the --- DETERMINISTIC FINDINGS --- block for reflexes."""
    if not findings:
        return "--- DETERMINISTIC FINDINGS ---\n(none — deterministic checks found nothing)\n"
    lines = [
        "--- DETERMINISTIC FINDINGS ---",
        f"{len(findings)} rule-based findings. Each carries MITRE technique(s), "
        "a scope verdict (all in-scope), and a paradox lens telling you WHERE to aim.",
        "",
    ]
    for i, f in enumerate(findings, 1):
        mitre = ", ".join(f["mitre"])  # type: ignore[arg-type]
        names = ", ".join(f["mitre_names"])  # type: ignore[arg-type]
        lines += [
            f"**D-FINDING [{i}]** [{f['severity']}] {f['check']}",
            f"- Asset: {f['asset']}",
            f"- Evidence: {f['evidence']}",
            f"- MITRE: {mitre} ({names})",
            f"- Paradox lens: {f['paradox']}",
            f"- Repro: `{f['repro']}`",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Deterministic seam verification — the "no debate" machine.
#
# A seam card is a TEST CASE: Assertion A (the claim), Assertion B (the wire
# reality), and an Expected line (machine-readable prediction). This verifier
# is the test runner. The LLM writes the test; code runs it. A passing test
# is not debated — it passed.
#
# Verdicts: CONFIRMED (all gates pass) or REJECTED (exact reason). There is
# no INCONCLUSIVE, no LLM assessment, no "maybe". A card that cannot be
# verified is REJECTED, never confirmed.
# ---------------------------------------------------------------------------


def parse_expected(expected_str: str) -> Dict[str, object]:
    """Parse an Expected line into a machine-readable prediction.

    Format: 'status 200' | 'status 200, body contains "users"' |
            'status 401, body not contains "token"'
    Returns status, body predicates, and header predicates.
    """
    out: Dict[str, object] = {
        "status": None,
        "body_contains": [],
        "body_not_contains": [],
        "body_contains_any": [],
        "headers_absent": [],
        "headers_contains": {},
        "web3_detector": None,
        "forge_verdict": None,
    }
    if not expected_str:
        return out
    s = expected_str.strip()
    m_det = re.search(r'detector\s+["\']?([a-zA-Z0-9_-]+)["\']?', s, re.IGNORECASE)
    if m_det:
        out["web3_detector"] = m_det.group(1).lower()
    m_forge = re.search(r"forge\s*\[?(PASS|FAIL)\]?", s, re.IGNORECASE)
    if m_forge:
        out["forge_verdict"] = m_forge.group(1).upper()
    m = re.search(r"status\s+(\d{3})", s)
    if m:
        out["status"] = int(m.group(1))
    # OR-set: 'body contains any of "a","b",...' — at least one must be present.
    # Parsed (and stripped from s) before the plain 'body contains "X"' parser so
    # its quoted tokens are not also counted as AND predicates.
    m_any = re.search(r"body\s+contains\s+any\s+of\s+(.+?)(?:;|$)", s, re.IGNORECASE)
    if m_any:
        out["body_contains_any"] = re.findall(r'"([^"]+)"', m_any.group(1))
        s = (s[: m_any.start()] + s[m_any.end() :]).strip()
    for m in re.finditer(r'body\s+contains\s+"([^"]+)"', s):
        out["body_contains"].append(m.group(1))  # type: ignore[attr-defined]
    for m in re.finditer(r'body\s+not\s+contains\s+"([^"]+)"', s):
        out["body_not_contains"].append(m.group(1))  # type: ignore[attr-defined]
    # unquoted fallback: body contains users
    if not out["body_contains"]:
        m = re.search(r"body\s+contains\s+(\S+)", s)
        if m and m.group(1) != '"':
            out["body_contains"].append(m.group(1).strip('"'))  # type: ignore[attr-defined]
    for m in re.finditer(r"header\s+([a-z0-9-]+)\s+absent", s, re.IGNORECASE):
        out["headers_absent"].append(m.group(1).lower())  # type: ignore[attr-defined]
    for m in re.finditer(
        r'header\s+([a-z0-9-]+)\s*(?:contains|:)\s*["\']?([^,"\']+)', s, re.IGNORECASE
    ):
        name, value = m.group(1).lower(), m.group(2).strip()
        if value and value.lower() != "absent":
            out["headers_contains"][name] = value  # type: ignore[index]
    return out


def extract_check_url(check_cmd: str) -> str:
    """Extract the first http(s) URL from a curl check command."""
    m = re.search(r"https?://[^\s'\"<>`]+", check_cmd or "")
    return m.group(0).rstrip("`").rstrip("*") if m else ""


def extract_check_target(check_cmd: str) -> str:
    """Extract primary target (URL, file path, or contract address) from a check command."""
    url = extract_check_url(check_cmd)
    if url:
        return url
    try:
        parts = shlex.split(check_cmd or "")
        if len(parts) > 1:
            for p in parts[1:]:
                if not p.startswith("-"):
                    return p
    except Exception:
        pass
    return ""


def extract_status_from_curl_output(stdout: str) -> Optional[int]:
    """Pull the HTTP status code from curl -i output.

    Takes the LAST status line: with -L (follow redirects) curl prints one
    per hop, and the final hop is the actual observation.
    """
    matches = re.findall(r"HTTP/[\d.]+\s+(\d{3})", stdout or "")
    return int(matches[-1]) if matches else None


def extract_headers_from_curl_output(stdout: str) -> Dict[str, str]:
    """Extract the final HTTP response headers from a ``curl -i`` response."""
    blocks = re.split(r"(?:\r?\n){2}", stdout or "")
    header_blocks = [b for b in blocks if re.match(r"^HTTP/[\d.]+\s+\d{3}", b)]
    if not header_blocks:
        return {}
    headers: Dict[str, str] = {}
    for line in header_blocks[-1].splitlines()[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _grounded(url: str, recon_urls: List[str]) -> bool:
    """Is this URL grounded in recon data? Exact-host matching only.

    A check URL is grounded when some recon entry has the SAME host
    (no substring games: api.wolt.com.evil.com != api.wolt.com) and the
    recon path is the check path or a proper path prefix of it. Query
    strings are probe payloads, not provenance, so they never affect
    grounding — a bare-host recon entry grounds root probes like
    ``http://host?id=...`` (the old string-prefix test required a "/"
    after the host and rejected every root query probe).
    Scheme-less recon entries ("wolt.com") are treated as https://.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    path = parsed.path or "/"
    for raw in recon_urls:
        u = (raw or "").strip().split()[0].strip("`\"'") if (raw or "").strip() else ""
        if not u:
            continue
        if "://" not in u:
            u = "https://" + u
        try:
            ru = urlparse(u)
            rhost = (ru.hostname or "").lower()
        except Exception:
            continue
        if rhost != host:
            continue
        rpath = ru.path or "/"
        if rpath == "/" or path == rpath or path.startswith(rpath.rstrip("/") + "/"):
            return True
    return False


# Denial/absence markers — byte-identical mirror of _assess_response
# rules 3-4 (oracle_hunter.py). Both verdict paths must agree that a
# denial status is evidence FOR Assertion A (the barrier holds), never
# a confirmation of B. test_verdict_direction_parity locks the mirror.
_DENIAL_MARKERS = (
    "401 unauthorized",
    "403 forbidden",
    "access denied",
    "attention required! | cloudflare",
    "error 530",
    "status 401",
    "status 403",
    "http/1.1 401",
    "http/1.1 403",
    "http/2 401",
    "http/2 403",
)
_ABSENT_MARKERS = ("404 not found", "http/1.1 404", "http/2 404")

# Generic envelope words that appear in any JSON/HTML 200 and therefore
# discriminate nothing as leak markers (hunt-2 precision postmortem).
_GENERIC_MARKERS = frozenset(
    {
        "id",
        "ids",
        "data",
        "error",
        "errors",
        "err",
        "message",
        "messages",
        "msg",
        "result",
        "results",
        "item",
        "items",
        "status",
        "success",
        "successful",
        "ok",
        "true",
        "false",
        "null",
        "none",
        "nil",
        "page",
        "total",
        "count",
        "list",
        "object",
        "array",
    }
)


# Gate 7: prediction-adequacy claim vocabularies (hunt-3: 3/411
# confirmed, all vacuous — the verifier checked prediction-match but
# never prediction-adequacy). Single words match on a leading word
# boundary so "ships" never fires on "relationships".
_CONTENT_WORD_RES = tuple(
    re.compile(r"\b" + w)
    for w in (
        "leak",
        "expos",
        "disclos",
        "ship",
        "secret",
        "credential",
        "passw",
        "ssn",
        "pii",
        "apikey",
    )
)
_CONTENT_PHRASES = ("social security", "api key", "private key")
_SECRET_WORD_RES = tuple(
    re.compile(r"\b" + w) for w in ("secret", "credential", "passw", "apikey")
)
_SECRET_PHRASES = ("api key", "private key")
_SHIPPED_WORD_RES = tuple(
    re.compile(r"\b" + w + r"\b")
    for w in ("shipped", "ships", "bundle", "javascript", "js")
)
_SHIPPED_PHRASES = ("client-side",)
VARIATION_CLAIM_RES = tuple(
    re.compile(r"\b" + w)
    for w in ("header", "inject", "spoof", "override", "bypass", "tamper", "smuggl")
)
VARIATION_CLAIM_PHRASES = ("x-forwarded", "x-original", "x-http-method")
# Omission frame: "without/missing/absent/lacking <cred>" claims are
# tested BY omission — a plain check with no credentials IS the test,
# so Rule B2 must not demand an injected artifact for them.
_OMISSION_FRAME_RE = re.compile(
    r"\b(without|missing|absent|lacking)\b.{0,30}\b(auth|authorization|headers?|credentials?|tokens?|cookies?|jwt|logins?|api[_-]?key)\b"  # noqa: E501
)


def _claim_hits(text: str, reses, phrases) -> bool:
    if any(p in text for p in phrases):
        return True
    return any(r.search(text) for r in reses)


def _marker_shaped(marker: str) -> bool:
    """Is a body marker specific enough to prove a shipped secret?

    A bare identifier ("authToken") matches code plumbing, not a
    secret. Adequate markers pin an assignment fragment (contains
    = : ' ") or a long/pure literal (12+, or 8+ with digits — too
    specific to be plumbing by accident).
    """
    m = (marker or "").strip()
    if any(c in m for c in "=:'\""):
        return True
    if len(m) >= 12:
        return True
    return len(m) >= 8 and any(ch.isdigit() for ch in m)


def verify_seam_card(
    seam: Dict,
    recon_urls: List[str],
    scope_gate=None,
    status: Optional[int] = None,
    body: str = "",
) -> Dict[str, object]:
    """Deterministically verify one seam card. No LLM, no debate.

    seam: parsed card dict (needs "check", "assertion_a", "assertion_b",
          "expected", "n").
    recon_urls: URLs / targets verbatim from recon data (grounding).
    scope_gate: ProgramScopeGate or None.
    status/body: the observed wire/execution behavior from running the check.

    Returns {"verdict": "CONFIRMED"|"REJECTED", "reason": str,
             "url": str, "expected": dict, "observed": dict}.
    """
    from oracle_foundation import validate_card_shape, validate_discriminating

    _shape_reason = validate_card_shape(seam)
    if _shape_reason is not None:
        return {
            "verdict": "REJECTED",
            "reason": _shape_reason,
            "url": "",
            "expected": {},
            "observed": {},
        }
    n = seam.get("n", "?")
    check = (seam.get("check") or "").strip()
    if not check:
        return {
            "verdict": "REJECTED",
            "reason": f"Seam {n}: no reproducible check command — cannot verify",
            "url": "",
            "expected": {},
            "observed": {},
        }

    is_web3 = any(check.startswith(b) for b in ("slither", "forge", "cast"))
    target = extract_check_target(check) if is_web3 else extract_check_url(check)

    if not target:
        reason_noun = "target" if is_web3 else "URL"
        return {
            "verdict": "REJECTED",
            "reason": f"Seam {n}: no {reason_noun} in check command — cannot verify",
            "url": "",
            "expected": {},
            "observed": {},
        }

    # Gate 1: grounding
    if is_web3:
        target_p = Path(target)
        grounded = (
            target in recon_urls
            or target_p.name in [Path(u).name for u in recon_urls]
            or any(target in u or u in target for u in recon_urls)
            or target_p.exists()
        )
        if not grounded:
            return {
                "verdict": "REJECTED",
                "reason": f"Seam {n}: target '{target}' not grounded in recon data or repository",
                "url": target,
                "expected": {},
                "observed": {},
            }
    else:
        # The URL's host must appear in recon data with an
        # exact host match (lookalike hosts rejected), URL verbatim or sub-path.
        if not _grounded(target, recon_urls):
            return {
                "verdict": "REJECTED",
                "reason": f"Seam {n}: URL not grounded in recon data (unknown or lookalike host)",
                "url": target,
                "expected": {},
                "observed": {},
            }

    # Gate 2: scope — the bounty program's rules, enforced by code.
    # A gate exception fails closed (REJECTED), never crashes the caller.
    if scope_gate is not None:
        try:
            ok, reason = scope_gate.is_in_scope(target)
        except Exception as e:
            return {
                "verdict": "REJECTED",
                "reason": f"Seam {n}: scope check errored ({e}) — failing closed",
                "url": target,
                "expected": {},
                "observed": {},
            }
        if not ok:
            return {
                "verdict": "REJECTED",
                "reason": f"Seam {n}: out of scope — {reason}",
                "url": target,
                "expected": {},
                "observed": {},
            }

    # Gate 2b: discrimination — an unvaried request with a status-only
    # expectation proves nothing about an identity/access claim
    # (GET / → 200 holds whether the session is verified or not).
    _disc_reason = validate_discriminating(seam)
    if _disc_reason is not None:
        return {
            "verdict": "REJECTED",
            "reason": _disc_reason,
            "url": target,
            "expected": {},
            "observed": {},
        }

    # Gate 3: the card must state a machine-readable expectation.
    # For web2, expectation MUST include a status code.
    # For web3, expectation can include a detector prediction, forge verdict, or status.
    expected = parse_expected(str(seam.get("expected") or ""))
    has_web3_exp = bool(expected.get("web3_detector") or expected.get("forge_verdict"))
    if expected["status"] is None and not has_web3_exp:
        return {
            "verdict": "REJECTED",
            "reason": f"Seam {n}: Expected line must include a status code — card incomplete",
            "url": target,
            "expected": expected,
            "observed": {},
        }

    # Gate 4: claim source — Assertion A must cite a real in-scope program
    # source, so the claimed guarantee can't be invented (only the wire was
    # grounded before; this grounds the claim too).
    assertion_source = str(seam.get("assertion_a_source") or "").strip()
    if not assertion_source:
        return {
            "verdict": "REJECTED",
            "reason": f"Seam {n}: Assertion A has no cited program source — cannot prove a conflict",
            "url": target,
            "expected": expected,
            "observed": {},
        }

    # Gate 5: the wire/execution must match the prediction.
    if status is None and not body:
        return {
            "verdict": "REJECTED",
            "reason": f"Seam {n}: no observation (check did not produce a status)",
            "url": target,
            "expected": expected,
            "observed": {},
        }
    headers = extract_headers_from_curl_output(body) if not is_web3 else {}
    observed: Dict[str, object] = {"status": status, "headers": headers}
    failures = []

    if is_web3:
        if expected.get("web3_detector"):
            det = str(expected["web3_detector"]).lower()
            b_low = body.lower()
            if not (
                f'"{det}"' in b_low
                or f"detector: {det}" in b_low
                or f"detector {det}" in b_low
                or det in b_low
            ):
                failures.append(f'detector "{det}" not found in static analysis output')
        if expected.get("forge_verdict"):
            v = str(expected["forge_verdict"]).upper()
            if f"[{v}]" not in body.upper() and f"SUITE {v}" not in body.upper():
                failures.append(f"forge test did not produce expected verdict [{v}]")
        if expected["status"] is not None and status != expected["status"]:
            failures.append(f"expected return code {expected['status']}, got {status}")
    else:
        if expected["status"] is not None and status != expected["status"]:
            failures.append(f"expected status {expected['status']}, got {status}")

    for pat in expected["body_contains"]:  # type: ignore[attr-defined]
        if pat not in body:
            failures.append(f'body missing "{pat}"')
    if expected["body_contains_any"]:  # type: ignore[union-attr]
        # Generic envelope words ("id", "data", "error"...) appear in any
        # JSON/HTML 200 and discriminate nothing (hunt-2: 7 SPA-shell
        # confirms). At least one NON-generic marker must match.
        specific = [
            pat
            for pat in expected["body_contains_any"]  # type: ignore[attr-defined]
            if pat.lower() not in _GENERIC_MARKERS
        ]
        if not any(pat in body for pat in specific):
            failures.append(
                "body contains none of the expected leak markers"
                + (
                    " (only generic words matched — not discriminating)"
                    if any(pat in body for pat in expected["body_contains_any"])  # type: ignore[attr-defined]
                    else ""
                )
            )
    for pat in expected["body_not_contains"]:  # type: ignore[attr-defined]
        if pat in body:
            failures.append(f'body unexpectedly contains "{pat}"')
    for name in expected["headers_absent"]:  # type: ignore[attr-defined]
        if name in headers:
            failures.append(f'header "{name}" is present')
    for name, value in expected["headers_contains"].items():  # type: ignore[attr-defined]
        observed_value = headers.get(name, "")
        if value.lower() not in observed_value.lower():
            failures.append(f'header "{name}" missing value "{value}"')
    if failures:
        return {
            "verdict": "REJECTED",
            "reason": f"Seam {n}: {'execution' if is_web3 else 'wire'} did not match prediction — {'; '.join(failures)}",  # noqa: E501
            "url": target,
            "expected": expected,
            "observed": observed,
        }

    # Gate 5b: verdict direction — the prediction matched, but a denial
    # or absence status supports A (barrier holds / nothing there), not
    # B. A card whose expectation predicts the secure outcome is
    # self-inverted (R3 Seam 5: B claimed access, expected 403); the
    # wire cannot confirm B no matter what the card predicted.
    if not is_web3:
        _wire = body.lower()
        _b_text = str(seam.get("assertion_b", "")).lower()
        _denied = any(m in _wire for m in _DENIAL_MARKERS)
        _absent = any(m in _wire for m in _ABSENT_MARKERS)
        _absent = _absent and "404" not in _b_text
        if _denied or _absent:
            _why = (
                "access denial proves the barrier holds"
                if _denied
                else "endpoint absent, nothing to access"
            )
            return {
                "verdict": "REJECTED",
                "reason": f"Seam {n}: wire supports A, not B — {_why} (status {status})",  # noqa: E501
                "url": target,
                "expected": expected,
                "observed": observed,
            }

    # Gate 7: prediction adequacy — the wire matched, but a matching
    # wire proves nothing when the prediction itself cannot discriminate
    # the claim (hunt-3: status-200 alone confirmed body-content,
    # bypass, and spoof claims). Web-only: static-analysis cards speak
    # a different prediction language (detectors / forge verdicts).
    if not is_web3:
        _b_low = str(seam.get("assertion_b", "")).lower()
        _claim_low = f"{_b_low} {str(seam.get('impact', '')).lower()}"
        _specific_markers = [
            pat for pat in expected["body_contains"]  # type: ignore[attr-defined]
        ] + [
            pat
            for pat in expected["body_contains_any"]  # type: ignore[attr-defined]
            if pat.lower() not in _GENERIC_MARKERS
        ]
        _has_header_disc = bool(expected["headers_contains"]) or bool(
            expected["headers_absent"]
        )
        # Rule A: a content claim on a status-200 prediction needs a
        # body marker or header discriminator — 200 alone is the null
        # hypothesis. Non-200 expectations (500 crash, 302 target...)
        # are self-discriminating events and stay exempt.
        if (
            expected["status"] == 200
            and not _specific_markers
            and not _has_header_disc
            and _claim_hits(_claim_low, _CONTENT_WORD_RES, _CONTENT_PHRASES)
        ):
            return {
                "verdict": "REJECTED",
                "reason": f"Seam {n}: prediction inadequate — content claim with status-only expectation (status 200 proves nothing by itself)",  # noqa: E501
                "url": target,
                "expected": expected,
                "observed": observed,
            }
        # Rule S: a shipped-secret claim pinned on a bare identifier
        # matches code plumbing, not a secret (hunt-3 seam 40:
        # "authToken" matched this.options.authToken). Require an
        # assignment fragment or a shaped literal.
        if _claim_hits(_claim_low, _SECRET_WORD_RES, _SECRET_PHRASES) and (
            str(target).lower().split("?")[0].endswith(".js")
            or _claim_hits(_claim_low, _SHIPPED_WORD_RES, _SHIPPED_PHRASES)
        ):
            if _specific_markers and not any(
                _marker_shaped(m) for m in _specific_markers
            ):
                return {
                    "verdict": "REJECTED",
                    "reason": f"Seam {n}: prediction inadequate — identifier-only marker cannot prove a hardcoded secret in shipped code (matches plumbing; pin an assignment fragment or literal)",  # noqa: E501
                    "url": target,
                    "expected": expected,
                    "observed": observed,
                }
        # Rule B2: a variation claim (B only — B is the tested claim,
        # impact is consequence prose) whose check executes no
        # variation cannot have tested the claim. Header-observation
        # cards (prediction inspects headers) are exempt, as are
        # reframes (their variation is proven by Gate 6a instead) and
        # omission frames ("without auth" is tested by sending none).
        if (
            not seam.get("reframe_transform")
            and not _has_header_disc
            and not _OMISSION_FRAME_RE.search(_b_low)
            and _claim_hits(_b_low, VARIATION_CLAIM_RES, VARIATION_CLAIM_PHRASES)
        ):
            from oracle_foundation import check_executes_variation as _varies

            if not _varies(check):
                return {
                    "verdict": "REJECTED",
                    "reason": f"Seam {n}: prediction inadequate — check does not execute the claimed variation (variation claim on an unvaried request)",  # noqa: E501
                    "url": target,
                    "expected": expected,
                    "observed": observed,
                }

    from oracle_foundation import grade_strength, generate_proof_packet

    _strength = grade_strength(seam)

    # Build the proof packet for audit trail
    proof_packet = generate_proof_packet(
        seam=seam,
        verification_result={
            "verdict": "CONFIRMED",
            "reason": f"Seam {n}: {'execution' if is_web3 else 'wire'} matches prediction ({'detector confirmed' if is_web3 else f'status {status}'}) — binary conflict proven [{_strength}]",
            "observed": observed,
            "expected": expected,
            "url": target,
            "strength": _strength,
        },
        scope_gate=scope_gate,
    )

    return {
        "verdict": "CONFIRMED",
        "reason": f"Seam {n}: {'execution' if is_web3 else 'wire'} matches prediction ({'detector confirmed' if is_web3 else f'status {status}'}) — binary conflict proven [{_strength}]",
        "url": target,
        "expected": expected,
        "observed": observed,
        "strength": _strength,
        "proof_packet": proof_packet,
    }
