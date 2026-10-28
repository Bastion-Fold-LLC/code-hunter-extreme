#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: AccountSession, DualAccountHarness, substitute_probe_placeholders, evaluate_cross_account_idor, auto_provision_accounts, AutoProvisionError  # noqa: E501
# TOPICS: none
"""
Oracle Auth & Dual-Account Session Engine
──────────────────────────────────────────
Provides authenticated live website inspection within bounty program rules:
  1. Bounty Program Email Aliases (@wearehackerone.com, @bugcrowdninja.com, @intigriti.me).
  2. Dual-Account Session Management (Account A [Victim] vs Account B [Attacker]).
  3. Interactive & Automated Session Ingestion (Prompts, Cookies, Bearer Tokens).
  4. Mandatory Program Header Injection (X-Bug-Bounty, custom User-Agents).
  5. Cross-Account IDOR & Access Control Probing (Reflex 2).
"""

from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from oracle_foundation import sanitize_header_val

try:
    from rich.console import Console
    from rich.panel import Panel

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]

# Platform alias domains — one inbox per researcher handle per platform.
# Account A  = handle@domain          (primary inbox, use this to sign up)
# Account B  = handle+2@domain        (second account for IDOR/cross-account tests)
# Confirmed from downloaded program briefs: "[username]@bugcrowdninja.com" (Rapyd, Chime, Okta).
PLATFORM_ALIAS_DOMAINS = {
    "hackerone": "wearehackerone.com",
    "bugcrowd": "bugcrowdninja.com",
    "intigriti": "intigriti.me",
    "yeswehack": "yeswehack.me",
    "generic": "gmail.com",
}

# Some platforms use a different handle spelling.
# Verified 2025-10-03 from live profile pages via Chromium Profile 2.
PLATFORM_HANDLE_OVERRIDES = {
    "intigriti": "code_hunter_extreme",  # profile: code_hunter_extreme (underscore)
    "bugbop": "CodeHunter",  # profile: CodeHunter (capitalised)
}


@dataclass
class AccountSession:
    """Credentials and active session state for a single test account."""

    label: str  # 'account_a' or 'account_b'
    role: str  # 'victim' or 'attacker'
    email: str
    username: str
    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    owned_resources: List[str] = field(default_factory=list)


# Placeholder sentinels for stored probe checks (C2 fix). Stored seam `check`
# strings carry these instead of live credential values. Real values are
# substituted only inside verify_seams at execution time and tracked for
# output scrubbing. A check that still carries a placeholder with no secret
# available is never executed (fail-closed).
ACCOUNT_B_AUTH_PLACEHOLDER = "__ORACLE_ACCOUNT_B_AUTH__"
ACCOUNT_B_COOKIES_PLACEHOLDER = "__ORACLE_ACCOUNT_B_COOKIES__"
ACCOUNT_A_AUTH_PLACEHOLDER = "__ORACLE_ACCOUNT_A_AUTH__"
ACCOUNT_A_COOKIES_PLACEHOLDER = "__ORACLE_ACCOUNT_A_COOKIES__"
_ALL_PROBE_PLACEHOLDERS = (
    ACCOUNT_A_AUTH_PLACEHOLDER,
    ACCOUNT_A_COOKIES_PLACEHOLDER,
    ACCOUNT_B_AUTH_PLACEHOLDER,
    ACCOUNT_B_COOKIES_PLACEHOLDER,
)


def _probe_placeholders_for(as_account: str) -> tuple:
    """Return (auth_placeholder, cookies_placeholder) for an account selector."""
    if (as_account or "").lower() in ("b", "attacker"):
        return ACCOUNT_B_AUTH_PLACEHOLDER, ACCOUNT_B_COOKIES_PLACEHOLDER
    return ACCOUNT_A_AUTH_PLACEHOLDER, ACCOUNT_A_COOKIES_PLACEHOLDER


def substitute_probe_placeholders(
    check_cmd: str, harness: "DualAccountHarness", as_account: str = "b"
) -> tuple:
    """Substitute stored placeholders with live secrets at execution time.

    Returns (resolved_check, secrets_list). When a placeholder is present but
    the harness holds no secret for it, returns (check, []) so the caller can
    fail closed and never execute.
    """
    secrets: list = []
    resolved = check_cmd or ""
    account = (
        harness.account_b
        if (as_account or "").lower() in ("b", "attacker")
        else harness.account_a
    )
    token = account.token
    cookies = dict(account.cookies or {})
    auth_ph, cookie_ph = _probe_placeholders_for(as_account)
    if auth_ph in resolved:
        if not token:
            return resolved, []
        clean = sanitize_header_val(token)
        norm = (
            clean
            if clean.lower().startswith(("bearer ", "basic "))
            else f"Bearer {clean}"
        )
        resolved = resolved.replace(auth_ph, norm)
        secrets.append(norm)
    if cookie_ph in resolved:
        if not cookies:
            return resolved, []
        # Stored session values are substituted AFTER scope validation, so
        # a quote/CR/LF here would break -H quoting (extra-URL fetch) or
        # inject curl -K directives (file write). Strip at the source.
        cookie_str = "; ".join(
            f"{sanitize_header_val(str(k))}={sanitize_header_val(str(v))}"
            for k, v in cookies.items()
        )
        resolved = resolved.replace(cookie_ph, cookie_str)
        secrets.append(cookie_str)
    if any(p in resolved for p in _ALL_PROBE_PLACEHOLDERS):
        return resolved, []
    return resolved, secrets


def _chromium_login_db_candidates():
    """Login Data candidates: env override first, then platform dirs.

    ORACLE_CHROMIUM_PROFILE_DIR names one profile directory explicitly.
    Otherwise enumerate Snap/native Chromium + Chrome profile dirs under
    the user's home — never a baked username or single profile name.
    """
    explicit = os.environ.get("ORACLE_CHROMIUM_PROFILE_DIR", "").strip()
    if explicit:
        yield Path(explicit).expanduser() / "Login Data"
        return
    home = Path.home()
    roots = [
        home / "snap" / "chromium" / "common" / "chromium",
        home / ".config" / "chromium",
        home / ".config" / "google-chrome",
        home / ".config" / "google-chrome-beta",
    ]
    seen = set()
    for root in roots:
        try:
            profiles = sorted(root.glob("*")) if root.is_dir() else []
        except OSError:
            profiles = []
        for prof in profiles:
            db = prof / "Login Data"
            if db.is_file() and str(db) not in seen:
                seen.add(str(db))
                yield db


def _extract_handle_from_browser_profile() -> Optional[str]:
    """Inspect local Chromium Login Data for real saved bounty credentials."""
    import sqlite3
    import tempfile
    import shutil

    for login_db in _chromium_login_db_candidates():
        tmp = None
        try:
            _fd, tmp = tempfile.mkstemp()
            os.close(_fd)
            shutil.copyfile(login_db, tmp)
            conn = sqlite3.connect(tmp)
            try:
                cur = conn.cursor()
                cur.execute("SELECT origin_url, username_value FROM logins")
                rows = cur.fetchall()
            finally:
                conn.close()
            for url, user in rows:
                if user and any(
                    p in url.lower()
                    for p in ["bugcrowd", "intigriti", "yeswehack", "hackerone", "bugbop"]
                ):
                    return user.split("@")[0].strip()
        except Exception:
            continue
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
    return None


def _get_configured_handle() -> Optional[str]:
    """Retrieve researcher handle from environment, .env file, or saved browser profile credentials."""
    if os.environ.get("RESEARCHER_HANDLE"):
        return os.environ["RESEARCHER_HANDLE"].strip()
    env_file = Path(__file__).resolve().parent / ".env"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if k.strip() in (
                    "RESEARCHER_HANDLE",
                    "BOUNTY_USERNAME",
                    "HACKERONE_USERNAME",
                ):
                    return v.strip().strip('"').strip("'")
    # Ground truth: extract directly from saved credentials in Chromium Profile 2
    browser_handle = _extract_handle_from_browser_profile()
    if browser_handle:
        return browser_handle
    return None


class DualAccountHarness:
    """
    Manages Account A and Account B for live website inspection,
    ensuring compliance with bug bounty rules of engagement.
    """

    def __init__(
        self,
        target_domain: str,
        platform: str = "generic",
        researcher_username: Optional[str] = None,
    ):
        self.target_domain = target_domain
        self.platform = platform.lower()

        handle = (researcher_username or _get_configured_handle() or "").strip()
        if not handle:
            raise ValueError(
                "Rule 2 Violation: No researcher handle configured! "
                "Set RESEARCHER_HANDLE=<your_bounty_handle> in .env or pass --researcher <handle>."
            )
        # Per-platform handle override (e.g. intigriti uses code_hunter_extreme, not codehunterextreme)
        self.researcher_username = PLATFORM_HANDLE_OVERRIDES.get(self.platform, handle)
        self.alias_domain = PLATFORM_ALIAS_DOMAINS.get(
            self.platform, "wearehackerone.com"
        )

        # Account A = primary inbox:  handle@domain
        # Account B = second account: handle+2@domain  (Chime brief: "alias+test1@bugcrowdninja.com")
        self.alias_a = f"{self.researcher_username}@{self.alias_domain}"
        self.alias_b = f"{self.researcher_username}+2@{self.alias_domain}"

        self.account_a = AccountSession(
            label="Account A",
            role="victim/primary",
            email=self.alias_a,
            username=f"{self.researcher_username}_a",
        )
        self.account_b = AccountSession(
            label="Account B",
            role="attacker/secondary",
            email=self.alias_b,
            username=f"{self.researcher_username}_b",
        )

        # Base compliance headers required by program rules
        self.compliance_headers = self._build_compliance_headers()

    def _build_compliance_headers(self) -> Dict[str, str]:
        """Construct standard mandatory researcher identification headers."""
        headers = {
            "X-Bug-Bounty": self.researcher_username,
            "User-Agent": f"OracleHunter-Research/{self.researcher_username} (+https://{self.alias_domain})",
        }
        if self.platform == "hackerone":
            headers["X-HackerOne-Research"] = self.researcher_username
        elif self.platform == "bugcrowd":
            headers["User-Agent"] = f"Bugcrowdninja-{self.researcher_username}"
        elif self.platform == "intigriti":
            headers["X-Intigriti-Researcher"] = self.researcher_username
        return headers

    def prompt_credentials(self) -> None:
        """Interactively prompt user for Account A and Account B session tokens or cookies."""
        if RICH and console:
            console.print(
                Panel(
                    f"[bold cyan]Target Live Inspection Setup:[/bold cyan] {self.target_domain}\n"
                    f"[dim]Platform Rules Active:[/dim] {self.platform.upper()}\n"
                    f"• [green]Account A (Primary/Victim) Alias:[/green] {self.alias_a}\n"
                    f"• [red]Account B (Secondary/Attacker) Alias:[/red] {self.alias_b}\n"
                    f"• [yellow]Compliance Header:[/yellow] X-Bug-Bounty: {self.researcher_username}",
                    title="Oracle Dual-Account Auth Harness",
                )
            )
        else:
            print(
                f"=== Oracle Dual-Account Live Website Setup: {self.target_domain} ==="
            )
            print(f"Account A Alias: {self.alias_a}")
            print(f"Account B Alias: {self.alias_b}")

        # Account A setup
        token_a = input(
            "\nEnter Auth Token or Cookie for Account A (or press Enter to skip): "
        ).strip()
        if token_a:
            if token_a.lower().startswith("bearer ") or token_a.startswith("ey"):
                self.account_a.token = (
                    token_a
                    if token_a.lower().startswith("bearer ")
                    else f"Bearer {token_a}"
                )
            else:
                self.account_a.cookies = self._parse_cookie_string(token_a)

        # Account B setup
        token_b = input(
            "Enter Auth Token or Cookie for Account B (or press Enter to skip): "
        ).strip()
        if token_b:
            if token_b.lower().startswith("bearer ") or token_b.startswith("ey"):
                self.account_b.token = (
                    token_b
                    if token_b.lower().startswith("bearer ")
                    else f"Bearer {token_b}"
                )
            else:
                self.account_b.cookies = self._parse_cookie_string(token_b)

    def _parse_cookie_string(self, raw_cookies: str) -> Dict[str, str]:
        """Convert 'key=value; key2=value2' into a dictionary."""
        cookie_dict = {}
        for item in raw_cookies.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                cookie_dict[k.strip()] = v.strip()
        return cookie_dict

    def save_session(self, output_dir: Path) -> Path:
        """Persist session configuration and tokens into target recon directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        session_file = output_dir / "sessions.json"
        data = {
            "target": self.target_domain,
            "platform": self.platform,
            "researcher": self.researcher_username,
            "compliance_headers": self.compliance_headers,
            "account_a": {
                "email": self.account_a.email,
                "token": self.account_a.token,
                "cookies": self.account_a.cookies,
                "owned_resources": self.account_a.owned_resources,
            },
            "account_b": {
                "email": self.account_b.email,
                "token": self.account_b.token,
                "cookies": self.account_b.cookies,
                "owned_resources": self.account_b.owned_resources,
            },
        }
        # Credential-at-rest: sessions.json holds live account tokens + cookies.
        # Write owner-only (0600) atomically and enforce it on any pre-existing
        # file; default write_text() leaves it group/world-readable.
        fd = os.open(session_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2))
        os.chmod(session_file, 0o600)
        return session_file

    def load_session(self, session_file: Path) -> bool:
        """Load saved sessions from file."""
        if not session_file.is_file():
            return False
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
            self.account_a.token = data.get("account_a", {}).get("token")
            self.account_a.cookies = data.get("account_a", {}).get("cookies", {})
            self.account_a.owned_resources = data.get("account_a", {}).get(
                "owned_resources", []
            )

            self.account_b.token = data.get("account_b", {}).get("token")
            self.account_b.cookies = data.get("account_b", {}).get("cookies", {})
            self.account_b.owned_resources = data.get("account_b", {}).get(
                "owned_resources", []
            )
            return True
        except Exception:
            return False

    @classmethod
    def from_session_file(cls, session_file: Path) -> "DualAccountHarness":
        """Instantiate DualAccountHarness directly from an existing sessions.json file."""
        if not session_file.is_file():
            raise FileNotFoundError(f"Session file not found: {session_file}")
        data = json.loads(session_file.read_text(encoding="utf-8"))
        harness = cls(
            target_domain=data["target"],
            platform=data.get("platform", "generic"),
            researcher_username=data["researcher"],
        )
        harness.load_session(session_file)
        return harness

    def build_curl_probe(
        self,
        endpoint_url: str,
        as_account: str = "b",
        method: str = "GET",
        data: Optional[str] = None,
    ) -> str:
        """
        Build an authorized curl probe adhering strictly to program rules.
        Injects compliance headers, researcher User-Agent, and account session tokens.
        """
        account = (
            self.account_b
            if as_account.lower() in ("b", "attacker")
            else self.account_a
        )
        cmd_parts = ["curl", "-i", "-s", "-X", method]

        # Invert compliance headers
        for k, v in self.compliance_headers.items():
            cmd_parts.extend(["-H", f'"{k}: {v}"'])

        # Invert auth — C2 fix: store placeholders, never live secrets.
        # Real values are substituted only inside verify_seams at execution
        # time (see substitute_probe_placeholders) and tracked for scrubbing.
        auth_ph, cookie_ph = _probe_placeholders_for(as_account)
        if account.token:
            cmd_parts.extend(["-H", f'"Authorization: {auth_ph}"'])
        if account.cookies:
            cmd_parts.extend(["-H", f'"Cookie: {cookie_ph}"'])

        if data and method in ("POST", "PUT", "PATCH"):
            cmd_parts.extend(
                ["-H", '"Content-Type: application/json"', "--data", json.dumps(data)]
            )

        cmd_parts.append(f'"{endpoint_url}"')
        return " ".join(cmd_parts)

    def build_idor_probes(
        self, seams: list, scope_gate=None, recon_hosts: Optional[list] = None
    ) -> list:
        """
        Given a list of recon seams, extract candidate resource-bearing endpoints
        and build cross-account IDOR probe seam cards (Account B accessing Account A resource).
        Returns a list of seam dicts ready to feed into verify_seams.

        C1 fix: candidate URLs come ONLY from `check` fields (never LLM-written
        assertion prose). Each candidate must pass: (a) host parses, (b) the
        scope gate allows it when a gate is supplied (else the harness
        target_domain must match), (c) the host is recon-verified when a recon
        host list is supplied. Anything else is dropped and counted in the
        returned list's trailing `_dropped` marker (not a probe).
        C2 fix: emitted checks carry placeholders, never live tokens.
        """
        import re as _re

        probes: List[Any] = []
        seen_urls: set = set()
        dropped = {"prose_only": 0, "scope": 0, "recon": 0, "no_host": 0}

        # Patterns that suggest a resource ID is in the path
        _id_pattern = _re.compile(
            r'https?://[^\s"\']+/(?:'
            r"\d{4,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            r"|[a-z0-9]{20,}|ord_\w+|usr_\w+|acc_\w+|inv_\w+|pay_\w+|txn_\w+"
            r')[^\s"\']*',
            _re.IGNORECASE,
        )

        def _host_of(url: str) -> str:
            try:
                return (
                    urllib.parse.urlsplit(url)
                    .netloc.lower()
                    .split("@")[-1]
                    .split(":")[0]
                )
            except Exception:
                return ""

        recon_set = set()
        for h in recon_hosts or []:
            host = _host_of(h if "://" in h else f"https://{h}")
            if host:
                recon_set.add(host)

        for s in seams:
            # C1: check field only — assertion prose is LLM-written and may
            # hallucinate third-party URLs.
            check_text = s.get("check", "") or ""
            for m in _id_pattern.finditer(check_text):
                url = m.group(0).rstrip(".,)")
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                host = _host_of(url)
                if not host:
                    dropped["no_host"] += 1
                    continue
                if scope_gate is not None:
                    try:
                        ok, _reason = scope_gate.is_in_scope(url)
                    except Exception:
                        ok = False
                    if not ok:
                        dropped["scope"] += 1
                        continue
                elif self.target_domain and host != (self.target_domain or "").lower():
                    dropped["scope"] += 1
                    continue
                if recon_set and host not in recon_set:
                    dropped["recon"] += 1
                    continue
                probe_cmd = self.build_curl_probe(url, as_account="b", method="GET")
                probes.append(
                    {
                        "n": len(probes)
                        + 9000,  # high n so they sort after recon seams
                        "assertion_a": (
                            f"Resource at {url} is owned by Account A "
                            f"({self.alias_a}) and requires Account A authorization."
                        ),
                        "assertion_b": (
                            f"Account B ({self.alias_b}) may be able to access "
                            f"Account A's resource using Account B's session token."
                        ),
                        "check": probe_cmd,
                        "impact": (
                            "Broken Object Level Authorization: attacker reads or modifies "
                            "another user's private resource without owning it."
                        ),
                        "reflex": "Reflex 2 — DECOUPLE (identity ≠ ownership)",
                        # R4: horizontal BOLA with the attacker's own session —
                        # no valid-other-account abuse, so T1190, not T1078.
                        "mitre": "CWE-639 / T1190",
                        "bug_type": "TYPE_2_LOGIC",
                        "origin": "dual-account-idor",
                        "raw": "",
                        "idor_target": url,
                    }
                )
        if any(dropped.values()):
            probes.append(
                {
                    "n": 9999,
                    "origin": "dual-account-idor",
                    "_dropped": dict(dropped),
                    "assertion_a": "IDOR candidate filter",
                    "assertion_b": f"dropped out-of-scope/unverified candidates: {dropped}",
                    "check": "",
                    "impact": "No impact — filter marker, never verified.",
                    "reflex": "Reflex 2 — DECOUPLE (filter)",
                    # R4: filter marker, never verified — carries no MITRE.
                    "mitre": "N/A",
                    "bug_type": "TYPE_2_LOGIC",
                    "raw": "",
                }
            )
        return probes


def evaluate_cross_account_idor(
    harness: DualAccountHarness, endpoint_template: str, resource_id_a: str
) -> Dict[str, Any]:
    """
    Automated Reflex 2 Check:
    Issues an HTTP request to Account A's resource using Account B's authentication.
    Returns proof card and binary verdict.
    """
    url = endpoint_template.replace("{id}", str(resource_id_a))
    check_cmd = harness.build_curl_probe(url, as_account="b", method="GET")

    return {
        "reflex": "REFLEX 2: Insecure Direct Object Reference (Cross-Account IDOR)",
        "mitre": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "assertion_a": f"Resource {resource_id_a} is owned by Account A ({harness.alias_a}) and requires Account A authorization.",  # noqa: E501
        "assertion_b": f"Account B ({harness.alias_b}) successfully retrieved Account A's private resource via {url}.",
        "check": check_cmd,
        "impact": "Broken Object Level Authorization allows unprivileged horizontal account takeover and unauthorized data exfiltration.",  # noqa: E501
    }


# ── Registration auto-provisioning (wall gap 4.2) ────────────────────────────

PROVISION_TOKEN_KEYS = (
    "token",
    "access_token",
    "accessToken",
    "jwt",
    "idToken",
    "id_token",
    "auth_token",
    "session_token",
)

_PROVISION_NESTS = ("data", "authentication", "auth", "user", "result")


class AutoProvisionError(RuntimeError):
    """Registration or token extraction failed — no silent half-accounts."""


def _extract_provision_token(payload: Any) -> Optional[str]:
    """First known token key, top-level or one nest down (juice-style)."""
    if not isinstance(payload, dict):
        return None
    for key in PROVISION_TOKEN_KEYS:
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    for nest in _PROVISION_NESTS:
        inner = payload.get(nest)
        if isinstance(inner, dict):
            for key in PROVISION_TOKEN_KEYS:
                val = inner.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return None


def auto_provision_accounts(
    harness: DualAccountHarness,
    register_url: str,
    *,
    email_field: str = "email",
    password_field: str = "password",
    password: Optional[str] = None,
    extra_fields: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0,
) -> Dict[str, str]:
    """Register the harness's two alias emails; extract session tokens.

    POSTs JSON ``{email_field, password_field, **extra}`` once per account
    to ``register_url`` (the program's own registration endpoint — in-scope
    by construction when the URL is under the hunt target). The returned
    JWT/Bearer [REDACTED] (or session cookie) lands on ``account_a``/``account_b``
    so ``build_idor_probes`` and ``evaluate_cross_account_idor`` run with
    zero manual token injection. Any failure raises :class:`AutoProvisionError`
    — a hunt never proceeds on a silently half-provisioned pair.

    Returns ``{"a": <token-or-cookie>, "b": <token-or-cookie>}``.
    """
    import http.cookiejar
    import secrets
    import urllib.error
    import urllib.request

    secret = password or secrets.token_urlsafe(16)
    minted: Dict[str, str] = {}
    for tag, account in (("a", harness.account_a), ("b", harness.account_b)):
        body = json.dumps(
            {
                email_field: account.email,
                password_field: secret,
                **(extra_fields or {}),
            }
        ).encode()
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )
        req = urllib.request.Request(
            register_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "oracle-auth-provision/1.0",
                **harness.compliance_headers,
            },
            method="POST",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = int(resp.status)
                raw = resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(4096).decode("utf-8", "replace")
            except Exception:
                raw = ""
            raise AutoProvisionError(
                f"account {tag} ({account.email}): registration HTTP"
                f" {e.code}: {raw[:200]}"
            ) from e
        except Exception as e:
            raise AutoProvisionError(
                f"account {tag} ({account.email}): registration failed: {e}"
            ) from e
        if status >= 400:
            raise AutoProvisionError(
                f"account {tag} ({account.email}): registration HTTP"
                f" {status}: {raw[:200]}"
            )
        token: Optional[str] = None
        try:
            token = _extract_provision_token(json.loads(raw or "{}"))
        except ValueError:
            token = None
        cookies = {c.name: c.value for c in jar}
        if token:
            account.token = (
                token if token.lower().startswith("bearer ") else f"Bearer {token}"
            )
            account.cookies.update(cookies)
            minted[tag] = account.token
        elif cookies:
            account.cookies.update(cookies)
            minted[tag] = "; ".join(f"{k}={v}" for k, v in sorted(cookies.items()))
        else:
            raise AutoProvisionError(
                f"account {tag} ({account.email}): registration returned"
                f" HTTP {status} with no token and no session cookie"
            )
    return minted
