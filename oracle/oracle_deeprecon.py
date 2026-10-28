# LAYER: find
# DEST: basilisk
# ENDPOINTS: mine_js, mine_crawled_pages, discover_api_specs, fuzz_hidden_paths
# TOPICS: none
"""Oracle deep recon — JS mining, API spec discovery, content discovery.

All network touches are scope-gated BEFORE any packet is sent: with no
scope gate, nothing runs (fail-closed). Redirects are followed at most
2 hops and only when every hop passes the gate. Polite by default:
short timeouts, sequential requests, capped downloads.
"""

import json
import hashlib
import re
import ssl
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from oracle_harvest import _attribution_headers  # noqa: F401 (probe attribution)

_HERE = Path(__file__).resolve().parent
_WORDLIST_DIR = _HERE / "wordlists"


# ── tiny log helpers (match oracle_hunter.py prefixes) ───────────────────────
def _info(m):
    print(f"→  {m}", flush=True)


def _ok(m):
    print(f"✓ {m}", flush=True)


def _warn(m):
    print(f"⚠  {m}", flush=True)


# ── scope-gated fetching ─────────────────────────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )


def _in_scope(url: str, scope_gate) -> bool:
    if scope_gate is None:
        return False
    try:
        ok, _ = scope_gate.is_in_scope(url)
        return bool(ok)
    except Exception:
        return False


def _fetch(
    url: str,
    scope_gate,
    timeout: int = 15,
    max_bytes: int = 2_000_000,
    extra_headers: Optional[List[str]] = None,
) -> Tuple[Optional[bytes], int, str]:
    """GET url (max 2 in-scope redirect hops). Returns (body, status, final_url).
    (None, 0, url) on any failure or scope rejection.
    extra_headers: "Name: value" request headers (already sanitized upstream)."""
    if not _in_scope(url, scope_gate):
        return None, 0, url
    opener = _opener()
    seen = set()
    cur = url
    for _ in range(3):  # initial + 2 redirect hops
        if cur in seen:
            return None, 0, url
        seen.add(cur)
        if not _in_scope(cur, scope_gate):
            return None, 0, url
        try:
            hdrs = {"User-Agent": "oracle-recon/1.0", **_attribution_headers()}
            for h in extra_headers or []:
                if ":" in h:
                    k, v = h.split(":", 1)
                    hdrs[k.strip()] = v.strip()
            req = urllib.request.Request(cur, headers=hdrs)
            try:
                resp = opener.open(req, timeout=timeout)
                status = resp.status
                headers = resp.headers
            except urllib.error.HTTPError as e:
                # _NoRedirect turns 3xx into HTTPError — harvest code+Location
                status, headers, resp = e.code, e.headers, None
                if status not in (301, 302, 303, 307, 308):
                    return None, 0, url
            if status in (301, 302, 303, 307, 308):
                loc = headers.get("Location")
                if not loc:
                    return None, status, cur
                cur = urllib.parse.urljoin(cur, loc)
                continue
            with resp:
                body = resp.read(max_bytes + 1)
                if len(body) > max_bytes:
                    body = body[:max_bytes]
                return body, status, cur
        except Exception:
            return None, 0, url
    return None, 0, url


# ── 1. JS mining ─────────────────────────────────────────────────────────────
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
# Quoted string that starts with / — capture up to the closing quote, then
# validate (allows query strings: "/api/v1/orders?status=open").
_QUOTED_SLASH_STR = re.compile(r"""["'`](/(?:[^"'`\s\\]|\\.)*)["'`]""")
_ABSOLUTE_URL = re.compile(r"""https?://[^\s"'<>\\`]+""")
# key = "value" / key: "value" / key=value shapes for common secret names.
# Values may be quoted or bare (bare terminates at whitespace/semicolon/comma).
_SECRET = re.compile(
    # The value must be a QUOTED literal: unquoted matches are JS
    # plumbing (hunt-3: this.authToken=this.options.authToken was
    # fingerprinted as a secret). ${} is excluded so runtime template
    # expressions (Bearer ${localStorage...}) never qualify either.
    r"""(?i)(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|"""
    r"""auth[_-]?token|aws_access_key_id|aws_secret_access_key|private[_-]?key|"""
    r"""db[_-]?password|password)["']?\s*[:=]\s*["']([^"'`\s;,\\${}]{8,200})["']"""
)

_JS_SKIP_EXTS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
)


def _looks_like_path(p: str) -> bool:
    # strip query/fragment for the shape check, keep original for output
    core = p.split("?", 1)[0].split("#", 1)[0]
    if len(core) < 2 or len(core) > 180:
        return False
    if not core.startswith("/"):
        return False
    if core.startswith("//"):
        return False
    # must contain at least one letter; skip pure numeric/extension noise
    if not re.search(r"[A-Za-z]", core):
        return False
    # each segment should look like a path token (letters, digits, - _ . ~ % { })
    if not re.fullmatch(
        r"[A-Za-z0-9_\-\.~%{}:@$]+(?:/[A-Za-z0-9_\-\.~%{}:@$]+)*/?", core.strip("/")
    ):
        return False
    # reject path-traversal noise
    if "/../" in core or core.endswith("/..") or "/./" in core:
        return False
    if core.lower().endswith(_JS_SKIP_EXTS):
        return False
    return True


def mine_js(
    live_hosts: List[str],
    scope_gate,
    out_dir: Path,
    max_js_per_host: int = 15,
    extra_headers: Optional[List[str]] = None,
) -> Tuple[int, int]:
    """Download in-scope JS from each live host and mine endpoints + secrets.
    Writes js_endpoints.txt and js_secrets.txt. Returns (n_endpoints, n_secrets)."""
    out_dir = Path(out_dir)
    endpoints, secrets = set(), set()
    js_seen = set()
    if scope_gate is None:
        _warn("js mining: no scope gate — skipping (fail-closed)")
        return 0, 0
    for host in live_hosts:
        host = (host or "").strip().split()[0]
        if not host or not _in_scope(host, scope_gate):
            continue
        body, status, final = _fetch(host, scope_gate, extra_headers=extra_headers)
        if not body or status != 200:
            continue
        try:
            html = body.decode("utf-8", errors="ignore")
        except Exception:
            continue
        srcs = _SCRIPT_SRC.findall(html)
        n = 0
        for src in srcs:
            if n >= max_js_per_host:
                break
            src = src.strip()
            if not src or src.startswith("data:"):
                continue
            js_url = urllib.parse.urljoin(final, src)
            # strip query for dedup, keep full URL for fetch
            dedup = js_url.split("?")[0]
            if dedup in js_seen:
                continue
            if dedup.lower().endswith(_JS_SKIP_EXTS):
                continue
            if not _in_scope(js_url, scope_gate):
                continue
            js_seen.add(dedup)
            js_body, js_status, _ = _fetch(
                js_url, scope_gate, max_bytes=1_500_000, extra_headers=extra_headers
            )
            if not js_body or js_status != 200:
                continue
            n += 1
            try:
                js = js_body.decode("utf-8", errors="ignore")
            except Exception:
                continue
            for p in _QUOTED_SLASH_STR.findall(js):
                if _looks_like_path(p):
                    # strip query/fragment — the route is the signal
                    endpoints.add(p.split("?", 1)[0].split("#", 1)[0])
            for u in _ABSOLUTE_URL.findall(js):
                u = u.rstrip(".,;)")
                if _in_scope(u, scope_gate):
                    endpoints.add(u)
            for m in _SECRET.finditer(js):
                value = m.group(2)
                fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
                # Format: "key=sha256:FINGERPRINT\tsource_js_url" so _t_t1552 can
                # emit a real curl probe against the JS file that contains the secret.
                secrets.add(f"{m.group(1)}=sha256:{fingerprint}\t{js_url}")
    ep_file = out_dir / "js_endpoints.txt"
    se_file = out_dir / "js_secrets.txt"
    ep_file.write_text("\n".join(sorted(endpoints)) + ("\n" if endpoints else ""))
    se_file.write_text("\n".join(sorted(secrets)) + ("\n" if secrets else ""))
    _ok(
        f"js mining: {len(endpoints)} endpoints, {len(secrets)} secret shapes "
        f"from {len(js_seen)} JS files"
    )
    return len(endpoints), len(secrets)


# ── 1b. Crawled-page mining (inline JS navigation) ────────────────────────────
# mine_js only fetches live-host ROOTS for script srcs; katana only extracts
# href/src/action URLs. Pages that navigate via inline handlers
# (onclick="window.location.href='/xssL'") are invisible to both — pygoat
# E2E missed /xssL (a bar item) for exactly this reason. This pass refetches
# a capped set of crawled HTML pages and mines the same endpoint shapes
# mine_js mines, so inline-navigated routes become template targets.
_CRAWL_SKIP_EXTS = _JS_SKIP_EXTS + (".js", ".json", ".xml", ".txt", ".map")


def mine_crawled_pages(
    out_dir: Path,
    scope_gate,
    extra_headers: Optional[List[str]] = None,
    cap: int = 25,
) -> int:
    """Mine crawled pages for inline-navigated endpoints. Returns new count.

    Reads crawl.txt from ``out_dir``, fetches up to ``cap`` in-scope HTML
    pages (deduped, static/logout-shaped skipped), and merges mined
    endpoints into js_endpoints.txt. Fail-closed without a gate; missing
    crawl.txt yields 0, never an error.
    """
    out_dir = Path(out_dir)
    if scope_gate is None:
        _warn("crawled-page mining: no scope gate — skipping (fail-closed)")
        return 0
    crawl_file = out_dir / "crawl.txt"
    if not crawl_file.exists():
        return 0
    try:
        from oracle_foundation import LOGOUT_PATH_PATTERN as _logout_pat

        _logout_re = re.compile(_logout_pat, re.IGNORECASE)
    except Exception:
        _logout_re = None
    seen: set = set()
    targets: List[str] = []
    for line in crawl_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        url = (line or "").strip().split()[0] if (line or "").strip() else ""
        if not url or not url.startswith(("http://", "https://")):
            continue
        url = url.split("#", 1)[0]
        if url in seen:
            continue
        seen.add(url)
        path = urllib.parse.urlparse(url).path or ""
        if path.lower().endswith(_CRAWL_SKIP_EXTS):
            continue
        if _logout_re is not None and _logout_re.search(path):
            continue
        if not _in_scope(url, scope_gate):
            continue
        targets.append(url)
        if len(targets) >= cap:
            break
    endpoints: set = set()
    fetched = 0
    for url in targets:
        body, status, _ = _fetch(
            url, scope_gate, timeout=10, max_bytes=1_000_000,
            extra_headers=extra_headers,
        )
        if not body or status != 200:
            continue
        fetched += 1
        try:
            html = body.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for p in _QUOTED_SLASH_STR.findall(html):
            if _looks_like_path(p):
                endpoints.add(p.split("?", 1)[0].split("#", 1)[0])
        for u in _ABSOLUTE_URL.findall(html):
            u = u.rstrip(".,;)")
            if _in_scope(u, scope_gate):
                endpoints.add(u)
    if not endpoints:
        _ok(f"crawled-page mining: 0 endpoints from {fetched} pages")
        return 0
    ep_file = out_dir / "js_endpoints.txt"
    have = set()
    if ep_file.exists():
        have = {
            ln.strip()
            for ln in ep_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip()
        }
    new = endpoints - have
    ep_file.write_text("\n".join(sorted(have | endpoints)) + "\n")
    _ok(f"crawled-page mining: {len(new)} new endpoints from {fetched} pages")
    return len(new)


# ── 2. API spec discovery ────────────────────────────────────────────────────
_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/redoc",
    "/.well-known/openapi.json",
    "/api/openapi.json",
    "/openapi.yaml",
    "/swagger.yaml",
    "/api/swagger.json",
]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql"]


def _looks_like_spec(body: bytes) -> bool:
    try:
        t = body[:4000].decode("utf-8", errors="ignore").lower()
    except Exception:
        return False
    return (
        '"openapi"' in t
        or "'openapi'" in t
        or '"swagger"' in t
        or '"info"' in t
        and '"paths"' in t
    )


def discover_api_specs(
    live_hosts: List[str],
    scope_gate,
    out_dir: Path,
    extra_headers: Optional[List[str]] = None,
) -> int:
    """Probe each live host for OpenAPI/Swagger specs + GraphQL introspection.
    Writes api_specs.txt as `URL [type]`. Returns hit count.

    Runs 32 host workers in parallel so 64 hosts × 15 probes at 10s timeout
    completes in ~30s instead of ~160 minutes sequentially.
    """
    out_dir = Path(out_dir)
    if scope_gate is None:
        _warn("api spec discovery: no scope gate — skipping (fail-closed)")
        return 0

    # Build per-host work items up front (scope-filtered)
    scoped_hosts = []
    for h in live_hosts:
        h = (h or "").strip().split()[0].rstrip("/")
        if h and _in_scope(h, scope_gate):
            scoped_hosts.append(h)

    def _probe_host(host: str) -> List[str]:
        """All probes for one host. Returns list of hit strings."""
        local_hits: List[str] = []
        # OpenAPI / Swagger spec paths — stop on first hit per host
        for sp in _SPEC_PATHS:
            url = host + sp
            body, status, _ = _fetch(
                url,
                scope_gate,
                timeout=10,
                max_bytes=500_000,
                extra_headers=extra_headers,
            )
            if body and status == 200 and _looks_like_spec(body):
                local_hits.append(f"{url} [openapi/swagger]")
                _ok(f"api spec found: {url}")
                break  # one spec per host is enough
        # GraphQL paths
        for gq in _GRAPHQL_PATHS:
            url = host + gq
            if not _in_scope(url, scope_gate):
                continue
            # GET: playground / landing
            body, status, _ = _fetch(
                url,
                scope_gate,
                timeout=10,
                max_bytes=100_000,
                extra_headers=extra_headers,
            )
            if body and status == 200:
                try:
                    t = body.decode("utf-8", errors="ignore").lower()
                except Exception:
                    t = ""
                if "graphql" in t and (
                    "playground" in t or "graphiql" in t or "__schema" in t
                ):
                    local_hits.append(f"{url} [graphql-playground]")
                    _ok(f"graphql playground: {url}")
                    continue
            # POST: introspection probe
            try:
                data = json.dumps({"query": "{__typename}"}).encode()
                post_hdrs = {
                    "User-Agent": "oracle-recon/1.0",
                    "Content-Type": "application/json",
                    **_attribution_headers(),
                }
                for h_hdr in extra_headers or []:
                    if ":" in h_hdr:
                        k, v = h_hdr.split(":", 1)
                        post_hdrs[k.strip()] = v.strip()
                req = urllib.request.Request(url, data=data, headers=post_hdrs)
                with _opener().open(req, timeout=10) as r:
                    rb = r.read(100_000)
                    if r.status == 200 and b"__typename" in rb:
                        local_hits.append(f"{url} [graphql-introspection]")
                        _ok(f"graphql introspection live: {url}")
            except Exception:
                pass
        return local_hits

    hits: List[str] = []
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(_probe_host, h): h for h in scoped_hosts}
        for fut in as_completed(futures):
            try:
                hits.extend(fut.result())
            except Exception:
                pass

    f = out_dir / "api_specs.txt"
    f.write_text("\n".join(sorted(set(hits))) + ("\n" if hits else ""))
    if not hits:
        _info("api spec discovery: no specs found")
    return len(set(hits))


# ── 3. Content discovery (ffuf) ─────────────────────────────────────────────
def _ffuf_bin() -> Optional[str]:
    from shutil import which

    p = Path.home() / "go" / "bin" / "ffuf"
    if p.exists():
        return str(p)
    w = which("ffuf")
    return w


def _sanitized_wordlist(wl: Path, out_dir: Path) -> Path:
    """Copy a wordlist minus comments/blanks (ffuf fuzzes raw lines).

    Returns the original path when there is nothing to strip or the
    copy cannot be written.
    """
    try:
        lines = wl.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return wl
    clean = []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#"):
            clean.append(s)
    if len(clean) == sum(1 for ln in lines if ln.strip()):
        return wl
    tmp = out_dir / f"_wl_{wl.stem}.txt"
    try:
        tmp.write_text("\n".join(clean) + "\n", encoding="utf-8")
    except OSError:
        return wl
    return tmp


def fuzz_hidden_paths(
    live_hosts: List[str],
    scope_gate,
    out_dir: Path,
    wordlist: Optional[Path] = None,
    max_hosts: int = 6,
    extra_headers: Optional[List[str]] = None,
) -> int:
    """ffuf each in-scope live host for hidden paths. Writes fuzzed_paths.txt
    as `URL [status]`. Returns count of interesting hits."""
    out_dir = Path(out_dir)
    ffuf = _ffuf_bin()
    if not ffuf:
        _warn("ffuf not found — skipping content discovery")
        return 0
    if scope_gate is None:
        _warn("content discovery: no scope gate — skipping (fail-closed)")
        return 0
    wl = Path(wordlist) if wordlist else None
    if not wl or not wl.exists():
        wl = _WORDLIST_DIR / "oracle-api-paths.txt"
    if not wl.exists():
        wl = _WORDLIST_DIR / "raft-small-words.txt"
    if not wl.exists():
        _warn("content discovery: no wordlist — skipping")
        return 0
    wl = _sanitized_wordlist(wl, out_dir)
    hits = set()
    _lengths: Dict[str, int] = {}
    n = 0
    for host in live_hosts:
        if n >= max_hosts:
            break
        host = (host or "").strip().split()[0].rstrip("/")
        if not host or not _in_scope(host, scope_gate):
            continue
        n += 1
        _info(f"ffuf: content discovery on {host}")
        tmp_json = out_dir / f"_ffuf_{n}.json"
        try:
            cmd = [
                ffuf,
                "-u",
                host + "/FUZZ",
                "-w",
                str(wl),
            ]
            for h in extra_headers or []:
                # ffuf -H takes one "Name: value" per flag; values were
                # sanitized upstream (CR/LF stripped) and argv is local-only.
                if ":" in h:
                    cmd += ["-H", h.strip()]
            cmd += [
                "-mc",
                "200,204,301,302,307,401,403",
                "-rate",
                "40",
                "-t",
                "10",
                "-s",
                "-o",
                str(tmp_json),
                "-of",
                "json",
                "-timeout",
                "10",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if tmp_json.exists():
                data = json.loads(tmp_json.read_text())
                for res in data.get("results", []):
                    url = res.get("url", "")
                    status = res.get("status", 0)
                    if url and _in_scope(url, scope_gate):
                        hits.add(f"{url} [{status}]")
                        try:
                            _lengths[url] = int(res.get("length", -1))
                        except (TypeError, ValueError):
                            pass
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            _warn(f"ffuf on {host}: {type(e).__name__} — continuing")
            continue
        finally:
            try:
                tmp_json.unlink()
            except OSError:
                pass
    f = out_dir / "fuzzed_paths.txt"
    f.write_text("\n".join(sorted(hits)) + ("\n" if hits else ""))
    # Response sizes ride a side file (fuzzed_paths.txt format is frozen —
    # templates parse `URL [status]`). harvest_listings spends its fetch
    # budget rarity-first: SPA fallbacks share one size, listings don't.
    sizes = {u: n for u, n in _lengths.items() if n is not None and n >= 0}
    sf = out_dir / "fuzzed_sizes.txt"
    sf.write_text("".join(f"{u} {n}\n" for u, n in sorted(sizes.items())))
    _ok(f"content discovery: {len(hits)} interesting paths")
    return len(hits)


# ── 4. Directory-listing harvest ─────────────────────────────────────────────
_LISTING_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#?]+)["']""", re.IGNORECASE)
_LISTING_MAX_DIRS = 60
_LISTING_MAX_TOTAL = 500
_LISTING_SKIP_HREFS = frozenset({".", "", "/", "../", ".."})


def harvest_listings(
    out_dir: Path,
    scope_gate,
    extra_headers: Optional[List[str]] = None,
) -> int:
    """Fetch fuzzed dir-like URLs, parse directory listings, write listed_paths.txt.

    A fuzzed 200 without a file extension is fetched; when its body links
    >= 2 same-subtree children it is treated as a listing (shape-based —
    no server-brand literals) and the children are recorded as bare URLs.
    Call after fuzz_hidden_paths (reads its fuzzed_paths.txt). Bounded:
    60 dirs max, 500 children max, one level (no recursion), no subtree
    escapes. Returns child count.
    """
    out_dir = Path(out_dir)
    if scope_gate is None:
        _warn("listing harvest: no scope gate — skipping (fail-closed)")
        return 0
    fuzzed_file = out_dir / "fuzzed_paths.txt"
    found: List[str] = []
    if not fuzzed_file.is_file():
        (out_dir / "listed_paths.txt").write_text("")
        return 0
    try:
        lines = fuzzed_file.read_text(errors="ignore").splitlines()
    except OSError:
        (out_dir / "listed_paths.txt").write_text("")
        return 0
    # Rarity-first fetch order: SPA fallbacks answer 200 with one shared
    # body size, burying real listings past the fetch cap (juice: 739
    # same-size 200s, /ftp/ 260th, cap 60 — never fetched). ffuf-recorded
    # sizes deprioritize the modal size; unsized lines sort as their own
    # group (never dropped — recall-safe). Absent side file: alpha order.
    sizes: Dict[str, int] = {}
    try:
        for sline in (
            (out_dir / "fuzzed_sizes.txt").read_text(errors="ignore").splitlines()
        ):
            size_bits = sline.rsplit(" ", 1)
            if len(size_bits) == 2 and size_bits[1].strip().isdigit():
                sizes[size_bits[0].strip()] = int(size_bits[1].strip())
    except OSError:
        pass
    freq: Dict[int, int] = {}
    for size in sizes.values():
        freq[size] = freq.get(size, 0) + 1

    def _rarity(line: str) -> Tuple[int, str]:
        url = line.split()[0].strip() if line.split() else ""
        return (freq.get(sizes.get(url, -1), 0), line)

    n_dirs = 0
    for line in sorted(set(lines), key=_rarity):
        if len(found) >= _LISTING_MAX_TOTAL or n_dirs >= _LISTING_MAX_DIRS:
            break
        url = line.split()[0].strip() if line.split() else ""
        if not url.lower().startswith(("http://", "https://")):
            continue
        if "[200]" not in line:
            continue
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        last = parts.path.rstrip("/").rsplit("/", 1)[-1]
        if "." in last:
            continue  # file, not a directory
        if not _in_scope(url, scope_gate):
            continue
        n_dirs += 1
        # Canonical slash form: relative listing hrefs resolve against the
        # slash-terminated dir; fetching slashless doubles path segments
        # on servers that serve the listing at both spellings.
        fetch_url = url if parts.path.endswith("/") else url + "/"
        body, status, final = _fetch(
            fetch_url,
            scope_gate,
            timeout=10,
            max_bytes=300_000,
            extra_headers=extra_headers,
        )
        if not body or status != 200:
            continue
        try:
            html = body.decode("utf-8", errors="ignore")
        except Exception:
            continue
        # Listing-relative links assume a trailing slash; most servers
        # redirect to it (_fetch follows), but slashless listings exist.
        if not urllib.parse.urlsplit(final).path.endswith("/"):
            final = final + "/"
        try:
            base_path = urllib.parse.urlsplit(final).path.rstrip("/") + "/"
            base_host = urllib.parse.urlsplit(final).netloc.lower()
        except ValueError:
            continue
        children = []
        for href in _LISTING_HREF_RE.findall(html):
            href = href.strip()
            if href in _LISTING_SKIP_HREFS or "/../" in href:
                continue
            child = urllib.parse.urljoin(final, href).split("#", 1)[0]
            try:
                cparts = urllib.parse.urlsplit(child)
            except ValueError:
                continue
            if cparts.netloc.lower() != base_host:
                continue
            if not cparts.path.startswith(base_path.rstrip("/")):
                continue
            if cparts.path.rstrip("/") == base_path.rstrip("/"):
                continue
            if not _in_scope(child, scope_gate):
                continue
            children.append(child)
        children = sorted(set(children))
        if len(children) >= 2:  # listing shape: links a family, not a page
            for child in children:
                if len(found) >= _LISTING_MAX_TOTAL:
                    break
                if child not in found:
                    found.append(child)
    (out_dir / "listed_paths.txt").write_text(
        "\n".join(sorted(found)) + ("\n" if found else "")
    )
    if found:
        _ok(f"listing harvest: {len(found)} listed file(s) from {n_dirs} dir(s)")
    return len(found)
