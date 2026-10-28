#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: fetch_programs, triage_prescan_overlay, fetch_contests, resolve, verify_in_scope, print_ranked  # noqa: E501
# TOPICS: none
"""
oracle_scan4me.py — Scan4Me ↔ Oracle bridge plugin
════════════════════════════════════════════════════
Wires Scan4Me's ranked program intelligence into Oracle's P11 intake path.

  oracle-hunter prescan --sync        # signed-in Scan4Me ranked sweep
  oracle-hunter scan -N 1 --download  # Oracle re-scan + workspace + handoff
  oracle-hunter queue --execute       # hunt the handoff
  python3 oracle_scan4me.py           # interactive ranked list (standalone)

What it does:
  1. Reads Scan4Me's ranked DB / evaluate_targets() output
  2. Converts each result into the Oracle program dict schema
     (structured_scopes, max_payout_usd, platform, handle, url, name, …)
  3. Scope gate: oracle_hunter.ProgramScopeGate uses Scan4Me's in-scope asset list
     so every recon probe is scope-gated against the exact live DB
  4. Optionally calls `scan4me check <domain>` before any live probe

Integration points:
  - oracle_intake.run_prescan()/run_scan()  →  Scan4Me ranked feed
  - oracle_hunter._scope_from_programs()    →  scan4me_scope_for()
  - oracle_scan4me.resolve()               →  named-program lookup

Usage from oracle_hunter:
    import oracle_scan4me
    prog = oracle_scan4me.resolve("8x8")
    oracle_scan4me.verify_in_scope("api.8x8.com", prog)
"""

from __future__ import annotations

import copy
import ipaddress
import math
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Scan4Me location ──────────────────────────────────────────────────────────
def scan4me_home() -> Path:
    """Resolve the Scan4Me checkout.

    SCAN4ME_HOME wins; else the sibling-of-this-repo candidate. The
    candidate is returned unverified (callers check existence) — never
    a workstation-specific absolute path.
    """
    env = os.environ.get("SCAN4ME_HOME")
    if env:
        return Path(env).expanduser()
    return Path(__file__).resolve().parent.parent / "Scan4Me"


def scan4me_db_path() -> Path:
    """Resolved scan4me.db path (may not exist — callers must check)."""
    return scan4me_home() / "scan4me.db"


_SCAN4ME_DIR = scan4me_home()
_DB_PATH = scan4me_db_path()

# ── Asset type mapping → Oracle structured_scope type ────────────────────────
# Oracle consumers match UPPERCASE vocabulary exactly (oracle_hunter.py dead
# web filter: URL/WILDCARD/DOMAIN/WEB; scope gates .upper() everything), so
# the bridge emits uppercase. Covers legacy verbatim values AND the new
# canonical lowercase enum from Scan4Me's normalizer (#4). Unknown → OTHER
# (fail closed: OTHER is non-DNS in intake, so strays never slip into the
# DNS probe path the way default-"url" mistypings did).
_ASSET_TYPE_MAP = {
    # url-ish → URL
    "URL": "URL",
    "url": "URL",
    "DOMAIN": "URL",
    "domain": "URL",
    "WEB": "URL",
    "web": "URL",
    "WEBSITE": "URL",
    "website": "URL",
    "WEB_APPLICATION": "URL",
    "web_application": "URL",
    "web-application": "URL",
    # wildcard → WILDCARD
    "WILDCARD": "WILDCARD",
    "wildcard": "WILDCARD",
    # ip-ish → CIDR
    "CIDR": "CIDR",
    "cidr": "CIDR",
    "IP": "CIDR",
    "ip": "CIDR",
    "IP_ADDRESS": "CIDR",
    "ip_address": "CIDR",
    "IPRANGE": "CIDR",
    "iprange": "CIDR",
    "IP_RANGE": "CIDR",
    "ip_range": "CIDR",
    # api → API
    "API": "API",
    "api": "API",
    # source → SOURCE_CODE
    "SOURCE_CODE": "SOURCE_CODE",
    "source_code": "SOURCE_CODE",
    "GITHUB": "SOURCE_CODE",
    "github": "SOURCE_CODE",
    # mobile → store-ID vocabulary the hunter already filters on
    "APPLE_STORE_APP_ID": "APPLE_STORE_APP_ID",
    "ios_app": "APPLE_STORE_APP_ID",
    "IOS": "APPLE_STORE_APP_ID",
    "ios": "APPLE_STORE_APP_ID",
    "GOOGLE_PLAY_APP_ID": "GOOGLE_PLAY_APP_ID",
    "android_app": "GOOGLE_PLAY_APP_ID",
    "ANDROID": "GOOGLE_PLAY_APP_ID",
    "android": "GOOGLE_PLAY_APP_ID",
    # binaries → EXECUTABLE
    "EXECUTABLE": "EXECUTABLE",
    "executable": "EXECUTABLE",
    "DOWNLOADABLE_EXECUTABLES": "EXECUTABLE",
    "downloadable_executables": "EXECUTABLE",
    # web3 → SMART_CONTRACT
    "SMART_CONTRACT": "SMART_CONTRACT",
    "smart_contract": "SMART_CONTRACT",
    "SmartContract": "SMART_CONTRACT",
    # fallback → OTHER
    "OTHER": "OTHER",
    "other": "OTHER",
    "UNKNOWN": "OTHER",
    "unknown": "OTHER",
    "": "OTHER",
}


def canon_asset_type(raw: Any) -> str:
    """Canonical Oracle asset type for any raw Scan4Me value (default OTHER)."""
    key = str(raw or "").strip()
    if key in _ASSET_TYPE_MAP:
        return _ASSET_TYPE_MAP[key]
    lowered = key.lower().replace("-", "_").replace(" ", "_")
    for candidate in (key.upper(), lowered, lowered.upper()):
        if candidate in _ASSET_TYPE_MAP:
            return _ASSET_TYPE_MAP[candidate]
    return "OTHER"


# Local mirror of Scan4Me _MULTI_LABEL_PUBLIC_SUFFIXES (keep in sync).
_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset({
    "ac.uk", "co.uk", "gov.uk", "org.uk",
    "com.au", "net.au", "org.au", "co.nz", "org.nz",
    "com.br", "com.cn", "com.tw", "com.hk", "com.sg",
    "co.jp", "co.kr", "co.in", "com.mx", "com.ar",
    "co.za", "com.tr", "com.pl", "com.ru", "co.il",
})


def _wildcard_base_is_registrable(rest: str) -> bool:
    """Local mirror of Scan4Me _wildcard_base_is_registrable (keep in sync)."""
    cand = (rest or "").lstrip("-.").lower().rstrip(".")
    if not cand or ".." in cand:
        return False
    labels = [part for part in cand.split(".") if part]
    if len(labels) != len(cand.split(".")) or len(labels) < 2:
        return False
    if cand in _MULTI_LABEL_PUBLIC_SUFFIXES:
        return False
    if ".".join(labels[-2:]) in _MULTI_LABEL_PUBLIC_SUFFIXES and len(labels) < 3:
        return False
    return True


def _strip_rule(ident: str) -> str:
    """Match-time host strip mirroring Scan4Me's normalizer (#4).

    Local mirror (no scan4me import) so the direct-DB fallback path gets
    identical match semantics: scheme/userinfo/path/port removed, lowercase.
    Control/whitespace input strips to "" so it can never match (fail-closed).
    """
    if any(ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in (ident or "")):
        return ""
    text = (ident or "").strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/")[0].split("@")[-1].strip().rstrip(".")
    if text.startswith("[") and "]" in text:
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1 and "*" not in text:
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def _db() -> Optional[sqlite3.Connection]:
    """Open the Scan4Me SQLite DB read-only. None when DB not found.

    The bridge never writes Scan4Me's database; a read-only handle
    makes that structural (and side-steps WAL/journal creation in a
    foreign checkout).
    """
    db_path = scan4me_db_path()
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def handle_from_url(url: str) -> str:
    """Canonical URL-slug handle: last path segment, no trailing slash."""
    return (url or "").rstrip("/").split("/")[-1].strip()


def _table_columns(conn: sqlite3.Connection, table: str) -> set:
    """Column names of a table, or empty set when unreadable (old schema)."""
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except Exception:
        return set()


_ASSET_WANT = (
    "asset_identifier",
    "asset_type",
    "is_wildcard",
    "eligible_for_bounty",
    "eligible_for_submission",
    "instruction",
    "max_severity",
    "deleted_timestamp",
)


def _live_assets(conn: sqlite3.Connection, program_id: Any) -> List[Dict]:
    """Live (non-tombstoned) asset rows as plain dicts.

    Tolerant of pre-migration schemas: only selects columns that exist, and
    filters tombstones in Python so old DBs (no deleted_timestamp) keep
    working until their next Scan4Me sync migrates them.
    """
    have = _table_columns(conn, "assets") & set(_ASSET_WANT)
    have.add("asset_identifier")
    sel = ", ".join(sorted(have))
    try:
        rows = conn.execute(
            f"SELECT {sel} FROM assets WHERE program_id=?", (program_id,)
        ).fetchall()
    except Exception:
        return []
    out = []
    for r in rows:
        try:
            d = {k: r[k] for k in r.keys()}
        except Exception:
            continue
        if (d.get("deleted_timestamp") or 0) != 0:
            continue
        out.append(d)
    return out


def _live_oos(conn: sqlite3.Connection, program_id: Any) -> List[str]:
    """Live out-of-scope identifiers for a program ([] on old schemas)."""
    try:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    except Exception:
        return []
    if "oos_assets" not in tables:
        return []
    have = _table_columns(conn, "oos_assets")
    sel = "asset_identifier" + (", deleted_timestamp" if "deleted_timestamp" in have else "")
    try:
        rows = conn.execute(
            f"SELECT {sel} FROM oos_assets WHERE program_id=?", (program_id,)
        ).fetchall()
    except Exception:
        return []
    out = []
    for r in rows:
        try:
            if "deleted_timestamp" in have and (r["deleted_timestamp"] or 0) != 0:
                continue
            ident = (r["asset_identifier"] or "").strip()
        except Exception:
            continue
        if ident:
            out.append(ident)
    return out


def _col(row: Any, key: str, default: Any = None) -> Any:
    """Mapping-style cell read for sqlite Rows and plain dicts."""
    try:
        val = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if val is None else val


def _scopes_from_assets(assets: List[Any]) -> List[Dict]:
    """Asset rows → Oracle structured_scopes with REAL eligibility flags.

    Unknown (old schema / NULL) defaults to eligible — the consumer
    (ProgramScopeGate) treats only explicit False as out-of-scope.
    """
    scopes = []
    for a in assets:
        scopes.append(
            {
                "asset_identifier": _col(a, "asset_identifier", "") or "",
                "asset_type": canon_asset_type(_col(a, "asset_type")),
                "is_wildcard": bool(_col(a, "is_wildcard", False)),
                "eligible_for_bounty": bool(_col(a, "eligible_for_bounty", True)),
                "eligible_for_submission": bool(
                    _col(a, "eligible_for_submission", True)
                ),
                "instruction": _col(a, "instruction", "") or "",
                "max_severity": _col(a, "max_severity", "") or "",
            }
        )
    return scopes


def _db_handle_for(conn: Optional[sqlite3.Connection], program_id: Any) -> str:
    """DB ``handle`` for a program id, or "" when unknown/unreadable."""
    if conn is None or program_id is None:
        return ""
    try:
        row = conn.execute(
            "SELECT handle FROM programs WHERE id=?", (program_id,)
        ).fetchone()
    except Exception:
        return ""
    if not row:
        return ""
    try:
        return row["handle"] or ""
    except Exception:
        return ""


def _row_to_program(
    row, assets: List[Dict], oos_identifiers: Optional[List[str]] = None
) -> Dict:
    """Convert a Scan4Me programs row + asset list → Oracle program dict."""
    structured_scopes = _scopes_from_assets(assets)

    cols = set(row.keys())
    return {
        "name": row["name"],
        "handle": row["handle"] or "",
        "url": row["url"] or "",
        "website": row["website"] if "website" in cols else "",
        "platform": row["platform"],
        "max_payout": row["max_payout"] or None,
        "max_payout_usd": row["max_payout"] or None,
        "currency": row["currency"] or "USD",
        "offers_bounties": bool(row["offers_bounties"]),
        "managed_triage": bool(row["managed_triage"]),
        "fast_triage": bool(
            row["managed_triage"]
            or (row["first_response_hours"] is not None and row["first_response_hours"] <= 72)
        ),
        "safe_harbor": row["safe_harbor"] or "Standard",
        "kind": row["program_kind"] or "web2",
        "program_kind": row["program_kind"] or "web2",
        # Speed / competition signals (used by oracle_hunt_filter)
        "first_response_hours": row["first_response_hours"],
        "response_efficiency": row["response_efficiency"],
        "validation_days": row["validation_days"],
        "rewarded_vulnerabilities": row["rewarded_vulnerabilities"],
        "average_payout": row["average_payout"],
        # Scope
        "structured_scopes": structured_scopes,
        # Explicit out-of-scope identifiers (ProgramScopeGate consumes these)
        "out_of_scope": list(oos_identifiers or []),
        # Source tag
        "_source": "scan4me",
    }


def _diversify_ranked_by_platform(
    ranked: List[Dict], limit: int
) -> List[Dict]:
    """Interleave a globally scored list by platform for Oracle prescan.

    Scan4Me's composite score is useful *within* a platform, but its
    largest component depends on telemetry that platforms do not publish
    uniformly: HackerOne supplies first-response hours for most programs,
    Bugcrowd supplies validation days for some, and the other feeds may
    supply neither. Taking one global top-N therefore turns a telemetry
    availability gap into a HackerOne-only shortlist. Round-robin by
    platform preserves each platform's own ranked order while ensuring
    the best currently ranked program from every represented platform is
    selected before second-ranked programs. This changes selection only;
    it does not alter Scan4Me's scores or `radar` ordering.
    """
    if limit is None:
        limit = len(ranked)
    if limit <= 0:
        return []

    groups: Dict[str, List[Dict]] = {}
    for item in ranked:
        platform = str(item.get("platform") or "")
        groups.setdefault(platform, []).append(item)

    selected: List[Dict] = []
    platform_rank = 0
    while len(selected) < limit:
        progressed = False
        for items in groups.values():
            if platform_rank >= len(items):
                continue
            progressed = True
            item = dict(items[platform_rank])
            item["_platform_rank"] = platform_rank + 1
            item["_selection_rank"] = len(selected) + 1
            selected.append(item)
            if len(selected) >= limit:
                break
        if not progressed:
            break
        platform_rank += 1
    return selected


def triage_prescan_overlay(base_cfg: Dict, triage_cfg: Dict) -> Dict:
    """Apply Oracle's triage.yaml profile over a Scan4Me config (pure).

    Boss file: triage.yaml owns the shared fast-money knobs — surface,
    fast triage, new assets, new company, low reports — for every ranking
    path. Scan4Me keeps its own scoring math and standalone defaults; this
    translation only runs inside the Oracle bridge at prescan time.

    Payout is a GATE, never a rank weight (owner rule): the triage payout
    weight (0.0) maps to payout_size, and hunt_filter.min_payout_usd
    becomes the prescan payout floor. Prescan is the public,
    outside-the-wall pass, so it stays loose: strict newness gates off and
    measured triage never required — signed-in Oracle stages re-measure
    and gate strictly. Scan4Me-only keys (platforms, wildcard, SLA
    baseline, API keys) pass through untouched. Inputs are not mutated.
    """
    out = copy.deepcopy(base_cfg or {})
    tri = triage_cfg or {}

    weights = tri.get("weights") or {}
    if weights:
        mapped = {
            "attack_surface_size": float(weights.get("asset_count", 1.0) or 0),
            "triage_speed": float(weights.get("fast_triage", 0.40) or 0),
            "freshness_and_low_saturation": float(
                (weights.get("new_assets", 0.30) or 0)
                + (weights.get("recency", 0.10) or 0)
                + (weights.get("low_reports", 0.10) or 0)
            ),
            "payout_size": float(weights.get("payout", 0.0) or 0),
        }
        for _k, _v in mapped.items():
            if not math.isfinite(_v) or _v < 0:
                raise ValueError(
                    f"triage.yaml weight {_k!r} must be finite and >= 0, got {_v!r}"
                )
        total = sum(mapped.values())
        if total <= 0:
            raise ValueError(
                "triage.yaml weights map to a zero total — the boss file "
                "must rank by something (fix triage.yaml weights)"
            )
        out["ranking_weights"] = {k: v / total for k, v in mapped.items()}

    filters = out.setdefault("filters", {})
    fresh = filters.setdefault("freshness_and_competition", {})
    new_asset_days = tri.get("new_asset_full_days")
    if new_asset_days is not None:
        # 0 is meaningful in triage.yaml ("0 disables the signal"): a
        # zero-day window counts nothing as new. Never treat it as unset.
        fresh["new_asset_days"] = int(float(new_asset_days))
    new_company_days = tri.get("recency_full_days")
    if new_company_days is not None:
        fresh["new_company_days"] = int(float(new_company_days))
    fresh["strict_new_assets"] = False
    fresh["strict_new_companies"] = False

    fast = filters.setdefault("fast_triage", {})
    fast["require_measured_response_time"] = False
    fast["prefer_managed_triage"] = True

    hunt_filter = tri.get("hunt_filter") or {}
    if hunt_filter.get("min_payout_usd") is not None:
        payouts = filters.setdefault("payouts", {})
        payouts["min_max_payout_usd"] = float(hunt_filter["min_payout_usd"] or 0)

    kind = str(tri.get("kind") or "").strip().lower()
    if kind == "all":
        filters["program_kind"] = {"web2": True, "web3": True}
    elif kind == "web2":
        filters["program_kind"] = {"web2": True, "web3": False}
    elif kind == "web3":
        filters["program_kind"] = {"web2": False, "web3": True}
    return out


def _triage_cfg_or_none() -> Optional[Dict]:
    """Load the sibling triage.yaml boss file, or None when it is ABSENT.

    A present-but-corrupt boss file fails loud — silently ranking by
    Scan4Me defaults instead of the owner's profile is exactly the
    failure the shared config exists to prevent.
    """
    path = Path(__file__).resolve().parent / "triage.yaml"
    if not path.exists():
        return None
    try:
        from oracle_triage import load_config as _load_triage

        cfg = _load_triage(path)
    except Exception as exc:
        raise ValueError(f"triage.yaml is present but unreadable: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ValueError(f"triage.yaml must parse to a mapping, got {type(cfg).__name__}")
    return cfg


def _prescan_config(load_scan4me_config) -> Dict:
    """Scan4Me config with the triage.yaml boss profile overlaid."""
    cfg = load_scan4me_config()
    tri = _triage_cfg_or_none()
    if tri is None:
        print("[scan4me bridge] triage.yaml unreadable — prescan uses Scan4Me config alone")
        return cfg
    return triage_prescan_overlay(cfg, tri)


def fetch_programs(limit: int = 50, config=None) -> List[Dict]:
    """Return a platform-diversified Scan4Me shortlist for Oracle.

    Pulls evaluate_targets() from Scan4Me directly, preserves its ranked
    order inside each platform, and interleaves platforms for the Oracle
    prescan so non-uniform triage telemetry cannot monopolize the whole
    shortlist. Falls back to a diversified direct DB query when the
    Scan4Me module cannot be imported.

    With no explicit config, scoring obeys the triage.yaml boss profile
    via triage_prescan_overlay (payout gates, never ranks; prescan loose,
    signed-in stages strict). An explicit config wins untouched.
    """
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
    ):
        raise ValueError(f"fetch_programs limit must be None or an int >= 0, got {limit!r}")
    if limit == 0:
        return []
    # Prefer the full evaluate_targets() scorer
    try:
        home = str(scan4me_home())
        if home not in sys.path:
            sys.path.insert(0, home)
        import scan4me as s4m

        cfg = config if config is not None else _prescan_config(s4m.load_config)
        ranked = s4m.evaluate_targets(cfg)
        conn = _db()
        out = []
        for p in _diversify_ranked_by_platform(ranked, limit):
            if conn:
                assets = _live_assets(conn, p["id"])
                oos = _live_oos(conn, p["id"])
            else:
                assets = []
                oos = []
            # Unified handle: the DB handle when readable (what resolve()
            # matches exactly), else the canonical URL slug. Both paths
            # agree, so fetch → resolve round-trips.
            prog = {
                "name": p["name"],
                "handle": _db_handle_for(conn, p.get("id"))
                or handle_from_url(p.get("url", "")),
                "url": p["url"],
                "website": p.get("website") or "",
                "platform": p["platform"],
                "max_payout": p.get("max_payout") or None,
                "max_payout_usd": p.get("max_payout") or None,
                "currency": p.get("currency") or "USD",
                "offers_bounties": True,
                "managed_triage": bool(p.get("managed", False)),
                "fast_triage": bool(
                    p.get("managed", False)
                    or (p.get("first_resp") is not None and p["first_resp"] <= 72)
                    or (p.get("first_response_hours") is not None and p["first_response_hours"] <= 72)
                    or p.get("speed_score", 0) >= 50.0
                ),
                "safe_harbor": p.get("safe_harbor") or "Standard",
                "kind": p.get("program_kind") or "web2",
                "program_kind": p.get("program_kind") or "web2",
                "first_response_hours": p.get("first_resp"),
                "response_efficiency": p.get("efficiency"),
                "validation_days": p.get("validation_days"),
                "rewarded_vulnerabilities": p.get("rewarded_vulnerabilities"),
                "average_payout": p.get("average_payout"),
                "score": p.get("score", 0),
                "speed_score": p.get("speed_score", 0),
                "fresh_score": p.get("fresh_score", 0),
                "surface_score": p.get("surface_score", 0),
                "payout_score": p.get("payout_score", 0),
                "surface_tier": p.get("surface_tier", ""),
                "structured_scopes": _scopes_from_assets(assets),
                "out_of_scope": oos,
                "_source": "scan4me",
                "_db_id": p["id"],
                "_platform_rank": p.get("_platform_rank"),
                "_selection_rank": p.get("_selection_rank"),
            }
            out.append(prog)
        return out
    except Exception as e:
        print(
            f"[scan4me bridge] evaluate_targets failed ({e}), falling back to direct DB query"
        )

    # Fallback: direct DB query without scoring
    conn = _db()
    if not conn:
        print(
            f"[scan4me bridge] DB not found at {scan4me_db_path()} — run `python3 scan4me.py sync` first"
        )
        return []

    rows = conn.execute(
        """
        SELECT p.*, count(a.id) as asset_count
        FROM programs p
        LEFT JOIN assets a ON p.id = a.program_id
        WHERE p.offers_bounties = 1
        GROUP BY p.id
        ORDER BY asset_count DESC, p.first_response_hours ASC
    """
    ).fetchall()

    row_dicts = [{k: row[k] for k in row.keys()} for row in rows]
    out = []
    for row in _diversify_ranked_by_platform(row_dicts, limit):
        assets = _live_assets(conn, row["id"])
        program = _row_to_program(row, assets, _live_oos(conn, row["id"]))
        program["_platform_rank"] = row.get("_platform_rank")
        program["_selection_rank"] = row.get("_selection_rank")
        out.append(program)
    return out


def resolve(name: str) -> Optional[Dict]:
    """Look up a program by name/handle and return its Oracle-compatible dict.

    Exact handle → URL-slug boundary → name/URL substring (case-insensitive).
    Falls back to the contests table (#6) so Sherlock/Code4rena-style rows
    resolve too. Returns the best match or None.
    """
    conn = _db()
    if not conn:
        return None

    # Exact handle first, then URL-slug boundary (covers slug handles from
    # fetch_programs when the DB handle differs), then loose substrings.
    slug = handle_from_url(name) if "://" in name or "/" in name else name.strip()
    for sql, params in (
        ("SELECT * FROM programs WHERE LOWER(handle)=LOWER(?)", (name,)),
        (
            "SELECT * FROM programs WHERE LOWER(RTRIM(url, '/')) LIKE LOWER(?)",
            (f"%/{slug}",),
        ),
        ("SELECT * FROM programs WHERE LOWER(name) LIKE LOWER(?)", (f"%{name}%",)),
        ("SELECT * FROM programs WHERE LOWER(url) LIKE LOWER(?)", (f"%{name}%",)),
    ):
        row = conn.execute(sql, params).fetchone()
        if row:
            assets = _live_assets(conn, row["id"])
            return _row_to_program(row, assets, _live_oos(conn, row["id"]))
    return resolve_contest(name, conn)


def _contest_to_program(row: Any) -> Dict:
    """Contest row → Oracle program dict (#6).

    Contests carry no scope assets, so structured_scopes is honestly empty:
    intake's scope-live leg fails on them (declared behavior) until a
    contest-scope source exists. Contest metadata rides in ``contest``.
    """
    return {
        "name": _col(row, "name", ""),
        "handle": _col(row, "handle", "") or "",
        "url": _col(row, "url", "") or "",
        "website": "",
        "platform": _col(row, "platform", "") or "",
        "max_payout": _col(row, "max_payout") or None,
        "max_payout_usd": _col(row, "max_payout") or None,
        "currency": _col(row, "currency", "USD") or "USD",
        "offers_bounties": bool(_col(row, "offers_bounties", False)),
        "managed_triage": False,
        "fast_triage": False,
        "safe_harbor": "Standard",
        "kind": "web3",
        "program_kind": "web3",
        "first_response_hours": None,
        "response_efficiency": None,
        "validation_days": None,
        "rewarded_vulnerabilities": None,
        "average_payout": None,
        "structured_scopes": [],
        "out_of_scope": [],
        "contest": {
            "status": _col(row, "status", "") or "",
            "starts_at": _col(row, "starts_at", "") or "",
            "ends_at": _col(row, "ends_at", "") or "",
            "description": _col(row, "description", "") or "",
        },
        "_source": "scan4me-contest",
    }


def fetch_contests(limit: int = 50) -> List[Dict]:
    """Contest rows (Sherlock et al.) as Oracle program dicts, richest first."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"fetch_contests limit must be an int >= 0, got {limit!r}")
    if limit == 0:
        return []
    conn = _db()
    if not conn:
        return []
    try:
        rows = conn.execute(
            "SELECT * FROM contests ORDER BY max_payout DESC LIMIT ?", (limit,)
        ).fetchall()
    except Exception:
        return []
    return [_contest_to_program(r) for r in rows]


def resolve_contest(name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict]:
    """Resolve a contest by handle/name substring (case-insensitive)."""
    own = conn is None
    if own:
        conn = _db()
    if conn is None:
        return None
    try:
        for sql, params in (
            ("SELECT * FROM contests WHERE LOWER(handle)=LOWER(?)", (name,)),
            ("SELECT * FROM contests WHERE LOWER(name) LIKE LOWER(?)", (f"%{name}%",)),
        ):
            try:
                row = conn.execute(sql, params).fetchone()
            except Exception:
                return None
            if row:
                return _contest_to_program(row)
    finally:
        if own:
            conn.close()
    return None


def _ident_matches(domain_lower: str, ident_raw: str, is_wildcard: bool) -> bool:
    """Host/wildcard match, local mirror of Scan4Me scope_match().

    '*.base' matches proper subdomains of base only (never the apex, never
    lookalike suffixes); '*-prefix.host' matches targets ending in the literal
    rest; a non-wildcard rule requires an exact host match. Fail-closed.
    """
    ident = _strip_rule(ident_raw or "")
    if not ident or not domain_lower:
        return False
    if not (is_wildcard or ident.startswith("*")):
        return ident == domain_lower
    if ident.startswith("*."):
        base = ident[2:]
        return (
            bool(base)
            and "*" not in base
            and _wildcard_base_is_registrable(base)
            and domain_lower.endswith("." + base)
        )
    if ident.startswith("*"):
        rest = ident[1:]
        return (
            bool(rest)
            and "*" not in rest
            and _wildcard_base_is_registrable(rest)
            and domain_lower.endswith(rest)
        )
    return False  # is_wildcard set but no '*' prefix: fail closed


def _ip_in_rule(target: str, rule_identifier: str) -> bool:
    """True when `target` is an IP inside `rule_identifier` (CIDR or bare IP).

    Local mirror of Scan4Me _ip_matches_rule() so an out-of-scope IP range
    (10.0.0.0/8) correctly excludes an address inside it — string matching
    alone never would. Non-IP target or unparseable rule → False (this only
    ever adds an exclusion, never removes one).
    """
    try:
        ip = ipaddress.ip_address((target or "").strip())
    except ValueError:
        return False
    rule = (rule_identifier or "").strip()
    try:
        return ip in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        try:
            return ip == ipaddress.ip_address(rule)
        except ValueError:
            return False


def _oos_excludes(domain_lower: str, oos_list) -> bool:
    """A target matched by any out-of-scope rule (host, wildcard, or IP/CIDR)
    is disqualified. Exclusions win over an in-scope wildcard — parity with
    the fixed Scan4Me cmd_check."""
    for raw in oos_list or []:
        wildcard = str(raw or "").strip().startswith("*")
        if _ident_matches(domain_lower, raw, wildcard):
            return True
        if _ip_in_rule(domain_lower, raw):
            return True
    return False


def verify_in_scope(domain: str, prog: Dict) -> Tuple[bool, str]:
    """Check whether `domain` is in scope for `prog`.

    S4 unification: the execution gate (ProgramScopeGate) is the sole
    scope judge — this bridge delegates the verdict to it so pre-checks
    can never disagree with the load-bearing control. The local mirror
    survives only to name the matched rule for reporting. Import
    failure fails closed, loudly in the reason. Returns
    (is_in_scope: bool, matched_rule: str).
    """
    # Outer padding is caller sloppiness, not a different host: strip it
    # so the gate judges the same string here as everywhere else. Any
    # remaining (internal) whitespace still strips to "" -> fail-closed.
    domain = (domain or "").strip()
    domain_lower = _strip_rule(domain)
    if not domain_lower:
        return False, ""
    try:
        from oracle_hunter import ProgramScopeGate
    except Exception as exc:  # scope engine unavailable: fail closed
        return False, f"scope engine unavailable: {exc}"
    gate_ok, _reason = ProgramScopeGate(prog, "").is_host_in_scope(domain)
    if not gate_ok:
        return False, ""
    # Verdict is the gate's; rule naming reuses the local mirror.
    if _oos_excludes(domain_lower, prog.get("out_of_scope", [])):
        return False, ""  # mirror OOS IP ranges the gate may not model
    for scope in prog.get("structured_scopes", []):
        if scope.get("eligible_for_submission") is False:
            continue
        if scope.get("eligible_for_bounty") is False:
            continue
        ident_raw = scope.get("asset_identifier") or ""
        wildcard = bool(scope.get("is_wildcard")) or _strip_rule(ident_raw).startswith("*")
        if _ident_matches(domain_lower, ident_raw, wildcard):
            return True, _strip_rule(ident_raw)
        if _ip_in_rule(domain_lower, ident_raw):
            return True, _strip_rule(ident_raw)
    return True, ""


def print_ranked(limit: int = 25, config=None):
    """Print the Scan4Me ranked list in a compact table — mirrors `scan4me.py radar`."""
    programs = fetch_programs(limit=limit, config=config)
    if not programs:
        print("[scan4me] No programs found — run `python3 scan4me.py sync` first")
        return

    print()
    print("=" * 90)
    print("  SCAN4ME RANKED PROGRAMS  →  Oracle Hunt Queue")
    print("=" * 90)
    print(
        f"  {'#':>3}  {'Score':>5}  {'Platform':<12}  {'Name':<35}  {'Surface':<18}  Payout"
    )
    print("  " + "-" * 86)
    for i, p in enumerate(programs, 1):
        score = p.get("score", 0)
        platform = p["platform"][:12]
        name = p["name"][:35]
        tier = p.get("surface_tier", "")
        tier_short = {
            "🔥 MASSIVE SURFACE": "MASSIVE",
            "⚡ WIDE SURFACE": "WIDE",
            "🎯 MODERATE": "MODERATE",
            "🔍 NARROW/FOCUSED": "NARROW",
        }.get(tier, tier[:18])
        payout = (
            f"${p.get('max_payout_usd') or 0:,.0f} {p.get('currency', 'USD')}"
            if (p.get("max_payout_usd") or 0) > 0
            else "Paid"
        )
        speed = (
            f"{p['first_response_hours']}h"
            if p.get("first_response_hours") is not None
            else "?"
        )
        print(
            f"  [{i:>2}]  {score:>5.1f}  {platform:<12}  {name:<35}  {tier_short:<18}  {payout}  (resp {speed})"
        )
    print()


# ── CLI for standalone use ────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan4Me→Oracle bridge — ranked program list and scope checks"
    )
    parser.add_argument("--limit", type=int, default=25, help="Programs to show")
    parser.add_argument(
        "--check", metavar="DOMAIN", help="Check if domain is in scope for a program"
    )
    parser.add_argument(
        "--program", metavar="NAME", help="Program name/handle for --check"
    )
    parser.add_argument(
        "--resolve",
        metavar="NAME",
        help="Resolve a program by name and print its scope",
    )
    parser.add_argument(
        "--contests",
        action="store_true",
        help="List contest rows (Sherlock et al.) instead of ranked programs",
    )
    args = parser.parse_args()

    if args.contests:
        contests = fetch_contests(limit=args.limit)
        if not contests:
            print("[scan4me] No contests found in scan4me.db")
        for i, c in enumerate(contests, 1):
            print(
                f"  [{i:>2}] [{c['platform']}] {c['name']}  "
                f"${(c.get('max_payout_usd') or 0):,.0f} {c.get('currency', '')}  "
                f"{c.get('contest', {}).get('status', '')}  {c['url']}"
            )
        sys.exit(0)

    if args.resolve:
        prog = resolve(args.resolve)
        if prog:
            print(f"\n[+] {prog['name']}  [{prog['platform']}]  {prog['url']}")
            print(
                f"    Max payout: ${(prog.get('max_payout_usd') or 0):,.0f}  "
                f"Response: {prog.get('first_response_hours', '?')}h  "
                f"Assets: {len(prog.get('structured_scopes', []))}"
            )
            print("\n    In-scope assets:")
            for s in prog.get("structured_scopes", []):
                wc = "🌐" if s["is_wildcard"] else "  "
                print(f"      {wc} {s['asset_identifier']}  ({s['asset_type']})")
        else:
            print(f"[!] No program matching '{args.resolve}' found in Scan4Me DB")

    elif args.check:
        prog_name = args.program or ""
        prog = resolve(prog_name) if prog_name else None
        if not prog:
            print(
                "[!] Use --program <name> to specify which program to check scope against"
            )
            sys.exit(1)
        in_scope, rule = verify_in_scope(args.check, prog)
        if in_scope:
            print(
                f"✅  '{args.check}' is IN SCOPE for [{prog['platform']}] {prog['name']}"
            )
            print(f"    Matched rule: {rule}")
        else:
            print(
                f"❌  '{args.check}' is NOT in scope for [{prog['platform']}] {prog['name']}"
            )

    else:
        print_ranked(limit=args.limit)
