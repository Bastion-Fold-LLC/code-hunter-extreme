#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: run_prescan, run_scan, select_deep_dive, write_handoff, latest_report
# TOPICS: none
"""oracle_intake.py — P11 prescan / scan / -N intake sweep (Oracle-side).

Doctrine ORACLE_DOCTRINE.md §3 pipeline, implemented against Scan4Me intel:

  1. ``prescan`` — fast Scan4Me sweep (local ranked DB via the
     ``oracle_scan4me`` bridge; ``--sync`` refreshes first). Produces a
     **prescan report**. Raw output; ``trusted: false`` — nothing downstream
     trusts it. The product path refuses a stale feed, a failed refresh, a
     `public-file` (unauthenticated) platform rows, or a feed with no
     authenticated platform rows. The rejected report is written first so
     the evidence and runlog survive the failure.
  2. ``scan`` — Oracle's verification pass over the prescan. Produces a
     **scan report** with a per-program verdict. A program is verified iff
     no leg blocks (doctrine §3 verify-pass definition):
       - scope URLs resolve / are live (direct local probes, scope-gated);
       - payouts match the fresh platform listing (re-resolved via bridge),
         tri-state: match / mismatch / unknown — only mismatch blocks;
       - bounty rules text is unchanged since prescan (sha256 comparison),
         ADVISORY skip-when-unavailable: unknown never blocks, only a
         proven change does (no feed carries rules text; it is never faked).
     Only verified programs proceed. Unverified programs NEVER proceed.
  3. ``-N`` / ``--sites`` — deep-dive the top N **verified** programs (full
     assets, company info, resources). Naming sites explicitly overrides the
     count. The result is the **ranked-verified list** handed to P12.
     Deep-dive assets are re-resolved fresh at dive time (``resolve_fn``); a
     stale prescan snapshot can never feed deep-dive.

Scan4Me is intel-only (no scanner/prober of its own), so the whole sweep
lives here, Oracle-side, consuming the bridge (``oracle_scan4me``).

Apex exclusion (P7) holds throughout: wildcard scope rules (``*.base``) are
never expanded, so an apex host is probed only when it is itself an
explicitly listed in-scope asset. All matching goes through
``bridge.verify_in_scope``, which rejects apex-under-wildcard fail-closed.

Offline (``--no-cloud``): prescan reads the local DB only (``--sync`` is
refused); scan skips all network probing, so the scope-live leg fails
closed with an explicit ``offline`` reason. Reports are still written.

P12 handoff format (``oracle.p12.handoff/v1``) — ``reports/`` JSON file::

    {
      "_schema": "oracle.p12.handoff/v1",
      "created_utc": "2026-10-12T00:00:00+00:00",
      "prescan_report": "reports/prescan_<stamp>.json",
      "scan_report": "reports/scan_<stamp>.json",
      "no_cloud": false,
      "selector": {"top_n": 5, "sites": null},
      "ranked_verified": [
        {
          "rank": 1,
          "name": "...", "handle": "...", "platform": "...", "url": "...",
          "score": 87.5, "max_payout_usd": 25000, "currency": "USD",
          "verdict": "verified",
          "checks": {"scope_live": {...}, "payouts_match": {...},
                      "rules_unchanged": {...}},
          "deep_dive": {
            "assets": [...], "company": {...}, "resources": {...},
            "sources": ["scan4me:programs+assets"]
          }
        }
      ],
      "excluded_named": [],
      "note": "unverified programs never appear here; see the scan report"
    }

No ``queue`` config is read here (zero queue refs exist; P12 owns
scheduling, order, concurrency, and ``default_count``). Without ``-N`` or
``--sites``, ALL verified programs are handed off, ranked by score.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPORTS_DIR = HERE / "reports"

PRESCAN_SCHEMA = "oracle.intake.prescan/v1"
SCAN_SCHEMA = "oracle.intake.scan/v1"
HANDOFF_SCHEMA = "oracle.p12.handoff/v1"

ProbeFn = Callable[[str, float], Dict[str, Any]]
FetchFn = Callable[[], List[Dict[str, Any]]]
ResolveFn = Callable[[str], Optional[Dict[str, Any]]]
RescanFn = Callable[[Dict[str, Any]], Tuple[Optional[Dict[str, Any]], Dict[str, Any]]]

# Scope asset types that can never yield a DNS probe target.
_NON_DNS_ASSET_TYPES = {
    "cidr",
    "ios_app",
    "android_app",
    "executable",
    "smart_contract",
    "source_code",
    "other",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(now: Optional[datetime] = None) -> str:
    return (now or _utc_now()).strftime("%Y%m%d_%H%M%S")


# ── rules text ──────────────────────────────────────────────────────────────


def rules_text_of(prog: Dict[str, Any]) -> str:
    """Best-available bounty rules text for a program ("" when none)."""
    for key in ("rules_text", "policy"):
        val = prog.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def rules_hash_of(prog: Dict[str, Any]) -> Optional[str]:
    """sha256 of the rules text, or None when no rules text is available."""
    text = rules_text_of(prog)
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── probe-host derivation (apex-excluded, scope-gated) ──────────────────────


def _is_dns_target(host: str) -> bool:
    """The one shared DNS predicate: hunter._is_dns_target (lazy import).

    No local fallback — a divergent copy once accepted the very app IDs
    the predicate exists to reject. Import failure fails closed.
    """
    try:
        import oracle_hunter as _h  # lazy: hunter is heavy, intake stays light

        return bool(_h._is_dns_target(host))
    except Exception:
        return False


def _strip_to_host(ident: str) -> str:
    text = (ident or "").strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/")[0].split("@")[-1]
    if text.startswith("[") and "]" in text:  # IPv6 literal
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:  # host:port
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def derive_probe_hosts(prog: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Explicit in-scope DNS hosts to probe + skip reasons.

    Wildcard rules are never expanded: an apex host is probed only when it
    is itself explicitly listed. Every candidate must pass
    ``bridge.verify_in_scope`` (P7 fail-closed: apex-under-wildcard fails).
    """
    import oracle_scan4me as bridge

    hosts: List[str] = []
    skipped: List[str] = []
    for scope in prog.get("structured_scopes", []) or []:
        if not isinstance(scope, dict):
            continue
        ident = (scope.get("asset_identifier") or "").strip()
        if not ident:
            continue
        atype = (scope.get("asset_type") or "").strip().lower()
        lowered = ident.lower().rstrip(".")
        if atype in _NON_DNS_ASSET_TYPES:
            skipped.append(f"{ident}: non-DNS asset type ({atype or 'unknown'})")
            continue
        if lowered.startswith("*") or scope.get("is_wildcard"):
            base = lowered[2:] if lowered.startswith("*.") else lowered.lstrip("*")
            skipped.append(
                f"{ident}: wildcard not expanded"
                + (f" (apex {base} excluded per P7)" if base else "")
            )
            continue
        host = _strip_to_host(ident)
        if not host or not _is_dns_target(host):
            skipped.append(f"{ident}: not a DNS target")
            continue
        ok, _rule = bridge.verify_in_scope(host, prog)
        if not ok:
            skipped.append(f"{ident}: out of scope (fail-closed)")
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts, skipped


# ── liveness probing (direct sockets only — never cloud/LLM) ────────────────


def default_probe_host(host: str, timeout: float = 8.0) -> Dict[str, Any]:
    """DNS-resolve + HTTPS/HTTP HEAD a host. No redirects followed."""
    result: Dict[str, Any] = {
        "host": host,
        "resolves": False,
        "live": False,
        "status": None,
        "error": "",
    }
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        result["resolves"] = True
    except Exception as e:
        result["error"] = f"dns: {e}"
        return result

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            req: object,
            fp: object,
            code: int,
            msg: str,
            headers: object,
            newurl: str,
        ) -> None:
            return None

    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )
    last_err = ""
    for url in (f"https://{host}", f"http://{host}"):
        try:
            req = urllib.request.Request(
                url, method="HEAD", headers={"User-Agent": "oracle-intake/1.0"}
            )
            with opener.open(req, timeout=timeout) as resp:
                result["live"] = True
                result["status"] = int(resp.status)
                result["error"] = ""
                return result
        except Exception as e:
            last_err = f"{url}: {e}"
    result["error"] = last_err
    return result


# ── the three verify checks (doctrine §3) ───────────────────────────────────


# ── non-DNS liveness leg (#8): web3 scope-live proof ──────────────────────────
# DNS probing can never verify contract-only scope, so web3 programs need an
# alternate proof or the verify pass blocks them by design. Two target kinds:
#   evm-address  0x + 40 hex → eth_getCode via JSON-RPC; live iff code != 0x
#   repo-url     scheme URL (the shape real SMART_CONTRACT rows carry, e.g.
#                github repo links) → live iff the artifact URL serves HTTP
_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def derive_contract_targets(
    prog: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """SMART_CONTRACT scope entries → probe targets + skip reasons."""
    targets: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for scope in prog.get("structured_scopes", []) or []:
        if not isinstance(scope, dict):
            continue
        atype = (scope.get("asset_type") or "").strip().lower()
        if atype not in ("smart_contract", "smartcontract"):
            continue
        ident = (scope.get("asset_identifier") or "").strip()
        if not ident:
            continue
        if _EVM_ADDR_RE.match(ident):
            targets.append({"kind": "evm-address", "address": ident})
        elif ident.lower().startswith(("http://", "https://")):
            targets.append({"kind": "repo-url", "url": ident})
        else:
            skipped.append(f"{ident}: contract target is neither 0x-address nor URL")
    return targets, skipped


def default_contract_probe(
    target: Dict[str, Any], rpc_url: Optional[str] = None, timeout: float = 8.0
) -> Dict[str, Any]:
    """Probe one contract target. Direct sockets/HTTP only — never cloud/LLM."""
    kind = target.get("kind")
    if kind == "evm-address":
        result: Dict[str, Any] = {
            "target": target.get("address"),
            "kind": kind,
            "live": False,
            "error": "",
        }
        if not rpc_url:
            result["error"] = "no RPC configured (ORACLE_RPC_URL or rpc_url=)"
            return result
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getCode",
                "params": [target.get("address"), "latest"],
            }
        ).encode()
        try:
            req = urllib.request.Request(
                rpc_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                req, timeout=timeout, context=ctx
            ) as resp:  # nosec B310
                body = json.loads(resp.read().decode("utf-8", "replace"))
            code = body.get("result") or ""
            result["live"] = isinstance(code, str) and code not in ("", "0x", "0X")
            if not result["live"]:
                result["error"] = f"no code at address (got {code!r})"
            return result
        except Exception as e:
            result["error"] = f"rpc: {e}"
            return result
    if kind == "repo-url":
        result = {"target": target.get("url"), "kind": kind, "live": False, "error": ""}
        try:
            req = urllib.request.Request(
                target.get("url", ""),
                method="HEAD",
                headers={"User-Agent": "oracle-intake/1.0"},
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                req, timeout=timeout, context=ctx
            ) as resp:  # nosec B310
                result["live"] = 200 <= int(resp.status) < 400
                if not result["live"]:
                    result["error"] = f"http {resp.status}"
                return result
        except Exception as e:
            result["error"] = f"http: {e}"
            return result
    return {"target": None, "kind": kind, "live": False, "error": "unknown kind"}


def _is_wildcard_scope(scope: Dict[str, Any]) -> bool:
    """True when a structured-scope entry is a wildcard rule (never expanded)."""
    if not isinstance(scope, dict):
        return False
    ident = (scope.get("asset_identifier") or "").strip()
    if not ident:
        return False
    return ident.lower().rstrip(".").startswith("*") or bool(scope.get("is_wildcard"))


def check_scope_live(
    prog: Dict[str, Any],
    probe_fn: Optional[ProbeFn] = None,
    timeout: float = 8.0,
    no_cloud: bool = False,
    contract_probe_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    rpc_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Check 1: scope URLs resolve / are live. Pass iff ≥1 host is LIVE
    (serves HTTP/S) — resolves ≠ live: a parked DNS record that answers
    no HTTP is stale scope, not a verified target.

    Non-DNS leg (#8): SMART_CONTRACT scope is probed as an alternate
    proof — eth_getCode liveness for 0x addresses (needs ORACLE_RPC_URL),
    HTTP existence for repo-URL scope. Contract-only programs verify
    through this leg; it never rescues stale DNS scope.
    """
    hosts, skipped = derive_probe_hosts(prog)
    contracts, contract_skipped = derive_contract_targets(prog)
    skipped = skipped + contract_skipped
    if no_cloud:
        return {
            "pass": False,
            "reason": "offline (--no-cloud): liveness not probed",
            "hosts": hosts,
            "probed": [],
            "skipped": skipped,
            "contracts": contracts,
            "contracts_probed": [],
        }
    if not hosts and not contracts:
        # #14 POLICY (declared, not fixed — expansion is out of scope for
        # intake by design): a program whose scope is ONLY wildcard rules
        # can never verify here. Wildcards are never expanded (probing
        # hosts the program never named is out-of-scope scanning), and
        # the apex is excluded per P7 (fail-closed: apex-under-wildcard
        # is not in scope). Such programs need explicit hosts added to
        # scope (or an operator-supplied host list) before intake can
        # verify them. The distinct status keeps policy-unverifiable
        # apart from stale/empty scope in the report. Doctrine §3 should
        # state this (flagged for the doctrine owner — not edited here).
        _named = [
            s
            for s in (prog.get("structured_scopes") or [])
            if isinstance(s, dict) and (s.get("asset_identifier") or "").strip()
        ]
        _wild_only = bool(_named) and all(_is_wildcard_scope(s) for s in _named)
        if _wild_only:
            return {
                "pass": False,
                "status": "wildcard_only_unverifiable",
                "reason": (
                    "policy: wildcard-only scope cannot verify at intake "
                    "(wildcards never expanded; apex excluded per P7) — "
                    "add explicit in-scope hosts"
                ),
                "hosts": [],
                "probed": [],
                "skipped": skipped,
                "contracts": [],
                "contracts_probed": [],
            }
        return {
            "pass": False,
            "status": "no_probe_hosts",
            "reason": (
                "no probed scope hosts (empty or app-ID scope;" " apex excluded per P7)"
            ),
            "hosts": [],
            "probed": [],
            "skipped": skipped,
            "contracts": [],
            "contracts_probed": [],
        }
    fn = probe_fn or default_probe_host
    probed = [fn(h, timeout) for h in hosts]
    resolved = [p for p in probed if p.get("resolves")]
    live = [p for p in probed if p.get("live")]
    # Non-DNS leg: probe contract targets alongside (or instead of) DNS.
    cfn = contract_probe_fn or default_contract_probe
    rpc = rpc_url or os.environ.get("ORACLE_RPC_URL")
    contracts_probed = [cfn(t, rpc, timeout) for t in contracts]
    contracts_live = [p for p in contracts_probed if p.get("live")]
    ok = len(live) > 0 or len(contracts_live) > 0
    if ok:
        parts = []
        if live:
            parts.append(
                f"{len(live)}/{len(probed)} hosts live ({len(resolved)} resolve)"
            )
        if contracts_live:
            parts.append(
                f"{len(contracts_live)}/{len(contracts_probed)} contracts live"
            )
        reason = "; ".join(parts)
    elif resolved:
        reason = (
            f"0/{len(probed)} hosts live "
            f"({len(resolved)} resolve but no HTTP(S) response — stale scope)"
        )
    elif contracts_probed:
        reason = (
            f"0/{len(contracts_probed)} contracts live"
            + (f"; 0/{len(probed)} hosts resolve" if probed else "")
            + " (stale scope)"
        )
    else:
        reason = f"0/{len(probed)} hosts resolve (stale scope)"
    return {
        "pass": ok,
        "reason": reason,
        "hosts": hosts,
        "probed": probed,
        "skipped": skipped,
        "resolved_count": len(resolved),
        "live_count": len(live),
        "contracts": contracts,
        "contracts_probed": contracts_probed,
        "contracts_live_count": len(contracts_live),
    }


def check_payouts_match(
    prescan_prog: Dict[str, Any], fresh_prog: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Check 2: payouts match the fresh platform listing (tri-state).

    status is match / mismatch / unknown / missing. Only mismatch and
    missing block verification: unknown (a feed with no payout field, e.g.
    HackerOne's bool-only offers_bounties) is explicit and non-blocking.
    """
    if fresh_prog is None:
        return {
            "pass": False,
            "status": "missing",
            "reason": "program missing from fresh listing",
            "prescan": prescan_prog.get("max_payout_usd"),
            "fresh": None,
        }
    pre = prescan_prog.get("max_payout_usd")
    fr = fresh_prog.get("max_payout_usd")
    if pre is None or fr is None:
        return {
            "pass": True,
            "status": "unknown",
            "reason": (
                "payout unknown (prescan or fresh listing has none);"
                " tri-state unknown does not block verification"
            ),
            "prescan": pre,
            "fresh": fr,
        }
    try:
        _pre_f, _fr_f = float(pre), float(fr)
    except (TypeError, ValueError):
        match = pre == fr
        _delta = None
    else:
        # #24 POLICY: exact float equality blocked verification on any
        # payout wobble (currency-conversion dust, str/float round-trips).
        # Tolerance covers float dust + sub-dollar rounding ONLY — a real
        # payout change still mismatches and blocks.
        match = math.isclose(_pre_f, _fr_f, rel_tol=1e-6, abs_tol=1.0)
        _delta = abs(_fr_f - _pre_f)
    pre_cur = prescan_prog.get("currency") or fresh_prog.get("currency")
    fr_cur = fresh_prog.get("currency") or pre_cur
    if match and pre_cur and fr_cur and pre_cur != fr_cur:
        match = False
    if match:
        _amt = f"${float(fr):,.0f}" if _delta is not None else str(fr)
        reason = f"payout {_amt} {fr_cur or 'USD'} matches prescan"
    elif _delta is None:
        reason = f"payout mismatch: prescan {pre} {pre_cur} vs fresh {fr} {fr_cur}"
    else:
        reason = (
            f"payout mismatch: prescan {pre} {pre_cur} vs fresh {fr} {fr_cur} "
            f"(Δ ${_delta:,.2f})"
        )
    return {
        "pass": match,
        "status": "match" if match else "mismatch",
        "reason": reason,
        "prescan": pre,
        "fresh": fr,
    }


def check_rules_unchanged(
    prescan_prog: Dict[str, Any], fresh_prog: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Check 3: bounty rules text unchanged since prescan (sha256). ADVISORY.

    No feed carries rules/policy text, so this leg is skip-when-unavailable:
    status unknown (either side hashless) is explicit and non-blocking. Only
    a proven change (both hashes present and different) or a vanished program
    fails the leg. Rules text is NEVER faked — unknown stays unknown.
    """
    pre_hash = prescan_prog.get("rules_hash") or rules_hash_of(prescan_prog)
    if fresh_prog is None:
        return {
            "pass": False,
            "status": "missing",
            "advisory": True,
            "reason": "program missing from fresh listing",
            "prescan_hash": pre_hash,
            "fresh_hash": None,
        }
    fr_hash = rules_hash_of(fresh_prog)
    if not pre_hash or not fr_hash:
        return {
            "pass": True,
            "status": "unknown",
            "advisory": True,
            "reason": (
                "rules text unavailable (prescan or fresh has none);"
                " advisory leg skipped, unknown does not block verification"
            ),
            "prescan_hash": pre_hash,
            "fresh_hash": fr_hash,
        }
    match = pre_hash == fr_hash
    return {
        "pass": match,
        "status": "match" if match else "mismatch",
        "advisory": True,
        "reason": (
            "rules text unchanged since prescan"
            if match
            else "rules text changed since prescan"
        ),
        "prescan_hash": pre_hash,
        "fresh_hash": fr_hash,
    }


def verify_program(
    prescan_prog: Dict[str, Any],
    fresh_prog: Optional[Dict[str, Any]],
    probe_fn: Optional[ProbeFn] = None,
    timeout: float = 8.0,
    no_cloud: bool = False,
) -> Dict[str, Any]:
    """Run all three checks; verdict is verified iff NO leg blocks.

    scope_live is fail-closed (must pass). payouts_match is tri-state: only
    mismatch/missing block — unknown is explicit and non-blocking. rules is
    advisory skip-when-unavailable: only a proven change or a vanished
    program fails it. A program the feeds can actually describe (live scope,
    unknown payouts, unknown rules) therefore verifies.
    """
    if fresh_prog is None:
        # The program vanished from the fresh listing: a stale snapshot's
        # scope is never probed — fail all three legs explicitly.
        scope: Dict[str, Any] = {
            "pass": False,
            "reason": "program missing from fresh listing",
            "hosts": [],
            "probed": [],
            "skipped": [],
        }
    else:
        scope = check_scope_live(
            fresh_prog, probe_fn=probe_fn, timeout=timeout, no_cloud=no_cloud
        )
    payout = check_payouts_match(prescan_prog, fresh_prog)
    rules = check_rules_unchanged(prescan_prog, fresh_prog)
    verified = bool(scope["pass"] and payout["pass"] and rules["pass"])
    failed = [
        name
        for name, chk in (
            ("scope_live", scope),
            ("payouts_match", payout),
            ("rules_unchanged", rules),
        )
        if not chk["pass"]
    ]
    return {
        "name": prescan_prog.get("name", ""),
        "handle": prescan_prog.get("handle", ""),
        "platform": prescan_prog.get("platform", ""),
        "url": prescan_prog.get("url", ""),
        "score": prescan_prog.get("score", 0) or 0,
        "max_payout_usd": prescan_prog.get("max_payout_usd"),
        "currency": prescan_prog.get("currency", "USD"),
        "verdict": "verified" if verified else "unverified",
        "failed_checks": failed,
        "checks": {
            "scope_live": scope,
            "payouts_match": payout,
            "rules_unchanged": rules,
        },
    }


# ── prescan ─────────────────────────────────────────────────────────────────


def _snapshot_program(prog: Dict[str, Any]) -> Dict[str, Any]:
    scopes = prog.get("structured_scopes", []) or []
    rules_hash = rules_hash_of(prog)
    return {
        "name": prog.get("name", ""),
        "handle": prog.get("handle", ""),
        "platform": prog.get("platform", ""),
        "url": prog.get("url", ""),
        "website": prog.get("website", "") or "",
        "score": prog.get("score", 0) or 0,
        "max_payout_usd": prog.get("max_payout_usd"),
        "currency": prog.get("currency", "USD"),
        "safe_harbor": prog.get("safe_harbor", ""),
        "managed_triage": bool(prog.get("managed_triage", False)),
        "program_kind": prog.get("program_kind", "web2"),
        "first_response_hours": prog.get("first_response_hours"),
        "response_efficiency": prog.get("response_efficiency"),
        "scope_count": len(scopes),
        "structured_scopes": scopes,
        "out_of_scope": list(prog.get("out_of_scope") or []),
        "rules_hash": rules_hash,
        "rules_source": "program.rules_text/policy" if rules_hash else None,
        "trusted": False,
    }


def run_prescan(
    fetch_fn: Optional[FetchFn] = None,
    limit: int = 50,
    sync: bool = False,
    no_cloud: bool = False,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
    allow_public_feed: bool = False,
) -> Dict[str, Any]:
    """Fast Scan4Me sweep → prescan report (raw, untrusted). Returns report.

    Product callers (``fetch_fn is None``) must have an authenticated, fresh
    Scan4Me feed. When that is not true the report is still written with its
    ``feed_trust`` verdict, then :class:`FeedTrustError` is raised so the
    runlog and the artifact both tell the truth. ``allow_public_feed`` is an
    injected-test/embedded escape hatch, never an operator flag.

    The returned dict carries its file path under ``_report_path``.
    Empty fetch is a valid fail-closed outcome for synthetic callers.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"prescan limit must be an int >= 0, got {limit!r}")
    if sync and no_cloud:
        raise ValueError("--sync refused under --no-cloud (offline: local DB only)")
    if sync:
        import oracle_scan4me as bridge

        home = str(bridge.scan4me_home())
        import sys

        if home not in sys.path:
            sys.path.insert(0, home)
        import scan4me as s4m

        try:
            # Auth is the product default. Missing keys fall back inside
            # Scan4Me to public feeds, which the trust gate then rejects.
            s4m.sync_data(refresh=True, use_auth=True)
        except Exception as e:
            raise RuntimeError(f"Scan4Me sync failed: {e}") from e

    if fetch_fn is not None:
        programs = list(fetch_fn())[:limit]
    else:
        import oracle_scan4me as bridge

        programs = bridge.fetch_programs(limit=limit)

    provenance = feed_provenance_block()
    trust = feed_trust_block(provenance, allow_public_feed=allow_public_feed)
    trust["enforced"] = fetch_fn is None

    directory = out_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"prescan_{tag}.json"
    report = {
        "_schema": PRESCAN_SCHEMA,
        "created_utc": _utc_now().isoformat(),
        "trusted": False,
        "source": "scan4me-ranked-db",
        "synced": bool(sync),
        "no_cloud": bool(no_cloud),
        "limit": limit,
        "count": len(programs),
        "programs": [_snapshot_program(p) for p in programs],
        "feed_provenance": provenance,
        "feed_trust": trust,
        "note": "raw prescan output — untrusted until the scan verify pass",
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["_report_path"] = str(path)
    if fetch_fn is None and not trust["ok"]:
        issues = trust.get("issues") or ["unknown feed trust failure"]
        raise FeedTrustError(
            "Scan4Me feed is not authenticated/trusted: "
            + "; ".join(issues)
            + f". Prescan report preserved: {path}",
            report=report,
        )
    return report


# ── feed provenance stamping (#5/#9) ──────────────────────────────────────────


def feed_provenance_block() -> Dict[str, Any]:
    """Scan4Me feed provenance for prescan/scan/handoff stamps.

    Upstream SHA + per-platform status + row counts + age + coverage gaps,
    read live from scan4me.db. Unreadable DB → explicit unavailable marker,
    never a silent omission or a zero-filled guess.
    """
    try:
        import oracle_scan4me as bridge

        home = str(bridge.scan4me_home())
        import sys

        if home not in sys.path:
            sys.path.insert(0, home)
        import scan4me as s4m

        return s4m.feed_provenance()
    except Exception as e:
        return {"unavailable": f"scan4me.db unreadable: {e}"}


class FeedTrustError(RuntimeError):
    """The Scan4Me feed is not authenticated/fresh enough to be truth.

    Carries the rejected prescan report so the caller can preserve/name the
    artifact instead of losing the evidence when the process exits.
    """

    def __init__(self, message: str, report: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.report = report or {}
        self.report_path = str(self.report.get("_report_path") or "")


def feed_trust_block(
    provenance: Optional[Dict[str, Any]] = None,
    *,
    allow_public_feed: bool = False,
) -> Dict[str, Any]:
    """Pure trust verdict for a Scan4Me provenance stamp.

    Product truth must be authenticated and fresh. Only rows whose source
    is exactly ``authenticated`` are trusted; every other counted source
    (``public-file``, live boards/listings, public mirrors, unlabeled, or
    a label invented tomorrow) is public truth and fails closed. Neither
    can a stale snapshot or a failed refresh pass. ``allow_public_feed``
    is an injected-test/embedded escape hatch only — the operator CLI does
    not expose it and never sets it.
    """
    prov = provenance if isinstance(provenance, dict) else {}
    issues: List[str] = []
    warnings: List[str] = []
    if prov.get("unavailable"):
        issues.append(str(prov["unavailable"]))
    if prov.get("refresh_ok") is False:
        issues.append("last Scan4Me refresh failed (refresh_ok=false)")
    age = prov.get("age_hours")
    if prov.get("stale") is True:
        issues.append(f"feed is stale ({age}h old)")
    elif age is None:
        issues.append("feed has no successful sync timestamp")
    platforms = prov.get("platforms") if isinstance(prov.get("platforms"), dict) else {}
    public_rows = sorted(
        str(name)
        for name, entry in platforms.items()
        if isinstance(entry, dict)
        and (entry.get("count") or 0) > 0
        and entry.get("source") != "authenticated"
    )
    public_labels = {
        str(name): str(entry.get("source"))
        for name, entry in platforms.items()
        if str(name) in public_rows and isinstance(entry, dict)
    }
    authenticated = sorted(
        str(name)
        for name, entry in platforms.items()
        if isinstance(entry, dict)
        and (entry.get("count") or 0) > 0
        and entry.get("source") == "authenticated"
    )
    errored = sorted(
        str(name)
        for name, entry in platforms.items()
        if isinstance(entry, dict) and entry.get("status") == "error"
    )
    labeled_public = ", ".join(
        f"{name} ({public_labels.get(name)})" for name in public_rows
    )
    if public_rows and not allow_public_feed:
        issues.append("unauthenticated feed rows: " + labeled_public)
    elif public_rows:
        warnings.append(
            "unauthenticated rows explicitly allowed for this call: "
            + labeled_public
        )
    if not authenticated:
        if allow_public_feed:
            warnings.append("no authenticated platform rows (explicit public override)")
        else:
            issues.append("no authenticated platform rows in the feed")
    if errored:
        issues.append("platform refresh errors: " + ", ".join(errored))
    return {
        "ok": not issues,
        "issues": issues,
        "warnings": warnings,
        "stale": prov.get("stale"),
        "age_hours": age,
        "public_platforms": public_rows,
        "public_sources": public_labels,
        "authenticated_platforms": authenticated,
        "errored_platforms": errored,
        "allow_public_feed": bool(allow_public_feed),
        "overridden": bool(allow_public_feed and public_rows),
    }


def _prescan_trust(prescan: Dict[str, Any]) -> Dict[str, Any]:
    """Trust block for an existing prescan; fail closed when unstamped.

    Older prescans predate the trust field. Their provenance can be
    re-evaluated, but a report with neither a trust block nor provenance
    cannot establish authenticated truth and is rejected.
    """
    trust = prescan.get("feed_trust")
    if isinstance(trust, dict) and "ok" in trust:
        return trust
    prov = prescan.get("feed_provenance")
    if isinstance(prov, dict) and prov:
        return feed_trust_block(prov)
    return {
        "ok": False,
        "issues": ["prescan carries no feed_trust/feed_provenance stamp"],
        "warnings": [],
        "stale": None,
        "age_hours": None,
        "public_platforms": [],
        "authenticated_platforms": [],
        "errored_platforms": [],
        "allow_public_feed": False,
        "overridden": False,
    }


def require_trusted_prescan(prescan: Dict[str, Any]) -> Dict[str, Any]:
    """Return the prescan trust block or raise FeedTrustError.

    Product scan consumes only authenticated, fresh prescans. Synthetic
    callers/tests can call run_scan directly for pure verdict tests.
    """
    trust = _prescan_trust(prescan)
    if not trust.get("ok"):
        issues = trust.get("issues") or ["unknown feed trust failure"]
        raise FeedTrustError(
            "prescan feed is not authenticated/trusted: " + "; ".join(issues)
        )
    return trust


# ── scan (verify pass) ──────────────────────────────────────────────────────


def load_prescan(source: Any) -> Dict[str, Any]:
    """Load a prescan report from a path or pass through a dict."""
    if isinstance(source, dict):
        return source
    return json.loads(Path(source).read_text(encoding="utf-8"))


def latest_report(out_dir: Optional[Path], prefix: str) -> Optional[Path]:
    """Newest ``<prefix>_*.json`` in a reports dir, or None when absent."""
    directory = out_dir or REPORTS_DIR
    if not directory.is_dir():
        return None
    cands = sorted(directory.glob(f"{prefix}_*.json"))
    return cands[-1] if cands else None


def _default_resolve(name_or_handle: str) -> Optional[Dict[str, Any]]:
    import oracle_scan4me as bridge

    return bridge.resolve(name_or_handle)


def oracle_rescan(
    prog: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Oracle-owned re-scan for the verify pass.

    HackerOne programs are fetched from HackerOne's own authenticated Hacker
    API with Oracle's credentials, never from Scan4Me's DB copy. Other
    platforms have no Oracle-side API adapter yet and fall back to the bridge,
    explicitly marked ``independent: false``. HackerOne credentials missing or
    rejected raise (H1AuthError) — an auth failure must never masquerade as a
    vanished program.
    """
    platform = str(prog.get("platform") or "").strip()
    handle = str(prog.get("handle") or prog.get("name") or "").strip()
    key = handle or str(prog.get("name") or "")
    if platform.lower() == "hackerone":
        import oracle_h1_api as h1

        fresh = h1.fetch_program(handle)
        if fresh is None:
            return None, {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "platform": platform,
                "handle": handle,
                "found": False,
            }
        meta = fresh.pop("_oracle_rescan", {})
        meta.setdefault("source", "hackerone-api-authenticated")
        meta["independent"] = True
        # OOS is safety-critical: union the platform's explicit fresh OOS with
        # known snapshot OOS. Never union in-scope assets (that would revive
        # revoked scope).
        known_oos = {
            str(x).strip() for x in (prog.get("out_of_scope") or []) if str(x).strip()
        }
        fresh_oos = {
            str(x).strip() for x in (fresh.get("out_of_scope") or []) if str(x).strip()
        }
        if known_oos - fresh_oos:
            fresh["out_of_scope"] = sorted(known_oos | fresh_oos)
            meta["out_of_scope_union"] = sorted(known_oos - fresh_oos)
        return fresh, meta
    fresh = _default_resolve(key) if key else None
    return fresh, {
        "source": "scan4me-db" if fresh is not None else "missing",
        "independent": False,
        "platform": platform,
        "handle": handle,
    }


def run_scan(
    prescan: Any,
    resolve_fn: Optional[ResolveFn] = None,
    probe_fn: Optional[ProbeFn] = None,
    timeout: float = 8.0,
    no_cloud: bool = False,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
    require_trusted_prescan: bool = False,
    rescan_fn: Optional[RescanFn] = None,
) -> Dict[str, Any]:
    """Oracle verification pass over a prescan → scan report with verdicts.

    Product scan passes ``require_trusted_prescan=True`` and
    ``rescan_fn=oracle_rescan``: a public-file/stale prescan can never be
    laundered into a verified handoff, and HackerOne scope must come from
    Oracle's own authenticated API rather than Scan4Me's DB copy. Synthetic
    callers/tests may leave both unset for pure verdict fixtures.
    """
    report_in = load_prescan(prescan)
    if not isinstance(report_in.get("programs"), list):
        raise ValueError("prescan report has no 'programs' list")
    if require_trusted_prescan:
        prescan_trust = _prescan_trust(report_in)
        if not prescan_trust.get("ok"):
            issues = prescan_trust.get("issues") or ["unknown feed trust failure"]
            raise FeedTrustError(
                "prescan feed is not authenticated/trusted: "
                + "; ".join(issues)
                + f". Prescan: {report_in.get('_report_path', '')}"
            )
    provenance = feed_provenance_block()
    feed_trust = feed_trust_block(provenance)
    feed_trust["enforced"] = bool(require_trusted_prescan)
    if require_trusted_prescan and not feed_trust["ok"]:
        issues = feed_trust.get("issues") or ["unknown feed trust failure"]
        raise FeedTrustError(
            "current Scan4Me feed is not authenticated/trusted: " + "; ".join(issues)
        )
    resolve = resolve_fn or _default_resolve
    verdicts: List[Dict[str, Any]] = []
    for snap in report_in["programs"]:
        key = snap.get("handle") or snap.get("name") or ""
        rescan_meta: Dict[str, Any] = {
            "source": "scan4me-db",
            "independent": False,
        }
        if rescan_fn is not None:
            # Product path: an auth/transport failure is a failed scan, not a
            # vanished program. Never convert it into a silent fresh=None.
            try:
                fresh, rescan_meta = rescan_fn(snap)
            except Exception as exc:
                raise RuntimeError(
                    f"Oracle re-scan failed for {key or '<unknown>'}: {exc}"
                ) from exc
        else:
            try:
                fresh = resolve(key) if key else None
            except Exception:
                fresh = None
        verdict = verify_program(
            snap, fresh, probe_fn=probe_fn, timeout=timeout, no_cloud=no_cloud
        )
        verdict["oracle_rescan"] = rescan_meta
        # Keep the exact scope snapshot the verify pass used. Deep-dive must
        # consume this, not re-resolve the Scan4Me DB after an H1 re-scan.
        verdict["_fresh"] = fresh if isinstance(fresh, dict) else None
        verdicts.append(verdict)
    verified = [v for v in verdicts if v["verdict"] == "verified"]
    rescan_metas = [v.get("oracle_rescan") or {} for v in verdicts]
    independent_count = sum(
        1 for meta in rescan_metas if meta.get("independent") is True
    )
    if not rescan_metas:
        rescan_mode = "none"
    elif independent_count == len(rescan_metas):
        rescan_mode = "independent"
    elif independent_count:
        rescan_mode = "mixed"
    else:
        rescan_mode = "scan4me-db"
    rescan_sources = sorted(
        {str(meta.get("source")) for meta in rescan_metas if meta.get("source")}
    )
    directory = out_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"scan_{tag}.json"
    report = {
        "_schema": SCAN_SCHEMA,
        "created_utc": _utc_now().isoformat(),
        "prescan_report": str(report_in.get("_report_path", "")),
        "no_cloud": bool(no_cloud),
        "count": len(verdicts),
        "verified_count": len(verified),
        "verdicts": verdicts,
        "feed_provenance": provenance,
        "feed_trust": feed_trust,
        "oracle_rescan": {
            "mode": rescan_mode,
            "independent": bool(rescan_metas)
            and independent_count == len(rescan_metas),
            "programs": len(rescan_metas),
            "independent_programs": independent_count,
            "sources": rescan_sources,
        },
        "note": "only verdict=verified programs may proceed to deep-dive/handoff",
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["_report_path"] = str(path)
    return report


# ── -N deep-dive (verified only) + P12 handoff ───────────────────────────────


def _deep_dive_for(
    prog: Dict[str, Any],
    verdict: Dict[str, Any],
    fresh: bool = False,
    fresh_source: str = "",
) -> Dict[str, Any]:
    scopes = prog.get("structured_scopes", []) or []
    sources = ["scan4me:programs+assets"]
    if fresh:
        sources.append(fresh_source or "deep-dive:fresh-resolve")
    return {
        "assets": scopes,
        "out_of_scope": list(prog.get("out_of_scope") or []),
        "company": {
            "name": prog.get("name", ""),
            "handle": prog.get("handle", ""),
            "platform": prog.get("platform", ""),
            "program_url": prog.get("url", ""),
            "website": prog.get("website", "") or "",
            "safe_harbor": prog.get("safe_harbor", ""),
            "managed_triage": bool(prog.get("managed_triage", False)),
            "program_kind": prog.get("program_kind", "web2"),
            "first_response_hours": prog.get("first_response_hours"),
            "response_efficiency": prog.get("response_efficiency"),
        },
        "resources": {
            "program_url": prog.get("url", ""),
            "platform": prog.get("platform", ""),
            "max_payout_usd": prog.get("max_payout_usd"),
            "currency": prog.get("currency", "USD"),
            "scope_count": len(scopes),
        },
        "sources": sources,
        "checks": verdict.get("checks", {}),
    }


def _matches_site(prog: Dict[str, Any], site: str) -> bool:
    """Precise --sites matching: exact on name/handle, domain-boundary on URLs.

    Pure substring matching ("acm" hits "Acme", "evil-acme.com" hits
    "acme.com") caused false-positive deep-dives, so:
      - ``name`` / ``handle`` must equal the site (case-insensitive);
      - ``url`` / ``website`` compare by host: equal, or one a
        domain-boundary parent of the other (``app.acme.com`` matches a
        program on ``acme.com``, but ``notacme.com`` never matches).
    """
    needle = (site or "").strip().lower().rstrip(".")
    if not needle:
        return False
    for key in ("name", "handle"):
        val = prog.get(key)
        if isinstance(val, str) and val.strip().lower() == needle:
            return True
    needle_host = _strip_to_host(needle)
    if not needle_host:
        return False
    for key in ("url", "website"):
        val = prog.get(key)
        if not isinstance(val, str) or not val.strip():
            continue
        host = _strip_to_host(val)
        if not host:
            continue
        if needle_host == host:
            return True
        if host.endswith("." + needle_host) or needle_host.endswith("." + host):
            return True
    return False


def select_deep_dive(
    scan_report: Dict[str, Any],
    prescan_programs: Optional[List[Dict[str, Any]]] = None,
    top_n: Optional[int] = None,
    sites: Optional[List[str]] = None,
    resolve_fn: Optional[ResolveFn] = None,
) -> Dict[str, Any]:
    """Pick verified programs for deep-dive. Named sites override the count.

    Only ``verdict == verified`` entries are ever selected — unverified
    programs (including named ones) land in ``excluded`` and never proceed.
    Without ``top_n`` or ``sites``, ALL verified programs are selected,
    ranked by score (P12 owns ``default_count`` scheduling, not P11).

    When ``resolve_fn`` is given, every selected program is re-resolved at
    deep-dive time and its assets/company/resources come from that FRESH
    listing — a stale prescan snapshot can never feed deep-dive. A program
    missing from (or erroring on) the fresh listing is excluded fail-closed
    with a ``deep-dive-stale`` reason instead of falling back to snapshot
    data. Without ``resolve_fn`` the prescan snapshot is used (legacy path;
    callers that can reach the bridge should always pass a resolver).
    """
    if top_n is not None and (
        isinstance(top_n, bool) or not isinstance(top_n, int) or top_n < 0
    ):
        raise ValueError(f"-N/--top-n must be an int >= 0, got {top_n!r}")
    by_key: Dict[str, Dict[str, Any]] = {}
    for prog in prescan_programs or []:
        for key in (prog.get("handle") or "", prog.get("name") or ""):
            if key and key not in by_key:
                by_key[key] = prog

    verified = [
        v for v in scan_report.get("verdicts", []) if v.get("verdict") == "verified"
    ]
    verified.sort(key=lambda v: (v.get("score", 0) or 0), reverse=True)

    site_list = [s.strip() for s in (sites or []) if s and s.strip()]
    excluded: List[Dict[str, Any]] = []
    if site_list:
        picked: List[Dict[str, Any]] = []

        def _site_hit(verdict: Dict[str, Any], site: str) -> bool:
            if _matches_site(verdict, site):
                return True
            snap = by_key.get(verdict.get("handle") or verdict.get("name") or "", {})
            return _matches_site(snap, site)

        for site in site_list:
            match = next((v for v in verified if _site_hit(v, site)), None)
            if match is not None:
                if match not in picked:
                    picked.append(match)
                continue
            # No verified hit: name the reason — unverified match, or nothing.
            unverified_hit = next(
                (
                    v
                    for v in scan_report.get("verdicts", [])
                    if v.get("verdict") != "verified" and _site_hit(v, site)
                ),
                None,
            )
            if unverified_hit is not None:
                excluded.append(
                    {
                        "site": site,
                        "program": unverified_hit.get("name", ""),
                        "reason": (
                            "program is unverified "
                            f"(failed: {','.join(unverified_hit.get('failed_checks', []))});"  # noqa: E501
                            " unverified programs never proceed"
                        ),
                    }
                )
            else:
                excluded.append({"site": site, "reason": "no verified program matches"})
        selected = picked
    elif top_n is not None:
        selected = verified[:top_n]
    else:
        selected = verified

    ranked: List[Dict[str, Any]] = []
    rank = 0
    for verdict in selected:
        snap = by_key.get(verdict.get("handle") or verdict.get("name") or "", {})
        merged = {**snap, **verdict}
        fresh_used = False
        fresh_source = ""
        embedded_fresh = verdict.get("_fresh")
        if isinstance(embedded_fresh, dict):
            # The verify pass already fetched this scope (H1's authenticated
            # API or the bridge). Reuse it byte-for-byte; never re-resolve
            # through a stale DB after an independent re-scan.
            merged = {**snap, **embedded_fresh, **verdict}
            fresh_used = True
            fresh_source = str(
                (verdict.get("oracle_rescan") or {}).get("source") or "scan-rescan"
            )
            fresh_source = f"scan-rescan:{fresh_source}"
        elif resolve_fn is not None:
            key = verdict.get("handle") or verdict.get("name") or ""
            try:
                fresh_prog = resolve_fn(key) if key else None
            except Exception:
                fresh_prog = None
            if not isinstance(fresh_prog, dict):
                excluded.append(
                    {
                        "site": verdict.get("name", ""),
                        "program": verdict.get("name", ""),
                        "reason": (
                            "deep-dive-stale: program missing from the fresh"
                            " listing at deep-dive time; prescan snapshot"
                            " not used (fail-closed)"
                        ),
                    }
                )
                continue
            merged = {**snap, **fresh_prog, **verdict}
            fresh_used = True
            fresh_source = "deep-dive:fresh-resolve"
        rank += 1
        ranked.append(
            {
                "rank": rank,
                "name": verdict.get("name", ""),
                "handle": verdict.get("handle", ""),
                "platform": verdict.get("platform", ""),
                "url": verdict.get("url", ""),
                "score": verdict.get("score", 0) or 0,
                "max_payout_usd": verdict.get("max_payout_usd"),
                "currency": verdict.get("currency", "USD"),
                "verdict": "verified",
                "checks": verdict.get("checks", {}),
                "oracle_rescan": verdict.get("oracle_rescan", {}),
                "deep_dive": _deep_dive_for(
                    merged,
                    verdict,
                    fresh=fresh_used,
                    fresh_source=fresh_source,
                ),
            }
        )
    return {
        "ranked_verified": ranked,
        "excluded_named": excluded,
        "oracle_rescan": scan_report.get("oracle_rescan", {}),
    }


def write_handoff(
    selection: Dict[str, Any],
    scan_report_path: str = "",
    prescan_report_path: str = "",
    top_n: Optional[int] = None,
    sites: Optional[List[str]] = None,
    no_cloud: bool = False,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Write the P12 handoff file (ranked-verified list). Returns the payload.

    The payload carries its file path under ``_report_path``. An empty
    verified set still writes a file (fail-closed empty), never nothing.
    """
    directory = out_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"intake_ranked_verified_{tag}.json"
    provenance = feed_provenance_block()
    feed_trust = feed_trust_block(provenance)
    feed_trust["enforced"] = True
    payload = {
        "_schema": HANDOFF_SCHEMA,
        "created_utc": _utc_now().isoformat(),
        "prescan_report": prescan_report_path,
        "scan_report": scan_report_path,
        "no_cloud": bool(no_cloud),
        "selector": {"top_n": top_n, "sites": sites or None},
        "ranked_verified": selection.get("ranked_verified", []),
        "excluded_named": selection.get("excluded_named", []),
        "oracle_rescan": selection.get("oracle_rescan", {}),
        "feed_provenance": provenance,
        "feed_trust": feed_trust,
        "note": "unverified programs never appear here; see the scan report",
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    payload["_report_path"] = str(path)
    return payload


# ── workspace downloads for the verified selection ───────────────────────────


def _download_assets_list(raw: Any, *, field: str) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [line.strip() for line in raw.splitlines() if line.strip()]
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list or string, got {type(raw).__name__}")
    out: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
        elif isinstance(item, str) and item.strip():
            out.append({"asset_identifier": item.strip()})
        else:
            raise ValueError(f"{field} entries must be objects or strings")
    return out


def _download_oos_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [line.strip() for line in raw.splitlines() if line.strip()]
    if not isinstance(raw, list):
        raise ValueError(
            f"out_of_scope must be a list or string, got {type(raw).__name__}"
        )
    out: List[str] = []
    for item in raw:
        if isinstance(item, dict):
            ident = item.get("asset_identifier") or item.get("identifier") or ""
            if str(ident).strip():
                out.append(str(ident).strip())
        elif isinstance(item, str) and item.strip():
            out.append(item.strip())
        else:
            raise ValueError("out_of_scope entries must be objects or strings")
    return out


def _prog_for_download(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Map a ranked-verified handoff entry to the cache-shaped ``prog``
    dict the bulk downloader consumes (scopes at ``structured_scopes``,
    company fields flat). Passing the raw entry would silently degrade
    to scope-reintake plus a program-page-only download."""
    if not isinstance(entry, dict):
        raise TypeError(
            f"ranked_verified entry must be an object, got {type(entry).__name__}"
        )
    deep = entry.get("deep_dive")
    if deep is None:
        deep = {}
    if not isinstance(deep, dict):
        raise ValueError("deep_dive must be an object")
    company = deep.get("company") or {}
    if not isinstance(company, dict):
        raise ValueError("deep_dive.company must be an object")
    if "assets" in deep:
        assets_raw = deep.get("assets")
    elif "structured_scopes" in entry:
        assets_raw = entry.get("structured_scopes")
    else:
        raise ValueError("entry has no deep_dive.assets or structured_scopes")
    assets = _download_assets_list(assets_raw, field="deep_dive.assets")
    oos_raw = (
        deep.get("out_of_scope")
        if "out_of_scope" in deep
        else entry.get("out_of_scope")
    )
    oos = _download_oos_list(oos_raw)
    name = str(entry.get("name") or company.get("name", "") or "").strip()
    platform = str(entry.get("platform") or company.get("platform", "") or "").strip()
    if not name or not platform:
        raise ValueError("entry requires non-empty name and platform for a workspace")
    return {
        "name": name,
        "handle": entry.get("handle") or company.get("handle", ""),
        "platform": platform,
        "url": entry.get("url") or company.get("program_url", ""),
        "website": company.get("website", "") or entry.get("website", "") or "",
        "safe_harbor": company.get("safe_harbor", ""),
        "managed_triage": bool(company.get("managed_triage", False)),
        "program_kind": company.get("program_kind", "web2"),
        "first_response_hours": company.get("first_response_hours"),
        "response_efficiency": company.get("response_efficiency"),
        "max_payout_usd": entry.get("max_payout_usd"),
        "currency": entry.get("currency", "USD"),
        "structured_scopes": assets,
        "out_of_scope": oos,
    }


DownloadFn = Callable[[Dict[str, Any]], Dict[str, Any]]


def download_selected_workspaces(
    selection: Dict[str, Any],
    download_fn: Optional[DownloadFn] = None,
    cdp_port: int = 9227,
    take_screenshot: bool = False,
) -> Dict[str, Any]:
    """Download one workspace per ranked-verified entry in ``selection``.

    Each entry gains ``workspace: {path, status, detail}`` where status is
    ``present`` (manifest already on disk — skipped), the downloader's own
    status (``downloaded``/``empty``), or ``error``. A failure on one
    program never aborts the rest, and unverified/excluded programs are
    never touched (they are not in ``ranked_verified`` by construction).
    """
    from oracle_bulk_download import (
        already_downloaded,
        download_one,
        workspace_base_for,
    )

    fn: DownloadFn = download_fn or (
        lambda prog: download_one(
            prog, cdp_port=cdp_port, take_screenshot=take_screenshot
        )
    )
    if not isinstance(selection, dict):
        raise ValueError(f"selection must be an object, got {type(selection).__name__}")
    ranked = selection.get("ranked_verified", [])
    if ranked is None:
        ranked = []
    if not isinstance(ranked, list):
        raise ValueError("selection.ranked_verified must be a list")
    for entry in ranked:
        base = ""
        try:
            if not isinstance(entry, dict):
                raise TypeError(
                    f"ranked_verified entry must be an object, got {type(entry).__name__}"
                )
            verdict = entry.get("verdict")
            if verdict is not None and verdict != "verified":
                entry["workspace"] = {
                    "path": "",
                    "status": "skipped",
                    "detail": f"not verified (verdict={verdict!r})",
                }
                continue
            prog = _prog_for_download(entry)
            base = str(workspace_base_for(prog))
            if already_downloaded(prog):
                entry["workspace"] = {
                    "path": base,
                    "status": "present",
                    "detail": "manifest already on disk",
                }
                continue
            res = fn(prog) or {}
            entry["workspace"] = {
                "path": base,
                "status": str(res.get("status", "unknown")),
                "detail": str(res.get("detail", "")),
            }
        except Exception as exc:  # per-program isolation; status recorded
            if isinstance(entry, dict):
                entry["workspace"] = {
                    "path": base,
                    "status": "error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            else:
                selection.setdefault("download_errors", []).append(
                    f"{type(exc).__name__}: {exc}"
                )
    return selection
