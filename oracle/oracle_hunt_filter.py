#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: program_qualifies, apply_hunt_filter, variant_sweep_plan, load_hunt_filter_config  # noqa: E501
# TOPICS: none
"""Oracle hunt filter: fast-money scoping for the hunt phase.

Two-phase fast-money design (Alex's rule):

  Phase 1 — the hunt downloads ALL of a program's assets, but the mindset
  (system prompt), scope gate, and recon only ever see the assets that pass
  the hunt_filter. A 30-asset program with 1 new asset hunts that 1 asset.
  The model cannot cite, probe, or reason about the other 29 because they
  are not in its world — going outside is unrepresentable, not discouraged.

  Phase 2 — variant sweep: after a finding is CONFIRMED on a filtered
  asset, the remaining in-scope assets are re-hunted for the SAME issue
  class (the confirmed check, retargeted). One bug becomes N reports.

All functions here are pure (no network, no disk) so they are unit-testable.
"""
from __future__ import annotations

import copy
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

HERE = Path(__file__).resolve().parent

try:
    from oracle_triage import load_config as _load_triage_config
    from oracle_triage import parse_dt as _parse_dt
except ImportError:  # pragma: no cover — standalone fallback
    _load_triage_config = None  # type: ignore
    _parse_dt = None  # type: ignore


class HuntFilterEmpty(Exception):
    """Raised when the asset filter matches zero assets and on_empty=halt."""


HUNT_FILTER_DEFAULTS: Dict = {
    "mode": "all",
    "new_asset_max_age_days": 30,
    "min_payout_usd": 0,
    "require_fast_triage": False,
    "max_reports": None,
    "new_company_max_age_days": None,
    "on_empty": "halt",
    "variant_sweep": False,
}


def load_hunt_filter_config(config_path: Optional[Path] = None) -> Dict:
    """Load the hunt_filter block from triage.yaml (with safe defaults)."""
    cfg: Dict = {}
    path = config_path or (HERE / "triage.yaml")
    if _load_triage_config is not None and path.exists():
        try:
            cfg = _load_triage_config(path) or {}
        except Exception:
            cfg = {}
    hf = dict(HUNT_FILTER_DEFAULTS)
    block = cfg.get("hunt_filter") or {}
    if isinstance(block, dict):
        hf.update(block)
    return hf


# ── helpers ───────────────────────────────────────────────────────────────
def _norm_ident(ident: str) -> str:
    # Trailing dots ("a.com.") never survive DNS — normalize them away so
    # host/ident equality checks cannot miss (B9).
    return (ident or "").strip().lower().rstrip(".")


_HOST_RE = re.compile(r"https?://(?:[^/@\s]+@)?(\[[^\]]+\]|[^/'\"\s:]+)")
_PORT_RE = re.compile(r"https?://(?:[^/@\s]+@)?(?:\[[^\]]+\]|[^/'\"\s:]+):(\d+)")


def _extract_host(text: str) -> Optional[str]:
    """First http(s) host found in a check command, else None.

    Skips userinfo (http://user:pass@host/ → host, not user) and strips
    brackets from IPv6 literals. Scheme match stays lowercase-only on
    purpose: an uppercase scheme means "not a URL we understand" and the
    check is skipped fail-safe rather than mis-parsed.
    """
    m = _HOST_RE.search(text or "")
    if not m:
        return None
    host = m.group(1).lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # Trailing dots never survive DNS — strip so host equality holds (B9).
    host = host.rstrip(".")
    return host or None


def _extract_port(text: str) -> str:
    """Port from the first http(s) authority in text, "" when absent."""
    m = _PORT_RE.search(text or "")
    return m.group(1) if m else ""


def _asset_host(scope: Dict) -> Optional[str]:
    """Best-effort web host for a scope record (URL or bare domain)."""
    ident = (scope.get("asset_identifier") or "").strip()
    if not ident:
        return None
    host = _extract_host(ident)
    if host:
        return host
    # Bare domain (no scheme, no path, no spaces)?
    if re.fullmatch(r"[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.?(:\d+)?", ident.lower()):
        return ident.lower().split(":")[0].rstrip(".")  # B9: trailing dot
    return None


def _eligible(scope: Dict) -> bool:
    return bool(
        scope.get("eligible_for_submission", True)
        and scope.get("eligible_for_bounty", True)
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _num(hf: Dict, key: str, default=None) -> Optional[float]:
    """Coerce a numeric hunt_filter config value (B2).

    YAML users quote things; a quoted "10000" must not die with a bare
    TypeError deep in a comparison. Non-numeric values raise a ValueError
    that names the key.
    """
    v = hf.get(key, default)
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        raise ValueError(f"hunt_filter.{key} must be numeric, got {v!r}")


# ── program gates ─────────────────────────────────────────────────────────
def program_qualifies(prog: Dict, hf: Dict) -> Tuple[bool, List[str]]:
    """Program-level fast-money gates. Returns (ok, [failure reasons])."""
    reasons: List[str] = []

    min_payout = _num(hf, "min_payout_usd", 0) or 0
    payout = prog.get("max_payout_usd") or prog.get("max_payout") or 0
    try:
        payout = float(payout)
    except (TypeError, ValueError):
        payout = 0
    if payout < min_payout:
        reasons.append(f"max payout ${payout:,.0f} < min_payout_usd ${min_payout:,.0f}")

    fast_triage_val = prog.get("fast_triage")
    if fast_triage_val is None:
        fast_triage_val = prog.get("managed_triage")
    if hf.get("require_fast_triage") and fast_triage_val is not True:
        reasons.append("require_fast_triage set but program fast_triage is not true")

    max_reports = _num(hf, "max_reports", None)
    if max_reports is not None:
        rc = prog.get("reports_count")
        # Unknown report count (non-HackerOne platforms don't expose it) passes
        # through — reject only when the count is KNOWN and exceeds the limit.
        # Matches oracle_programs.filter_programs (CLI path). Previously a null
        # count was rejected, silently blocking every non-HackerOne platform.
        if rc is not None and rc > max_reports:
            reasons.append(f"reports_count {rc} > max_reports {max_reports:g}")

    company_days = _num(hf, "new_company_max_age_days", None)
    if company_days:
        launched = _parse_dt(prog.get("launched_at")) if _parse_dt is not None else None
        if launched is None:
            reasons.append(
                f"new_company_max_age_days={company_days:g} but launched_at unknown"
            )
        elif (_now() - launched).days > company_days:
            reasons.append(
                f"company launched {(_now() - launched).days}d ago "
                f"> new_company_max_age_days {company_days:g}"
            )

    return (not reasons, reasons)


# ── asset filter (phase 1) ────────────────────────────────────────────────
def apply_hunt_filter(prog: Dict, hf: Dict) -> Dict:
    """Return a filtered COPY of prog whose structured_scopes pass the filter.

    The returned dict carries prog["_hunt_filter"] metadata:
      mode, kept, dropped, kept_idents (normalized), kept_hosts.

    The scope/targets TEXT fields are rewritten to the kept idents (C1).
    The gate, recon target derivation, and every other consumer parse those
    text fields — leaving them verbatim would re-admit filtered-out assets
    through the "deterministic" gate. structured_scopes is the source of
    truth; the text fields mirror it. out_of_scope text is left verbatim
    (a denylist — keeping it whole is fail-safe).

    Raises HuntFilterEmpty when nothing matches and on_empty=halt.
    Raises ValueError on unknown mode/on_empty (fail-closed, never widen).
    """

    def _cfg_str(key: str, default: str, allowed: tuple) -> str:
        v = hf.get(key)
        if v is None:
            return default
        if isinstance(v, bool):
            # B2c: a YAML boolean (e.g. `on_empty: true`) is never valid
            # here — fail closed with a clear error, not AttributeError.
            raise ValueError(
                f"hunt_filter.{key} must be a string, got boolean {v!r} "
                f"(want one of: {', '.join(allowed)})"
            )
        v = str(v).strip().lower()
        if v not in allowed:
            raise ValueError(
                f"unknown hunt_filter.{key}: {v!r} (want {'|'.join(allowed)})"
            )
        return v

    mode = _cfg_str("mode", "all", ("new_only", "all"))
    on_empty = _cfg_str("on_empty", "halt", ("halt", "fall_back_to_all"))
    out = copy.deepcopy(prog)
    scopes = out.get("structured_scopes")
    if not isinstance(scopes, list):
        scopes = []

    future_dated: List[str] = []
    if mode == "new_only":
        max_age = _num(hf, "new_asset_max_age_days", 30) or 30
        now = _now()
        cutoff = now - timedelta(days=max_age)
        kept: List[Dict] = []
        for s in scopes:
            if not isinstance(s, dict):
                continue
            first_seen = (
                _parse_dt(s.get("first_seen")) if _parse_dt is not None else None
            )
            # Unknown age is EXCLUDED: we cannot prove it is new.
            if first_seen is not None and first_seen >= cutoff:
                if first_seen > now + timedelta(days=1):
                    # Data error, not a new asset — but fail OPEN toward
                    # hunting (a skewed clock shouldn't hide a target).
                    # Flag loudly so the bad timestamp gets fixed.
                    ident = _norm_ident(s.get("asset_identifier", "")) or "?"
                    future_dated.append(f"{ident} (first_seen={s.get('first_seen')})")
                    print(
                        f"WARNING: hunt filter: asset {ident} has a future "
                        f"first_seen ({s.get('first_seen')}) — treating as "
                        f"new (fail-open), but the timestamp is a data error",
                        file=sys.stderr,
                    )
                s["_hunt_new"] = True
                kept.append(s)
    else:  # mode == "all"
        kept = [s for s in scopes if isinstance(s, dict)]

    kept_idents: Set[str] = set()
    kept_hosts: Set[str] = set()
    for s in kept:
        ident = _norm_ident(s.get("asset_identifier", ""))
        if ident:
            kept_idents.add(ident)
        host = _asset_host(s)
        if host:
            kept_idents.add(host)
            kept_hosts.add(host)

    if not kept:
        if on_empty == "halt":
            raise HuntFilterEmpty(
                f"hunt filter mode={mode!r} matched 0 of {len(scopes)} assets — "
                "refusing to hunt (on_empty=halt). Re-intake scope to stamp "
                "first_seen, or set hunt_filter.mode: all."
            )
        # fall_back_to_all: explicit operator opt-in to widen scope
        kept = [s for s in scopes if isinstance(s, dict)]
        kept_idents = {_norm_ident(s.get("asset_identifier", "")) for s in kept}
        kept_hosts = {
            host for host in (_asset_host(s) for s in kept) if host is not None
        }

    out["structured_scopes"] = kept
    # C1: mirror the kept idents into the scope/targets text fields so every
    # consumer that parses program text (scope gate, recon target derivation)
    # sees exactly the hunt scope — never the full program scope. Original
    # ident strings are kept verbatim (no normalization: app IDs and paths
    # can be case-sensitive; the gate normalizes when compiling patterns).
    kept_lines = [(s.get("asset_identifier") or "").strip() for s in kept]
    kept_lines = [entry for entry in kept_lines if entry]
    if isinstance(out.get("scope"), str):
        out["scope"] = "\n".join(kept_lines)
    elif isinstance(out.get("scope"), list):
        out["scope"] = list(kept_lines)
    if isinstance(out.get("targets"), str):
        out["targets"] = "\n".join(kept_lines)
    elif isinstance(out.get("targets"), list):
        out["targets"] = list(kept_lines)
    out["_hunt_filter"] = {
        "mode": mode,
        "kept": len(kept),
        "dropped": len(scopes) - len(kept),
        "kept_idents": sorted(kept_idents),
        "kept_hosts": sorted(kept_hosts),
        "future_first_seen": future_dated,
    }
    return out


# ── variant sweep plan (phase 2) ──────────────────────────────────────────
def _retarget_check(
    check: str, orig_host: str, orig_port: str, new_host: str, new_port: str
) -> str:
    """Rewrite a check's URL authority from (orig_host, orig_port) to
    (new_host, new_port). Case-insensitive, authority-only, first match.

    Only the authority component is rewritten — the same hostname appearing
    in a path or query string is data, not the target, and is left alone
    (B7). An uppercase host in the check still matches (B3); userinfo and
    IPv6-literal brackets are tolerated. Returns the check unchanged when
    no authority match is found (the caller skips such plans rather than
    firing the original check at the wrong asset).
    """
    esc = re.escape(orig_host)
    host_pat = r"(?:\[" + esc + r"\]|" + esc + r")"
    pat = re.compile(
        r"(?i)(://(?:[^/@\s]+@)?)" + host_pat + r"(:\d+)?(?=[/\"'\s?#\]]|$)"
    )
    authority = new_host + (":" + new_port if new_port else "")

    def _sub(m: "re.Match") -> str:
        return m.group(1) + authority

    new_check, n = pat.subn(_sub, check, count=1)
    return new_check


class SweepPlan(list):
    """A variant-sweep plan that behaves exactly like a list of plan dicts
    but also carries a machine-readable diagnosis of what was skipped and
    why the plan is empty (when it is). Lets callers distinguish "no
    confirmed parents" from "no remaining assets" from "no retargetable
    checks" instead of printing one ambiguous message."""

    diagnosis: Dict[str, Any]


def variant_sweep_plan(
    confirmed: Dict, full_prog: Dict, hunt_prog: Dict, hf: Dict
) -> List[Dict]:
    """Build "same bug elsewhere" probes for assets outside the phase-1 scope.

    confirmed: {seam_n: {"seam":..., "check":..., "confirmed": bool, ...}}
               (the verify_seams result dict)
    full_prog: the unfiltered program (remaining assets live here)
    hunt_prog: the filtered program (its _hunt_filter.kept_idents are skipped)

    Returns a SweepPlan (a list) of plan dicts:
      {parent_seam, parent_mindset, claim, asset_ident, asset_host, check,
       original_host, original_check}
    with .diagnosis = {confirmed_parents, remaining_assets,
      retargetable_checks, skipped_static, skipped_same_origin}.
    Findings whose check has no retargetable http(s) host (static code
    findings like "review file:line") are skipped — counted in the
    diagnosis, not silently absent.
    """
    hf_meta = (hunt_prog or {}).get("_hunt_filter") or {}
    if not hf_meta:
        # B5: without the phase-1 kept set we would re-probe already-hunted
        # assets as "variants". Fail closed instead of guessing.
        raise ValueError(
            "variant_sweep_plan requires hunt_prog with _hunt_filter metadata "
            "(pass the filtered program from apply_hunt_filter)"
        )
    kept_idents = set(hf_meta.get("kept_idents") or [])

    # Candidate remaining assets: eligible, in-scope, not hunted in phase 1,
    # and addressable as a web host (host-swappable checks only).
    # Deduped by (host, port): two idents on one origin get one probe (B6).
    remaining: List[Tuple[str, str, str]] = []  # (ident, host, port)
    seen: Set[str] = set()
    for s in full_prog.get("structured_scopes") or []:
        if not isinstance(s, dict):
            continue
        ident = _norm_ident(s.get("asset_identifier", ""))
        if not ident or ident in kept_idents or ident in seen:
            continue
        if not _eligible(s):
            continue
        host = _asset_host(s)
        if not host or host in kept_idents:
            continue
        port = _extract_port(s.get("asset_identifier", ""))
        origin = f"{host}:{port}"
        if origin in seen:
            continue
        seen.add(ident)
        seen.add(origin)
        remaining.append((s.get("asset_identifier", "").strip(), host, port))

    plans: List[Dict] = []
    confirmed_parents = 0
    retargetable_checks = 0
    skipped_static = 0
    skipped_same_origin = 0
    for n, c in (confirmed or {}).items():
        if not isinstance(c, dict) or not c.get("confirmed"):
            continue
        confirmed_parents += 1
        check = (c.get("check") or "").strip()
        if not check:
            skipped_static += 1
            continue
        orig_host = _extract_host(check)
        if not orig_host:
            skipped_static += 1
            continue  # static/code finding — no host to retarget; skip
        retargetable_checks += 1
        orig_port = _extract_port(check)
        seam = c.get("seam") or {}
        for ident, host, port in remaining:
            if (host, port) == (orig_host, orig_port):
                skipped_same_origin += 1
                continue
            new_check = _retarget_check(check, orig_host, orig_port, host, port)
            if new_check == check:
                # Authority did not match (should be unreachable given the
                # host came from this check) — never fire the original
                # check and misattribute it to another asset.
                continue
            plans.append(
                {
                    "parent_seam": n,
                    "parent_mindset": seam.get("mindset") or "",
                    "claim": seam.get("claim_type") or seam.get("reflex") or "?",
                    "asset_ident": ident,
                    "asset_host": host,
                    "check": new_check,
                    "original_host": orig_host,
                    "original_check": check,
                }
            )
    plan = SweepPlan(plans)
    plan.diagnosis = {
        "confirmed_parents": confirmed_parents,
        "remaining_assets": len(remaining),
        "retargetable_checks": retargetable_checks,
        "skipped_static": skipped_static,
        "skipped_same_origin": skipped_same_origin,
    }
    return plan
