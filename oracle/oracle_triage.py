#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: score_programs, asset_count, main
# TOPICS: none
"""Oracle fast-triage: rank bug-bounty programs from the local cache.

Zero network. Reads programs_cache.json (+ downloaded programs/<platform>/
<slug>/program.json scope data when present) and prints a ranked table so the
operator can pick the best first target.

Alex's standing rule: asset count / attack surface size is the PRIMARY
ranking signal. Secondary: recency, low resolved-report counts, kind.

Asset-count sources, in precedence order:
  1. measured  — len(structured_scopes) (or scope lines) from a downloaded
                 program.json. Ground truth from the platform page/API.
  2. reported  — platform-reported scopes_count in the cache raw dict
                 (yeswehack listings carry it).
  3. estimated — log-scaled reports_count proxy, discounted by
                 asset_proxy_trust, flagged with ~ in the table.

Usage:
  python3 oracle_triage.py [--config triage.yaml] [--top 20] [--kind web2]
                           [--min-assets N] [--require-known-assets]
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent


# ── config ────────────────────────────────────────────────────────────────
def load_config(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None  # type: ignore[assignment]
    text = path.read_text()
    if yaml is not None:
        return yaml.safe_load(text)
    # Minimal fallback parser: handles this file's simple key: value shape,
    # including one level of nesting under `weights:`.
    cfg: dict = {}
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            section = stripped[:-1]
            cfg[section] = {}
            continue
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            k, v = k.strip(), v.strip()
            # strip inline comments (" # ...") the way YAML does
            if " #" in v:
                v = v.split(" #", 1)[0].rstrip()
            try:
                parsed: Any = int(v)
            except ValueError:
                try:
                    parsed = float(v)
                except ValueError:
                    parsed = {"true": True, "false": False}.get(v.lower(), v)
            if line[0] in (" ", "\t") and section:
                cfg[section][k] = parsed
            else:
                cfg[k] = parsed
                section = None
    return cfg


# ── data ──────────────────────────────────────────────────────────────────
def slugify(name: str) -> str:
    return re.sub(r"[^\w-]", "_", name.lower())


def downloaded_program(prog: dict, programs_dir: Path):
    """Load the saved program record, if scope intake has completed."""
    plat = prog.get("platform") or ""
    name = prog.get("name") or ""
    pj: Optional[Path] = programs_dir / plat / slugify(name) / "program.json"
    if pj is not None and not pj.exists():
        # fall back to the bulk-download workspace: targets/<plat>/*/.oracle_bulk.json
        pj = None
        tdir = Path("targets") / plat
        if tdir.is_dir():
            for mf in tdir.glob("*/.oracle_bulk.json"):
                try:
                    m = json.loads(mf.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                if (m.get("program") or "") == name:
                    cand = mf.parent / "program.json"
                    if cand.exists():
                        pj = cand
                        break
    if pj is None or not pj.exists():
        return None
    try:
        return json.loads(pj.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def scope_records(prog: dict, programs_dir: Path):
    """Return current scope records, preferring freshly intaken program data."""
    saved = downloaded_program(prog, programs_dir) or {}
    scopes = saved.get("structured_scopes") or prog.get("structured_scopes") or []
    if not isinstance(scopes, list):
        scopes = []
    return scopes


def downloaded_asset_count(prog: dict, programs_dir: Path):
    """(count, 'measured') from a downloaded program.json, else (None, None)."""
    data = downloaded_program(prog, programs_dir)
    if not data:
        return None, None
    scopes = data.get("structured_scopes") or []
    if not isinstance(scopes, list):
        scopes = []

    # Count eligible entries only: out-of-scope notes (eligible_for_bounty /
    # eligible_for_submission False) are preserved for the scope wall but must
    # not inflate the attack-surface count (e.g. Infomaniak 51, not 68).
    def _eligible(s):
        return (
            isinstance(s, dict)
            and s.get("eligible_for_bounty", True)
            and s.get("eligible_for_submission", True)
        )

    n = sum(1 for s in scopes if _eligible(s))
    if n == 0:
        scope_txt = data.get("scope") or ""
        n = len([ln for ln in scope_txt.splitlines() if ln.strip()])
    return (n, "measured") if n > 0 else (None, None)


def asset_count(prog: dict, programs_dir: Path):
    """Return (count|None, source) with source in measured/reported/unknown."""
    n, src = downloaded_asset_count(prog, programs_dir)
    if n is not None:
        return n, src
    raw = prog.get("raw") or {}
    sc = raw.get("scopes_count")
    if isinstance(sc, (int, float)) and sc > 0:
        return int(sc), "reported"
    return None, "unknown"


def parse_dt(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def lognorm(value, vmax):
    """log1p-normalized 0..1 against a max."""
    if value is None or vmax <= 0:
        return 0.0
    return math.log1p(max(0.0, value)) / math.log1p(vmax)


# ── scoring ───────────────────────────────────────────────────────────────
def score_programs(programs, programs_dir: Path, cfg: dict):
    w = cfg.get("weights", {})
    w_asset = float(w.get("asset_count", 1.0))
    w_proxy_trust = float(w.get("asset_proxy_trust", 0.5))
    w_recency = float(w.get("recency", 0.10))
    w_low = float(w.get("low_reports", 0.10))
    w_payout = float(
        w.get("payout", 0.0)
    )  # yaml is source of truth; off per Alex's rule
    w_fast = float(
        w.get("fast_triage", 0.40)
    )  # yaml is source of truth; fast triage = get paid faster
    w_new_assets = float(w.get("new_assets", 0.30))
    full_days = float(cfg.get("recency_full_days", 90))
    half_life = float(cfg.get("recency_half_life_days", 180))
    new_full_days = float(cfg.get("new_asset_full_days", 30))
    new_half_life = float(cfg.get("new_asset_half_life_days", 90))

    enriched = []
    for p in programs:
        n, src = asset_count(p, programs_dir)
        enriched.append((p, n, src))
    max_assets = max([n for _, n, _ in enriched if n] or [1])
    max_reports = max([p.get("reports_count") or 0 for p, _, _ in enriched] or [1])
    max_payout = max([p.get("max_payout_usd") or 0 for p, _, _ in enriched] or [1])
    now = datetime.now(timezone.utc)

    rows = []
    for p, n, src in enriched:
        rc = p.get("reports_count")
        # size signal: measured/reported count, else discounted proxy
        if n is not None:
            size = lognorm(n, max_assets)
            size_est = False
        elif rc:
            size = lognorm(rc, max_reports) * w_proxy_trust
            size_est = True
        else:
            size = 0.0
            size_est = True
        # recency signal
        launched = parse_dt(p.get("launched_at"))
        if launched and full_days > 0 and half_life > 0:
            age_days = max(0.0, (now - launched).total_seconds() / 86400.0)
            recency = (
                1.0
                if age_days <= full_days
                else 0.5 ** ((age_days - full_days) / half_life)
            )
        else:
            recency = 0.0
        # low-reports signal: fewer resolved reports = less picked over
        low_reports = 1.0 - lognorm(rc, max_reports) if rc else 0.0
        # payout signal (off by default)
        payout = lognorm(p.get("max_payout_usd"), max_payout)
        # new-assets signal: age of the most recently added asset. Fresh
        # assets are where the bugs are; programs whose scopes never change
        # score 0 here. Assets with unknown first_seen are ignored.
        newest_seen = None
        for s in scope_records(p, programs_dir):
            dt = parse_dt(s.get("first_seen")) if isinstance(s, dict) else None
            if dt and (newest_seen is None or dt > newest_seen):
                newest_seen = dt
        if newest_seen and new_full_days > 0 and new_half_life > 0:
            age_days = max(0.0, (now - newest_seen).total_seconds() / 86400.0)
            new_assets = (
                1.0
                if age_days <= new_full_days
                else 0.5 ** ((age_days - new_full_days) / new_half_life)
            )
        else:
            new_assets = 0.0

        # fast_triage: 1.0 if True, 0.5 if None/unknown, 0.0 if False
        ft = p.get("fast_triage")
        fast = 1.0 if ft is True else (0.5 if ft is None else 0.0)

        score = (
            w_asset * size
            + w_recency * recency
            + w_low * low_reports
            + w_payout * payout
            + w_new_assets * new_assets
            + w_fast * fast
        )
        rows.append(
            {
                # Spread original program fields first so our explicit keys override
                **{
                    k: v
                    for k, v in p.items()
                    if k not in ("name", "platform", "kind", "url", "reports_count")
                },
                # Explicit scored fields (override anything from spread)
                "name": p.get("name") or "?",
                "platform": p.get("platform") or "?",
                "kind": p.get("kind") or "?",
                "assets": n,
                "asset_src": src,
                "asset_est": size_est and n is None,
                "reports": rc,
                "reports_count": rc,
                "launched": p.get("launched_at"),
                "newest_asset": (
                    newest_seen.strftime("%Y-%m-%d") if newest_seen else None
                ),
                "fast_triage": ft,
                "max_payout_usd": p.get("max_payout_usd") or 0,
                "score": round(score, 4),
                "url": p.get("url") or "",
            }
        )
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


# ── CLI ───────────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Oracle fast-triage: rank programs from the local cache."
    )
    ap.add_argument("--config", default="triage.yaml", help="triage config file")
    ap.add_argument(
        "--top", type=int, default=None, help="rows to print (overrides config)"
    )
    ap.add_argument(
        "--kind",
        default=None,
        choices=["web2", "web3", "ai", "all"],
        help="program kind filter (overrides config)",
    )
    ap.add_argument("--min-assets", type=int, default=None)
    ap.add_argument("--require-known-assets", action="store_true")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = HERE / cfg_path
    cfg = load_config(cfg_path)

    cache_path = Path(cfg.get("cache", "programs_cache.json"))
    if not cache_path.is_absolute():
        cache_path = HERE / cache_path
    programs_dir = Path(cfg.get("programs_dir", "programs"))
    if not programs_dir.is_absolute():
        programs_dir = HERE / programs_dir

    cache = json.loads(cache_path.read_text())
    programs = cache.get("programs", [])

    kind = args.kind or cfg.get("kind", "all")
    if kind != "all":
        programs = [p for p in programs if (p.get("kind") or "") == kind]

    rows = score_programs(programs, programs_dir, cfg)

    min_assets = (
        args.min_assets
        if args.min_assets is not None
        else int(cfg.get("min_assets", 0))
    )
    require_known = args.require_known_assets or bool(
        cfg.get("require_known_assets", False)
    )
    if require_known:
        rows = [r for r in rows if r["assets"] is not None]
    if min_assets > 0:
        rows = [
            r
            for r in rows
            if (r["assets"] or 0) >= min_assets
            or (r["assets"] is None and not require_known)
        ]

    top = args.top or int(cfg.get("top", 20))
    rows = rows[:top]

    # measured/reported/unknown stats for the filtered set
    n_known = sum(1 for r in rows if r["assets"] is not None)

    hdr = f"{'#':>3}  {'program':<32} {'platform':<11} {'kind':<5} {'assets':>8} {'reports':>8} {'newest':<10} {'score':>6}"  # noqa: E501
    print(hdr)
    print("-" * len(hdr))
    for i, r in enumerate(rows, 1):
        if r["assets"] is not None:
            mark = "" if r["asset_src"] == "measured" else " (r)"
            assets = f"{r['assets']}{mark}"
        elif r["asset_est"]:
            assets = "~est"
        else:
            assets = "-"
        reports = str(r["reports"]) if r["reports"] is not None else "-"
        name = r["name"][:32]
        newest = r["newest_asset"] or "-"
        print(
            f"{i:>3}  {name:<32} {r['platform']:<11} {r['kind']:<5} "
            f"{assets:>8} {reports:>8} {newest:<10} {r['score']:>6.3f}"
        )
    print(
        f"\n{len(rows)} shown | {n_known} with measured/reported asset counts "
        f"| (r)=platform-reported  ~=proxy estimate  plain=measured from download"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
