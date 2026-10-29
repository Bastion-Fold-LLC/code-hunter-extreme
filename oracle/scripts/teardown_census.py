#!/usr/bin/env python3
"""Rejection-reason census over a hunt's finding JSONs.

The finish board's M6 blocker used to read "teardown demoted 53/53". That is
one number where there are several different failures, and they need different
fixes: a card that red-team rejected is not the same as a card whose PoC failed
to replay, which is not the same as a card that never reached a runnable check.

This script assigns every candidate exactly one terminal stage — the first gate
it failed, walking the same order the hunt does — so the counts sum to the
number of candidates and each line names a fixable surface.

Usage:
    python3 scripts/teardown_census.py targets/HackerOne/matomo
    python3 scripts/teardown_census.py <workspace> --json
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

# Ordered stages. The first one a candidate fails is its terminal stage; a
# candidate that passes all of them is CONFIRMED.
STAGE_ORDER = [
    "schema",
    "redteam",
    "corroboration",
    "runnable-check",
    "teardown",
    "wire-verify",
]

STAGE_BLURB = {
    "schema": "card is missing fields a later gate needs",
    "redteam": "self-defeating / out-of-scope / benign by the card's own claim",
    "corroboration": "conflicting cross-lens claims — unreviewed pending arbitration",
    "runnable-check": "no executable check: static conflict with no probe to run",
    "teardown": "ran, but the PoC did not survive replay/mutation",
    "wire-verify": "reached verification and the wire did not confirm it",
}

_TRUE = {"1", "true", "yes", "y", "pass", "passed", "confirmed"}
_FALSE = {"0", "false", "no", "n", "fail", "failed", "rejected"}


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def _load(path: Path) -> Dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def finding_paths(workspace: Path) -> List[Path]:
    """Candidate JSONs, excluding the `.xref.json` sidecars."""
    return sorted(
        p
        for p in (workspace / "findings").glob("*.json")
        if not p.name.endswith(".xref.json")
    )


def classify(finding: Dict[str, Any]) -> Tuple[str, str]:
    """Return (stage, reason) for one candidate. Terminal stage only."""
    check = str(finding.get("check") or "").strip()

    verdict = str(finding.get("verdict") or "").upper()
    if not check or not finding.get("assertion_a"):
        return "schema", "missing check or assertion"

    redteam = str(
        finding.get("m3_redteam_verdict")
        or finding.get("redteam_verdict")
        or ""
    ).strip().lower()
    if redteam in {"rejected", "refuted", "no", "killed"}:
        return "redteam", f"redteam={redteam}"

    state = str(finding.get("m3_seam_state") or "").strip().lower()
    if state == "conflicted" or _as_bool(finding.get("m3_seam_conflict")):
        return "corroboration", "conflicting cross-lens claims"

    # UNSOLVED cards carry a static check (grep/file inspection) rather than a
    # probe with an observable failure signal, so nothing downstream can run.
    if verdict == "UNSOLVED":
        return "runnable-check", "static conflict, no observable probe"

    teardown = finding.get("poc_teardown")
    if isinstance(teardown, dict):
        td_verdict = str(teardown.get("verdict") or "").upper()
        if td_verdict and td_verdict != "PASS":
            failed = [
                f"{a.get('name')}: {a.get('detail')}"
                for a in teardown.get("attacks") or []
                if isinstance(a, dict)
                and str(a.get("result") or "").upper() == "FAIL"
            ]
            reason = "; ".join(failed) or str(teardown.get("notes") or "teardown FAIL")
            return "teardown", reason

    if _as_bool(finding.get("verify_confirmed")) is False:
        text = str(finding.get("verify_verdict") or "not confirmed")
        return "wire-verify", text.split("—")[0].strip()[:120] or "not confirmed"

    if verdict and verdict not in {"CERTAIN", "CONFIRMED", "VERIFIED"}:
        return "wire-verify", f"verdict={verdict}"

    return "CONFIRMED", "confirmed"


def census(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate terminal stages, per lens and with reasons collapsed."""
    findings = [f for f in findings if isinstance(f, dict)]
    stages: collections.Counter[str] = collections.Counter()
    reasons: collections.Counter[str] = collections.Counter()
    per_lens: Dict[str, collections.Counter[str]] = collections.defaultdict(
        collections.Counter
    )
    lenses: collections.Counter[str] = collections.Counter()

    for finding in findings:
        stage, reason = classify(finding)
        lens = str(finding.get("lens") or "unknown")
        lenses[lens] += 1
        stages[stage] += 1
        per_lens[lens][stage] += 1
        if stage != "CONFIRMED":
            # Bucket by the head of the reason so near-identical teardown
            # notes collapse instead of producing one row per candidate.
            reasons[f"{stage}: {reason.split(';')[0][:90]}"] += 1

    total = len(findings)
    return {
        "total": total,
        "confirmed": stages.get("CONFIRMED", 0),
        "stages": {stage: stages.get(stage, 0) for stage in STAGE_ORDER},
        "per_lens": {lens: dict(counts) for lens, counts in per_lens.items()},
        "lenses": dict(lenses),
        "top_reasons": reasons.most_common(15),
    }


def render(result: Dict[str, Any], workspace: Path) -> str:
    lines: List[str] = []
    total = result["total"]
    lines.append(f"Teardown census — {workspace}")
    lines.append(f"candidates: {total}  confirmed: {result['confirmed']}")
    lines.append("")
    if total:
        lines.append(f"{'stage':<16}{'count':>6}  {'share':>6}  meaning")
        for stage in STAGE_ORDER + ["CONFIRMED"]:
            count = result["stages"].get(stage, 0) if stage != "CONFIRMED" else result["confirmed"]
            if not count:
                continue
            share = f"{count / total:.0%}"
            blurb = STAGE_BLURB.get(stage, "survived every gate")
            lines.append(f"{stage:<16}{count:>6}  {share:>6}  {blurb}")
        accounted = sum(result["stages"].values()) + result["confirmed"]
        lines.append("")
        lines.append(f"accounted for: {accounted}/{total}")
    lines.append("")
    for lens, stages in sorted(result["per_lens"].items(), key=lambda kv: -sum(kv[1].values())):
        summary = ", ".join(f"{k}={v}" for k, v in sorted(stages.items(), key=lambda kv: -kv[1]))
        lines.append(f"  {lens}: {summary}")
    if result["top_reasons"]:
        lines.append("")
        lines.append("top rejection reasons:")
        for reason, count in result["top_reasons"]:
            lines.append(f"  {count:>4}  {reason}")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("workspace", type=Path, help="Path to targets/<platform>/<slug>")
    parser.add_argument("--json", action="store_true", help="Emit the census as JSON")
    args = parser.parse_args(argv)

    if not args.workspace.is_dir():
        print(f"not a workspace: {args.workspace}", file=sys.stderr)
        return 2
    paths = finding_paths(args.workspace)
    findings = [doc for doc in (_load(p) for p in paths) if doc]
    result = census(findings)
    result["workspace"] = str(args.workspace)
    result["unreadable"] = len(paths) - len(findings)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result, args.workspace))
        if result["unreadable"]:
            print(f"\n  ({result['unreadable']} unreadable finding file(s) skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
