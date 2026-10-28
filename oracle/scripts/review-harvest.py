#!/usr/bin/env python3
# LAYER: seal
# DEST: codecrusher
# ENDPOINTS: main
# TOPICS: none
"""review-harvest — unify every reviewer's findings for one PR into one checklist.

Wires the review tools together so none gets skipped: pulls Greptile + CodeRabbit
inline comments AND the deterministic CI check conclusions for a PR, dedupes by
path:line (agreement = high confidence), and prints one actionable list.

Usage:
    scripts/review-harvest.py <repo> <pr-number>
    e.g. scripts/review-harvest.py Scan4Me 4

Reviewers covered: greptile-apps[bot], coderabbitai[bot], and the GitHub check
runs (validate stack: bandit/semgrep/gitleaks/ruff/mypy, Snyk, Socket, OSV).
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict

ORG = "code-hunter-extreme"
BOTS = {"greptile-apps[bot]": "GREPTILE", "coderabbitai[bot]": "CODERABBIT"}


def _gh(path: str) -> list | dict:
    out = subprocess.run(
        ["gh", "api", f"repos/{ORG}/{path}", "--paginate"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return []
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        # --paginate can concatenate arrays; wrap the stream
        try:
            return json.loads("[" + out.stdout.replace("][", ",") + "]")
        except json.JSONDecodeError:
            return []


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    repo, pr = sys.argv[1], sys.argv[2]

    # 1. inline review comments from both AI reviewers
    by_loc: dict[tuple, list[str]] = defaultdict(list)
    findings: list[tuple] = []
    for c in _gh(f"{repo}/pulls/{pr}/comments"):
        if not isinstance(c, dict):
            continue
        src = BOTS.get((c.get("user") or {}).get("login", ""))
        if not src:
            continue
        loc = (c.get("path", "?"), c.get("line") or c.get("original_line") or "?")
        body = " ".join((c.get("body") or "").split())
        # first bolded claim or first sentence
        claim = body
        if "**" in body:
            parts = body.split("**")
            claim = next((p for p in parts if p.strip() and not p.startswith(("🧰", "http"))), body)
        findings.append((src, loc, claim[:160]))
        by_loc[loc].append(src)

    # 2. CI check conclusions
    pr_obj = _gh(f"{repo}/pulls/{pr}")
    sha = (pr_obj or {}).get("head", {}).get("sha") if isinstance(pr_obj, dict) else None
    checks = []
    if sha:
        runs = _gh(f"{repo}/commits/{sha}/check-runs")
        if isinstance(runs, dict):
            for cr in runs.get("check_runs", []):
                checks.append((cr.get("name", "?"), cr.get("conclusion") or cr.get("status")))

    # 3. print unified checklist
    print(f"\n=== REVIEW HARVEST — {ORG}/{repo} PR #{pr} ===")
    g = sum(1 for s, _, _ in findings if s == "GREPTILE")
    cr = sum(1 for s, _, _ in findings if s == "CODERABBIT")
    print(f"inline findings: Greptile={g}  CodeRabbit={cr}")
    agreed = [loc for loc, srcs in by_loc.items() if len(set(srcs)) > 1]
    if agreed:
        print(f"HIGH-CONFIDENCE (both reviewers flag same spot): {len(agreed)} — {agreed}")
    print("\n-- findings (verify each against current code; fix or mark-safe-with-reason) --")
    for src, (path, line), claim in sorted(findings):
        star = " ★BOTH" if len(set(by_loc[(path, line)])) > 1 else ""
        print(f"  [{src}] {path}:{line}{star}\n      {claim}")
    print("\n-- CI checks --")
    for name, concl in checks:
        mark = {"success": "✓", "failure": "✗", "neutral": "·"}.get(concl, "…")
        print(f"  {mark} {name}: {concl}")
    print("\nMERGE RULE: merge only when both AI reviewers are clean (or every finding\n"
          "dispositioned) AND the validate check is green.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
