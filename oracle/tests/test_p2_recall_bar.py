#!/usr/bin/env python3
"""P2-lock: zero-miss recall bar — machine-enforced, not decorative.

Doctrine #5 (ORACLE_DOCTRINE.md) decides: ZERO MISSES IN COVERED CLASSES
(SQLi, XSS, auth bypass, IDOR, exposure) across juice-shop / DVWA / PyGoat;
anything outside the covered classes is named explicitly as uncovered.

This file enforces the decision three ways:
1. config pins gate_recall_min == 1.0 (recall fraction; 1.0 == zero misses).
2. doctrine #5 carries the closed bar text (no OPEN marker left on the bar).
3. every fixture-planted covered-class bug confirms on the REAL
   template->check->verify path, and every covered class owns >= 1 planted
   fixture. Bare classes and uncovered bugs are named, never silently missed.

Expected state at lock time: test 3 RED — fixtures plant no SQLi / XSS /
IDOR and no per-bench (juice/DVWA/PyGoat) mappings exist yet. Do NOT weaken
this test to green it; green it by planting the fixtures and closing the gap.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import test_golden_hunt as gh  # noqa: E402  (tests dir on sys.path via pytest)

COVERED_CLASSES = ("sqli", "xss", "auth-bypass", "idor", "exposure")
UNCOVERED = "uncovered"

# Classification of every golden-hunt planted bug into a covered class (or
# explicitly uncovered). Rationales cite tests/vuln_testbed_full.py behavior.
# (tid_sub, path_sub, class, rationale)
GOLDEN_CLASS: List[Tuple[str, str, str, str]] = [
    (
        "self-observing",
        "/debug/config",
        "exposure",
        "debug endpoint leaks creds + broker URL (CWE-200)",
    ),
    ("t1190-artifact", "/.env", "exposure", "env file with secrets served (CWE-552)"),
    ("t1190-artifact", "/package.json", "exposure", "infra artifact disclosure"),
    ("t1082-spec", "/openapi.json", "exposure", "API spec disclosure"),
    ("observer", "/graphql", "exposure", "introspection surface disclosure"),
    (
        "vacuum",
        "/api/internal/dashboard",
        "auth-bypass",
        "privileged path, no auth, returns priv data (missing auth, CWE-306)",
    ),
    (
        "beautiful-liar",
        "/api/v1/admin/metrics",
        "auth-bypass",
        "trusts client-supplied role header (CWE-287)",
    ),
    (
        "mirror",
        "/api/v1/orders",
        "exposure",
        "stale API version still live and serving data",
    ),
    (
        "repulsive",
        "/api/orders",
        "auth-bypass",
        "alternate spelling bypasses middleware binding",
    ),
    (
        "deathless",
        "/api/legacy/users",
        "exposure",
        "forgotten legacy route still routable and serving data",
    ),
    (
        "cliff-and-current",
        "/api/internal/secrets",
        "auth-bypass",
        "unguarded alternate of a 403-guarded path (CWE-306)",
    ),
    (
        "single-token",
        "/api/crash",
        "exposure",
        "500 traceback information disclosure (CWE-209)",
    ),
    (
        "injection-sqli",
        "/api/search",
        "sqli",
        "quote in ?q= breaks the backend query — 500 SQL error (CWE-89)",
    ),
    (
        "injection-xss",
        "/greet",
        "xss",
        "script probe in ?q= reflects unescaped — reflected XSS (CWE-79)",
    ),
    (
        "idor-direct-object",
        "/api/profile/8",
        "idor",
        "object 8 serves another user's record with no session (CWE-639)",
    ),
    (
        "t601-open-redirect",
        "/redirect",
        UNCOVERED,
        "open redirect is outside the 5 covered classes; named, not missed",
    ),
]


def _gate_recall_min() -> float:
    cfg = json.loads((ROOT / "oracle.config.json").read_text())
    return float(cfg["quality_gates"]["gate_recall_min"])


def _doctrine_section5() -> str:
    text = (ROOT / "ORACLE_DOCTRINE.md").read_text()
    start = text.index("## 5. Bar")
    return text[start:]


def _run_golden_confirms() -> List[Tuple[str, str]]:
    """Run the real template->check->verify path; return confirmed (tid, path)."""
    started = None
    if not gh._wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(ROOT / "tests" / "vuln_testbed_full.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not gh._wait_up(10):
            raise RuntimeError("golden testbed did not come up on :8765")
    try:
        tmp = Path(tempfile.mkdtemp(prefix="p2bar_recon_"))
        gh._seed(tmp)
        confirmed, _ = gh._confirmed_set(tmp)
        return [(tid, path) for tid, path in confirmed]
    finally:
        if started:
            started.terminate()


def _classify() -> Tuple[Dict[str, List[str]], List[str]]:
    """Return (planted per class incl. uncovered, unclassified golden entries)."""
    planted: Dict[str, List[str]] = {c: [] for c in COVERED_CLASSES + (UNCOVERED,)}
    mapped = {(t, p) for t, p, _, _ in GOLDEN_CLASS}
    unclassified = [
        f"{t} on {p}" for t, p in gh.EXPECTED_CONFIRMS if (t, p) not in mapped
    ]
    for tid_sub, path_sub, cls, _why in GOLDEN_CLASS:
        planted[cls].append(f"{tid_sub} on {path_sub}")
    return planted, unclassified


def test_config_pins_zero_miss_bar():
    bar = _gate_recall_min()
    assert bar == 1.0, (
        f"P2-lock: gate_recall_min must be 1.0 (zero misses), got {bar}. "
        "Do not lower it without a doctrine change."
    )


def test_doctrine_bar_is_closed():
    sec5 = _doctrine_section5()
    assert "zero misses in\ncovered classes" in sec5.replace(
        "**", ""
    ) or "zero misses in covered classes" in sec5.replace(
        "**", ""
    ), "doctrine #5 must state the zero-miss bar"
    assert "OPEN" not in sec5, "doctrine #5 bar must be DECIDED, not OPEN"


def test_every_golden_plant_is_classified():
    _, unclassified = _classify()
    assert not unclassified, (
        "golden-hunt planted bugs with no P2 class (classify or name uncovered): "
        + "; ".join(unclassified)
    )


def test_zero_miss_on_covered_class_fixtures():
    planted, unclassified = _classify()
    assert not unclassified, "classify new golden entries first: " + "; ".join(
        unclassified
    )
    confirmed = _run_golden_confirms()

    def _hit(tid_sub: str, path_sub: str) -> bool:
        return any(tid_sub in tid and path_sub in path for tid, path in confirmed)

    bar = _gate_recall_min()
    misses: Dict[str, List[str]] = {c: [] for c in COVERED_CLASSES}
    found_total = 0
    planted_total = 0
    for tid_sub, path_sub, cls, _why in GOLDEN_CLASS:
        if cls == UNCOVERED:
            continue
        planted_total += 1
        if _hit(tid_sub, path_sub):
            found_total += 1
        else:
            misses[cls].append(f"{tid_sub} on {path_sub}")
    recall = found_total / planted_total if planted_total else 0.0

    bare = [c for c in COVERED_CLASSES if not planted[c]]
    uncovered_named = planted[UNCOVERED]
    lines = [
        f"covered recall on fixtures: {found_total}/{planted_total} = {recall:.3f} (bar {bar})",
        *[
            f"  class {c}: planted={len(planted[c])} missed={len(misses[c])}"
            for c in COVERED_CLASSES
        ],
        *[f"  MISS [{c}]: {m}" for c in COVERED_CLASSES for m in misses[c]],
        *[
            f"  BARE CLASS (no fixture plants {c}): zero-miss unverifiable"
            for c in bare
        ],
        *[f"  UNCOVERED (named, out of bar): {u}" for u in uncovered_named],
    ]
    report = "\n".join(lines)
    print("\n" + report)
    assert not bare, f"P2-lock: covered classes with zero planted fixtures:\n{report}"
    assert recall >= bar, f"P2-lock: covered-class misses on fixtures:\n{report}"
