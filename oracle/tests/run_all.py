#!/usr/bin/env python3
"""Unified test runner — all verification layers, one command, one exit code.

    python3 tests/run_all.py          # exit 0 = everything green, 1 = regression

Layers (in order, fastest first):
  1. card-structure smoke  — all templates emit well-formed cards (no network)
  2. wordlist coverage     — every planted vuln route is in oracle-api-paths.txt
  3. golden hunt           — recall + precision against the live vuln testbed

Exit 0 only when ALL three layers pass. First failure is reported immediately;
subsequent layers still run so you see the full picture in one shot.
"""
from __future__ import annotations
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

_LAYERS = [
    ("card-structure smoke",  [sys.executable, str(TESTS / "test_card_structure.py")]),
    ("injection templates",   [sys.executable, str(TESTS / "test_injection_templates.py")]),
    ("wordlist coverage",     [sys.executable, str(TESTS / "test_wordlist_coverage.py")]),
    ("golden hunt",           [sys.executable, str(TESTS / "test_golden_hunt.py")]),
    ("red-team verifier+chain", [sys.executable, str(TESTS / "test_redteam_verifier.py")]),
    ("severity ladder",       [sys.executable, "-m", "pytest", "-q", str(TESTS / "test_severity_ladder.py")]),
    ("omnicli red-team gates", [sys.executable, str(TESTS / "test_omnicli_redteam.py")]),
    ("known-bug corpus",      [sys.executable, str(TESTS / "test_known_bugs.py")]),
    ("web3 contract layer",   [sys.executable, str(TESTS / "test_web3_layer.py")]),
    ("3-mindset scenario gauntlet", [sys.executable, str(TESTS / "test_full_scenario_gauntlet.py")]),
    ("cold benchmark eval",   [sys.executable, "-m", "pytest", "-q", str(TESTS / "test_cold_benchmark_eval.py")]),
]


def _run_layer(name: str, cmd: list[str]) -> tuple[bool, str]:
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - t0
    out = (r.stdout + r.stderr).strip()
    ok = r.returncode == 0
    last_line = out.splitlines()[-1] if out else "(no output)"
    print(f"  {'✓' if ok else '✗'} [{name}] {last_line}  ({elapsed:.1f}s)")
    if not ok and out:
        # print full output for failing layers (indented)
        for line in out.splitlines():
            print(f"      {line}")
    return ok, out


def main() -> int:
    print(f"\n{'═'*60}")
    print("  oracle test suite")
    print(f"{'═'*60}")
    results = []
    for name, cmd in _LAYERS:
        ok, _ = _run_layer(name, cmd)
        results.append((name, ok))

    print(f"\n{'─'*60}")
    all_pass = all(ok for _, ok in results)
    if all_pass:
        print("  RESULT: PASS — all layers green")
    else:
        print("  RESULT: FAIL — failing layers:")
        for name, ok in results:
            if not ok:
                print(f"    ✗ {name}")
    print(f"{'═'*60}\n")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
