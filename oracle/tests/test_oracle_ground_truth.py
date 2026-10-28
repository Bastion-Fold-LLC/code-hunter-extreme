#!/usr/bin/env python3
"""
Oracle Ground-Truth Benchmark Runner
─────────────────────────────────────
Tests Oracle's 8-Reflex deterministic engine on a known flawed application (bad_code_app.py).
Evaluates whether Oracle detects:
  1. Identity / Untrusted Header Role Elevation (Reflex 1 / T1550)
  2. State-Machine Coupon / Negative Balance Invariant (Reflex 2 / T1190)
  3. Sensitive Debug Configuration Exposure (Reflex 3 / T1552)

Runs the reproducible checks deterministically against localhost:8765 and outputs verification verdicts.
"""

import sys
import os
import time
import subprocess
import json
from pathlib import Path

# Ensure paths
_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

from oracle_hunter import (
    ProgramScopeGate,
    run_reflexes,
    _parse_seams,
    verify_seams,
    RECON_DIR,
)

APP_PORT = 8765
TARGET_NAME = "bad_code_testbed"
RECON_OUT = RECON_DIR / TARGET_NAME
MODEL = os.environ.get("ORACLE_BATTERY_MODEL", "qwen2.5:3b")

def setup_testbed():
    RECON_OUT.mkdir(parents=True, exist_ok=True)
    
    # 1. Setup mock recon artifacts representing bad_code_app
    (RECON_OUT / "live_hosts.txt").write_text(
        f"http://127.0.0.1:{APP_PORT} [200] [vulnerable_testbed] [Python,http.server]\n"
    )
    (RECON_OUT / "known_urls.txt").write_text("\n".join([
        f"http://127.0.0.1:{APP_PORT}/health",
        f"http://127.0.0.1:{APP_PORT}/debug/config",
        f"http://127.0.0.1:{APP_PORT}/api/v1/admin/metrics",
        f"http://127.0.0.1:{APP_PORT}/api/v1/orders/ord_101",
        f"http://127.0.0.1:{APP_PORT}/api/v1/orders/ord_101/apply_discount",
    ]) + "\n")
    (RECON_OUT / "subdomains.txt").write_text("127.0.0.1\n")
    (RECON_OUT / "dns.txt").write_text("127.0.0.1 A 127.0.0.1\n")

def run_benchmark():
    print("=" * 70)
    print("  ORACLE GROUND-TRUTH BENCHMARK: TESTING ON INTENTIONALLY FLAWED CODE")
    print("=" * 70)

    # 1. Spawn bad_code_app
    app_proc = subprocess.Popen(
        [sys.executable, str(_HERE / "tests" / "bad_code_app.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1)

    try:
        setup_testbed()
        print(f"[*] Bad code testbed live on http://127.0.0.1:{APP_PORT}")
        print("[*] Running Oracle 8-Reflex Engine with 16 Philosophies + MITRE TTPs...")

        # 2. Run reflexes using local qwen2.5:3b
        raw_output = run_reflexes(RECON_OUT, model=MODEL, target=TARGET_NAME)
        print("\n--- RAW ORACLE REFLEX OUTPUT ---")
        print(raw_output)
        print("--------------------------------\n")

        # 3. Parse seams
        seams = _parse_seams(raw_output)
        print(f"[*] Parsed {len(seams)} candidate Seam Card(s)")

        if not seams:
            print("[!] No seams parsed. Raw output did not format cards.")
            return

        # 4. Deterministic Verification Engine
        print("[*] Executing Deterministic Verification Engine (running checks against live app)...")
        # Declare the loopback benchmark so the scope gate allows 127.0.0.1
        # (bare testbed names are treated as external → localhost blocked).
        gate = ProgramScopeGate({}, f"127.0.0.1:{APP_PORT}")
        verdicts = verify_seams(
            seams,
            TARGET_NAME,
            RECON_OUT,
            model=MODEL,
            auto=True,
            scope_gate=gate,
            # Loopback benchmark: mutation-safe, so POST checks execute.
            is_testnet=True,
        )

        print("\n" + "=" * 70)
        print("  DETERMINISTIC VERIFICATION RESULTS")
        print("=" * 70)
        confirmed_count = 0
        for n, v in verdicts.items():
            s = v["seam"]
            status = "CONFIRMED ✅" if v["confirmed"] else "NOT CONFIRMED ❌"
            if v["confirmed"]:
                confirmed_count += 1
            print(f"\n[SEAM {n}] {status}")
            print(f"  Reflex : {s.get('reflex')}")
            print(f"  A      : {s.get('assertion_a')}")
            print(f"  B      : {s.get('assertion_b')}")
            print(f"  Check  : {s.get('check')}")
            print(f"  Verdict: {v.get('verdict')}")

        print("\n" + "-" * 70)
        print(f"Benchmark Summary: {confirmed_count}/{len(seams)} seams deterministically confirmed.")
        print("-" * 70)

    finally:
        app_proc.terminate()
        app_proc.wait()
        print("[*] Testbed application stopped.")

if __name__ == "__main__":
    run_benchmark()
