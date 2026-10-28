#!/usr/bin/env python3
"""Golden hunt harness — the "is every part still working" button.

Starts the vulnerable testbed, runs the REAL template->check->verify path against
it, and asserts:
  * every PLANTED vuln confirms   (recall — no misses)
  * every BENIGN control rejects  (precision — no false positives)

One command, pass/fail, re-runnable after any change. This is a real run, not a
green unit test — it is exactly what would have caught Bug B.

    python3 tests/test_golden_hunt.py     # exit 0 = all good, 1 = regression
"""
from __future__ import annotations
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import oracle_seam_templates as st  # noqa: E402
import oracle_hunter as oh  # noqa: E402
from oracle_deterministic import (  # noqa: E402
    verify_seam_card,
    extract_status_from_curl_output,
)

BASE = "http://127.0.0.1:8765"

# Planted routes to seed recon with: (path, fuzz status tag)
ROUTES = [
    ("/", "200"),
    ("/health", "200"),
    ("/debug/config", "200"),
    ("/package.json", "200"),
    ("/.env", "200"),
    ("/openapi.json", "200"),
    ("/graphql", "200"),
    ("/api/internal/dashboard", "200"),
    ("/api/v1/admin/metrics", "403"),
    ("/api/v1/orders/ord_101", "200"),
    ("/api/v2/orders/ord_101", "200"),
    ("/api/orders", "200"),
    ("/api/orders/", "200"),
    ("/api/legacy/users", "200"),
    ("/old/users", "200"),
    ("/api/v1/secrets", "403"),
    ("/api/internal/secrets", "200"),
    ("/api/crash", "500"),
    ("/redirect", "302"),
    ("/api/search", "200"),
    ("/greet", "200"),
    ("/api/profile/7", "200"),
    ("/api/profile/8", "200"),
    ("/api/users", "200"),
    ("/api/users/123", "200"),
    ("/upload", "200"),
    ("/static/app.css", "200"),
]
API_SPECS = [("/graphql", "graphql-introspection"), ("/openapi.json", "openapi")]

# Truth table ----------------------------------------------------------------
# Each planted vuln: (template-tid substring, path that MUST confirm)
EXPECTED_CONFIRMS = [
    ("self-observing", "/debug/config"),
    ("t1190-artifact", "/.env"),
    ("t1190-artifact", "/package.json"),
    ("t1082-spec", "/openapi.json"),
    ("observer", "/graphql"),
    ("vacuum", "/api/internal/dashboard"),
    ("beautiful-liar", "/api/v1/admin/metrics"),
    ("mirror", "/api/v1/orders"),
    ("repulsive", "/api/orders"),
    ("deathless", "/api/legacy/users"),
    ("cliff-and-current", "/api/internal/secrets"),
    ("single-token", "/api/crash"),
    ("t601-open-redirect", "/redirect"),
    ("injection-sqli", "/api/search"),
    ("injection-xss", "/greet"),
    ("idor-direct-object", "/api/profile/8"),
]
# Benign controls: these EXACT paths must never appear in any CONFIRMED card.
BENIGN_PATHS = {
    "/",
    "/health",
    "/upload",
    "/static/app.css",
    "/api/users",
    "/api/users/123",
    "/api/v1/secrets",  # 403 guarded — proper boundary
}


def _seed(recon: Path) -> None:
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "live_hosts.txt").write_text(BASE + "\n")
    (recon / "fuzzed_paths.txt").write_text(
        "\n".join(f"{BASE}{p} [{t}]" for p, t in ROUTES) + "\n"
    )
    (recon / "js_endpoints.txt").write_text(
        "\n".join(f"{BASE}{p}" for p, _ in ROUTES) + "\n"
    )
    (recon / "api_specs.txt").write_text(
        "\n".join(f"{BASE}{p} [{t}]" for p, t in API_SPECS) + "\n"
    )
    (recon / "js_secrets.txt").write_text("")


def _wait_up(timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _confirmed_set(recon: Path):
    seams = st.scan_template_seams(
        recon_dir=recon,
        repo_path=None,
        program=None,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
    )
    confirmed = []
    confirmed_seams = []
    for s in seams:
        check = s.get("check", "")
        rc, out, err = oh._run_check(check)
        if "[BLOCKED]" in err:
            continue
        status = extract_status_from_curl_output(out)
        url = check.split("'")[-2] if "'" in check else check
        v = verify_seam_card(s, [url], status=status, body=out)
        if v["verdict"] == "CONFIRMED":
            confirmed.append((s.get("claim_type", ""), urlsplit(url).path))
            confirmed_seams.append({"seam": s, "output": out[:150]})
    return confirmed, confirmed_seams


def main() -> int:
    started = None
    if not _wait_up(0.5):
        started = subprocess.Popen(
            [sys.executable, str(ROOT / "tests" / "vuln_testbed_full.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not _wait_up(10):
            print("FAIL: testbed did not come up")
            return 1
    confirmed, confirmed_seams, chains, crit = [], [], [], []
    try:
        tmp = Path(tempfile.mkdtemp(prefix="golden_recon_"))
        _seed(tmp)
        confirmed, confirmed_seams = _confirmed_set(tmp)
        # chain recall: confirmed seams must compose, and compound to Critical
        from oracle_mindset_context import OracleMindsetContext

        _ctx = OracleMindsetContext(
            program={"name": "t", "platform": "direct"}, voice=False, mindset="mitre"
        )
        chains = [
            c for c in _ctx.chain_seams(confirmed_seams) if c.get("type") == "chain"
        ]
        crit = [
            c
            for c in chains
            if str(c.get("combined_severity", "")).lower() == "critical"
        ]
    finally:
        if started:
            started.terminate()

    fails = []
    if not chains:
        fails.append("  MISS  (chain): confirmed seams did not compose into any chain")
    elif not crit:
        fails.append("  WEAK  (chain): chains formed but none compounded to Critical")
    for tid_sub, path_sub in EXPECTED_CONFIRMS:
        if not any(tid_sub in tid and path_sub in path for tid, path in confirmed):
            fails.append(f"  MISS  (recall): {tid_sub} must confirm on {path_sub}")
    for tid, path in confirmed:
        if path in BENIGN_PATHS:
            fails.append(f"  FALSE+ (precision): {tid} confirmed benign {path}")

    print(
        f"golden hunt: {len(confirmed)} CONFIRMED, "
        f"{len(EXPECTED_CONFIRMS)} planted vulns expected, "
        f"{len(BENIGN_PATHS)} benign controls, "
        f"{len(chains)} chains ({len(crit)} Critical)"
    )
    if fails:
        print("RESULT: FAIL")
        print("\n".join(fails))
        return 1
    print("RESULT: PASS — every planted vuln confirmed, every benign control rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
