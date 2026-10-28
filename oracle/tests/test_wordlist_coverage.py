#!/usr/bin/env python3
"""Wordlist coverage test — every planted vuln route must be in oracle-api-paths.txt.

If a path isn't in the wordlist, a real ffuf/katana run will miss it and the
golden harness only passes because recon is hand-seeded. This test closes that
gap: it ensures the wordlist can discover every planted route independently.

    python3 tests/test_wordlist_coverage.py     # exit 0 = covered, 1 = gaps
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORDLIST = ROOT / "wordlists" / "oracle-api-paths.txt"

# Every path that a real ffuf run needs to find for the hunt to work.
# These are the routes planted in vuln_testbed_full.py that template checks
# fire against — if they're not in the wordlist, discovery is hand-seeded only.
REQUIRED_PATHS = [
    # vuln routes — each maps to at least one template
    "debug/config",  # self-observing
    ".env",  # t1190-artifact
    "package.json",  # t1190-artifact
    "openapi.json",  # t1082-spec
    "graphql",  # observer
    "api/internal/dashboard",  # vacuum
    "api/v1/admin/metrics",  # beautiful-liar
    "api/v1/orders",  # mirror (old version)
    "api/v2/orders",  # mirror (new version — needs to be fuzzable)
    "api/orders",  # repulsive
    "api/legacy/users",  # deathless
    "old/users",  # deathless alt path
    "api/v1/secrets",  # cliff-and-current guarded
    "api/internal/secrets",  # cliff-and-current unguarded
    "api/crash",  # single-token
    "redirect",  # t601-open-redirect
    # P13 routes — sqli / xss / idor fixtures (hand-seeded recon hid these;
    # without wordlist entries a real ffuf run never discovers them)
    "api/search",  # injection-sqli
    "greet",  # injection-xss
    "api/profile/7",  # idor-direct-object (pair leg 1)
    "api/profile/8",  # idor-direct-object (pair leg 2)
    # invisible-architect infra files
    "yarn.lock",
    # benign control routes — also need to be fuzzable to prove no false positives
    "api/users",
    "upload",
]

# Session-suicide entries: fuzzing these WITH a session cookie destroys
# the session (logout.php GET → session_destroy), silently 302ing every
# later authed probe. The crawler excludes them via katana -cos; the
# wordlist must not contain them at all.
FORBIDDEN_PATHS = {
    "logout",
    "logoff",
    "signout",
    "sign_out",
    "logout.php",
    "users/logout",
    "auth/logout",
}


def test_wordlist_covers_planted_routes():
    """Pytest hook so the suite (not just run_all) enforces coverage."""
    assert main() == 0


def main() -> int:
    if not WORDLIST.exists():
        print(f"FAIL: wordlist not found: {WORDLIST}")
        return 1

    entries: set[str] = set()
    for line in WORDLIST.read_text(errors="ignore").splitlines():
        line = line.strip().lstrip("/")
        if line and not line.startswith("#"):
            entries.add(line)

    missing = [p for p in REQUIRED_PATHS if p.lstrip("/") not in entries]
    forbidden = sorted(p for p in FORBIDDEN_PATHS if p.lstrip("/") in entries)

    print(
        f"wordlist coverage: {len(entries)} entries, "
        f"{len(REQUIRED_PATHS)} required paths checked"
    )
    if missing:
        print("RESULT: FAIL — paths missing from wordlist:")
        for p in missing:
            print(f"  ✗ {p}")
        return 1
    if forbidden:
        print("RESULT: FAIL — session-suicide entries present:")
        for p in forbidden:
            print(f"  ✗ {p}")
        return 1
    print("RESULT: PASS — all planted vuln routes covered in wordlist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
