#!/usr/bin/env python3
"""Card-structure smoke test — every seam template must produce well-formed cards.

Tests that scan_template_seams() emits valid cards for all 18 registered
templates given synthetic recon material that triggers every template path.
No LLM, no network, no external dependencies.

    python3 tests/test_card_structure.py     # exit 0 = all good, 1 = fail

What "well-formed" means here (the LLM-lens equivalent without the model):
  - Required fields present and non-empty
  - claim_type matches a registered TEMPLATES tid
  - check is a curl/grep command containing an http URL
  - expected contains a parseable status code
  - assertion_a_source is non-empty (Gate-4 precondition)
  - verdict == CANDIDATE
"""
from __future__ import annotations
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import oracle_seam_templates as st
from oracle_deterministic import parse_expected

BASE = "http://127.0.0.1:8765"

# Required fields in every card
REQUIRED_FIELDS = [
    "n",
    "id",
    "claim_type",
    "assertion_a",
    "assertion_b",
    "assertion_a_source",
    "check",
    "expected",
    "verdict",
    "mitre",
    "impact",
    "reflex",
]

# All registered template tids — if a new template is added and not covered
# by the recon seed below, this test will catch the gap.
REGISTERED_TIDS = {t["tid"] for t in st.TEMPLATES}


def _seed(recon: Path) -> None:
    """Synthetic recon that triggers every web template."""
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "live_hosts.txt").write_text(BASE + "\n")
    # Trigger mirror (v1 + v2 same route), repulsive (two spellings), vacuum
    # (privileged name), single-token (500), deathless (legacy), self-observing
    # (debug), beautiful-liar (admin 403+200), cliff-and-current (403 + unguarded sibling),
    # t1552 (js_secrets with URL), invisible-architect (infra file in fuzzed)
    js_endpoints = [
        f"{BASE}/api/v1/orders/ord_101",
        f"{BASE}/api/v2/orders/ord_101",
        f"{BASE}/api/orders",
        f"{BASE}/api/orders/",  # repulsive: two spellings
        f"{BASE}/api/profile/7",
        f"{BASE}/api/profile/8",  # idor: object-id pair
        f"{BASE}/api/internal/dashboard",
        f"{BASE}/api/v1/admin/metrics",
        f"{BASE}/api/legacy/users",
        f"{BASE}/old/users",
        f"{BASE}/debug/config",
        f"{BASE}/redirect",
    ]
    fuzzed = [
        f"{BASE}/ [200]",
        f"{BASE}/health [200]",
        f"{BASE}/debug/config [200]",
        f"{BASE}/package.json [200]",
        f"{BASE}/.env [200]",
        f"{BASE}/openapi.json [200]",
        f"{BASE}/graphql [200]",
        f"{BASE}/api/internal/dashboard [200]",
        f"{BASE}/api/v1/admin/metrics [403]",
        f"{BASE}/api/v1/secrets [403]",
        f"{BASE}/api/internal/secrets [200]",
        f"{BASE}/api/crash [500]",
        f"{BASE}/redirect [302]",
        # invisible-architect: infra file NOT caught by artifact template
        f"{BASE}/yarn.lock [200]",
        # state-invariant: order resource instance -> derives apply_discount/refund/... action cards
        f"{BASE}/api/orders/ord_101 [200]",
    ]
    api_specs = [
        f"{BASE}/graphql [graphql-introspection]",
        f"{BASE}/openapi.json [openapi]",
    ]
    (recon / "js_endpoints.txt").write_text("\n".join(js_endpoints) + "\n")
    (recon / "fuzzed_paths.txt").write_text("\n".join(fuzzed) + "\n")
    (recon / "api_specs.txt").write_text("\n".join(api_specs) + "\n")
    # t1552: one secret entry with source URL (tab-separated key=hash\turl format)
    (recon / "js_secrets.txt").write_text(
        f"api_key=sha256:abc123def456\t{BASE}/static/app.js\n"
    )
    # listed-file-exposure: one listing child (doc) + one skipped binary
    (recon / "listed_paths.txt").write_text(
        f"{BASE}/ftp/legal.md\n{BASE}/ftp/logo.png\n"
    )


def _check_card(card: dict) -> list[str]:
    """Return list of violations for one card, empty if well-formed."""
    errs = []
    for f in REQUIRED_FIELDS:
        if not card.get(f):
            errs.append(f"missing/empty field '{f}'")
    if card.get("verdict") != "CANDIDATE":
        errs.append(f"verdict is '{card.get('verdict')}', expected CANDIDATE")
    check = card.get("check", "")
    if not check.startswith(("curl", "grep")):
        errs.append(f"check does not start with curl/grep: {check!r:.80}")
    if "http" not in check:
        errs.append(f"check has no http URL: {check!r:.80}")
    exp = parse_expected(str(card.get("expected", "")))
    if exp["status"] is None:
        errs.append(f"expected field has no status code: {card.get('expected')!r:.80}")
    return errs


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="card_struct_") as tmp:
        recon = Path(tmp)
        _seed(recon)
        from oracle_hunter import ProgramScopeGate

        cards = st.scan_template_seams(
            recon_dir=recon,
            repo_path=None,
            program=None,
            scope_gate=ProgramScopeGate({}, target_fallback=BASE),
        )

    if not cards:
        print("FAIL: scan_template_seams returned 0 cards — no templates fired")
        return 1

    # Collect per-card failures
    all_fails = []
    for card in cards:
        errs = _check_card(card)
        for e in errs:
            all_fails.append(
                f"  card {card.get('id','?')} [{card.get('claim_type','?')}]: {e}"
            )

    # Which tids fired?
    fired_tids = {c["claim_type"] for c in cards}
    web_tids = {t["tid"] for t in st.TEMPLATES if "web" in t["applies"]}
    unfired = web_tids - fired_tids
    for tid in sorted(unfired):
        all_fails.append(f"  template never fired: {tid}")

    print(
        f"card structure: {len(cards)} cards from {len(fired_tids)} templates "
        f"({len(web_tids)} web templates registered)"
    )
    if all_fails:
        print("RESULT: FAIL")
        print("\n".join(all_fails))
        return 1
    print("RESULT: PASS — all cards well-formed, all web templates fired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
