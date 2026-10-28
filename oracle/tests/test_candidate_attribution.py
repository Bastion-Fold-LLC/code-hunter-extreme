import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_hunter import _attribute_candidate_lenses, _merge_seams, _parse_seams


def test_merged_candidates_keep_reasoning_lens_provenance():
    reflex = {
        "assertion_a": "A route requires ownership.",
        "assertion_b": "Observed request accepts a foreign object.",
        "check": "curl -i -s https://example.test/orders/2",
        "reflex": "Reflex 2 — DECOUPLE",
        "mitre": "T1078",
        "origin": "cloud-full-342",
    }
    code = {
        "assertion_a": "The handler verifies ownership.",
        "assertion_b": "The source path omits the check.",
        "check": "pytest -q test_owner.py",
        "reflex": "SPEC-AUDIT",
        "mitre": "CWE-639",
        "origin": "invisible-seam",
    }

    merged = _merge_seams([reflex], [code])

    assert merged[0]["reasoning_lenses"] == [
        "mitre-invisible-seam", "mindset-invisible-seam"
    ]
    assert merged[1]["reasoning_lenses"] == [
        "deterministic-invisible-seam",
        "mitre-invisible-seam",
        "mindset-invisible-seam",
    ]
    assert all(candidate["candidate_status"] == "CANDIDATE" for candidate in merged)


def test_uncited_card_is_unattributed_not_self_certified():
    # #20: no reflex line, no MITRE code → no lens tags. Provenance
    # inflation (every card minting "mindset-invisible-seam") is cut.
    bare = {
        "assertion_a": "Docs claim auth.",
        "assertion_b": "Wire skips auth.",
        "check": "curl -i -s https://example.test/x",
        "reflex": "",
        "mitre": "N/A",
        "origin": "cloud-paradox",
    }
    out = _attribute_candidate_lenses(dict(bare))
    assert out["reasoning_lenses"] == ["unattributed"]


def test_retired_reflex_default_earns_no_lens():
    # Cards persisted before #20 carry the old "Oracle Reflex" parser
    # default without any model citation — it must not mint provenance.
    stale = {
        "assertion_a": "A",
        "assertion_b": "B",
        "check": "curl -i -s https://example.test/x",
        "reflex": "Oracle Reflex",
        "mitre": "N/A",
        "origin": "cloud-paradox",
    }
    out = _attribute_candidate_lenses(dict(stale))
    assert out["reasoning_lenses"] == ["unattributed"]


def test_parse_leaves_uncited_reflex_empty():
    # End to end at the parser: a card with no Reflex line keeps an
    # empty reflex and merges as unattributed.
    raw = """**SEAM 1**
- Assertion A: Docs claim auth is enforced
- Assertion B: Wire returns data without creds
- Reproducible check: `curl -i -s https://example.test/api`
- Expected: status 200
- Impact: data exposure
"""
    (parsed,) = _parse_seams(raw)
    assert parsed["reflex"] == ""
    (merged,) = _merge_seams([parsed], [])
    assert merged["reasoning_lenses"] == ["unattributed"]
