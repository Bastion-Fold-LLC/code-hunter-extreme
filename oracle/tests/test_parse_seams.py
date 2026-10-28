"""Regression tests for _parse_seams header matching.

Bug (2026-09-26): the split regex required a bold/heading marker before SEAM,
so a model emitting a bare `SEAM 1` header produced 0 parsed cards even with a
complete body. See docs/superpowers/specs/2026-09-26-provider-router-design.md.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh

TB = "http://127.0.0.1:3000"

_BODY = (
    "- Assertion A: App uses HTTPS. (source: docs)\n"
    "- Assertion B: Served over HTTP per live_hosts.txt. (source: live_hosts.txt)\n"
    "- Reflex: 1\n"
    "- MITRE: T1557\n"
    "- Reproducible check: `curl -i -s http://127.0.0.1:3000/`\n"
    "- Impact: MITM."
)


def _one(header: str) -> int:
    return len(oh._parse_seams(f"{header}\n{_BODY}", target_base=TB))


def test_bare_header_parses():
    assert _one("SEAM 1") == 1


def test_bold_header_parses():
    assert _one("**SEAM 1**") == 1


def test_heading_header_parses():
    assert _one("# SEAM 1") == 1


def test_bracketed_header_parses():
    assert _one("SEAM [1]") == 1


def test_no_seam_parses_zero():
    assert len(oh._parse_seams("No conflicts found. The surface looks clean.", target_base=TB)) == 0


def test_seam_word_without_number_is_not_a_card():
    # "SEAM cards below:" must not be treated as a card header (no digit)
    txt = "SEAM cards below:\nnothing here"
    assert len(oh._parse_seams(txt, target_base=TB)) == 0


def test_multiple_bare_cards_from_real_model_output():
    raw = (
        "SEAM 1\n" + _BODY + "\n\n" +
        "SEAM 2\n"
        "- Assertion A: redirect requires absolute URL. (source: docs)\n"
        "- Assertion B: /redirect?to=http accepted per crawl.txt. (source: crawl.txt)\n"
        "- Reproducible check: `curl -i -s http://127.0.0.1:3000/redirect?to=http://evil.com`\n"
        "- Impact: open redirect phishing."
    )
    assert len(oh._parse_seams(raw, target_base=TB)) == 2


def test_assertion_a_source_is_parsed_separately():
    raw = (
        "SEAM 1\n"
        "- Assertion A: The service requires authentication.\n"
        "- Assertion A source: `api-spec.md`\n"
        "- Assertion B: An endpoint returns data anonymously.\n"
        "- Reproducible check: `curl -i -s http://127.0.0.1:3000/api`\n"
        "- Expected: status 200\n"
    )
    seam = oh._parse_seams(raw, target_base=TB)[0]
    assert seam["assertion_a_source"] == "api-spec.md"


def test_parses_seam_card_header_and_fenced_curl():
    # Real nemotron-120b output format from the full run: "SEAM CARD N" header
    # (not "SEAM N") and the curl inside a ```bash fenced block. The old parser
    # returned 0 cards on this — silently dropping a real finding.
    raw = (
        "**SEAM CARD 1 - Identity / Proxy Seam**\n"
        "- **Assertion A (intended guarantee):** /api/v1/admin/metrics is admin-only.\n"
        "- **Assertion A source:** Code comment in app.py (lines 30-33).\n"
        "- **Assertion B (actual behavior):** The handler trusts the client header X-Original-Role.\n"
        "- **Reflex:** SPEC-AUDIT\n"
        "- **Reproducible check:**\n"
        "  ```bash\n"
        "  curl -s http://127.0.0.1:8765/api/v1/admin/metrics -H \"X-Original-Role: admin\"\n"
        "  ```\n"
        "- **Impact:** Unauthorized access to billing metrics.\n"
    )
    seams = oh._parse_seams(raw, target_base=TB)
    assert len(seams) >= 1
    assert "curl" in seams[0]["check"] and "admin/metrics" in seams[0]["check"]
    assert seams[0]["check_missing"] is False


def test_garbage_card_tagged_unparseable_not_fabricated():
    # #11: a card stating neither assertion keeps empty A/B and is tagged
    # unparseable — the parser invents no assertion text.
    raw = (
        "**SEAM 1**\n"
        "- Some rambling prose with no structure at all\n"
        "- More noise, nothing shaped like a card\n"
    )
    (card,) = oh._parse_seams(raw)
    assert card["assertion_a"] == ""
    assert card["assertion_b"] == ""
    assert card["unparseable"] is True


def test_distinct_garbage_survives_merge_identical_collapses():
    # #11: unparseable cards dedupe on raw text — two different garbage
    # cards both survive; a byte-identical repeat still collapses.
    g1 = oh._parse_seams("**SEAM 1**\n- first flavor of noise\n")[0]
    g2 = oh._parse_seams("**SEAM 2**\n- second flavor of noise\n")[0]
    assert g1["unparseable"] and g2["unparseable"]
    merged = oh._merge_seams([g1], [dict(g2)])
    assert len(merged) == 2
    merged2 = oh._merge_seams([g1], [dict(g1)])
    assert len(merged2) == 1


def test_model_text_rescues_survive_without_invented_prefix():
    # #11: loose-pattern rescues reuse model text verbatim — no invented
    # "Documentation /" framing around a cited TTP code.
    raw = "**SEAM 1**\n- note T1595 active recon observed\n- check missing\n"
    (card,) = oh._parse_seams(raw)
    assert card["assertion_a"] == "T1595 active recon observed"
    assert "Documentation" not in card["assertion_a"]
