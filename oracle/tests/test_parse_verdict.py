"""parse_verdict grammar — anchored verdict classification (E0, 2026-10-20).

The assess-prompt contract ("start with exactly one" verdict) is now
enforced by the classifier itself, not trusted from prose. Every honest
_assess_response return shape must keep classifying; the fake class must
not.
"""

from oracle_foundation import parse_verdict


def test_confirmed_deterministic_shape():
    assert (
        parse_verdict(
            "CONFIRMED (deterministic) — Sensitive configuration exposed."
        )  # noqa: E501
        == "CONFIRMED"
    )


def test_confirmed_plain_shape():
    assert parse_verdict("CONFIRMED — proves assertion B.") == "CONFIRMED"


def test_confirmed_markdown_bold():
    assert parse_verdict("**CONFIRMED** — proof follows.") == "CONFIRMED"


def test_false_positive_shape():
    assert (
        parse_verdict(
            "FALSE_POSITIVE — Target returned access denial (401/403)."
        )  # noqa: E501
        == "FALSE_POSITIVE"
    )


def test_false_positive_hyphen_shape():
    assert (
        parse_verdict("False-positive — benign behavior.") == "FALSE_POSITIVE"
    )  # noqa: E501


def test_inconclusive_shape():
    assert (
        parse_verdict("INCONCLUSIVE" " — no backend available for assessment.")
        == "INCONCLUSIVE"
    )


def test_unconfirmed_is_unknown():
    assert parse_verdict("UNCONFIRMED — probe did not reproduce.") == "UNKNOWN"


def test_not_confirmed_is_unknown():
    assert (
        parse_verdict("NOT CONFIRMED — expected 403, seen 403.") == "UNKNOWN"
    )  # noqa: E501


def test_possibly_confirmed_is_unknown():
    assert parse_verdict("POSSIBLY CONFIRMED IF misauth applies.") == "UNKNOWN"


def test_confirmed_mentioned_mid_text_is_unknown():
    assert (
        parse_verdict("The 403 wire could never read as CONFIRMED here.")  # noqa: E501
        == "UNKNOWN"
    )


def test_leading_whitespace_is_anchored_too():
    assert (
        parse_verdict("  CONFIRMED — after a newline lead-in.") == "CONFIRMED"
    )  # noqa: E501


def test_garbage_empty_none_rejected():
    assert parse_verdict("") == "UNKNOWN"
    assert parse_verdict(None) == "UNKNOWN"
    assert (
        parse_verdict("REJECTED — wire differs from expectation.") == "UNKNOWN"
    )  # noqa: E501
    assert parse_verdict("200 OK — response looks normal.") == "UNKNOWN"
