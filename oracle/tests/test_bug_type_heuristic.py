"""#21: bug-type labels are an honest keyword heuristic, not a classifier."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import TYPE_1, TYPE_2, OracleMindsetContext


def test_lens_origin_word_is_not_a_code_signal():
    # The bare word "paradox" (lens-origin prose) must not push TYPE_1.
    seam = {
        "assertion_a": "Checkout totals are server-computed",
        "assertion_b": "The paradox lens notes coupon totals shift client-side",
        "impact": "coupon discount abuse",
        "origin": "local-paradox",
    }
    assert OracleMindsetContext.classify_seam(seam) == TYPE_2


def test_zero_signal_tie_defaults_type1_by_convention():
    # No signals either way: the documented tie convention, not evidence.
    seam = {"assertion_a": "A", "assertion_b": "B", "origin": "cloud-mitre"}
    assert OracleMindsetContext.classify_seam(seam) == TYPE_1


def test_code_signals_still_win():
    seam = {
        "assertion_a": "Handler validates input",
        "assertion_b": "SQL injection reaches the query",
        "origin": "cloud-mitre",
    }
    assert OracleMindsetContext.classify_seam(seam) == TYPE_1
