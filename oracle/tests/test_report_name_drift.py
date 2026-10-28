"""Phase 2.4 — report name drift prevention.

The reporting_prompt() must explicitly forbid paraphrasing the check URL path
in the finding title. This locks the rule so model drift (e.g. '/.git/config'
renamed 'self-observe endpoint') is caught at prompt generation time.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext


def test_reporting_prompt_contains_title_rule():
    """TITLE RULE must be present in the reporting prompt for every mindset."""
    for mindset in ("seam", "mitre", "paradox"):
        ctx = OracleMindsetContext(mindset=mindset)
        p = ctx.reporting_prompt()
        assert "TITLE RULE" in p, f"{mindset}: TITLE RULE missing from reporting_prompt"
        assert "verbatim" in p, f"{mindset}: 'verbatim' missing from reporting_prompt"
        assert "character-for-character" in p, (
            f"{mindset}: 'character-for-character' missing from reporting_prompt"
        )


def test_reporting_prompt_names_paraphrase_example():
    """The prompt must name the exact bad example so the model can recognise it."""
    ctx = OracleMindsetContext(mindset="seam")
    p = ctx.reporting_prompt()
    assert "self-observe endpoint" in p, (
        "Example bad paraphrase 'self-observe endpoint' missing — "
        "model cannot pattern-match against unnamed examples"
    )
    assert "/.git/config" in p, (
        "Canonical URL example '/.git/config' missing from the rule"
    )


def test_reporting_prompt_shorter_than_hunting_prompt():
    """The reporting prompt must be lean — must not embed the full TTP library
    (hunt-4c lesson: 106KB + 16k context = 600s idle timeout)."""
    ctx = OracleMindsetContext(mindset="seam")
    report_p = ctx.reporting_prompt()
    hunt_p = ctx.system_prompt()
    assert len(report_p) < len(hunt_p) // 2, (
        f"reporting_prompt ({len(report_p)}B) is not significantly smaller than "
        f"system_prompt ({len(hunt_p)}B) — TTP corpus may have leaked in"
    )
