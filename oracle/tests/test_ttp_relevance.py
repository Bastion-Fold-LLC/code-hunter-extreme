"""#23: TTP relevance is target-grounded; compact count is 3/group."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext


def _ctx(**kw):
    return OracleMindsetContext(program={}, voice=False, **kw)


def test_recon_token_boosts_matching_technique():
    ctx = _ctx()
    ctx.inject_recon_context(
        ["https://graphql.acme.com"], ["https://graphql.acme.com/graphql"]
    )
    matching = {
        "code": "T1595",
        "name": "GraphQL Introspection Abuse",
        "tactic": "RECONNAISSANCE",
        "description": "Probe exposed GraphQL endpoints.",
    }
    unrelated = {
        "code": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "CREDENTIAL ACCESS",
        "description": "Dump SAM hashes from disk.",
    }
    assert ctx._ttp_score(matching) > ctx._ttp_score(unrelated)
    assert ctx._ttp_score(unrelated) == 0


def test_no_signal_scores_zero_and_stays_deterministic():
    # No recon, no assets: every record scores 0 (stable file order), and
    # the ordering is deterministic across calls.
    ctx = _ctx()
    recs = ctx._load_ttps()
    assert recs and all(ctx._ttp_score(r) == 0 for r in recs)
    once = [r["code"] for r in sorted(recs, key=ctx._ttp_score, reverse=True)]
    twice = [r["code"] for r in sorted(recs, key=ctx._ttp_score, reverse=True)]
    assert once == twice


def test_compact_selects_three_per_reflex_group():
    # The rule (not "top 15"): min(3, group size) per reflex group.
    ctx = _ctx(ttp_mode="compact")
    recs = ctx._load_ttps()
    expected = sum(min(3, n) for n in Counter(
        r.get("primary_reflex", 0) for r in recs
    ).values())
    block = ctx._ttp_block()
    # Every record opens with a line-start **CODE — name** header.
    headers = [ln for ln in block.splitlines() if ln.startswith("**T")]
    assert len(headers) == expected
    assert "ORACLE TTP REFERENCE" in block
