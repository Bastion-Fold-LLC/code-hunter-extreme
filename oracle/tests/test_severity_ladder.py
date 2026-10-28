"""Severity-ladder contracts for the bug-chain engine.

The ladder is highest-first and promotion is conservative:
  * a complete verified edge may compound impact by one severity step;
  * mere chain length must not manufacture Critical from low findings;
  * structured severity wins over free-form impact wording;
  * explicitly unconfirmed findings never compose;
  * returned chains are ordered by combined severity, then depth.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext


def _finding(
    n,
    severity,
    impact,
    *,
    outputs=None,
    needs=None,
    consumes=None,
    confirmed=True,
    verdict="CONFIRMED",
    origin="model",
):
    binding = consumes or (needs[0] if needs else f"finding-{n}")
    seam = {
        "n": n,
        "assertion_a": f"claim-{n}",
        "assertion_b": f"observed-{n}",
        "severity": severity,
        "impact": impact,
        "check": f"curl -s http://h.test/{binding}",
        "origin": origin,
        "chain_preconditions": list(needs or []),
    }
    return {
        "seam": seam,
        "confirmed": confirmed,
        "verdict": verdict,
        "output": " ".join(outputs or []),
        "chain_outputs": list(outputs or []),
    }


def _chains(results):
    return [item for item in results if item.get("type") == "chain"]


def _only_chain(results):
    chains = _chains(results)
    assert len(chains) == 1, chains
    return chains[0]


def test_small_small_promotes_to_medium_only():
    a = _finding(1, "low", "Low information disclosure", outputs=["tok-1"])
    b = _finding(2, "low", "Low limited profile read", needs=["tok-1"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["links"] == [1, 2]
    assert chain["combined_severity"] == "Medium"


def test_medium_medium_promotes_to_high():
    a = _finding(1, "medium", "Medium partial object read", outputs=["obj-7"])
    b = _finding(2, "medium", "Medium partial state change", needs=["obj-7"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "High"


def test_medium_to_high_promotes_to_critical():
    a = _finding(1, "medium", "Medium partial token disclosure", outputs=["tok-9"])
    b = _finding(2, "high", "High privilege escalation", needs=["tok-9"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Critical"


def test_high_to_critical_stays_critical():
    a = _finding(1, "high", "High privilege escalation", outputs=["admin-1"])
    b = _finding(2, "critical", "Critical account takeover", needs=["admin-1"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Critical"
    assert chain["depth"] == 2


def test_three_hop_low_medium_high_reaches_critical():
    a = _finding(1, "low", "Low identifier disclosure", outputs=["id-1"])
    b = _finding(
        2,
        "medium",
        "Medium partial session access",
        outputs=["sess-2"],
        needs=["id-1"],
    )
    c = _finding(3, "high", "High privilege escalation", needs=["sess-2"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b, c]))
    assert chain["links"] == [1, 2, 3]
    assert chain["combined_severity"] == "Critical"


def _low_chain(count):
    items = []
    for i in range(1, count + 1):
        items.append(
            _finding(
                i,
                "low",
                "Low information disclosure",
                outputs=[f"hop-{i}"] if i < count else [],
                needs=[f"hop-{i - 1}"] if i > 1 else [],
            )
        )
    return items


def test_four_lows_do_not_become_critical_by_count_alone():
    chain = _only_chain(OracleMindsetContext.chain_seams(_low_chain(4)))
    assert chain["depth"] == 4
    assert chain["combined_severity"] == "Medium"


def test_structured_severity_wins_over_generic_impact_text():
    a = _finding(1, "low", "Low identifier disclosure", outputs=["tok-11"])
    b = _finding(2, "high", "Partial access change", needs=["tok-11"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    # Structured High + one verified compounding edge = Critical. The
    # free-form impact alone would only parse as Medium.
    assert chain["combined_severity"] == "Critical"


def test_chains_return_highest_severity_first_not_longest_first():
    lows = _low_chain(4)
    high = _finding(10, "high", "High privilege escalation", outputs=["admin-9"])
    crit = _finding(11, "critical", "Critical account takeover", needs=["admin-9"])
    chains = _chains(OracleMindsetContext.chain_seams(lows + [high, crit]))
    assert len(chains) == 2
    assert chains[0]["links"] == [10, 11]
    assert chains[0]["combined_severity"] == "Critical"
    assert chains[1]["combined_severity"] == "Medium"


def test_explicitly_unconfirmed_sink_never_composes():
    a = _finding(1, "low", "Low information disclosure", outputs=["tok-13"])
    b = _finding(
        2,
        "high",
        "High privilege escalation",
        needs=["tok-13"],
        confirmed=False,
        verdict="REJECTED",
    )
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_broken_wire_edge_does_not_promote():
    a = _finding(1, "medium", "Medium partial disclosure", outputs=["tok-14"])
    b = _finding(
        2,
        "high",
        "High privilege escalation",
        needs=["tok-14"],
        consumes="different-token",
    )
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_direct_critical_single_finding_needs_no_chain():
    only = _finding(1, "critical", "Critical remote code execution")
    results = OracleMindsetContext.chain_seams([only])
    assert results == [only]
    assert _chains(results) == []


def test_typed_template_chain_promotes_and_labels_edge():
    a = _finding(
        1,
        "medium",
        "Medium secret disclosure",
        outputs=["secret"],
        origin="seam-template",
    )
    b = _finding(
        2,
        "high",
        "High privilege escalation",
        needs=["secret"],
        consumes="unrelated-check",
        origin="seam-template",
    )
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Critical"
    assert chain["edge_kinds"] == ["typed"]


def test_maximal_chain_drops_subchains():
    a = _finding(1, "low", "Low disclosure", outputs=["x-1", "x-2"])
    b = _finding(
        2, "medium", "Medium partial access", outputs=["x-2"], needs=["x-1"]
    )
    c = _finding(3, "high", "High privilege escalation", needs=["x-2"])
    chains = _chains(OracleMindsetContext.chain_seams([a, b, c]))
    assert [chain["links"] for chain in chains] == [[1, 2, 3]]


import pytest


@pytest.mark.parametrize(
    "verdict",
    [
        "REJECTED ",
        " rejected",
        "Rejected.",
        "REJECTED — Seam 2 failed",
        "NOT CONFIRMED",
        "NOT-CONFIRMED",
        "UNCONFIRMED",
        "FALSE_POSITIVE",
        "DISPROVEN",
    ],
)
def test_negative_verdict_variants_never_compose(verdict):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-v"])
    b = _finding(
        2, "high", "High privilege escalation", needs=["tok-v"], verdict=verdict
    )
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


@pytest.mark.parametrize("confirmed", [0, "false", None])
def test_present_nontrue_confirmed_flag_never_composes(confirmed):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-c"])
    b = _finding(
        2,
        "high",
        "High privilege escalation",
        needs=["tok-c"],
        confirmed=confirmed,
    )
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_masked_verify_verdict_never_composes():
    a = _finding(1, "low", "Low disclosure", outputs=["tok-m"])
    b = _finding(2, "high", "High privilege escalation", needs=["tok-m"])
    b["seam"]["verify_verdict"] = "REJECTED — wire mismatch"
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_unknown_severity_and_impact_fail_closed():
    a = _finding(1, None, "", outputs=["tok-u"])
    b = _finding(2, None, "", needs=["tok-u"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Low"


def test_severity_synonyms_are_canonicalized():
    a = _finding(1, "information", "", outputs=["tok-i"])
    b = _finding(2, "information", "", needs=["tok-i"])
    assert _only_chain(OracleMindsetContext.chain_seams([a, b]))[
        "combined_severity"
    ] == "Low"
    c = _finding(3, "moderate", "", outputs=["tok-mod"])
    d = _finding(4, "moderate", "", needs=["tok-mod"])
    assert _only_chain(OracleMindsetContext.chain_seams([c, d]))[
        "combined_severity"
    ] == "High"


def test_negated_impact_keywords_do_not_inflate():
    a = _finding(1, "low", "Low disclosure", outputs=["tok-n"])
    b = _finding(
        2,
        "",
        "Not critical; no account takeover; informational only",
        needs=["tok-n"],
    )
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


def test_duplicate_card_cannot_self_chain_or_duplicate_chain():
    self_feed = _finding(
        1,
        "medium",
        "Medium partial access",
        outputs=["loop-1"],
        needs=["loop-1"],
    )
    assert _chains(OracleMindsetContext.chain_seams([self_feed, dict(self_feed)])) == []
    a = _finding(1, "low", "Low disclosure", outputs=["dup-1"])
    b = _finding(2, "high", "High privilege escalation", needs=["dup-1"])
    chains = _chains(OracleMindsetContext.chain_seams([a, b, dict(b)]))
    assert [chain["links"] for chain in chains] == [[1, 2]]


def test_wire_binding_must_be_observed_and_exact():
    ghost = _finding(1, "low", "Low disclosure", outputs=["ghost-tok"])
    ghost["output"] = "nothing useful"
    sink = _finding(2, "high", "High privilege escalation", needs=["ghost-tok"])
    assert _chains(OracleMindsetContext.chain_seams([ghost, sink])) == []

    a = _finding(1, "low", "Low disclosure", outputs=["tok-1"])
    near = _finding(
        2, "high", "High privilege escalation", needs=["tok-1"], consumes="tok-10"
    )
    assert _chains(OracleMindsetContext.chain_seams([a, near])) == []


def test_golden_shape_nested_candidate_still_composes_typed():
    a = _finding(
        1, "medium", "Medium secret disclosure", outputs=["secret"], origin="seam-template"
    )
    b = _finding(
        2,
        "high",
        "High privilege escalation",
        needs=["secret"],
        consumes="unrelated",
        origin="seam-template",
    )
    for item in (a, b):
        item.pop("confirmed")
        item.pop("verdict")
        item.pop("output")
        item.pop("chain_outputs")
        item["seam"]["verdict"] = "CANDIDATE"
    a["seam"]["chain_outputs"] = ["secret"]
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["edge_kinds"] == ["typed"]


def test_wrapper_chain_outputs_precedence_and_empty_fallback():
    a = _finding(1, "low", "Low disclosure", outputs=[], origin="seam-template")
    a["seam"]["chain_outputs"] = ["secret"]
    b = _finding(
        2,
        "high",
        "High privilege escalation",
        needs=["secret"],
        consumes="unrelated",
        origin="seam-template",
    )
    assert _chains(OracleMindsetContext.chain_seams([a, b]))
    a["chain_outputs"] = ["stale"]
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_wrapper_executed_check_controls_wire_consumption():
    a = _finding(1, "low", "Low disclosure", outputs=["tok-w"])
    b = _finding(2, "high", "High privilege escalation", needs=["tok-w"])
    b["check"] = "curl -s http://h.test/other"
    b["output"] = "clean"
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def _model_seam(n, impact, check, **extra):
    seam = {
        "n": n,
        "assertion_a": f"claim-{n}",
        "assertion_b": f"observed-{n}",
        "check": check,
        "expected": "status 200",
        "impact": impact,
        "origin": "cloud-mitre",
    }
    seam.update(extra)
    return seam


def _run_finalize_chain(tmp_path, monkeypatch, *, observed=True, chain_fn="ctx"):
    import oracle_hunter as oh
    from oracle_mindset_context import ProgramWorkspace

    monkeypatch.setattr(oh, "_synthesize_poc", lambda *a, **k: "poc")
    monkeypatch.setattr(oh, "_correlate_seams", lambda *a, **k: None)
    ws = ProgramWorkspace({"name": "Lab", "platform": "lab"}, base=tmp_path)
    recon = tmp_path / "recon"
    recon.mkdir(exist_ok=True)
    src = _model_seam(
        1,
        "Low information disclosure",
        "curl -s http://h.test/source",
        chain_output_candidates=["tok-final"],
    )
    sink = _model_seam(
        2,
        "High privilege escalation",
        "curl -s http://h.test/use/tok-final",
        chain_preconditions=["tok-final"],
    )
    results = {
        1: {
            "seam": src,
            "check": src["check"],
            "output": "tok-final" if observed else "nothing",
            "verdict": "CONFIRMED — stub",
            "confirmed": True,
        },
        2: {
            "seam": sink,
            "check": sink["check"],
            "output": "tok-final consumed",
            "verdict": "CONFIRMED — stub",
            "confirmed": True,
        },
    }
    ctx = OracleMindsetContext(program={"name": "Lab"}, voice=False, mindset="mitre")
    oh._finalize_verify(
        results,
        [src, sink],
        "lab-target",
        ws,
        recon_dir=recon,
        no_cloud=True,
        chain_seams_fn=ctx.chain_seams if chain_fn == "ctx" else None,
        teardown_runner=lambda c: (0, "VULN", ""),
        teardown_evaluator=lambda s, o: {
            "verdict": "CONFIRMED" if "VULN" in o else "REJECTED",
            "reason": "stub",
        },
    )
    tops = sorted(ws.reports_dir.glob("report_compound_chain_TOP*.md"))
    return results, tops


def test_finalize_promotes_only_observed_model_outputs(tmp_path, monkeypatch):
    results, tops = _run_finalize_chain(tmp_path, monkeypatch, observed=True)
    assert results[1]["chain_outputs"] == ["tok-final"]
    assert len(tops) == 1
    assert "Critical" in tops[0].read_text(encoding="utf-8")


def test_finalize_unobserved_candidate_and_standalone_make_no_top(tmp_path, monkeypatch):
    results, tops = _run_finalize_chain(tmp_path, monkeypatch, observed=False)
    assert results[1]["chain_outputs"] == []
    assert tops == []
    _results2, tops2 = _run_finalize_chain(
        tmp_path / "standalone", monkeypatch, observed=True, chain_fn=None
    )
    assert tops2 == []


@pytest.mark.parametrize("severity", ["not critical", "NOT CRITICAL — low"])
def test_negated_structured_severity_does_not_inflate(severity):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-ns"])
    b = _finding(2, severity, "", needs=["tok-ns"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


@pytest.mark.parametrize(
    "severity",
    ["P4", "bogus", "9.8", "severe", "not critical", "low (not high)"],
)
def test_unparseable_structured_severity_never_falls_through_to_impact(severity):
    # A present structured severity that cannot be canonicalized must
    # fail closed at info rank. Hot impact wording must not launder it
    # into a Critical chain (audit S1).
    a = _finding(1, "low", "Low disclosure", outputs=["tok-up"])
    b = _finding(
        2,
        severity,
        "Critical account takeover via remote code execution",
        needs=["tok-up"],
    )
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


@pytest.mark.parametrize(
    "impact",
    [
        "This control prevents account takeover",
        "The mitigation blocks remote code execution",
        "Patched: previously allowed remote code execution",
        "Unlikely to enable account takeover",
    ],
)
def test_mitigated_impact_phrasings_do_not_inflate(impact):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-mi"])
    b = _finding(2, "", impact, needs=["tok-mi"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


@pytest.mark.parametrize(
    "severity",
    [
        "patched: critical",
        "not; critical",
        "critical. prevented",
        "prevent critical",
        "fixed critical",
        "resolved critical",
        "can’t critical",
    ],
)
def test_negated_structured_severity_across_separators_fails_closed(severity):
    # A negation marker anywhere in a structured severity zeroes it,
    # even when a clause separator strands the severity token.
    a = _finding(1, "low", "Low disclosure", outputs=["tok-nx"])
    b = _finding(
        2,
        severity,
        "Critical account takeover via remote code execution",
        needs=["tok-nx"],
    )
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


@pytest.mark.parametrize(
    "severity",
    [["critical"], {"level": "low", "note": "critical"}, b"critical", ("critical",)],
)
def test_container_severity_is_never_string_scanned(severity):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-cs"])
    b = _finding(
        2,
        severity,
        "Critical account takeover via remote code execution",
        needs=["tok-cs"],
    )
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


def test_embedded_med_and_underscore_composites_still_rank():
    a = _finding(1, "low", "Low disclosure", outputs=["tok-em"])
    b = _finding(2, "severity: med", "Partial state change", needs=["tok-em"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "High"

    a = _finding(1, "low", "Low disclosure", outputs=["tok-em2"])
    b = _finding(2, "critical_severity", "Account takeover", needs=["tok-em2"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Critical"


@pytest.mark.parametrize(
    "impact",
    [
        "no evidence of RCE",
        "cannot lead to account takeover",
        "Non-critical information only",
        "isn't critical",
    ],
)
def test_broad_negated_impact_does_not_inflate(impact):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-ni"])
    b = _finding(2, "", impact, needs=["tok-ni"])
    chain = _only_chain(OracleMindsetContext.chain_seams([a, b]))
    assert chain["combined_severity"] == "Medium"


@pytest.mark.parametrize(
    "verdict",
    [
        "CANDIDATE — never executed",
        "Verdict: REJECTED",
        "UNVERIFIED",
        "PENDING",
        "NOT_VERIFIED",
    ],
)
def test_wrapper_nonconfirmed_verdict_phrases_never_compose(verdict):
    a = _finding(1, "low", "Low disclosure", outputs=["tok-wv"])
    b = _finding(
        2, "high", "High privilege escalation", needs=["tok-wv"], verdict=verdict
    )
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_nested_seam_rejected_verdict_never_composes():
    a = _finding(1, "low", "Low disclosure", outputs=["tok-nv"])
    b = _finding(2, "high", "High privilege escalation", needs=["tok-nv"])
    b["seam"]["verdict"] = "REJECTED"
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []


def test_empty_wrapper_check_does_not_resurrect_declared_check():
    a = _finding(1, "low", "Low disclosure", outputs=["tok-ec"])
    b = _finding(2, "high", "High privilege escalation", needs=["tok-ec"])
    b["check"] = ""
    b["output"] = "clean"
    assert _chains(OracleMindsetContext.chain_seams([a, b])) == []
