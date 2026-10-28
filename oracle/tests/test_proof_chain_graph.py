import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_mindset_context import OracleMindsetContext


def _confirmed(number, impact, **fields):
    seam = {"n": number, "assertion_a": "A", "assertion_b": "B",
            "impact": impact, "check": f"check-{number}"}
    seam.update(fields)
    return {"seam": seam, "confirmed": True}


def test_chain_requires_observed_output_to_match_declared_precondition():
    source = _confirmed(1, "Information disclosure", chain_outputs=["order:123"])
    sink = _confirmed(2, "Privilege escalation", chain_preconditions=["order:123"])
    # #22: the sink's executed check must consume the binding — a bare
    # declaration in card prose forms no edge.
    sink["seam"]["check"] = "curl -s http://h.test/orders/order:123/status"

    results = OracleMindsetContext.chain_seams([source, sink])
    chains = [item for item in results if item.get("type") == "chain"]

    assert len(chains) == 1
    assert chains[0]["edge_bindings"] == ["order:123"]


def test_declared_but_unconsumed_precondition_forms_no_edge():
    # #22 negative: B declares the value but its check/output never touch
    # it — model prose alone is not a chain edge.
    source = _confirmed(1, "Information disclosure", chain_outputs=["order:123"])
    sink = _confirmed(2, "Privilege escalation", chain_preconditions=["order:123"])

    results = OracleMindsetContext.chain_seams([source, sink])
    assert [item for item in results if item.get("type") == "chain"] == []


def test_wire_edges_are_labeled_wire():
    source = _confirmed(1, "Information disclosure", chain_outputs=["order:123"])
    sink = _confirmed(2, "Privilege escalation", chain_preconditions=["order:123"])
    sink["seam"]["check"] = "curl -s http://h.test/orders/order:123/status"

    (chain,) = [
        item
        for item in OracleMindsetContext.chain_seams([source, sink])
        if item.get("type") == "chain"
    ]
    assert chain["edge_kinds"] == ["wire"]
    assert "executed check/output consumed" in chain["chain_assertion_b"]


def test_typed_vocabulary_composes_without_wire_text():
    # Deterministic template cards bind on the _CHAIN_IO category labels
    # (never wire literals) — grounding them against the wire would be a
    # category error. The chain says so (edge_kinds + narrative).
    leak = _confirmed(1, "Information disclosure", chain_outputs=["secret"])
    leak["seam"]["origin"] = "seam-template"
    use = _confirmed(2, "Privilege escalation", chain_preconditions=["secret"])
    use["seam"]["origin"] = "seam-template"

    (chain,) = [
        item
        for item in OracleMindsetContext.chain_seams([leak, use])
        if item.get("type") == "chain"
    ]
    assert chain["edge_kinds"] == ["typed"]
    assert "category composition" in chain["chain_assertion_b"]


def test_keyword_similar_findings_do_not_chain_without_typed_binding():
    source = _confirmed(1, "Token information disclosure")
    sink = _confirmed(2, "Authentication bypass using a token")

    results = OracleMindsetContext.chain_seams([source, sink])

    assert [item for item in results if item.get("type") == "chain"] == []
