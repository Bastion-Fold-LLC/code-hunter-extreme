"""R4 mistag regression: emitter MITRE/CWE literals must stay corrected.

Locks the corrected tags at all four emitters so the systematic T1078
mistag (and the CWE-1104 / T1190 misfires) cannot silently return.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_auth_session as auth_sess
import oracle_code_seam as code_seam
import oracle_seam_templates as st
from oracle_auth_session import DualAccountHarness
from oracle_deterministic import check_open_api, check_security_headers

_TEMPLATE_EXPECTED = {
    "vacuum-identity-decoupling": "CWE-285 / T1190",
    "single-token-symmetry-break": "CWE-20 / T1595",
    "repulsive-gravity-axiom-rewrite": "CWE-289 / T1190",
    "deathless-hierarchy": "CWE-1068 / T1595",
    "t1190-artifact-exposure": "CWE-538 / T1592",
    "code-mirror-config-drift": "CWE-1068",
    "code-deathless-deprecated": "CWE-1068",
    "beautiful-liar-trust-bypass": "CWE-290 / T1550",
    "cliff-and-current-alt-path": "CWE-288 / T1190",
    "injection-sqli-probe": "CWE-89 / T1190",
    "injection-xss-probe": "CWE-79 / T1190",
    "idor-direct-object-reference": "CWE-639 / T1190",
}

# The code-seam emitter is now the universal claim-vs-reality mapper.
# These cases intentionally use behavior text, not deleted per-language
# claim-type IDs, and lock the mapper to corrected CWE labels.
_CODE_CASES = {
    "credential-paradox": (
        {
            "assertion_a": "The api_key secret is strictly required",
            "assertion_b": "The runtime accepts the built-in default secret",
            "question": "",
            "classification": "PARADOX",
        },
        "CWE-798: Use of Hard-coded Credentials / CWE-1188: Insecure Default Initialization",
    ),
    "auth-fail-open": (
        {
            "assertion_a": "The auth token check raises on malformed tokens",
            "assertion_b": "The token check returns False and execution continues",
            "question": "",
            "classification": "FIXABLE",
        },
        "CWE-287: Improper Authentication / CWE-754: Improper Check for Exceptional Conditions",
    ),
    "config-paradox": (
        {
            "assertion_a": "The configuration schema requires an explicit value",
            "assertion_b": "The implementation uses a contradictory default",
            "question": "",
            "classification": "PARADOX",
        },
        "CWE-1068: Inconsistency Between Implementation and Documented Design",
    ),
    "return-contract": (
        {
            "assertion_a": "The function always returns a list",
            "assertion_b": "The function returns None for an empty result",
            "question": "",
            "classification": "FIXABLE",
        },
        "CWE-476: NULL Pointer Dereference / CWE-843: Type Confusion",
    ),
    "config-fixable": (
        {
            "assertion_a": "The configuration schema requires an explicit timeout",
            "assertion_b": "The implementation silently applies a fallback value",
            "question": "",
            "classification": "FIXABLE",
        },
        "CWE-16: Configuration Weakness / CWE-1068",
    ),
    "default-generic": (
        {
            "assertion_a": "Order total must be strictly positive",
            "assertion_b": "Order handler accepts negative quantities without raising",
            "question": "",
            "classification": "FIXABLE",
        },
        "CWE-754: Improper Check for Exceptional Conditions",
    ),
}


def test_template_tags_corrected():
    by_tid = {t["tid"]: t["mitre"] for t in st.TEMPLATES}
    for tid, expected in _TEMPLATE_EXPECTED.items():
        assert by_tid[tid] == expected, f"{tid}: {by_tid[tid]} != {expected}"


def test_no_template_carries_t1078_or_cwe1104():
    for t in st.TEMPLATES:
        assert "T1078" not in t["mitre"], f"{t['tid']} regressed to T1078"
        assert "CWE-1104" not in t["mitre"], f"{t['tid']} regressed to CWE-1104"


def _mapped_code_seam_tags():
    for label, (fields, expected) in _CODE_CASES.items():
        seam = SimpleNamespace(**fields)
        candidate = SimpleNamespace()
        _reflex, mitre, _impact = code_seam._map_seam_to_security_reflex(
            seam, candidate
        )
        yield label, mitre, expected


def test_code_seam_tags_corrected():
    for _label, mitre, expected in _mapped_code_seam_tags():
        assert mitre == expected


def test_no_code_seam_carries_t1078():
    for label, mitre, _expected in _mapped_code_seam_tags():
        assert "T1078" not in mitre, f"{label} regressed to T1078"


def test_missing_headers_tagged_t1595_not_t1190():
    findings = check_security_headers("http://127.0.0.1:9999/", {})
    assert findings, "expected findings for fully-missing headers"
    for f in findings:
        if "strict-transport-security" in f["evidence"]:
            assert f["mitre"] == ["T1557"]
        else:
            assert f["mitre"] == ["T1595"], f["evidence"]


def test_open_api_dual_tags_locked():
    """Item 7: check_open_api keeps its deliberate dual T1190+T1595 tags.

    A 200 with no auth challenge on an API path is an exploitable
    misconfiguration (T1190), not mere observation; T1595 covers the
    active-probing discovery side. Locks the emitted finding's tags so a
    T1595-only "alignment" cannot silently land.
    """
    findings = check_open_api("http://127.0.0.1:9999/api/users", 200, {}, "{}")
    assert len(findings) == 1, f"expected one open_api finding, got {findings}"
    assert findings[0]["mitre"] == ["T1190", "T1595"], findings[0]["mitre"]


def test_idor_probe_tags_corrected():
    harness = DualAccountHarness(
        "target.com", platform="hackerone", researcher_username="phantomcore"
    )
    seams = [{"check": "curl -i -s 'https://target.com/api/orders/ord_12345'"}]
    probes = harness.build_idor_probes(seams)
    cards = [p for p in probes if not p.get("_dropped")]
    markers = [p for p in probes if p.get("_dropped")]
    assert cards, "expected at least one IDOR probe card"
    for c in cards:
        assert c["mitre"] == "CWE-639 / T1190", c["mitre"]
    for m in markers:
        assert m["mitre"] == "N/A", m["mitre"]
