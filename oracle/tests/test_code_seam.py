import os

import pytest
from pathlib import Path
from oracle_code_seam import (
    scan_repository_seams,
    generate_code_audit_report,
    seam_engine_status,
    _map_seam_to_security_reflex,
    _program_scope_gate,
)

# oracle_code_seam inserts INVISIBLE_SEAM_PATH / ~/invisible-seam/src into
# sys.path before importing the engine, so availability must be judged via
# seam_engine_status() AFTER that import — never by a bare importorskip
# here, which would false-skip a src-layout checkout.
_SEAM_STATUS = seam_engine_status()
_SEAM_EXPECTED = bool(os.environ.get("INVISIBLE_SEAM_PATH")) or (
    Path.home() / "invisible-seam"
).is_dir()
requires_seam_engine = pytest.mark.skipif(
    not _SEAM_STATUS["available"],
    reason=_SEAM_STATUS["reason"],
)


def test_seam_engine_available_when_checkout_present():
    """Absent sibling (CI) skips; present-but-broken sibling must FAIL,
    never silently skip — availability conflates the two otherwise."""
    if not _SEAM_EXPECTED and not _SEAM_STATUS["available"]:
        pytest.skip("no invisible-seam checkout on this machine")
    assert _SEAM_STATUS["available"], _SEAM_STATUS["reason"]


def _demo_repo() -> Path:
    """Locate the sibling checkout's demo_repo without hardcoding a user.

    Search: INVISIBLE_SEAM_PATH (src dir or checkout root), the installed
    package's location (src-layout checkout), then ~/invisible-seam.
    """
    candidates = []
    env = os.environ.get("INVISIBLE_SEAM_PATH")
    if env:
        base = Path(env)
        candidates += [base / "demo_repo", base.parent / "demo_repo"]
    try:
        import importlib.util

        spec = importlib.util.find_spec("invisible_seam")
        if spec and spec.origin:
            pkg = Path(spec.origin).resolve()
            candidates += [pkg.parents[2] / "demo_repo", pkg.parents[1] / "demo_repo"]
    except (ImportError, ValueError):
        pass
    candidates.append(Path.home() / "invisible-seam" / "demo_repo")
    for cand in candidates:
        if cand.is_dir():
            return cand
    return candidates[-1]


@requires_seam_engine
def test_scan_repository_seams_on_demo_repo():
    demo_path = _demo_repo()
    seams = scan_repository_seams(demo_path)

    assert len(seams) >= 5
    # Check that canonical IDs are assigned
    assert seams[0]["id"] == "S001"
    assert seams[1]["id"] == "S002"

    # Check that assertions exist
    for s in seams:
        assert s["assertion_a"]
        assert s["assertion_b"]
        assert s["source_a"]
        assert s["source_b"]
        assert s["verdict"] in ("RESOLVED", "CERTAIN", "CLOSED", "UNSOLVED")
        assert "REFLEX" in s["reflex"]
        assert "CWE" in s["mitre"]

    # Verify that the auth fail-open seam was caught
    auth_seams = [s for s in seams if "authenticate" in s["assertion_b"]]
    assert len(auth_seams) >= 1
    assert any("REFLEX 5" in s["reflex"] for s in auth_seams)
    assert any("RESOLVED" in s["verdict"] for s in auth_seams)

    # Verify that the api_key seams were caught
    key_seams = [s for s in seams if "api_key" in s["assertion_a"]]
    assert len(key_seams) == 2
    assert any(s["classification"] == "FIXABLE" for s in key_seams)
    assert any(s["classification"] == "PARADOX" for s in seams)


@requires_seam_engine
def test_produced_cards_satisfy_binary_card_contract():
    """Connection-trace DEAD #2: invisible-seam cards omitted `expected`,
    so validate_card_shape always failed and the hunt code_only confirm
    path could never confirm any card in this class."""
    from oracle_foundation import validate_card_shape

    seams = scan_repository_seams(_demo_repo())
    assert seams
    for s in seams:
        assert validate_card_shape(s) is None, (s["n"], s.get("check"))


@requires_seam_engine
def test_seam_reflex_mapping():
    from invisible_seam.models import Seam, SeamCandidate

    # Test credential fallback mapping
    seam_cred = Seam(
        id="S001",
        classification="PARADOX",
        assertion_a="Config requires api_key",
        source_a=Path("config.json"),
        line_a=1,
        assertion_b="Code uses secret default_key",
        source_b=Path("loader.py"),
        line_b=10,
        check=None,
        verdict="CERTAIN",
        question="Is api_key required?",
    )
    cand_cred = SeamCandidate(
        "C001", "Code uses secret default_key", Path("loader.py"), 10, True
    )
    reflex, mitre, impact = _map_seam_to_security_reflex(seam_cred, cand_cred)
    assert "REFLEX 5" in reflex
    assert "CWE-798" in mitre

    # Test type / null return mapping
    seam_type = Seam(
        id="S002",
        classification="FIXABLE",
        assertion_a="Function returns list[str]",
        source_a=Path("users.py"),
        line_a=1,
        assertion_b="Function returns None",
        source_b=Path("users.py"),
        line_b=5,
        check="python check.py",
        verdict="RESOLVED",
        question=None,
    )
    cand_type = SeamCandidate(
        "C002", "Function returns None", Path("users.py"), 5, True
    )
    reflex_t, mitre_t, impact_t = _map_seam_to_security_reflex(seam_type, cand_type)
    assert "REFLEX 2" in reflex_t
    assert "CWE-476" in mitre_t


@requires_seam_engine
def test_generate_code_audit_report():
    demo_path = _demo_repo()
    seams = scan_repository_seams(demo_path)
    compound = {
        "summary": "Compound Threat: Unauthenticated API Key extraction leads to total system takeover.",
        "report": "### Exploit Vector\nAttacker chains default key with auth fail-open.",
        "confidence": "HIGH",
        "count": len(seams),
    }

    report = generate_code_audit_report("demo_repo", seams, compound_report=compound)
    assert "# Oracle White-Hat Security Code Audit: demo_repo" in report
    assert "## Vulnerability & Seam Details" in report
    assert "## Compound Threat Modeling" in report
    assert "Deterministic PoC Check" in report


def test_program_scope_gate_skips_vendored_code():
    from pathlib import Path as _P

    for vendored in (
        "app/static/js/jquery-3.5.1.min.js",
        "app/static/css/bootstrap.min.css",
        "src/vendor/lib/util.js",
        "x/node_modules/pkg/index.js",
        "lib/third_party/auth.py",
    ):
        ok, reason = _program_scope_gate(_P(vendored), {"name": "P"})
        assert not ok, vendored
        assert "vendored" in reason
    # First-party code still passes, with and without program context.
    ok, _ = _program_scope_gate(_P("app/routes.py"), {"name": "P"})
    assert ok
    ok, _ = _program_scope_gate(_P("app/routes.py"), None)
    assert ok


# ── P9: Solidity matcher wiring ──────────────────────────────────────────────
# ARCHITECTURE.md promises a Solidity matcher; scan_repository_seams must route
# guard-asserting claims about .sol functions to match_solidity_doc_claim so a
# missing guard becomes a seam card, while guarded / non-guard fixtures stay
# silent (fail closed).

_SOL_MISSING_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    uint256 public price;

    /// @notice Only the owner can call setPrice. Reverts otherwise.
    function setPrice(uint256 p) public {
        price = p;
    }
}
"""

_SOL_GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address owner;
    uint256 public price;

    /// @notice Only the owner can call setPrice. Reverts otherwise.
    function setPrice(uint256 p) public onlyOwner {
        price = p;
    }
}
"""

_SOL_NO_GUARD_WORDING = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    uint256 public price;

    /// @notice Updates the stored price to the new value.
    function setPrice(uint256 p) public {
        price = p;
    }
}
"""


@requires_seam_engine
def test_solidity_natspec_missing_guard_matches():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(prefix="p9_sol_match_") as td:
        repo = Path(td)
        (repo / "Vault.sol").write_text(_SOL_MISSING_GUARD)
        seams = scan_repository_seams(repo)
    assert len(seams) >= 1
    sol_seams = [s for s in seams if str(s["source_b"]).endswith(".sol")]
    assert len(sol_seams) >= 1
    assert any("has NO" in s["assertion_b"] for s in sol_seams)
    for s in sol_seams:
        assert s["verdict"] in ("RESOLVED", "CERTAIN", "CLOSED", "UNSOLVED")
        assert "REFLEX" in s["reflex"]
        assert "CWE" in s["mitre"]


@requires_seam_engine
def test_solidity_matcher_wired_past_python_collision():
    """A claim whose subject also names a Python function must still match .sol.

    match_claims is Python-AST-first: it resolves `greet` to foo.py, finds no
    raises/never-None wording, and drops the claim. The explicit Solidity
    wiring must pick it up so the unguarded .sol function still becomes a seam.
    """
    from tempfile import TemporaryDirectory

    readme = "# Demo\n\n## `greet(name)`\n\ngreet requires the caller to be the owner; unauthorized calls revert.\n"
    foo_py = 'def greet(name):\n    """Say hi."""\n    return f"hi {name}"\n'
    greeter_sol = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Greeter {
    function greet(string memory name) public returns (string memory) {
        return name;
    }
}
"""
    with TemporaryDirectory(prefix="p9_sol_collide_") as td:
        repo = Path(td)
        (repo / "README.md").write_text(readme)
        (repo / "foo.py").write_text(foo_py)
        (repo / "Greeter.sol").write_text(greeter_sol)
        seams = scan_repository_seams(repo)
    sol_seams = [s for s in seams if str(s["source_b"]).endswith(".sol")]
    assert len(sol_seams) >= 1
    assert any("greet" in s["assertion_b"] for s in sol_seams)


@requires_seam_engine
def test_solidity_guarded_claim_fails_closed():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(prefix="p9_sol_closed_") as td:
        repo = Path(td)
        (repo / "Vault.sol").write_text(_SOL_GUARDED)
        seams = scan_repository_seams(repo)
    assert seams == []


@requires_seam_engine
def test_solidity_nonguard_natspec_fails_closed():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(prefix="p9_sol_nonbehav_") as td:
        repo = Path(td)
        (repo / "Vault.sol").write_text(_SOL_NO_GUARD_WORDING)
        seams = scan_repository_seams(repo)
    assert seams == []
