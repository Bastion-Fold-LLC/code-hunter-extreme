#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: scan_web3_seams
# TOPICS: none
"""
Oracle Web3 Seam Templates — paradox/invariant-driven smart contract seams.

8 specialized template functions operating deterministically over contract
ABI specifications and Slither analyzer detector outputs:

1. Reentrancy (_t_reentrancy):
   Assertion A: State mutations must finalize prior to external calls (Checks-Effects-Interactions).
   Assertion B: External call precedes state variable write; reentrancy window exposed.
2. Arbitrary Send / Fund Drain (_t_arbitrary_send):
   Assertion A: Funds/tokens can only be transferred to authorized recipients or msg.sender.
   Assertion B: Function allows caller to send contract assets to arbitrary recipient without authorization.
3. Tx.Origin Authentication (_t_tx_origin):
   Assertion A: Caller authorization must inspect immediate execution context (msg.sender).
   Assertion B: Authorization relies on tx.origin; vulnerable to phishing delegation attack.
4. Unchecked Low-Level Call (_t_unchecked_call):
   Assertion A: Low-level call return status must be validated and reverted on failure.
   Assertion B: Call return value ignored; transfer or external execution failure silently passes.
5. Suicidal / Unprotected Selfdestruct (_t_unprotected_destruction):
   Assertion A: Contract destruction restricted to verified multi-sig or governance.
   Assertion B: Publicly accessible selfdestruct() allows arbitrary callers to destroy contract.
6. Controlled Delegatecall (_t_untrusted_delegatecall):
   Assertion A: Delegatecall targets must be immutable or restricted to governance whitelist.
   Assertion B: Arbitrary caller controls delegatecall target; execution context hijackable.
7. Unprotected Upgrade / Init (_t_unprotected_upgrade_or_init):
   Assertion A: Initialization must be single-use and locked during construction.
   Assertion B: Initializer remains callable or uninitialized proxy can be seized.
8. ABI Privileged Seam (_t_abi_privileged_bypass):
   Assertion A: Critical state-changing ABI functions (withdraw/pause/mint) must enforce access control.
   Assertion B: ABI exposes sensitive nonpayable function with no modifier or authorization check.

Card schema matches oracle_seam_templates.py:
origin="seam-template-web3", verdict="CANDIDATE".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


def _load_json(p: Optional[Union[str, Path]]) -> Optional[Any]:
    if not p:
        return None
    path = Path(p)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def _find_sol_file(target_dir: Optional[Path], fallback_name: str = "") -> str:
    """Find the primary .sol file in directory or return fallback path."""
    if not target_dir or not target_dir.exists():
        return fallback_name or "Contract.sol"
    if target_dir.is_file() and target_dir.suffix.lower() == ".sol":
        return str(target_dir)
    sol_files = list(target_dir.rglob("*.sol"))
    if sol_files:
        return str(sol_files[0])
    return str(target_dir / fallback_name) if fallback_name else str(target_dir)


def _build_material(
    recon_dir: Optional[Path] = None,
    repo_path: Optional[Path] = None,
    abi_path: Optional[Path] = None,
    slither_json_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Gather ABI and Slither detector material from recon directory or parameters."""
    recon = Path(recon_dir) if recon_dir else None
    repo = Path(repo_path) if repo_path else None

    # Load ABI
    abi_data = None
    if abi_path:
        abi_data = _load_json(abi_path)
    elif recon and (recon / "abi.json").is_file():
        abi_data = _load_json(recon / "abi.json")
    elif repo and (repo / "abi.json").is_file():
        abi_data = _load_json(repo / "abi.json")

    # Load Slither Output
    slither_data = None
    if slither_json_path:
        slither_data = _load_json(slither_json_path)
    elif recon and (recon / "slither_output.json").is_file():
        slither_data = _load_json(recon / "slither_output.json")
    elif repo and (repo / "slither_output.json").is_file():
        slither_data = _load_json(repo / "slither_output.json")

    detectors = []
    if isinstance(slither_data, dict):
        detectors = slither_data.get("results", {}).get("detectors", [])
    elif isinstance(slither_data, list):
        detectors = slither_data

    # Locate source file
    src_file = ""
    if repo and repo.is_file() and repo.suffix.lower() == ".sol":
        src_file = str(repo)
    elif recon and (recon / "sources").is_dir():
        src_file = _find_sol_file(recon / "sources")
    elif repo and repo.is_dir():
        src_file = _find_sol_file(repo)

    return {
        "abi": abi_data or [],
        "detectors": detectors,
        "src_file": src_file or "Contract.sol",
        "recon_dir": recon,
        "repo_path": repo,
    }


def _extract_detector_elements(det: Dict[str, Any]) -> Tuple[str, str, int]:
    """Extract (contract_name, func_name, line_num) from detector element mapping."""
    elements = det.get("elements", [])
    func_name = ""
    contract_name = ""
    line_num = 0
    for el in elements:
        sm = el.get("source_mapping", {})
        lines = sm.get("lines", [])
        if lines and not line_num:
            line_num = lines[0]
        t = el.get("type", "")
        if t == "function" and not func_name:
            func_name = el.get("name", "")
            parent = el.get("type_specific_fields", {}).get("parent", {})
            if parent.get("type") == "contract":
                contract_name = parent.get("name", "")
        elif t == "contract" and not contract_name:
            contract_name = el.get("name", "")

    return contract_name or "Contract", func_name or "fallback", line_num


# ── 1. Reentrancy ─────────────────────────────────────────────────────────────


def _t_reentrancy(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check in (
            "reentrancy-eth",
            "reentrancy-no-eth",
            "reentrancy-unlimited-gas",
            "reentrancy-benign",
        ):
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"State transitions must finalize before external calls (Checks-Effects-Interactions) in {cname}",  # noqa: E501
                    "assertion_b": f"External call in {fname}() occurs before state write; reentrancy window exposed [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect {check}",
                    "expected": f'detector "{check}"',
                    "severity": "critical" if "eth" in check else "high",
                }
            )
    return out


# ── 2. Arbitrary Send / Fund Drain ───────────────────────────────────────────


def _t_arbitrary_send(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check in (
            "arbitrary-send-eth",
            "arbitrary-send-erc20",
            "arbitrary-send-erc20-permit",
        ):
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"Asset transfers in {cname} must strictly restrict recipient or require caller allowance",  # noqa: E501
                    "assertion_b": f"Function {fname}() permits caller to transfer funds to arbitrary destination without authorization [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect {check}",
                    "expected": f'detector "{check}"',
                    "severity": "critical",
                }
            )
    return out


# ── 3. Tx.Origin Authentication ──────────────────────────────────────────────


def _t_tx_origin(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check == "tx-origin":
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"Authorization in {cname} must inspect immediate caller msg.sender",
                    "assertion_b": f"Function {fname}() uses tx.origin for authentication; vulnerable to phishing delegation [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect tx-origin",
                    "expected": 'detector "tx-origin"',
                    "severity": "high",
                }
            )
    return out


# ── 4. Unchecked Low-Level Call ──────────────────────────────────────────────


def _t_unchecked_call(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check in ("unchecked-lowlevel", "unchecked-send", "unchecked-transfer"):
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"Low-level call return status in {cname} must be validated or reverted",
                    "assertion_b": f"Low-level call in {fname}() ignores return value; failure silently ignored [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect {check}",
                    "expected": f'detector "{check}"',
                    "severity": "medium",
                }
            )
    return out


# ── 5. Suicidal / Unprotected Selfdestruct ────────────────────────────────────


def _t_unprotected_destruction(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check == "suicidal":
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"Contract termination in {cname} must be restricted to verified governance",
                    "assertion_b": f"Function {fname}() allows arbitrary caller to execute selfdestruct() [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect suicidal",
                    "expected": 'detector "suicidal"',
                    "severity": "critical",
                }
            )
    return out


# ── 6. Untrusted Delegatecall ────────────────────────────────────────────────


def _t_untrusted_delegatecall(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check in ("controlled-delegatecall", "delegatecall-loop"):
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"Delegatecall targets in {cname} must be immutable or governance whitelisted",
                    "assertion_b": f"Function {fname}() executes delegatecall to user-controlled destination [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect {check}",
                    "expected": f'detector "{check}"',
                    "severity": "critical",
                }
            )
    return out


# ── 7. Unprotected Upgrade / Initializer ─────────────────────────────────────


def _t_unprotected_upgrade_or_init(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    target = mat.get("src_file", "Contract.sol")
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        if check in ("unprotected-upgrade", "missing-zero-check"):
            cname, fname, lnum = _extract_detector_elements(det)
            out.append(
                {
                    "assertion_a": f"Contract initialization in {cname} must be locked to a single invocation",
                    "assertion_b": f"Initializer or upgrade path in {fname}() exposed to arbitrary callers [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"Slither::{check}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect {check}",
                    "expected": f'detector "{check}"',
                    "severity": "high",
                }
            )
    return out


# ── 8. ABI Privileged Seam (ABI + Slither) ───────────────────────────────────

_PRIVILEGED_ABI_NAMES = {
    "withdraw",
    "drain",
    "transferownership",
    "setowner",
    "mint",
    "burn",
    "pause",
    "unpause",
    "emergencywithdraw",
    "upgradeto",
    "setadmin",
}


def _t_abi_privileged_bypass(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    target = mat.get("src_file", "Contract.sol")
    abi = mat.get("abi", [])
    if not isinstance(abi, list):
        return out

    # Look for functions in ABI that are state-changing and named with sensitive administrative keywords
    sensitive_funcs = []
    for item in abi:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "function":
            name = item.get("name", "")
            state = item.get("stateMutability", "")
            if (
                state in ("nonpayable", "payable", "")
                and name.lower() in _PRIVILEGED_ABI_NAMES
            ):
                sensitive_funcs.append(name)

    if not sensitive_funcs:
        return out

    # Correlate with detectors that flag unauthenticated execution
    for det in mat.get("detectors", []):
        check = det.get("check", "")
        cname, fname, lnum = _extract_detector_elements(det)
        if fname in sensitive_funcs or check in ("arbitrary-send-eth", "suicidal"):
            out.append(
                {
                    "assertion_a": f"Sensitive ABI function {fname}() in {cname} must enforce caller authorization",
                    "assertion_b": f"Public nonpayable ABI function {fname}() lacks verified access control [detector: {check}]",  # noqa: E501
                    "source_a": target,
                    "line_a": lnum or 1,
                    "source_b": f"ABI::{fname}",
                    "line_b": lnum or 1,
                    "check": f"slither {target} --detect {check}",
                    "expected": f'detector "{check}"',
                    "severity": "high",
                }
            )
    return out


# ── Registry & Scanning ──────────────────────────────────────────────────────

_WEB3_TEMPLATES: List[Tuple[str, Callable[[Dict[str, Any]], List[Dict[str, Any]]]]] = [
    ("reentrancy", _t_reentrancy),
    ("arbitrary_send", _t_arbitrary_send),
    ("tx_origin", _t_tx_origin),
    ("unchecked_call", _t_unchecked_call),
    ("unprotected_destruction", _t_unprotected_destruction),
    ("untrusted_delegatecall", _t_untrusted_delegatecall),
    ("unprotected_upgrade", _t_unprotected_upgrade_or_init),
    ("abi_privileged_bypass", _t_abi_privileged_bypass),
]


def _format_card(n: int, s: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "n": n,
        "title": f"seam-web3-{n}: {s.get('assertion_a', '')[:55]}",
        "assertion_a": s.get("assertion_a", ""),
        "assertion_b": s.get("assertion_b", ""),
        "assertion_a_source": s.get("source_a", ""),
        "assertion_b_source": s.get("source_b", ""),
        "source_a": s.get("source_a", ""),
        "line_a": s.get("line_a", 0),
        "source_b": s.get("source_b", ""),
        "line_b": s.get("line_b", 0),
        "check": s.get("check", ""),
        "expected": s.get("expected", ""),
        "severity": s.get("severity", "high"),
        "category": "smart-contract",
        "origin": "seam-template-web3",
        "verdict": "CANDIDATE",
    }


def scan_web3_seams(
    recon_dir: Optional[Path] = None,
    repo_path: Optional[Path] = None,
    abi_path: Optional[Path] = None,
    slither_json_path: Optional[Path] = None,
    scope_gate=None,
) -> List[Dict[str, Any]]:
    """
    Run all 8 web3 seam templates over ABI and Slither material.
    Returns standard candidate seam cards.
    """
    material = _build_material(
        recon_dir=recon_dir,
        repo_path=repo_path,
        abi_path=abi_path,
        slither_json_path=slither_json_path,
    )

    cards: List[Dict[str, Any]] = []
    n = 1
    for name, tpl_fn in _WEB3_TEMPLATES:
        try:
            candidates = tpl_fn(material)
        except Exception:
            candidates = []
        for c in candidates:
            # Check scope if scope_gate provided
            check_target = c.get("source_a", "")
            if scope_gate is not None:
                try:
                    in_scope, _ = scope_gate.is_in_scope(check_target)
                    if not in_scope:
                        continue
                except Exception:
                    pass
            cards.append(_format_card(n, c))
            n += 1

    return cards
