#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: fetch_sourcify, run_slither, recon_contract, parse_target_contract
# TOPICS: none
"""
Oracle Web3 Recon — smart contract source, ABI, and static analysis retrieval.

Components:
1. Sourcify API integration:
   - Fetches contract ABI and verified Solidity sources across 440+ chains.
   - Endpoint: GET https://sourcify.dev/server/v2/contract/{chainId}/{address}?fields=abi,sources
   - No API key required; zero-cost contract ingestion.
2. Slither Analyzer integration:
   - Runs static analysis over retrieved sources or local contract trees.
   - Invokes: slither <dir_or_file> --json <output_path>
   - Extracts structured detector findings for seam template evaluation.
3. Local/Direct Solidity target support:
   - Handles local .sol files or directories directly for offline/repo audits.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Common default chains
CHAIN_ETHEREUM = 1
CHAIN_SEPOLIA = 11155111
CHAIN_ARBITRUM = 42161
CHAIN_OPTIMISM = 10
CHAIN_POLYGON = 137
CHAIN_BASE = 8453
CHAIN_BNB = 56
CHAIN_AVALANCHE = 43114

SOURCIFY_V2_BASE = "https://sourcify.dev/server/v2/contract"
SOURCIFY_FILES_ANY_BASE = "https://sourcify.dev/server/files/any"

# Common Foundry and Python tool locations
DEFAULT_TOOL_PATHS = [
    os.path.expanduser("~/.foundry/bin"),
    os.path.expanduser("~/PhantomCore/PhantomCore/bin"),
    "/usr/local/bin",
    "/usr/bin",
]


def _build_env() -> Dict[str, str]:
    """Construct an execution environment guaranteed to include Slither and Foundry binaries."""
    env = os.environ.copy()
    current_path = env.get("PATH", "")
    needed_dirs = [p for p in DEFAULT_TOOL_PATHS if os.path.isdir(p)]
    env["PATH"] = ":".join(needed_dirs + [current_path])
    return env


def is_eth_address(val: str) -> bool:
    """Validate 20-byte hex Ethereum address (with or without 0x prefix)."""
    if not isinstance(val, str):
        return False
    val = val.strip()
    return bool(re.match(r"^(0x)?[0-9a-fA-F]{40}$", val))


def normalize_address(val: str) -> str:
    """Normalize address to lowercase 0x-prefixed 40 hex char format."""
    val = val.strip()
    if not val.startswith("0x") and not val.startswith("0X"):
        val = "0x" + val
    return val.lower()


def parse_target_contract(
    target: str, default_chain: int = CHAIN_ETHEREUM
) -> Tuple[int, Optional[str], Optional[Path]]:
    """
    Parse a web3 target string into (chain_id, address, local_path).
    Supports formats:
      - '0x...' -> (default_chain, address, None)
      - '1:0x...' -> (1, address, None)
      - 'ethereum:0x...' -> (1, address, None)
      - '/path/to/contract.sol' -> (0, None, Path)
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("web3 target cannot be empty")

    # Check if target is a local file or directory
    local_p = Path(target).resolve()
    if local_p.exists():
        return 0, None, local_p

    chain_aliases = {
        "eth": CHAIN_ETHEREUM,
        "ethereum": CHAIN_ETHEREUM,
        "mainnet": CHAIN_ETHEREUM,
        "sepolia": CHAIN_SEPOLIA,
        "arb": CHAIN_ARBITRUM,
        "arbitrum": CHAIN_ARBITRUM,
        "op": CHAIN_OPTIMISM,
        "optimism": CHAIN_OPTIMISM,
        "poly": CHAIN_POLYGON,
        "polygon": CHAIN_POLYGON,
        "base": CHAIN_BASE,
        "bnb": CHAIN_BNB,
        "bsc": CHAIN_BNB,
        "avax": CHAIN_AVALANCHE,
        "avalanche": CHAIN_AVALANCHE,
    }

    if ":" in target:
        chain_part, addr_part = target.split(":", 1)
        chain_part = chain_part.strip().lower()
        addr_part = addr_part.strip()
        if chain_part in chain_aliases:
            chain_id = chain_aliases[chain_part]
        elif chain_part.isdigit():
            chain_id = int(chain_part)
        else:
            raise ValueError(f"Unknown chain specifier: '{chain_part}'")
        if not is_eth_address(addr_part):
            raise ValueError(f"Invalid Ethereum address: '{addr_part}'")
        return chain_id, normalize_address(addr_part), None

    if is_eth_address(target):
        return default_chain, normalize_address(target), None

    raise ValueError(
        f"Unrecognized web3 target format: '{target}' (must be address, chain:address, or local path)"
    )


def fetch_sourcify(
    chain_id: int,
    address: str,
    out_dir: Optional[Union[str, Path]] = None,
    timeout: int = 20,
) -> Dict[str, Any]:
    """
    Fetch verified smart contract ABI and source code from Sourcify v2 API.
    Writes:
      - out_dir / "abi.json"
      - out_dir / "sources" / <filename.sol>
      - out_dir / "contract_meta.json"
    """
    norm_addr = normalize_address(address)
    url = f"{SOURCIFY_V2_BASE}/{chain_id}/{norm_addr}?fields=abi,sources"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Oracle-Security-Engine/1.0",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError(
                f"Contract {norm_addr} on chain {chain_id} not verified on Sourcify (HTTP 404)"
            )
        raise RuntimeError(f"Sourcify API error HTTP {e.code}: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"Sourcify connection failed: {e}")

    abi = data.get("abi") or []
    sources = data.get("sources") or {}

    written_files: List[Path] = []
    if out_dir:
        out_p = Path(out_dir).resolve()
        out_p.mkdir(parents=True, exist_ok=True)
        src_dir = out_p / "sources"
        src_dir.mkdir(parents=True, exist_ok=True)

        # Write ABI
        abi_file = out_p / "abi.json"
        abi_file.write_text(json.dumps(abi, indent=2), encoding="utf-8")

        # Write each source file
        for name, entry in sources.items():
            content = (
                entry.get("content", "") if isinstance(entry, dict) else str(entry)
            )
            # Flatten or preserve relative path safely
            safe_name = Path(name).name
            file_dest = src_dir / safe_name
            file_dest.write_text(content, encoding="utf-8")
            written_files.append(file_dest)

        # Write metadata
        meta = {
            "chain_id": chain_id,
            "address": norm_addr,
            "match": data.get("match"),
            "verified_at": data.get("verifiedAt"),
            "sources_count": len(sources),
            "abi_functions": len([x for x in abi if x.get("type") == "function"]),
        }
        (out_p / "contract_meta.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )

    return {
        "chain_id": chain_id,
        "address": norm_addr,
        "abi": abi,
        "sources": sources,
        "written_files": [str(p) for p in written_files],
    }


def run_slither(
    target_path: Union[str, Path],
    json_out_path: Optional[Union[str, Path]] = None,
    detectors: Optional[List[str]] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    """
    Run Slither static analyzer against a Solidity file or source tree.
    Returns parsed Slither detector results.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    if json_out_path is None:
        if target.is_file():
            json_out = target.parent / f"{target.stem}_slither.json"
        else:
            json_out = target / "slither_output.json"
    else:
        json_out = Path(json_out_path).resolve()

    json_out.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["slither", str(target), "--json", str(json_out)]
    if detectors:
        cmd.extend(["--detect", ",".join(detectors)])

    env = _build_env()

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("slither binary not found in PATH")
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"slither timed out after {timeout}s on {target}")

    # Slither returns non-zero when vulnerabilities are found; we verify via JSON presence
    raw_data: Dict[str, Any] = {}
    if json_out.exists():
        try:
            raw_data = json.loads(json_out.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raw_data = {"error": f"Corrupted slither JSON: {e}"}

    results = raw_data.get("results", {})
    detectors_found = results.get("detectors", [])

    return {
        "target": str(target),
        "json_path": str(json_out),
        "returncode": proc.returncode,
        "detectors": detectors_found,
        "detectors_count": len(detectors_found),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def recon_contract(
    target: str,
    out_dir: Union[str, Path],
    default_chain: int = CHAIN_ETHEREUM,
    timeout: int = 90,
) -> Dict[str, Any]:
    """
    End-to-end web3 contract recon:
    1. Parses target (address or local path).
    2. If address: fetches from Sourcify, writes ABI and sources to out_dir.
    3. If local path: copies or references sources, writes ABI if available.
    4. Runs Slither static analysis and saves slither_output.json.
    5. Writes live_contracts.txt and returns consolidated recon data.
    """
    out_p = Path(out_dir).resolve()
    out_p.mkdir(parents=True, exist_ok=True)

    chain_id, address, local_path = parse_target_contract(
        target, default_chain=default_chain
    )

    live_contracts_file = out_p / "live_contracts.txt"
    abi_file = out_p / "abi.json"
    slither_file = out_p / "slither_output.json"

    sources_dir: Path

    if address:
        fetch_sourcify(chain_id, address, out_dir=out_p, timeout=min(timeout, 30))
        sources_dir = out_p / "sources"
        live_contracts_file.write_text(f"{chain_id}:{address}\n", encoding="utf-8")
    elif local_path:
        if local_path.is_file():
            sources_dir = out_p / "sources"
            sources_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_path, sources_dir / local_path.name)
            live_contracts_file.write_text(
                f"local:{local_path.name}\n", encoding="utf-8"
            )
        else:
            sources_dir = local_path
            live_contracts_file.write_text(
                f"local_tree:{local_path}\n", encoding="utf-8"
            )
    else:
        raise ValueError("Neither address nor local path identified")

    # Run Slither analysis
    slither_res = run_slither(
        sources_dir,
        json_out_path=slither_file,
        timeout=timeout,
    )

    return {
        "chain_id": chain_id,
        "address": address,
        "sources_dir": str(sources_dir),
        "abi_path": str(abi_file) if abi_file.exists() else None,
        "slither_json": str(slither_file) if slither_file.exists() else None,
        "detectors": slither_res.get("detectors", []),
        "detectors_count": len(slither_res.get("detectors", [])),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python3 oracle_web3_recon.py <target_address_or_path> [out_dir] [chain_id]"
        )
        sys.exit(1)
    tgt = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "targets/web3_recon"
    cid = int(sys.argv[3]) if len(sys.argv) > 3 else CHAIN_ETHEREUM
    res = recon_contract(tgt, out, default_chain=cid)
    print(f"Recon complete for {tgt}: {res['detectors_count']} detectors identified.")
