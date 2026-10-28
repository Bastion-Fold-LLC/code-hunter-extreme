#!/usr/bin/env python3
"""
Clean Code False Positive Benchmark.

Scans known-clean codebases (Linux kernel, Redis, SQLite, etc.) to measure
Oracle's false positive rate. A good bug hunter should find ZERO vulnerabilities
in code that is known to be clean (or at least, no *exploitable* vulnerabilities
in the bug bounty sense).

This test:
1. Clones known-clean repositories
2. Runs Oracle's code seam scanner on them
3. Measures false positive rate
4. Tracks which "vulnerabilities" are flagged incorrectly
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oracle_code_seam import scan_repository_seams
from oracle_deterministic import verify_seam_card
from oracle_hunter import ProgramScopeGate


# Known-clean repositories for benchmarking
CLEAN_REPOS = [
    {
        "name": "redis",
        "url": "https://github.com/redis/redis.git",
        "branch": "7.2",  # Stable branch
        "description": "In-memory data structure store - battle-tested",
        "expected_fps": 0,  # Should find no exploitable vulns
    },
    {
        "name": "sqlite",
        "url": "https://github.com/sqlite/sqlite.git",
        "branch": "trunk",
        "description": "SQL database engine - extensively tested",
        "expected_fps": 0,
    },
    {
        "name": "nginx",
        "url": "https://github.com/nginx/nginx.git",
        "branch": "master",
        "description": "Web server - security-focused codebase",
        "expected_fps": 0,
    },
    {
        "name": "go",
        "url": "https://github.com/golang/go.git",
        "branch": "release-branch.go1.22",
        "description": "Go language - high quality standard library",
        "expected_fps": 0,
    },
    {
        "name": "cpython",
        "url": "https://github.com/python/cpython.git",
        "branch": "3.12",
        "description": "Python interpreter - mature codebase",
        "expected_fps": 0,
    },
    {
        "name": "openssl",
        "url": "https://github.com/openssl/openssl.git",
        "branch": "openssl-3.2",
        "description": "Cryptography library - heavily audited",
        "expected_fps": 0,
    },
    # Lighter alternatives for quick runs
    {
        "name": "jq",
        "url": "https://github.com/jqlang/jq.git",
        "branch": "master",
        "description": "JSON processor - small, clean",
        "expected_fps": 0,
    },
    {
        "name": "ripgrep",
        "url": "https://github.com/BurntSushi/ripgrep.git",
        "branch": "master",
        "description": "Fast grep - Rust, memory safe",
        "expected_fps": 0,
    },
]


class CleanCodeBenchmark:
    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or (ROOT / "tests" / "clean_repos_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.results = []

    def clone_or_update(self, repo: Dict) -> Path:
        """Clone or update a repository."""
        repo_dir = self.cache_dir / repo["name"]

        if repo_dir.exists():
            # Update
            try:
                subprocess.run(
                    ["git", "-C", str(repo_dir), "fetch", "origin"],
                    check=True, capture_output=True, timeout=60
                )
                subprocess.run(
                    ["git", "-C", str(repo_dir), "checkout", repo["branch"]],
                    check=True, capture_output=True, timeout=30
                )
                subprocess.run(
                    ["git", "-C", str(repo_dir), "pull", "--ff-only"],
                    check=True, capture_output=True, timeout=60
                )
                print(f"  Updated {repo['name']}")
            except subprocess.CalledProcessError:
                # Re-clone if update fails
                shutil.rmtree(repo_dir)
                return self.clone_or_update(repo)
        else:
            # Clone
            print(f"  Cloning {repo['name']}...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--branch", repo["branch"],
                     repo["url"], str(repo_dir)],
                    check=True, capture_output=True, timeout=180
                )
                print(f"  Cloned {repo['name']}")
            except subprocess.CalledProcessError as e:
                print(f"  Failed to clone {repo['name']}: {e}")
                raise

        return repo_dir

    def scan_repo(self, repo: Dict, repo_dir: Path) -> Dict:
        """Run code seam scan on a repository."""
        start = time.time()

        # Minimal program context for scope gate
        program = {
            "name": repo["name"],
            "platform": "benchmark",
            "structured_scopes": [
                {"asset_identifier": "*", "asset_type": "WILDCARD", "eligible_for_bounty": True}
            ],
        }
        scope_gate = ProgramScopeGate(program)

        # Run code seam scanner
        code_seams = list(scan_repository_seams(repo_dir, program=program))

        # Verify each seam (deterministic verification)
        verified = []
        for seam in code_seams:
            check = seam.get("check", "")
            if check:
                v = verify_seam_card(seam, recon_urls=[str(repo_dir)], scope_gate=scope_gate)
                if v.get("verdict") == "CONFIRMED":
                    verified.append({**seam, "verification": v})

        elapsed = time.time() - start

        return {
            "repo": repo["name"],
            "description": repo["description"],
            "scan_time_seconds": elapsed,
            "raw_seams": len(code_seams),
            "verified_seams": len(verified),
            "seams": verified,
        }

    def analyze_false_positives(self, result: Dict) -> Dict:
        """Analyze findings for likely false positives."""
        # Heuristics for false positives in clean code:
        # 1. Claims about missing auth on internal functions
        # 2. Claims about hardcoded secrets in test files
        # 3. Claims about debug endpoints in non-web code
        # 4. Type-hint mismatches that are intentional (e.g., Optional returns)

        fps = []
        for seam in result["seams"]:
            claim_type = seam.get("claim_type", "")
            source_a = seam.get("source_a", "")
            source_b = seam.get("source_b", "")
            check = seam.get("check", "")

            # Flag likely false positives
            is_fp = False
            reasons = []

            # Test files often have relaxed patterns
            if "test" in source_a.lower() or "test" in source_b.lower():
                is_fp = True
                reasons.append("test file")

            # Internal functions not exposed via HTTP
            if check and not check.startswith("curl"):
                is_fp = True
                reasons.append("non-HTTP check")

            # Type-hint mismatches in dynamic languages (often intentional)
            if claim_type == "type-hint" and result.get("repo") in ("cpython", "redis"):
                # These are often intentional in C/Python internals
                is_fp = True
                reasons.append("intentional type pattern in systems code")

            # Config fallback in example/default configs
            if claim_type == "config-fallback" and "example" in source_b.lower():
                is_fp = True
                reasons.append("example config file")

            if is_fp:
                fps.append({
                    "seam": seam,
                    "reasons": reasons,
                })

        return {
            "total_findings": len(result["seams"]),
            "likely_false_positives": len(fps),
            "false_positive_rate": len(fps) / len(result["seams"]) if result["seams"] else 0,
            "fps": fps,
        }

    def run_benchmark(self, repos: List[Dict] = None, quick: bool = False) -> Dict:
        """Run benchmark on selected repositories."""
        repos = repos or CLEAN_REPOS
        if quick:
            repos = repos[:3]  # Just first 3 for quick run

        benchmark_results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "repos_tested": len(repos),
            "total_raw_seams": 0,
            "total_verified": 0,
            "total_likely_fps": 0,
            "overall_fp_rate": 0,
            "repos": [],
        }

        for repo in repos:
            print(f"\n{'='*60}")
            print(f"Benchmarking: {repo['name']} - {repo['description']}")
            print(f"{'='*60}")

            try:
                repo_dir = self.clone_or_update(repo)
                result = self.scan_repo(repo, repo_dir)
                analysis = self.analyze_false_positives(result)

                repo_result = {**result, "analysis": analysis}
                benchmark_results["repos"].append(repo_result)

                benchmark_results["total_raw_seams"] += result["raw_seams"]
                benchmark_results["total_verified"] += result["verified_seams"]
                benchmark_results["total_likely_fps"] += analysis["likely_false_positives"]

                print(f"  Raw seams:      {result['raw_seams']}")
                print(f"  Verified:       {result['verified_seams']}")
                print(f"  Likely FPs:     {analysis['likely_false_positives']}")
                print(f"  FP Rate:        {analysis['false_positive_rate']:.1%}")

            except Exception as e:
                print(f"  ERROR: {e}")
                benchmark_results["repos"].append({
                    "repo": repo["name"],
                    "error": str(e),
                })

        # Overall stats
        if benchmark_results["total_verified"] > 0:
            benchmark_results["overall_fp_rate"] = (
                benchmark_results["total_likely_fps"] / benchmark_results["total_verified"]
            )

        print(f"\n{'='*60}")
        print("BENCHMARK SUMMARY")
        print(f"{'='*60}")
        print(f"Repos tested:          {benchmark_results['repos_tested']}")
        print(f"Total raw seams:       {benchmark_results['total_raw_seams']}")
        print(f"Total verified:        {benchmark_results['total_verified']}")
        print(f"Total likely FPs:      {benchmark_results['total_likely_fps']}")
        print(f"Overall FP rate:       {benchmark_results['overall_fp_rate']:.1%}")

        return benchmark_results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Clean code false positive benchmark")
    parser.add_argument("--quick", action="store_true", help="Run only first 3 repos")
    parser.add_argument("--repo", help="Run only specific repo")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    benchmark = CleanCodeBenchmark()

    repos = CLEAN_REPOS
    if args.repo:
        repos = [r for r in CLEAN_REPOS if r["name"] == args.repo]
        if not repos:
            print(f"Unknown repo: {args.repo}")
            sys.exit(1)

    results = benchmark.run_benchmark(repos, quick=args.quick)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults written to {args.output}")

    # Assert FP rate is low (<20%)
    assert results["overall_fp_rate"] < 0.2, \
        f"False positive rate {results['overall_fp_rate']:.1%} exceeds 20% threshold"

    print("\n✓ Clean code benchmark passed (FP rate < 20%)")


def test_clean_code_benchmark_local_clean_repo(tmp_path):
    """Verify CleanCodeBenchmark produces 0 verified false positives on a clean codebase."""
    clean_pkg = tmp_path / "clean_service"
    clean_pkg.mkdir()
    (clean_pkg / "auth.py").write_text(
        '"""Authentication service."""\n\n'
        "def verify_token(token: str) -> bool:\n"
        '    """Verify that the supplied bearer token matches an active session."""\n'
        "    if not token or not isinstance(token, str):\n"
        "        return False\n"
        "    return token.startswith('tok_') and len(token) == 36\n",
        encoding="utf-8",
    )
    (clean_pkg / "math_utils.py").write_text(
        '"""Arithmetic helpers."""\n\n'
        "def clamp(val: int, lo: int, hi: int) -> int:\n"
        '    """Clamp val between lo and hi inclusive."""\n'
        "    return max(lo, min(val, hi))\n",
        encoding="utf-8",
    )
    benchmark = CleanCodeBenchmark(cache_dir=tmp_path)
    repo_meta = {"name": "clean_service", "description": "Clean synthetic reference repo"}
    res = benchmark.scan_repo(repo_meta, clean_pkg)
    analysis = benchmark.analyze_false_positives(res)
    assert res["verified_seams"] == 0
    assert analysis["false_positive_rate"] == 0


if __name__ == "__main__":
    main()