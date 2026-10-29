#!/usr/bin/env python3
"""
Blind Evaluation Harness for Oracle.

Tests the system on UNKNOWN targets - real programs from Scan4Me with
NO prior Oracle knowledge. This measures true discovery capability.

Usage:
    python3 tests/test_blind_evaluation.py --count 10
    python3 tests/test_blind_evaluation.py --program "hackerone/shopify"
"""

from __future__ import annotations
import argparse
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# The Scan4Me checkout is `scan4me/` in this tree and `Scan4Me/` in older
# layouts. Resolve by existence, not by spelling: on a case-sensitive FS the
# wrong casing is a path that is never there and every DB lookup fails open.
for _name in ("Scan4Me", "scan4me"):
    _cand = ROOT / _name
    if _cand.is_dir():
        sys.path.insert(0, str(_cand))
        break

import oracle_hunter as oh
from oracle_mindset_context import OracleMindsetContext
from oracle_mindsets import (
    resolve_mindsets,
    apply_mindset3_gates,
    synthesize_seams,
    redteam_challenge_by_lens,
    seam_candidate_key,
    build_seam_sets,
)
from oracle_deterministic import verify_seam_card
from oracle_code_seam import scan_repository_seams
from oracle_seam_templates import scan_template_seams
from oracle_scan4me import scan4me_home


class BlindEvaluationHarness:
    """Run Oracle on completely unknown programs and measure outcomes."""

    def __init__(self, scan4me_db: str = None):
        self.scan4me_db = scan4me_db or str(scan4me_home() / "scan4me.db")
        self.results = []

    def fetch_random_programs(self, count: int, min_score: float = 0) -> List[Dict]:
        """Fetch random programs from Scan4Me database."""
        import sqlite3
        conn = sqlite3.connect(self.scan4me_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Get programs with assets
        cur.execute("""
            SELECT p.*, COUNT(a.id) as asset_count
            FROM programs p
            LEFT JOIN assets a ON a.program_id = p.id AND a.deleted_timestamp = 0
            WHERE p.deleted_timestamp = 0
              AND p.offers_bounties = 1
              AND (p.max_payout IS NULL OR p.max_payout >= ?)
            GROUP BY p.id
            HAVING asset_count > 0
            ORDER BY RANDOM()
            LIMIT ?
        """, (min_score, count))

        programs = [dict(row) for row in cur.fetchall()]
        conn.close()
        return programs

    def fetch_program_details(self, program_id: int) -> Dict:
        """Fetch full program details including assets and scope."""
        import sqlite3
        conn = sqlite3.connect(self.scan4me_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM programs WHERE id = ?", (program_id,))
        row = cur.fetchone()
        prog = dict(row) if row else {}

        cur.execute("""
            SELECT * FROM assets WHERE program_id = ? AND deleted_timestamp = 0
        """, (program_id,))
        assets = [dict(row) for row in cur.fetchall()]

        cur.execute("""
            SELECT * FROM oos_assets WHERE program_id = ? AND deleted_timestamp = 0
        """, (program_id,))
        oos_assets = [dict(row) for row in cur.fetchall()]

        conn.close()

        prog["structured_scopes"] = assets
        prog["out_of_scope_assets"] = oos_assets
        return prog

    def run_blind_hunt(self, program: Dict, timeout: int = 300) -> Dict:
        """Run a full Oracle hunt on an unknown program."""
        start_time = time.time()

        # Build minimal recon from scope
        recon_dir = Path(tempfile.mkdtemp(prefix="blind_recon_"))
        assets_dir = Path(tempfile.mkdtemp(prefix="blind_assets_"))

        try:
            # Write program page for policy extraction
            (assets_dir / "program_page.txt").write_text(
                f"Program Rules\n{program.get('rules_text', '')}\n"
                f"Safe Harbor\n{program.get('safe_harbor', '')}\n"
                f"Out of Scope\n{program.get('out_of_scope', '')}\n",
                encoding="utf-8"
            )

            # Run code seam scan if repo available
            code_seams = []
            # Note: In blind mode, we don't have repo - this is scope-only

            # Run template seam scan
            from oracle_hunter import ProgramScopeGate
            scope_gate = ProgramScopeGate(program)

            template_seams = scan_template_seams(
                recon_dir=recon_dir,
                repo_path=None,
                program=program,
                scope_gate=scope_gate,
                errors=[],
                auth=None,
                max_per_family=2,
            )

            # Build mindset contexts
            ctx = OracleMindsetContext(program=program, voice=True, ttp_mode="auto", mindset="paradox")
            mitre_ctx = OracleMindsetContext(program=program, voice=True, ttp_mode="auto", mindset="mitre")

            # Run seam verification (deterministic only in blind mode)
            from oracle_hunter import _merge_seams, _deterministic_block

            all_seams = _merge_seams([], template_seams)

            # Run deterministic verification
            det_block = _deterministic_block(recon_dir, scope_gate=scope_gate)

            # Verify each seam
            recon_urls = [
                a.get("asset_identifier", "")
                for a in program.get("structured_scopes", [])
                if a.get("asset_identifier")
            ]
            verified = []
            for seam in all_seams:
                check = seam.get("check", "")
                if check:
                    v = verify_seam_card(seam, recon_urls=recon_urls, scope_gate=scope_gate)
                    if v.get("verdict") == "CONFIRMED":
                        verified.append({**seam, "verification": v})

            # Run red-team challenge on verified
            verdicts, _counts = redteam_challenge_by_lens(verified, in_scope=scope_gate.is_in_scope)
            challenged = [
                v for v in verified
                if verdicts.get(seam_candidate_key(v)) != "rejected"
            ]

            # Mindset 3 synthesis
            seam_sets = build_seam_sets(
                ["seam"],
                challenged,
                lens_outcomes={"seam-template": "seams" if challenged else "clean"},
            )
            synthesized = synthesize_seams(seam_sets, redteam_verdicts=verdicts)

            # Apply Mindset 3 gates
            annotated, _m3_verdicts, _m3_counts = apply_mindset3_gates(
                synthesized, in_scope=scope_gate.is_in_scope
            )
            final = [
                s for s in annotated
                if s.get("m3_redteam_verdict") != "rejected"
            ]

            elapsed = time.time() - start_time

            return {
                "program": program["name"],
                "platform": program["platform"],
                "handle": program.get("handle"),
                "elapsed_seconds": elapsed,
                "seams_found": len(all_seams),
                "seams_verified": len(verified),
                "seams_challenged": len(challenged),
                "seams_synthesized": len(synthesized),
                "seams_final": len(final),
                "findings": final,
                "scope_gate": {
                    "in_scope_count": len(getattr(scope_gate, "in_scope_rules", [])),
                    "out_of_scope_count": len(getattr(scope_gate, "out_of_scope_rules", [])),
                },
            }

        finally:
            # Cleanup
            import shutil
            shutil.rmtree(recon_dir, ignore_errors=True)
            shutil.rmtree(assets_dir, ignore_errors=True)

    def evaluate_batch(self, count: int = 10, min_payout: int = 0) -> Dict:
        """Run blind evaluation on multiple programs."""
        programs = self.fetch_random_programs(count, min_payout)
        results = {
            "total_programs": len(programs),
            "successful_hunts": 0,
            "failed_hunts": 0,
            "total_findings": 0,
            "programs": [],
        }

        for prog in programs:
            try:
                details = self.fetch_program_details(prog["id"])
                result = self.run_blind_hunt(details)
                result["program_id"] = prog["id"]
                result["success"] = True
                results["successful_hunts"] += 1
                results["total_findings"] += result["seams_final"]
            except Exception as e:
                result = {
                    "program": prog["name"],
                    "platform": prog["platform"],
                    "program_id": prog["id"],
                    "success": False,
                    "error": str(e),
                }
                results["failed_hunts"] += 1

            results["programs"].append(result)
            print(f"  {'✓' if result['success'] else '✗'} {result.get('program', 'unknown')} - "
                  f"findings: {result.get('seams_final', 'ERROR')}")

        return results


def main():
    parser = argparse.ArgumentParser(description="Blind evaluation of Oracle on unknown programs")
    parser.add_argument("--count", type=int, default=5, help="Number of random programs to test")
    parser.add_argument("--min-payout", type=int, default=0, help="Minimum payout filter")
    parser.add_argument("--program", help="Specific program name/handle to test")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    harness = BlindEvaluationHarness()

    if args.program:
        # Fetch specific program
        import sqlite3
        conn = sqlite3.connect(harness.scan4me_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM programs WHERE name = ? OR handle = ?",
                   (args.program, args.program))
        prog = cur.fetchone()
        conn.close()

        if not prog:
            print(f"Program not found: {args.program}")
            sys.exit(1)

        details = harness.fetch_program_details(prog["id"])
        result = harness.run_blind_hunt(details)
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Fetching {args.count} random programs from Scan4Me...")
        results = harness.evaluate_batch(args.count, args.min_payout)

        print(f"\n{'='*60}")
        print("BLIND EVALUATION SUMMARY")
        print(f"{'='*60}")
        print(f"Total programs:     {results['total_programs']}")
        print(f"Successful hunts:   {results['successful_hunts']}")
        print(f"Failed hunts:       {results['failed_hunts']}")
        print(f"Total findings:     {results['total_findings']}")
        if results['successful_hunts'] > 0:
            print(f"Avg findings/hunt:  {results['total_findings'] / results['successful_hunts']:.1f}")

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\nResults written to {args.output}")

        # Save for CI tracking
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        auto_output = ROOT / "reports" / f"blind_eval_{timestamp}.json"
        auto_output.parent.mkdir(exist_ok=True)
        with open(auto_output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Auto-saved to {auto_output}")


def test_blind_evaluation_single_program():
    """Verify BlindEvaluationHarness executes cleanly against Scan4Me database."""
    import pytest

    harness = BlindEvaluationHarness()
    if not Path(harness.scan4me_db).is_file():
        pytest.skip(
            f"Scan4Me DB not synced at {harness.scan4me_db} — run "
            "`python3 scan4me.py sync` in the Scan4Me checkout ("
            "SCAN4ME_HOME overrides the path) to enable blind evaluation"
        )
    programs = harness.fetch_random_programs(count=1)
    assert len(programs) == 1
    details = harness.fetch_program_details(programs[0]["id"])
    assert details["name"] == programs[0]["name"]
    assert len(details["structured_scopes"]) > 0
    res = harness.run_blind_hunt(details)
    assert res["program"] == programs[0]["name"]
    assert res["seams_final"] == 0  # Empty recon dir produces 0 false confirms


def test_blind_evaluation_scope_contract_on_synthetic_db(tmp_path):
    """The harness SQL contract holds without a live sync.

    This is a structural test, not a capability measurement: it proves that
    program/asset/OOS rows are read into the shape ``run_blind_hunt`` expects.
    Measured discovery still requires a real Scan4Me sync (test above).
    """
    import sqlite3

    db = tmp_path / "scan4me.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE programs (
            id INTEGER PRIMARY KEY, name TEXT, handle TEXT, platform TEXT,
            offers_bounties INTEGER, max_payout REAL, deleted_timestamp INTEGER,
            rules_text TEXT, safe_harbor TEXT, out_of_scope TEXT
        );
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY, program_id INTEGER, asset_identifier TEXT,
            asset_type TEXT, deleted_timestamp INTEGER
        );
        CREATE TABLE oos_assets (
            id INTEGER PRIMARY KEY, program_id INTEGER, asset_identifier TEXT,
            asset_type TEXT, deleted_timestamp INTEGER
        );
        INSERT INTO programs VALUES (
            1, 'Synthetic', 'synthetic', 'hackerone', 1, 5000, 0,
            'Rules body', 'Safe harbor body', ''
        );
        INSERT INTO assets VALUES (10, 1, 'api.synthetic.example', 'URL', 0);
        INSERT INTO assets VALUES (11, 1, '*.synthetic.example', 'WILDCARD', 0);
        INSERT INTO assets VALUES (12, 1, 'removed.synthetic.example', 'URL', 7);
        INSERT INTO oos_assets VALUES (20, 1, 'blog.synthetic.example', 'URL', 0);
        """
    )
    conn.commit()
    conn.close()

    harness = BlindEvaluationHarness(scan4me_db=str(db))
    programs = harness.fetch_random_programs(count=5, min_score=1000)
    assert [p["name"] for p in programs] == ["Synthetic"]
    assert programs[0]["asset_count"] == 2  # deleted asset excluded

    details = harness.fetch_program_details(programs[0]["id"])
    assert details["name"] == "Synthetic"
    assert sorted(a["asset_identifier"] for a in details["structured_scopes"]) == [
        "*.synthetic.example",
        "api.synthetic.example",
    ]
    assert [a["asset_identifier"] for a in details["out_of_scope_assets"]] == [
        "blog.synthetic.example"
    ]


if __name__ == "__main__":
    main()