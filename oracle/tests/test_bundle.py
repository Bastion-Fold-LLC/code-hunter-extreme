#!/usr/bin/env python3
"""Product bundle: SHA-256 manifest, integrity verification, readiness gate.

No network. A bundle can be integrity-clean while the product is not
submission-ready; those are deliberately separate verdicts.
"""

import json
import sys
import warnings
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_bundle as ob


def _workspace(tmp_path, *, confirmed=1, poc=True, findings=True):
    root = tmp_path / "targets" / "HackerOne" / "acme"
    reports = root / "reports"
    findings_dir = root / "findings"
    reports.mkdir(parents=True)
    findings_dir.mkdir(parents=True)
    (root / "program.json").write_text(
        json.dumps({"name": "Acme", "platform": "HackerOne", "handle": "acme"})
    )
    (reports / "report_verify_results_20260101_000000.md").write_text(
        json.dumps(
            {
                "summary": {
                    "confirmed": confirmed,
                    "inconclusive": 0,
                    "total": max(confirmed, 1),
                    "verdict": "confirmed" if confirmed else "zero-confirmed",
                },
                "results": {
                    "1": {"confirmed": bool(confirmed), "verdict": "CONFIRMED"}
                },
                "hunt": {
                    "feed_trust": {"ok": True, "issues": []},
                    "oracle_rescan": {
                        "mode": "independent",
                        "source": "hackerone-api-authenticated",
                        "independent": True,
                        "programs": 1,
                        "independent_programs": 1,
                    },
                },
            }
        )
    )
    (reports / "report_full_20260101_000000.md").write_text("full report")
    if poc:
        (reports / "report_seam_1_20260101_000000.md").write_text("PoC body")
    if findings:
        (findings_dir / "finding_001.json").write_text(
            json.dumps({"n": 1, "verify_confirmed": bool(confirmed)})
        )
        (findings_dir / "finding_001.xref.json").write_text("{}")
    return root


def test_ready_bundle_integrity_and_readiness(tmp_path):
    root = _workspace(tmp_path)
    out = tmp_path / "out"
    result = ob.build_bundle(root, out_dir=out, stamp="ready")
    assert result["readiness"]["ready_for_submission"] is True
    assert result["readiness"]["status"] == "ready"
    assert result["zip_path"].endswith("product_ready.zip")
    assert Path(result["bundle_dir"], ob.MANIFEST_NAME).is_file()
    assert Path(result["bundle_dir"], ob.MANIFEST_SHA_NAME).is_file()
    manifest = json.loads(Path(result["bundle_dir"], ob.MANIFEST_NAME).read_text())
    paths = {f["path"] for f in manifest["files"]}
    assert "program.json" in paths
    assert "reports/report_full_20260101_000000.md" in paths
    assert "findings/finding_001.json" in paths
    assert all(len(f["sha256"]) == 64 for f in manifest["files"])
    check = ob.verify_bundle(Path(result["zip_path"]))
    assert check["integrity_ok"] is True
    assert check["ready_for_submission"] is True
    assert check["errors"] == []


def test_zero_confirmed_bundle_is_integrity_clean_but_not_ready(tmp_path):
    root = _workspace(tmp_path, confirmed=0, poc=False, findings=False)
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="zero")
    assert result["readiness"]["ready_for_submission"] is False
    assert result["readiness"]["status"] == "zero-confirmed"
    assert any("zero-confirmed" in r for r in result["readiness"]["reasons"])
    check = ob.verify_bundle(Path(result["zip_path"]))
    assert check["integrity_ok"] is True
    assert check["ready_for_submission"] is False
    assert check["status"] == "zero-confirmed"


def test_forged_manifest_readiness_does_not_verify_ready(tmp_path):
    root = _workspace(tmp_path, confirmed=0, poc=False, findings=False)
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="forged")
    bundle_dir = Path(result["bundle_dir"])
    manifest = json.loads((bundle_dir / ob.MANIFEST_NAME).read_text())
    manifest["readiness"] = {
        "ready_for_submission": True,
        "status": "ready",
        "reasons": [],
    }
    ob._write_manifest(bundle_dir, manifest)

    dir_check = ob.verify_bundle(bundle_dir)
    assert dir_check["integrity_ok"] is True  # hashes are self-consistent
    assert dir_check["ready_for_submission"] is False
    assert dir_check["status"] == "zero-confirmed"

    forged_zip = tmp_path / "forged.zip"
    ob._zip_bundle(bundle_dir, forged_zip)
    zip_check = ob.verify_bundle(forged_zip)
    assert zip_check["integrity_ok"] is True
    assert zip_check["ready_for_submission"] is False
    assert zip_check["status"] == "zero-confirmed"


def test_stale_artifacts_from_earlier_hunt_do_not_complete_new_snapshot(tmp_path):
    root = _workspace(tmp_path)
    reports = root / "reports"
    # A second hunt in the same workspace writes a newer snapshot but no
    # new PoC/full report of its own; the first hunt's leftovers must not
    # be silently paired with it.
    first_snapshot = reports / "report_verify_results_20260101_000000.md"
    (reports / "report_verify_results_20260102_000000.md").write_text(
        first_snapshot.read_text()
    )
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="mixed")
    assert result["readiness"]["ready_for_submission"] is False
    reasons = " ".join(result["readiness"]["reasons"])
    assert "predates" in reasons or "PoC" in reasons


def test_missing_poc_blocks_readiness(tmp_path):
    root = _workspace(tmp_path, poc=False)
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="nopoc")
    assert result["readiness"]["ready_for_submission"] is False
    assert result["readiness"]["status"] == "incomplete"
    assert any("without a non-empty PoC" in r for r in result["readiness"]["reasons"])


def test_tampered_bundle_fails_integrity(tmp_path):
    root = _workspace(tmp_path)
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="tamper")
    bad = tmp_path / "bad.zip"
    bad.write_bytes(Path(result["zip_path"]).read_bytes())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(bad, "a") as zf:
            zf.writestr("reports/report_full_20260101_000000.md", "tampered")
    check = ob.verify_bundle(bad)
    assert check["integrity_ok"] is False
    assert check["ready_for_submission"] is False
    assert any("duplicate" in e for e in check["errors"])


def test_extra_file_fails_directory_integrity(tmp_path):
    root = _workspace(tmp_path)
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="extra")
    (Path(result["bundle_dir"]) / "evil.txt").write_text("not in manifest")
    check = ob.verify_bundle(Path(result["bundle_dir"]))
    assert check["integrity_ok"] is False
    assert any("unlisted" in e for e in check["errors"])


def test_queue_bundle_helper_packages_completed_hunt(tmp_path, monkeypatch):
    import oracle_hunter as oh

    root = _workspace(tmp_path)
    events = []
    monkeypatch.setattr(
        oh, "_runlog_event", lambda event, **data: events.append((event, data))
    )
    monkeypatch.setattr(oh, "_runlog_artifact", lambda *a, **k: None)
    result = oh._bundle_hunt_product({"workspace": str(root), "confirmed": 1})
    assert result is not None
    assert result["readiness"]["ready_for_submission"] is True
    assert Path(result["zip_path"]).is_file()
    assert events[-1][0] == "product.bundle"
    assert events[-1][1]["ready_for_submission"] is True


def test_unserved_mindset_blocks_readiness(tmp_path):
    root = _workspace(tmp_path)
    snapshot = root / "reports" / "report_verify_results_20260101_000000.md"
    data = json.loads(snapshot.read_text())
    data["hunt"]["unserved_mindsets"] = ["mitre"]
    snapshot.write_text(json.dumps(data))
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="unserved")
    assert result["readiness"]["ready_for_submission"] is False
    assert result["readiness"]["status"] == "incomplete"
    assert any("mindset" in r for r in result["readiness"]["reasons"])


def test_missing_feed_trust_blocks_readiness(tmp_path):
    root = _workspace(tmp_path)
    snapshot = root / "reports" / "report_verify_results_20260101_000000.md"
    data = json.loads(snapshot.read_text())
    data["hunt"].pop("feed_trust")
    snapshot.write_text(json.dumps(data))
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="no-trust")
    assert result["readiness"]["ready_for_submission"] is False
    assert any("feed_trust" in r for r in result["readiness"]["reasons"])


def test_hackerone_requires_independent_rescan(tmp_path):
    root = _workspace(tmp_path)
    snapshot = root / "reports" / "report_verify_results_20260101_000000.md"
    data = json.loads(snapshot.read_text())
    data["hunt"]["oracle_rescan"]["independent"] = False
    data["hunt"]["oracle_rescan"]["mode"] = "scan4me-db"
    snapshot.write_text(json.dumps(data))
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="bridge-h1")
    assert result["readiness"]["ready_for_submission"] is False
    assert any("independently" in r for r in result["readiness"]["reasons"])


def test_non_hackerone_bridge_rescan_is_explicit_not_fatal(tmp_path):
    root = _workspace(tmp_path)
    program = root / "program.json"
    data = json.loads(program.read_text())
    data["platform"] = "Bugcrowd"
    program.write_text(json.dumps(data))
    snapshot = root / "reports" / "report_verify_results_20260101_000000.md"
    snap = json.loads(snapshot.read_text())
    snap["hunt"]["oracle_rescan"] = {
        "mode": "scan4me-db",
        "source": "scan4me-db",
        "independent": False,
    }
    snapshot.write_text(json.dumps(snap))
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="bridge-bug")
    assert result["readiness"]["ready_for_submission"] is True
    assert result["readiness"]["scope_independent"] is False
    assert result["readiness"]["oracle_rescan"]["independent"] is False


def test_chain_report_is_not_a_substitute_for_seam_poc(tmp_path):
    root = _workspace(tmp_path, poc=False)
    reports = root / "reports"
    (reports / "report_compound_chain_TOP_20260101_000000.md").write_text("chain PoC")
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="chain-only")
    assert result["readiness"]["ready_for_submission"] is False
    assert any("without a non-empty PoC" in r for r in result["readiness"]["reasons"])
