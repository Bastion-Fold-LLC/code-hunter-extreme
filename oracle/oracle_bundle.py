#!/usr/bin/env python3
# LAYER: seal
# DEST: basilisk
# ENDPOINTS: build_bundle, verify_bundle, assess_workspace, BundleError
# TOPICS: none
"""Verifiable product bundles for an Oracle hunt workspace.

A hunt produces reports, findings, and PoCs. This module turns that workspace
into a portable product only when the artifacts agree with each other:

  * a machine-readable verify-results snapshot exists;
  * confirmed findings exist in both the snapshot and ``findings/``;
  * every confirmed finding has a non-empty PoC report;
  * the full report and program record exist.

The bundle carries a SHA-256 manifest (and a hash of the manifest itself), so
``verify_bundle`` can detect missing, extra, or modified files from the
archive bytes. ``ready_for_submission`` is deliberately stricter than
integrity: it is recomputed from the bundled artifacts themselves, never
trusted from the manifest (hashes prove self-consistency, not truth), so a
zero-confirmed or incomplete hunt gets a valid archive, but never a green gate.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oracle_bulk_download import download_completeness
from oracle_intake import is_independent_rescan_meta

BUNDLE_SCHEMA = "oracle.product.bundle/v1"
READINESS_SCHEMA = "oracle.product.readiness/v1"
MANIFEST_NAME = "manifest.json"
MANIFEST_SHA_NAME = "manifest.sha256"
BUNDLE_DIR_PREFIX = "product_"
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


class BundleError(RuntimeError):
    """The workspace cannot be turned into a product bundle."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise BundleError(f"path escapes workspace: {path}") from exc
    if rel.is_absolute() or ".." in rel.parts:
        raise BundleError(f"unsafe relative path: {rel}")
    return rel.as_posix()


def _latest(root: Path, pattern: str) -> Optional[Path]:
    if not root.is_dir():
        return None
    files = sorted(root.glob(pattern), key=lambda p: p.name)
    return files[-1] if files else None


_STAMP_RE = re.compile(r"_(\d{8}_\d{6})(?:_|$)")


def _stamp_of(path: Optional[Path]) -> Optional[str]:
    """The workspace write stamp (YYYYMMDD_HHMMSS) in a report filename."""
    if path is None:
        return None
    m = _STAMP_RE.search(path.stem)
    return m.group(1) if m else None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BundleError(f"unreadable JSON artifact {path}: {exc}") from exc


def _kind(rel: str) -> str:
    name = Path(rel).name
    if name in ("program.json", "hunt_scope.json", "program_brief.md"):
        return "program"
    if name == ".oracle_bulk.json":
        return "download_manifest"
    if name == "site.log":
        return "site_log"
    if rel.startswith("reports/"):
        return "report"
    if rel.startswith("findings/"):
        return "finding"
    if rel.startswith("assets/"):
        return "asset_manifest"
    return "artifact"


def _candidate_paths(workspace: Path) -> List[Path]:
    root = workspace.resolve()
    if not root.is_dir():
        raise BundleError(f"workspace not found: {workspace}")
    names = [
        "program.json",
        "hunt_scope.json",
        "program_brief.md",
        ".oracle_bulk.json",
        "download_report.json",
        "site.log",
        "assets/_manifest.json",
    ]
    paths: List[Path] = []
    for rel in names:
        p = root / rel
        if p.is_file():
            paths.append(p)
    for sub in ("reports", "findings"):
        directory = root / sub
        if not directory.is_dir():
            continue
        for p in sorted(directory.rglob("*")):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            # Never package an earlier product bundle recursively.
            if any(part.startswith(BUNDLE_DIR_PREFIX) for part in rel_parts):
                continue
            if p.name in (MANIFEST_NAME, MANIFEST_SHA_NAME):
                continue
            paths.append(p)
    # Deterministic order, no duplicates.
    seen = set()
    out: List[Path] = []
    for p in sorted(paths, key=lambda x: _safe_rel(x, root)):
        rel = _safe_rel(p, root)
        if rel in seen:
            continue
        seen.add(rel)
        out.append(p)
    return out


def _confirmed_from_snapshot(snapshot: Dict[str, Any]) -> Tuple[int, List[int]]:
    summary = snapshot.get("summary")
    summary_confirmed = 0
    if isinstance(summary, dict):
        try:
            summary_confirmed = int(summary.get("confirmed") or 0)
        except (TypeError, ValueError):
            summary_confirmed = 0
    results = snapshot.get("results")
    confirmed_ns: List[int] = []
    if isinstance(results, dict):
        for raw_n, result in results.items():
            if not isinstance(result, dict) or not result.get("confirmed"):
                continue
            try:
                confirmed_ns.append(int(raw_n))
            except (TypeError, ValueError):
                continue
    return summary_confirmed, sorted(confirmed_ns)


def _confirmed_finding_ns(findings_dir: Path) -> List[int]:
    out: List[int] = []
    if not findings_dir.is_dir():
        return out
    for path in sorted(findings_dir.glob("finding_*.json")):
        if path.name.endswith(".xref.json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or not data.get("verify_confirmed"):
            continue
        try:
            out.append(int(data.get("n")))
        except (TypeError, ValueError):
            continue
    return sorted(set(out))


def _has_poc(
    reports_dir: Path, n: int, min_stamp: Optional[str] = None
) -> bool:
    # Every confirmed seam gets its own synthesized PoC (including low
    # severity). A compound-chain report is not a substitute: it proves the
    # chain, not that this finding has a standalone submission body. A PoC
    # written before the assessed hunt's snapshot belongs to an earlier
    # hunt in a reused workspace and does not count for this one.
    for path in reports_dir.glob(f"report_seam_{n}_*.md"):
        if min_stamp is not None:
            stamp = _stamp_of(path)
            if stamp is None or stamp < min_stamp:
                continue
        try:
            if path.is_file() and path.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def assess_workspace(
    workspace: Path, *, bundle_contents: bool = False
) -> Dict[str, Any]:
    """Score a hunt workspace against the submission-readiness gate."""
    root = workspace.resolve()
    if not root.is_dir():
        raise BundleError(f"workspace not found: {workspace}")
    reasons: List[str] = []
    checks: Dict[str, Any] = {}
    program: Dict[str, Any] = {}
    if not (root / "program.json").is_file():
        reasons.append("missing program.json")
        checks["program"] = False
    else:
        checks["program"] = True
        try:
            loaded_program = _read_json(root / "program.json")
        except BundleError as exc:
            reasons.append(str(exc))
            loaded_program = {}
        if isinstance(loaded_program, dict):
            program = loaded_program
        else:
            reasons.append("program.json is not an object")

    reports_dir = root / "reports"
    findings_dir = root / "findings"
    snapshot_path = _latest(reports_dir, "report_verify_results_*.md")
    checks["verify_results"] = bool(snapshot_path)
    snapshot: Dict[str, Any] = {}
    if snapshot_path is None:
        reasons.append("missing report_verify_results snapshot")
    else:
        try:
            loaded = _read_json(snapshot_path)
        except BundleError as exc:
            reasons.append(str(exc))
            loaded = {}
        if isinstance(loaded, dict):
            snapshot = loaded
        else:
            reasons.append("verify results snapshot is not an object")

    summary_confirmed, result_confirmed = _confirmed_from_snapshot(snapshot)
    finding_confirmed = _confirmed_finding_ns(findings_dir)
    checks["summary_confirmed"] = summary_confirmed
    checks["result_confirmed"] = result_confirmed
    checks["finding_confirmed"] = finding_confirmed
    if summary_confirmed != len(result_confirmed):
        reasons.append("verify summary confirmed count does not match result records")
    if result_confirmed != finding_confirmed:
        reasons.append("confirmed result records do not match findings/finding_*.json")

    snapshot_stamp = _stamp_of(snapshot_path)
    full_report = _latest(reports_dir, "report_full_*.md")
    if (
        full_report is not None
        and snapshot_stamp is not None
        and (_stamp_of(full_report) or "") < snapshot_stamp
    ):
        reasons.append(
            "full report predates the latest verify snapshot "
            "(stale artifact from an earlier hunt)"
        )
        full_report = None
    checks["full_report"] = bool(full_report)
    if full_report is None and not any("predates" in r for r in reasons):
        reasons.append("missing full report (report_full_*.md)")

    missing_poc = [
        n
        for n in finding_confirmed
        if not _has_poc(reports_dir, n, snapshot_stamp)
    ]
    checks["missing_poc"] = missing_poc
    if missing_poc:
        reasons.append(
            "confirmed finding(s) without a non-empty PoC report: "
            + ", ".join(str(n) for n in missing_poc)
        )

    hunt = snapshot.get("hunt") if isinstance(snapshot, dict) else None
    hunt = hunt if isinstance(hunt, dict) else {}
    if "unserved_mindsets" not in hunt or not isinstance(
        hunt.get("unserved_mindsets"), list
    ):
        # Missing yield accounting is not an all-served hunt. (Fail-open
        # defaulting here once let accounting failures mint readiness.)
        reasons.append(
            "hunt snapshot carries no mindset yield accounting "
            "(unserved_mindsets missing); lens service is unproven"
        )
        unserved = []
    else:
        unserved = hunt.get("unserved_mindsets") or []
    if unserved:
        reasons.append("mindset(s) unserved: " + ", ".join(str(x) for x in unserved))
    # The yield ledger is required, well-formed accounting — the hunt
    # snapshot writer always emits one entry per effective lens beside
    # unserved_mindsets. An omitted, non-list, empty, or malformed
    # ledger proves nothing about lens service and blocks readiness;
    # a well-formed one is cross-checked against the declared list so
    # a recorded-unserved lens cannot be declared away.
    _ledger = hunt.get("yield_ledger")
    _ledger_causes = {"minted", "qualified-clean", "unserved"}
    if not isinstance(_ledger, list) or not _ledger:
        reasons.append(
            "hunt snapshot carries no yield_ledger (missing, non-list, "
            "or empty); lens service is unproven"
        )
    else:
        _ledger_unserved = set()
        _ledger_malformed = False
        for _entry in _ledger:
            if not isinstance(_entry, dict):
                _ledger_malformed = True
                continue
            _mindset = _entry.get("mindset")
            _cause = str(_entry.get("cause") or "").strip().lower()
            if (
                not isinstance(_mindset, str)
                or not _mindset.strip()
                or _cause not in _ledger_causes
            ):
                _ledger_malformed = True
                continue
            if _cause == "unserved":
                _ledger_unserved.add(_mindset.strip())
        if _ledger_malformed:
            reasons.append(
                "yield_ledger contains malformed entries (non-object, "
                "missing mindset, or unknown cause); lens service is "
                "unproven"
            )
        _undeclared = sorted(
            _ledger_unserved - {str(x).strip() for x in unserved}
        )
        if _undeclared:
            reasons.append(
                "yield_ledger records unserved mindset(s) missing from "
                "unserved_mindsets: " + ", ".join(_undeclared)
            )
    # Coverage: the ledger must account for exactly the hunt's
    # effective mindsets (the snapshot writer emits both from the same
    # list). A subset or bogus-lens ledger proves nothing about the
    # lenses that were supposed to run.
    _effective = hunt.get("effective_mindsets")
    _effective_set = (
        {str(x).strip() for x in _effective if isinstance(x, str) and x.strip()}
        if isinstance(_effective, list)
        else set()
    )
    if not _effective_set or len(_effective_set) != len(
        _effective if isinstance(_effective, list) else []
    ):
        reasons.append(
            "hunt snapshot carries no effective_mindsets list for "
            "yield_ledger coverage; lens service is unproven"
        )
    elif isinstance(_ledger, list) and _ledger:
        _ledger_mindsets = {
            str(e.get("mindset")).strip()
            for e in _ledger
            if isinstance(e, dict)
            and isinstance(e.get("mindset"), str)
            and e.get("mindset", "").strip()
        }
        if _ledger_mindsets != _effective_set:
            reasons.append(
                "yield_ledger does not cover effective_mindsets "
                f"exactly (ledger={sorted(_ledger_mindsets)}, "
                f"effective={sorted(_effective_set)}); lens service "
                "is unproven"
            )

    # Scan4Me provenance is discovery evidence only. A fresh public feed
    # (or even a missing feed stamp on an older snapshot) neither creates
    # nor destroys product truth; Oracle's independent re-scan does.
    feed_trust = hunt.get("feed_trust")
    feed_ok = isinstance(feed_trust, dict) and feed_trust.get("ok") is True
    checks["feed_trust_ok"] = feed_ok

    rescan = hunt.get("oracle_rescan")
    # Shared strict check, handle-bound to this workspace's program:
    # independent + found + a real adapter source + a handle stamp that
    # is present and matches program.json. A contradictory stamp (bridge
    # source, found=false, missing/foreign handle) never passes, however
    # its independent flag is set.
    independent = (
        isinstance(rescan, dict)
        and isinstance(rescan.get("handle"), str)
        and bool(rescan.get("handle", "").strip())
        and is_independent_rescan_meta(
            rescan,
            {
                "handle": program.get("handle", ""),
                "name": program.get("name", ""),
            },
        )
    )
    checks["oracle_rescan"] = rescan if isinstance(rescan, dict) else None
    checks["oracle_independent"] = independent
    if not independent:
        reasons.append(
            "hunt scope was not independently re-scanned by Oracle; "
            "Scan4Me/bridge provenance alone is not product truth"
        )

    # Download completeness is recorded either way; only a proven-empty
    # download blocks readiness in v1 (stricter partial/NO_AUTH gating
    # is an open owner decision). An absent report is unknown, named in
    # checks, but does not by itself block a wire-confirmed finding.
    # Live workspaces must have the obtained files on disk; extracted
    # bundle contents never pack asset bodies, so there the report is
    # judged on provenance/denominator/counts (its integrity is covered
    # by the bundle manifest hashes checked by the verifier).
    completeness = download_completeness(
        root, require_files=not bundle_contents
    )
    checks["download_completeness"] = {
        "present": completeness["present"],
        "complete": completeness["complete"],
        "status": completeness["status"],
        "obtained_count": completeness["obtained_count"],
        "missing_count": completeness["missing_count"],
    }
    if completeness["present"] and (
        completeness["status"] == "empty" or completeness["obtained_count"] == 0
    ):
        reasons.append(
            "download report shows zero obtained assets (status=empty); "
            "hunt context had no downloaded program material"
        )

    if summary_confirmed <= 0:
        reasons.append("no confirmed findings (zero-confirmed)")
        status = "incomplete" if reasons[:-1] else "zero-confirmed"
    elif reasons:
        status = "incomplete"
    else:
        status = "ready"
    ready = status == "ready" and not reasons
    return {
        "_schema": READINESS_SCHEMA,
        "ready_for_submission": bool(ready),
        "status": status,
        "reasons": reasons,
        "confirmed_count": summary_confirmed,
        "checks": checks,
        "feed_trust": feed_trust if isinstance(feed_trust, dict) else None,
        "oracle_rescan": rescan if isinstance(rescan, dict) else None,
        "scope_independent": bool(independent),
        "verify_results": str(snapshot_path) if snapshot_path else None,
        "full_report": str(full_report) if full_report else None,
    }


def _manifest_for(
    root: Path, files: List[Path], readiness: Dict[str, Any]
) -> Dict[str, Any]:
    entries = []
    for path in files:
        rel = _safe_rel(path, root)
        entries.append(
            {
                "path": rel,
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
                "kind": _kind(rel),
            }
        )
    program: Dict[str, Any] = {}
    try:
        raw = json.loads((root / "program.json").read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            program = {
                "name": raw.get("name"),
                "platform": raw.get("platform"),
                "handle": raw.get("handle"),
            }
    except (OSError, ValueError):
        program = {}
    return {
        "_schema": BUNDLE_SCHEMA,
        "created_utc": _utc_now(),
        "program": program,
        "readiness": readiness,
        "files": entries,
        "excluded": {
            "assets": "downloaded assets are large; only the asset manifest is included",
            "recon": "raw recon output stays in the workspace",
            "repos": "cloned repositories stay in the workspace",
        },
        "note": (
            "Verify with oracle-hunter verify-download. A valid archive is not "
            "a submission-ready finding unless readiness.ready_for_submission "
            "is true."
        ),
    }


def _write_manifest(bundle_dir: Path, manifest: Dict[str, Any]) -> None:
    raw = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )
    (bundle_dir / MANIFEST_NAME).write_bytes(raw)
    digest = _sha256_bytes(raw)
    (bundle_dir / MANIFEST_SHA_NAME).write_text(
        f"{digest}  {MANIFEST_NAME}\n", encoding="utf-8"
    )


def _manifest_sha(raw_sha: bytes, raw_manifest: bytes, errors: List[str]) -> None:
    text = raw_sha.decode("utf-8", errors="replace").strip()
    expected = text.split()[0] if text else ""
    actual = _sha256_bytes(raw_manifest)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected or ""):
        errors.append("malformed manifest.sha256")
    elif expected.lower() != actual:
        errors.append("manifest.sha256 does not match manifest.json")


def _read_manifest_dir(bundle_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    manifest_path = bundle_dir / MANIFEST_NAME
    sha_path = bundle_dir / MANIFEST_SHA_NAME
    errors: List[str] = []
    if not manifest_path.is_file():
        raise BundleError(f"missing {MANIFEST_NAME}")
    raw = manifest_path.read_bytes()
    if not sha_path.is_file():
        errors.append(f"missing {MANIFEST_SHA_NAME}")
    else:
        _manifest_sha(sha_path.read_bytes(), raw, errors)
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise BundleError(f"manifest.json is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BundleError("manifest.json is not an object")
    return manifest, {"errors": errors}


def _verify_entries(
    root: Path, manifest: Dict[str, Any], actual: Dict[str, bytes]
) -> List[str]:
    errors: List[str] = []
    listed: Dict[str, Dict[str, Any]] = {}
    files = manifest.get("files")
    if not isinstance(files, list):
        return ["manifest.files is not a list"]
    for entry in files:
        if not isinstance(entry, dict):
            errors.append("manifest contains a non-object file entry")
            continue
        rel = entry.get("path")
        if not isinstance(rel, str) or not rel or rel.startswith("/"):
            errors.append(f"unsafe manifest path: {rel!r}")
            continue
        parts = Path(rel).parts
        if ".." in parts or rel in (MANIFEST_NAME, MANIFEST_SHA_NAME):
            errors.append(f"unsafe manifest path: {rel!r}")
            continue
        if rel in listed:
            errors.append(f"duplicate manifest path: {rel}")
            continue
        listed[rel] = entry
    for rel, entry in listed.items():
        if rel not in actual:
            errors.append(f"missing bundle file: {rel}")
            continue
        data = actual[rel]
        try:
            expected_size = int(entry.get("bytes"))
        except (TypeError, ValueError):
            expected_size = -1
        if expected_size != len(data):
            errors.append(f"size mismatch: {rel}")
        expected_sha = str(entry.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            errors.append(f"malformed hash: {rel}")
        elif _sha256_bytes(data) != expected_sha:
            errors.append(f"hash mismatch: {rel}")
    extra = sorted(set(actual) - set(listed))
    if extra:
        errors.append("unlisted bundle file(s): " + ", ".join(extra))
    return errors


def _recomputed_readiness(workspace: Path) -> Dict[str, Any]:
    """Re-assess readiness from artifact contents; never trust a manifest."""
    try:
        return assess_workspace(workspace, bundle_contents=True)
    except BundleError as exc:
        return {
            "ready_for_submission": False,
            "status": "unassessable",
            "reasons": [str(exc)],
        }


def _verify_result(
    path: Path,
    kind: str,
    manifest: Dict[str, Any],
    errors: List[str],
    readiness: Dict[str, Any],
) -> Dict[str, Any]:
    claimed = manifest.get("readiness") if isinstance(manifest, dict) else {}
    if not isinstance(claimed, dict):
        errors.append("manifest.readiness is not an object")
    return {
        "_schema": "oracle.product.verify/v1",
        "path": str(path),
        "kind": kind,
        "integrity_ok": not errors,
        "ready_for_submission": bool(
            readiness.get("ready_for_submission") is True and not errors
        ),
        "status": readiness.get("status") or "missing-readiness",
        "reasons": list(readiness.get("reasons") or []),
        "readiness_source": "recomputed-from-bundle-contents",
        "manifest": manifest,
        "errors": errors,
    }


def _verify_dir(bundle_dir: Path) -> Dict[str, Any]:
    manifest, meta = _read_manifest_dir(bundle_dir)
    actual: Dict[str, bytes] = {}
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle_dir).as_posix()
        if rel in (MANIFEST_NAME, MANIFEST_SHA_NAME):
            continue
        actual[rel] = path.read_bytes()
    errors = list(meta.get("errors") or [])
    errors.extend(_verify_entries(bundle_dir, manifest, actual))
    readiness = _recomputed_readiness(bundle_dir)
    return _verify_result(bundle_dir, "directory", manifest, errors, readiness)


def _verify_zip(path: Path) -> Dict[str, Any]:
    errors: List[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if len(names) != len(set(names)):
                errors.append("zip contains duplicate entry names")
            if MANIFEST_NAME not in names:
                raise BundleError(f"zip missing {MANIFEST_NAME}")
            raw = zf.read(MANIFEST_NAME)
            if MANIFEST_SHA_NAME not in names:
                errors.append(f"zip missing {MANIFEST_SHA_NAME}")
            else:
                _manifest_sha(zf.read(MANIFEST_SHA_NAME), raw, errors)
            try:
                manifest = json.loads(raw)
            except ValueError as exc:
                raise BundleError(f"manifest.json is not valid JSON: {exc}") from exc
            if not isinstance(manifest, dict):
                raise BundleError("manifest.json is not an object")
            actual_files: Dict[str, bytes] = {}
            for name in names:
                if name in (MANIFEST_NAME, MANIFEST_SHA_NAME) or name.endswith("/"):
                    continue
                if name.startswith("/") or ".." in Path(name).parts:
                    errors.append(f"unsafe zip entry: {name}")
                    continue
                actual_files[name] = zf.read(name)
    except zipfile.BadZipFile as exc:
        raise BundleError(f"not a valid zip archive: {exc}") from exc
    errors.extend(_verify_entries(path, manifest, actual_files))
    with tempfile.TemporaryDirectory(prefix="oracle-bundle-verify-") as td:
        extract_root = Path(td)
        for name, data in actual_files.items():
            target = extract_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        readiness = _recomputed_readiness(extract_root)
    return _verify_result(path, "zip", manifest, errors, readiness)


def verify_bundle(path: Path) -> Dict[str, Any]:
    """Verify a bundle directory or zip against its SHA-256 manifest."""
    p = Path(path)
    if p.is_dir():
        return _verify_dir(p)
    if p.is_file():
        return _verify_zip(p)
    raise BundleError(f"bundle not found: {path}")


def _zip_bundle(bundle_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as zf:
        for path in sorted(bundle_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(bundle_dir).as_posix()
            info = zipfile.ZipInfo(rel, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())


def build_bundle(
    workspace: Path,
    *,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a product bundle, manifest, and zip for one hunt workspace."""
    root = Path(workspace).resolve()
    readiness = assess_workspace(root)
    files = _candidate_paths(root)
    if not files:
        raise BundleError(f"workspace has no product artifacts: {root}")
    destination = Path(out_dir) if out_dir else root / "reports"
    destination.mkdir(parents=True, exist_ok=True)
    tag = stamp or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    bundle_dir = destination / f"{BUNDLE_DIR_PREFIX}{tag}"
    suffix = 1
    while bundle_dir.exists():
        suffix += 1
        bundle_dir = destination / f"{BUNDLE_DIR_PREFIX}{tag}_{suffix}"
    bundle_dir.mkdir(parents=True)
    for path in files:
        rel = _safe_rel(path, root)
        target = bundle_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    manifest = _manifest_for(root, files, readiness)
    _write_manifest(bundle_dir, manifest)
    dir_check = _verify_dir(bundle_dir)
    if not dir_check["integrity_ok"]:
        raise BundleError(
            "bundle failed its own manifest check: " + "; ".join(dir_check["errors"])
        )
    zip_path = destination / f"{bundle_dir.name}.zip"
    _zip_bundle(bundle_dir, zip_path)
    zip_check = verify_bundle(zip_path)
    if not zip_check["integrity_ok"]:
        raise BundleError(
            "zip failed its own manifest check: " + "; ".join(zip_check["errors"])
        )
    return {
        "_schema": BUNDLE_SCHEMA,
        "bundle_dir": str(bundle_dir),
        "zip_path": str(zip_path),
        "manifest": manifest,
        "readiness": readiness,
        "verify": zip_check,
    }
