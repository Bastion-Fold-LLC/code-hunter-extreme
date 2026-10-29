"""Stage 3 download-completeness contracts.

The canonical ``download_report.json`` is the honesty layer for every
download path: what was expected, attempted, obtained, and missing —
with the method that actually served each file. Partial work must say
``partial`` everywhere downstream, never ``downloaded``/``present``.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_bulk_download as obd
import oracle_mindset_context as omc
import oracle_programs as op
import oracle_scan


def test_fetch_with_via_names_the_serving_method(monkeypatch):
    monkeypatch.setattr(op, "_crawl4ai", lambda url, timeout=25: "r" * 300)
    text, via = op._fetch_with_via("https://app.example/", use_cdp=False)
    assert len(text) > 200
    assert via == "crawl4ai"
    # The bare-string wrapper keeps its old contract.
    assert op._fetch("https://app.example/", use_cdp=False) == text


def test_fetch_with_via_validator_is_plain_get(monkeypatch):
    monkeypatch.setattr(op, "_get", lambda url, timeout=60, **k: "body")
    text, via = op._fetch_with_via(
        "https://app.example/", redirect_validator=lambda u: True
    )
    assert text == "body"
    assert via == "plain-get"


def _prog():
    return {
        "name": "Acme Widgets",
        "platform": "TestPlat",
        "url": "https://platform.example/programs/acme",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }


def test_scan_report_is_canonical_and_partial_when_missing(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(oracle_scan, "_cdp_available", lambda port=9227: False)
    monkeypatch.setattr(
        oracle_scan,
        "_cascade_fetch_with_via",
        lambda url, timeout=45: ("rendered " + "x" * 80, "jina"),
    )
    monkeypatch.setattr(
        oracle_scan,
        "_collect_asset_urls",
        lambda prog: [
            ("app__homepage.html", "https://app.acme.example/"),
            ("app__openapi.json", "https://app.acme.example/openapi.json"),
            ("app__extra.html", "https://app.acme.example/extra"),
        ],
    )
    monkeypatch.setattr(oracle_scan, "_route_scope_records", lambda prog: {})
    # Plain GET: homepage fails (cascade serves it), openapi 404s. The
    # third URL is beyond no cap here, but page auth fails -> partial.
    class _Resp:
        ok = False
        status_code = 404
        text = ""

    monkeypatch.setattr("requests.get", lambda *a, **k: _Resp())
    # Cap the fetch loop at 2 by shrinking via collect order is not
    # possible; instead all three are attempted and extra.html cascades.
    _saved, info = oracle_scan.download_program_assets(
        _prog(), tmp_path, take_screenshot=False, clone_repos=False
    )
    report = json.loads((tmp_path / "download_report.json").read_text())
    assert report["schema"] == "oracle.download-report/v1"
    assert report["complete"] is False
    assert report["status"] == "partial"
    # Cascade renders are saved copies, not origin-obtained assets:
    # the origin 404 stays missing and the render is named separately.
    rendered = {o["file"]: o for o in report["rendered"]}
    assert rendered["app__homepage.html"]["via"] == "jina"
    missing_files = {m.get("file") for m in report["missing"]}
    assert "app__openapi.json" in missing_files
    assert "program_page.txt" in missing_files  # NO_AUTH_SESSION
    assert report["page_source"] == "NO_AUTH_SESSION"
    assert report["page_corroboration_via"] == "jina"
    assert report["methods"]["jina"]["attempted"] >= 1
    assert report["not_enumerated"]  # deferred lanes are named, not hidden
    assert info["download_report"]["status"] == "partial"


def test_cascade_render_is_not_origin_obtained():
    summary = obd.summarize_download_results(
        [
            {
                "file": "a.html",
                "url": "https://x/a",
                "status": "cascade",
                "via": "jina",
                "plain_status": 404,
            }
        ],
        expected_urls=1,
    )
    assert summary["complete"] is False
    assert summary["obtained"] == []
    assert summary["missing"][0]["file"] == "a.html"
    assert summary["rendered"][0]["via"] == "jina"


def test_empty_denominator_is_never_complete():
    summary = obd.summarize_download_results([], expected_urls=0)
    assert summary["complete"] is False
    assert summary["status"] == "empty"


def test_completeness_recomputes_inconsistent_self_assertion(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a").write_text("x")
    (tmp_path / "download_report.json").write_text(
        json.dumps(
            {
                "schema": "oracle.download-report/v1",
                "complete": True,
                "status": "complete",
                "obtained": [
                    {"file": "a", "url": "https://x/a", "status": 200,
                     "via": "plain-get"}
                ],
                "missing": [{"file": "b"}],
                "obtained_count": 1,
                "missing_count": 5,
                "expected_urls": 6,
            }
        )
    )
    comp = obd.download_completeness(tmp_path)
    assert comp["complete"] is False
    assert comp["status"] == "partial"


def test_hunt_report_preserves_prior_missing(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://app.acme.example/",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    (ws.base / "download_report.json").write_text(
        json.dumps(
            {
                "schema": "oracle.download-report/v1",
                "status": "partial",
                "complete": False,
                "page_source": "CDP_RENDERED",
                "obtained": [],
                "missing": [
                    {"file": "screenshot.png", "url": "https://x/", "status": "screenshot-failed"}
                ],
                "obtained_count": 0,
                "missing_count": 1,
                "expected_urls": 1,
            }
        )
    )
    monkeypatch.setattr(ws, "_collect_asset_urls", lambda: ["https://app.acme.example/"])
    monkeypatch.setattr(ws, "_fetch_asset", lambda url, **k: "ok " * 40)
    monkeypatch.setattr(omc, "_raw_get", lambda url, **k: "raw " * 40)
    ws.download_assets()
    report = json.loads((ws.base / "download_report.json").read_text())
    assert report["status"] == "partial"
    assert any(m.get("file") == "screenshot.png" for m in report["missing"])


def test_already_downloaded_requires_complete_report(tmp_path, monkeypatch):
    prog = {"name": "Acme", "platform": "TestPlat"}
    base = tmp_path / "ws"
    base.mkdir(parents=True)
    monkeypatch.setattr(obd, "workspace_base_for", lambda p: base)
    # Bare/empty manifest: not downloaded.
    (base / obd.MANIFEST).write_text("{}")
    assert obd.already_downloaded(prog) is False
    # Partial report: not downloaded (must re-fetch).
    (base / "download_report.json").write_text(
        json.dumps({"schema": "oracle.download-report/v1", "complete": False})
    )
    assert obd.already_downloaded(prog) is False
    # Complete AND internally consistent report (writer-shaped entries,
    # file on disk): present.
    (base / "assets").mkdir()
    (base / "assets" / "a").write_text("xyz")
    (base / "download_report.json").write_text(
        json.dumps({
            "schema": "oracle.download-report/v1",
            "complete": True,
            "coverage_pct": 100,
            "expected_urls": 1,
            "obtained": [
                {"url": "https://x.test/a", "file": "a",
                 "bytes": 3, "status": 200, "via": "plain-get"}
            ],
            "missing": [],
            "obtained_count": 1,
            "missing_count": 0,
            "not_enumerated": [],
        })
    )
    assert obd.already_downloaded(prog) is True
    comp = obd.download_completeness(base)
    assert comp["complete"] is True
    assert comp["status"] == "complete"


def test_hunt_download_assets_writes_canonical_report(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://app.acme.example/",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    monkeypatch.setattr(
        ws,
        "_collect_asset_urls",
        lambda: [
            "https://app.acme.example/",
            "https://app.acme.example/openapi.json",
            "https://app.acme.example/robots.txt",
        ],
    )

    def fake_fetch(url, cdp_port=9227, timeout=15):
        return "ok content " * 20 if url.endswith("/") else ""

    monkeypatch.setattr(ws, "_fetch_asset", fake_fetch)
    saved = ws.download_assets(max_urls=2)
    report = json.loads((ws.base / "download_report.json").read_text())
    assert report["schema"] == "oracle.download-report/v1"
    assert report["status"] == "partial"
    assert report["complete"] is False
    assert report["expected_urls"] == 3
    assert report["attempted_urls"] == 2
    assert report["unattempted_urls"] == 1
    missing_urls = {m.get("url") for m in report["missing"]}
    assert "https://app.acme.example/openapi.json" in missing_urls
    assert "https://app.acme.example/robots.txt" in missing_urls
    assert ws.program["download_completeness"]["status"] == "partial"
    assert saved  # the one good file still landed


def test_program_brief_always_shows_download_coverage(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://platform.example/acme",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    (ws.assets_dir / "a.html").write_text("page")
    (ws.base / "download_report.json").write_text(
        json.dumps(
            {
                "schema": "oracle.download-report/v1",
                "status": "partial",
                "complete": False,
                "obtained": [{"file": "a.html", "url": "https://x/",
                              "status": 200, "via": "plain-get"}],
                "missing": [
                    {"file": "b.json", "url": "https://x/b", "error": "404"}
                ],
                "not_enumerated": ["js-bundle crawl (deferred)"],
                "methods": {"jina": {"attempted": 1, "ok": 1, "fail": 0}},
            }
        )
    )
    ctx = omc.OracleMindsetContext(prog)
    # Point the brief's workspace discovery at our tmp tree.
    monkeypatch.setattr(omc, "_HERE", tmp_path)
    (tmp_path / "targets").mkdir(exist_ok=True)
    import shutil

    dest = tmp_path / "targets" / ws.platform / ws.slug
    if dest != ws.base:
        shutil.copytree(ws.base, dest, dirs_exist_ok=True)
    brief = ctx._program_brief()
    assert "DOWNLOAD COVERAGE" in brief
    assert "partial" in brief
    assert "b.json" in brief
    assert "js-bundle" in brief


def test_cascade_via_never_obtained_even_with_ok_status():
    # Round-2 verifier: _result_obtained ignored `via`, so a cascade
    # render labelled ok/200/cached counted as origin-obtained.
    summary = obd.summarize_download_results(
        [
            {"file": "a", "url": "https://x/a", "status": "ok", "via": "jina"},
            {"file": "b", "url": "https://x/b", "status": 200, "via": "firecrawl"},
            {"file": "c", "url": "https://x/c", "status": "cached", "via": "jina"},
        ],
        expected_urls=3,
    )
    assert summary["obtained"] == []
    assert len(summary["rendered"]) == 3
    assert summary["complete"] is False
    assert summary["coverage_pct"] == 0


def test_summarize_coverage_pct_and_denominator_floor():
    summary = obd.summarize_download_results(
        [{"file": "a", "url": "https://x/a", "status": 200, "via": "plain-get"}],
        expected_urls=4,
    )
    # Fewer obtained than the enumerated denominator can never complete,
    # even when nothing is explicitly listed missing.
    assert summary["complete"] is False
    assert summary["coverage_pct"] == 25


def test_completeness_fallback_and_malformed_counts_fail_closed(tmp_path):
    # No obtained/missing lists: self-asserted complete must not be trusted.
    (tmp_path / "download_report.json").write_text(
        json.dumps({
            "schema": "oracle.download-report/v1",
            "complete": True,
            "obtained_count": 1,
            "missing_count": 0,
            "expected_urls": 0,
        })
    )
    assert obd.download_completeness(tmp_path)["complete"] is False
    # Malformed counts must fail closed, never raise.
    (tmp_path / "download_report.json").write_text(
        json.dumps({
            "schema": "oracle.download-report/v1",
            "complete": True,
            "obtained_count": "abc",
            "missing_count": None,
        })
    )
    comp = obd.download_completeness(tmp_path)
    assert comp["complete"] is False


def test_completeness_validates_entries_denominator_and_disk(tmp_path):
    def write(report):
        (tmp_path / "download_report.json").write_text(json.dumps(report))

    base = {"schema": "oracle.download-report/v1", "missing": [], "expected_urls": 1}
    write({**base, "obtained": ["not-a-dict"]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    write({**base, "obtained": [
        {"file": "a", "url": "https://x/a", "status": "cascade", "via": "jina"}
    ]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # Ghost entry: file not on disk.
    write({**base, "obtained": [
        {"file": "ghost", "url": "https://x/g", "status": 200, "via": "plain-get"}
    ]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # Denominator larger than obtained.
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a").write_text("x")
    good = {"file": "a", "url": "https://x/a", "status": 200, "via": "plain-get"}
    write({**base, "expected_urls": 99, "obtained": [good]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # Zero/absent/non-int denominators never complete.
    for denom in (0, "0", 0.0, None):
        rep = {**base, "obtained": [good]}
        if denom is None:
            rep.pop("expected_urls")
        else:
            rep["expected_urls"] = denom
        write(rep)
        assert obd.download_completeness(tmp_path)["complete"] is False, denom
    # Counts inconsistent with the lists never complete.
    write({**base, "obtained": [good], "obtained_count": 7})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # Internally consistent + on disk: complete.
    write({**base, "obtained": [good], "obtained_count": 1, "missing_count": 0})
    assert obd.download_completeness(tmp_path)["complete"] is True


def test_scan_second_run_does_not_launder_cascade_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(oracle_scan, "_cdp_available", lambda port=9227: False)
    monkeypatch.setattr(
        oracle_scan,
        "_cascade_fetch_with_via",
        lambda url, timeout=45: ("rendered " + "x" * 80, "jina"),
    )
    monkeypatch.setattr(
        oracle_scan,
        "_collect_asset_urls",
        lambda prog: [("app__homepage.html", "https://app.acme.example/")],
    )
    monkeypatch.setattr(oracle_scan, "_route_scope_records", lambda prog: {})

    class _Resp:
        ok = False
        status_code = 404
        text = ""

    monkeypatch.setattr("requests.get", lambda *a, **k: _Resp())
    prog = _prog()
    prog["url"] = ""  # no program-page lane; isolate the asset cache
    for _ in range(2):
        oracle_scan.download_program_assets(
            prog, tmp_path, take_screenshot=False, clone_repos=False
        )
        report = json.loads((tmp_path / "download_report.json").read_text())
        # The cascade-saved file exists on disk after run 1; run 2 must
        # not reclassify it cached/origin-obtained.
        assert report["complete"] is False
        assert not any(
            o.get("file") == "app__homepage.html" for o in report["obtained"]
        )


def test_hunt_cache_requires_prior_origin_obtained(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://app.acme.example/",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    url = "https://app.acme.example/"
    fname = omc._url_to_filename(url)
    # A cascade leftover sits on disk; the prior report says it was only
    # rendered and the origin stayed missing.
    (ws.assets_dir / fname).write_text("cascade copy " * 20)
    (ws.base / "download_report.json").write_text(
        json.dumps({
            "schema": "oracle.download-report/v1",
            "status": "partial",
            "complete": False,
            "page_source": "CDP_RENDERED",
            "obtained": [],
            "rendered": [
                {"file": fname, "url": url, "status": "cascade", "via": "jina"}
            ],
            "missing": [
                {"file": fname, "url": url, "status": "cascade", "via": "jina"}
            ],
            "expected_urls": 1,
        })
    )
    monkeypatch.setattr(ws, "_collect_asset_urls", lambda: [url])
    monkeypatch.setattr(ws, "_fetch_asset", lambda u, **k: "")  # origin still down
    ws.download_assets()
    report = json.loads((ws.base / "download_report.json").read_text())
    assert report["complete"] is False
    assert not any(o.get("file") == fname for o in report["obtained"])
    assert any(m.get("file") == fname for m in report["missing"])


def test_hunt_malformed_prior_report_blocks_complete(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://app.acme.example/",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    (ws.base / "download_report.json").write_text("{corrupt json")
    monkeypatch.setattr(ws, "_collect_asset_urls", lambda: ["https://app.acme.example/"])
    monkeypatch.setattr(ws, "_fetch_asset", lambda url, **k: "ok " * 40)
    monkeypatch.setattr(omc, "_raw_get", lambda url, **k: "raw " * 40)
    ws.download_assets()
    report = json.loads((ws.base / "download_report.json").read_text())
    # The unreadable prior report's missing set is unknown — named, and
    # the rewrite cannot claim complete over it.
    assert report["complete"] is False
    assert any(
        m.get("status") == "prior-report-unreadable" for m in report["missing"]
    )


def test_bundle_packs_report_and_blocks_empty_download(tmp_path):
    import oracle_bundle as ob

    root = tmp_path / "ws"
    (root / "reports").mkdir(parents=True)
    (root / "findings").mkdir()
    (root / "program.json").write_text(
        json.dumps({"name": "Acme", "handle": "acme", "platform": "hackerone"})
    )
    (root / "reports" / "report_full.md").write_text("full report")
    snap = {
        "generated": "2026-01-01T00:00:00Z",
        "target": "https://app.example/",
        "hunt": {
            "unserved_mindsets": [],
            "oracle_rescan": {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "found": True,
                "handle": "acme",
            },
            "mindsets_unserved": [],
        },
        "summary": {"confirmed": 1},
        "results": {
            "1": {
                "verdict": "x",
                "confirmed": True,
                "poc_output": "--- HTTP Request ---\n GET / \n--- HTTP Response ---\n200",
            }
        },
    }
    (root / "reports" / "report_verify_results_20260101_000000.md").write_text(
        json.dumps(snap)
    )
    (root / "findings" / "seam_01_acme.json").write_text(json.dumps({"n": 1}))
    (root / "download_report.json").write_text(
        json.dumps(
            {
                "schema": "oracle.download-report/v1",
                "status": "empty",
                "complete": False,
                "obtained_count": 0,
                "missing_count": 3,
                "obtained": [],
                "missing": [{"file": "a.html", "url": "https://x/"}],
            }
        )
    )
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="empty-dl")
    assert result["readiness"]["ready_for_submission"] is False
    assert result["readiness"]["checks"]["download_completeness"]["status"] == "empty"
    rels = {e["path"] for e in result["manifest"]["files"]}
    assert "download_report.json" in rels


def test_completeness_round3_hardening(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a").write_text("x")
    (tmp_path / "assets" / "b").write_text("x")
    good = {"file": "a", "url": "https://x/a", "status": 200, "via": "plain-get"}

    def write(rep):
        (tmp_path / "download_report.json").write_text(json.dumps(rep))

    base = {"schema": "oracle.download-report/v1", "missing": [], "expected_urls": 1}
    # Compound / non-string / missing via is unknown provenance, never obtained.
    for via in ("jina-render", "cdp+plain-get", ["plain-get"], 200, "", None):
        entry = dict(good)
        if via is None:
            entry.pop("via")
        else:
            entry["via"] = via
        write({**base, "obtained": [entry]})
        assert obd.download_completeness(tmp_path)["complete"] is False, via
    # Duplicate obtained entries cannot inflate coverage to the denominator.
    write({**base, "expected_urls": 2, "obtained": [good, dict(good)]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # A present-but-malformed denominator poisons even with a valid second one.
    write({**base, "expected_urls": "abc", "enumerated": 1, "obtained": [good]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    write({**base, "expected_urls": 1, "enumerated": "x", "obtained": [good]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # Bundle mode drops only the disk check: entry shape still required.
    write({**base, "obtained": [{"status": 200, "via": "plain-get"}]})
    assert (
        obd.download_completeness(tmp_path, require_files=False)["complete"]
        is False
    )
    write({**base, "obtained": [
        {"file": "../evil", "status": 200, "via": "plain-get"}
    ]})
    assert (
        obd.download_completeness(tmp_path, require_files=False)["complete"]
        is False
    )
    # Ghost file passes bundle mode (asset bodies are not packed) only.
    ghost = {"file": "ghost", "url": "https://x/g", "status": 200, "via": "plain-get"}
    write({**base, "obtained": [ghost]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    assert (
        obd.download_completeness(tmp_path, require_files=False)["complete"]
        is True
    )
    # Recomputed methods + denominator are exposed for consumers (brief).
    comp = obd.download_completeness(tmp_path, require_files=False)
    assert comp["expected_urls"] == 1
    assert comp["methods"]["plain-get"]["ok"] == 1


def test_validated_obtained_files_tolerates_non_list_obtained(tmp_path):
    # A schema-valid prior report can still carry a non-iterable
    # obtained field; cache-provenance reading must fail closed to an
    # empty set (re-fetch), never crash the download paths.
    for bad in (5, 5.5, True, "x", {"file": "a"}):
        report = {"schema": "oracle.download-report/v1", "obtained": bad}
        assert obd.validated_obtained_files(tmp_path, report) == set(), bad


def test_hunt_raw_companion_requires_prior_provenance(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://app.acme.example/",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    url = "https://app.acme.example/"
    fname = omc._url_to_filename(url)
    raw_name = Path(fname).stem + ".raw.html"
    # Planted stale raw companion, no prior report proves it.
    (ws.assets_dir / raw_name).write_text("STALE RAW " * 30)
    calls = {"raw": 0}

    def fake_raw(u, **k):
        calls["raw"] += 1
        return "fresh raw " * 20

    monkeypatch.setattr(ws, "_collect_asset_urls", lambda: [url])
    monkeypatch.setattr(ws, "_fetch_asset", lambda u, **k: "ok " * 40)
    monkeypatch.setattr(omc, "_raw_get", fake_raw)
    ws.download_assets()
    assert calls["raw"] == 1  # re-fetched, not suppressed by existence
    assert "fresh raw" in (ws.assets_dir / raw_name).read_text()
    report = json.loads((ws.base / "download_report.json").read_text())
    assert any(r.get("file") == raw_name for r in report["raw_companions"])


def test_brief_tolerates_malformed_missing_fields(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://platform.example/acme",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    (ws.base / "download_report.json").write_text(
        json.dumps({
            "schema": "oracle.download-report/v1",
            "complete": True,
            "status": "complete",
            "obtained": [],
            "missing": 5,
            "not_enumerated": "oops",
            "expected_urls": 1,
        })
    )
    ctx = omc.OracleMindsetContext(prog)
    monkeypatch.setattr(omc, "_HERE", tmp_path)
    import shutil

    dest = tmp_path / "targets" / ws.platform / ws.slug
    if dest != ws.base:
        shutil.copytree(ws.base, dest, dirs_exist_ok=True)
    brief = ctx._program_brief()  # must not raise on malformed fields
    assert "DOWNLOAD COVERAGE" in brief
    assert "status=empty" in brief  # recomputed, not the forged complete


def test_completeness_round3b_edges(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a").write_text("x")
    good = {"file": "a", "url": "https://x/a", "status": 200, "via": "plain-get"}

    def write(rep):
        (tmp_path / "download_report.json").write_text(json.dumps(rep))

    base = {"schema": "oracle.download-report/v1", "missing": [], "expected_urls": 1}
    # crawl4ai must tokenize as one cascade token (digits kept).
    summary = obd.summarize_download_results(
        [{"file": "a", "url": "https://x/a", "status": "ok", "via": "crawl4ai"}],
        expected_urls=1,
    )
    assert summary["obtained"] == [] and summary["complete"] is False
    # A rendered file hidden from both obtained and missing blocks complete.
    write({**base, "obtained": [good],
           "rendered": [{"file": "b", "status": "cascade", "via": "jina"}]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # The report itself is not an obtained asset.
    write({**base, "obtained": [
        {"file": "download_report.json", "status": 200, "via": "plain-get"}
    ]})
    assert obd.download_completeness(tmp_path)["complete"] is False
    # An empty file on disk is not obtained coverage.
    (tmp_path / "assets" / "empty").write_text("")
    write({**base, "obtained": [
        {"file": "empty", "url": "https://x/e", "status": 200, "via": "plain-get"}
    ]})
    assert obd.download_completeness(tmp_path)["complete"] is False


def test_summarize_via_compound_and_dedup():
    summary = obd.summarize_download_results(
        [
            {"file": "a", "url": "https://x/a", "status": "ok", "via": "jina-render"},
            {"file": "b", "url": "https://x/b", "status": 200, "via": "plain-get"},
            {"file": "b", "url": "https://x/b", "status": 200, "via": "plain-get"},
        ],
        expected_urls=2,
    )
    assert [o["file"] for o in summary["obtained"]] == ["b"]
    assert summary["complete"] is False  # duplicate b cannot fill a's slot
    assert summary["coverage_pct"] == 50


def test_scan_page_cache_requires_prior_authenticated_proof(tmp_path, monkeypatch):
    monkeypatch.setattr(oracle_scan, "_cdp_available", lambda port=9227: False)
    monkeypatch.setattr(
        oracle_scan,
        "_cascade_fetch_with_via",
        lambda url, timeout=45: ("rendered " + "x" * 80, "jina"),
    )
    monkeypatch.setattr(
        oracle_scan,
        "_collect_asset_urls",
        lambda prog: [("app__openapi.json", "https://app.acme.example/openapi.json")],
    )
    monkeypatch.setattr(oracle_scan, "_route_scope_records", lambda prog: {})

    class _Resp:
        ok = True
        status_code = 200
        text = "openapi " * 20

    monkeypatch.setattr("requests.get", lambda *a, **k: _Resp())
    # A leftover program_page.txt with NO prior report proving an
    # authenticated fetch must not brief as a cached authenticated page.
    (tmp_path / "assets").mkdir(parents=True)
    (tmp_path / "assets" / "program_page.txt").write_text("stale page " * 20)
    _saved, info = oracle_scan.download_program_assets(
        _prog(), tmp_path, take_screenshot=False, clone_repos=False
    )
    assert info["page_source"] == "NO_AUTH_SESSION"
    report = json.loads((tmp_path / "download_report.json").read_text())
    assert any(m.get("file") == "program_page.txt" for m in report["missing"])


def test_hunt_malformed_prior_missing_entries_block_complete(tmp_path, monkeypatch):
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "url": "https://app.acme.example/",
        "structured_scopes": [{"asset_identifier": "app.acme.example"}],
    }
    ws = omc.ProgramWorkspace(prog, base=tmp_path / "targets")
    (ws.base / "download_report.json").write_text(
        json.dumps({
            "schema": "oracle.download-report/v1",
            "status": "partial",
            "complete": False,
            "page_source": "CDP_RENDERED",
            "obtained": [],
            "missing": ["not-a-dict", 42],
            "expected_urls": 1,
        })
    )
    monkeypatch.setattr(ws, "_collect_asset_urls", lambda: ["https://app.acme.example/"])
    monkeypatch.setattr(ws, "_fetch_asset", lambda url, **k: "ok " * 40)
    monkeypatch.setattr(omc, "_raw_get", lambda url, **k: "raw " * 40)
    ws.download_assets()
    report = json.loads((ws.base / "download_report.json").read_text())
    assert report["complete"] is False
    assert any(
        m.get("status") == "prior-missing-malformed" for m in report["missing"]
    )


def test_bundle_cross_checks_yield_ledger_against_unserved_claim(tmp_path):
    """An explicit unserved_mindsets=[] contradicted by the snapshot's own
    yield_ledger (a lens recorded unserved) must block readiness."""
    import oracle_bundle as ob

    root = tmp_path / "ws"
    (root / "reports").mkdir(parents=True)
    (root / "findings").mkdir()
    (root / "program.json").write_text(
        json.dumps({"name": "Acme", "handle": "acme", "platform": "hackerone"})
    )
    (root / "reports" / "report_full.md").write_text("full report")
    snap = {
        "generated": "2026-01-01T00:00:00Z",
        "target": "https://app.example/",
        "hunt": {
            "unserved_mindsets": [],
            "effective_mindsets": ["mitre", "paradox"],
            "yield_ledger": [
                {"mindset": "mitre", "minted": 1, "cause": "minted"},
                {"mindset": "paradox", "minted": 0, "cause": "unserved"},
            ],
            "oracle_rescan": {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "found": True,
                "handle": "acme",
            },
        },
        "summary": {"confirmed": 1},
        "results": {
            "1": {
                "verdict": "x",
                "confirmed": True,
                "poc_output": "--- HTTP Request ---\n GET / \n--- HTTP Response ---\n200",
            }
        },
    }
    (root / "reports" / "report_verify_results_20260101_000000.md").write_text(
        json.dumps(snap)
    )
    (root / "findings" / "seam_01_acme.json").write_text(json.dumps({"n": 1}))
    result = ob.build_bundle(root, out_dir=tmp_path / "out", stamp="ledger-x")
    assert result["readiness"]["ready_for_submission"] is False
    assert any(
        "yield_ledger" in r and "paradox" in r
        for r in result["readiness"]["reasons"]
    )


def test_bundle_yield_ledger_must_be_present_and_well_formed(tmp_path):
    """Fail-closed: omitted/non-list/empty/malformed yield ledgers and
    case/whitespace cause variants can never mint readiness."""
    import oracle_bundle as ob

    def assess_with(ledger_marker):
        root = tmp_path / f"ws-{abs(hash(str(ledger_marker))) % 10**6}"
        (root / "reports").mkdir(parents=True)
        (root / "findings").mkdir()
        (root / "program.json").write_text(
            json.dumps({"name": "Acme", "handle": "acme", "platform": "hackerone"})
        )
        (root / "reports" / "report_full_20260101_000000.md").write_text("full")
        (root / "reports" / "report_seam_1_20260101_000000.md").write_text("poc")
        (root / "findings" / "finding_001.json").write_text(
            json.dumps({"n": 1, "verify_confirmed": True})
        )
        hunt = {
            "unserved_mindsets": [],
            "effective_mindsets": ["mitre"],
            "oracle_rescan": {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "found": True,
                "handle": "acme",
            },
        }
        if ledger_marker != "OMITTED":
            hunt["yield_ledger"] = ledger_marker
        snap = {
            "generated": "2026-01-01T00:00:00Z",
            "target": "https://app.example/",
            "hunt": hunt,
            "summary": {"confirmed": 1, "total": 1},
            "results": {"1": {"verdict": "CONFIRMED", "confirmed": True}},
        }
        (root / "reports" / "report_verify_results_20260101_000000.md").write_text(
            json.dumps(snap)
        )
        return ob.assess_workspace(root)

    bad_ledgers = [
        "OMITTED",
        {"paradox": "unserved"},  # dict, not list
        [],  # empty: hunter always writes one entry per effective lens
        [{"mindset": "paradox", "cause": "Unserved"}],
        [{"mindset": "paradox", "cause": "unserved "}],
        [{"cause": "unserved"}],  # entry lacking mindset
        [{"mindset": "paradox", "cause": "bogus"}],
        ["not-a-dict"],
    ]
    for bad in bad_ledgers:
        readiness = assess_with(bad)
        assert readiness["ready_for_submission"] is False, bad
        assert any("yield_ledger" in r for r in readiness["reasons"]), bad
    good = assess_with([{"mindset": "mitre", "minted": 1, "cause": "minted"}])
    assert not any("yield_ledger" in r for r in good["reasons"]), good["reasons"]


def test_bundle_yield_ledger_must_cover_effective_mindsets(tmp_path):
    """A well-formed ledger naming the wrong lens set (subset, bogus
    extra, or no effective_mindsets to cover) cannot mint readiness."""
    import oracle_bundle as ob

    def assess_with(hunt_extra, tag):
        root = tmp_path / f"ws-{tag}"
        (root / "reports").mkdir(parents=True)
        (root / "findings").mkdir()
        (root / "program.json").write_text(
            json.dumps({"name": "Acme", "handle": "acme", "platform": "hackerone"})
        )
        (root / "reports" / "report_full_20260101_000000.md").write_text("full")
        (root / "reports" / "report_seam_1_20260101_000000.md").write_text("poc")
        (root / "findings" / "finding_001.json").write_text(
            json.dumps({"n": 1, "verify_confirmed": True})
        )
        hunt = {
            "unserved_mindsets": [],
            "oracle_rescan": {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "found": True,
                "handle": "acme",
            },
        }
        hunt.update(hunt_extra)
        snap = {
            "generated": "2026-01-01T00:00:00Z",
            "target": "https://app.example/",
            "hunt": hunt,
            "summary": {"confirmed": 1, "total": 1},
            "results": {"1": {"verdict": "CONFIRMED", "confirmed": True}},
        }
        (root / "reports" / "report_verify_results_20260101_000000.md").write_text(
            json.dumps(snap)
        )
        return ob.assess_workspace(root)

    def minted(m):
        return {"mindset": m, "minted": 1, "cause": "minted"}
    bad = [
        # Ledger covers only one of two effective lenses.
        {"effective_mindsets": ["mitre", "paradox"],
         "yield_ledger": [minted("mitre")]},
        # Ledger names a bogus lens instead of the effective one.
        {"effective_mindsets": ["mitre"],
         "yield_ledger": [minted("bogus")]},
        # No effective_mindsets to cover at all.
        {"yield_ledger": [minted("mitre")]},
        # Effective list malformed.
        {"effective_mindsets": "mitre",
         "yield_ledger": [minted("mitre")]},
        {"effective_mindsets": [],
         "yield_ledger": [minted("mitre")]},
    ]
    for i, hunt_extra in enumerate(bad):
        readiness = assess_with(hunt_extra, f"cov{i}")
        assert readiness["ready_for_submission"] is False, hunt_extra
        assert any(
            "yield_ledger" in r or "effective_mindsets" in r
            for r in readiness["reasons"]
        ), (hunt_extra, readiness["reasons"])
