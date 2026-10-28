"""Multi-path download verification contracts.

Multiple fetch paths exist to corroborate data, not merely to fail
over: the saved CDP session stays authoritative for platform pages,
an independent cascade render (Crawl4AI/Jina/Firecrawl/GET) cross-
checks it, renderable assets get a second path when plain GET fails,
and every result records which path served it.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_scan


def _prog():
    return {
        "name": "Acme Widgets",
        "platform": "TestPlat",
        "url": "https://platform.example/programs/acme",
        "structured_scopes": [
            {"asset_identifier": "*.acme.example"},
            {"asset_identifier": "app.acme.example"},
        ],
    }


def _setup(monkeypatch, cascade_text="x", asset_urls=None):
    monkeypatch.setattr(oracle_scan, "_cdp_available", lambda port=9227: False)
    monkeypatch.setattr(oracle_scan, "_cascade_fetch", lambda url, timeout=45: cascade_text)
    monkeypatch.setattr(oracle_scan, "_collect_asset_urls", lambda prog: asset_urls or [])
    monkeypatch.setattr(oracle_scan, "_route_scope_records", lambda prog: {})


def test_corroboration_never_substitutes_for_authenticated_page(tmp_path, monkeypatch):
    _setup(
        monkeypatch,
        cascade_text="Acme Widgets bounty. In scope: app.acme.example " + "y" * 80,
    )
    saved, info = oracle_scan.download_program_assets(
        _prog(), tmp_path, take_screenshot=False, clone_repos=False
    )
    # No saved session: authoritative page stays failed, loudly.
    assert info["page_source"] == "NO_AUTH_SESSION"
    assert not (tmp_path / "assets" / "program_page.txt").exists()
    # ...but the independent path still ran and cross-checked identity/scope.
    corr = info["page_corroboration"]
    assert corr["fetched"] is True
    assert corr["name_match"] is True
    assert "app.acme.example" in corr["scope_hits"]
    assert "program_page_corroboration.txt" in saved

    report = json.loads((tmp_path / "download_report.json").read_text())
    assert report["page_corroboration"]["scope_hit_count"] >= 1


def test_renderable_asset_falls_to_cascade_with_provenance(tmp_path, monkeypatch):
    _setup(
        monkeypatch,
        cascade_text="<html>rendered app shell with real content here</html>" + "z" * 60,
        asset_urls=[("app.acme.example__homepage.html", "https://app.acme.example/")],
    )

    class _Boom:
        pass

    def _fail(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr("requests.get", _fail)
    saved, info = oracle_scan.download_program_assets(
        _prog(), tmp_path, take_screenshot=False, clone_repos=False
    )
    report = json.loads((tmp_path / "download_report.json").read_text())
    (res,) = report["results"]
    assert res["via"] == "cascade"
    assert res["status"] == "cascade"
    assert res["plain_status"] == "fetch-failed"
    # Cascade content is saved for analysis but never counted as a
    # verified 2xx download.
    assert report["fetched_ok"] == 0
    assert report["cascade_fetched"] == 1
    assert "app.acme.example__homepage.html" in saved


def test_non_renderable_asset_failure_never_calls_cascade(tmp_path, monkeypatch):
    calls = []

    def _spy(url, timeout=45):
        calls.append(url)
        return "nope " * 30

    _setup(monkeypatch, asset_urls=[("app__openapi.json", "https://app.acme.example/openapi.json")])
    monkeypatch.setattr(oracle_scan, "_cascade_fetch", _spy)

    def _fail(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr("requests.get", _fail)
    oracle_scan.download_program_assets(
        _prog(), tmp_path, take_screenshot=False, clone_repos=False
    )
    # Only the program-page corroboration used the cascade.
    assert calls == ["https://platform.example/programs/acme"]
    report = json.loads((tmp_path / "download_report.json").read_text())
    (res,) = report["results"]
    assert res["via"] == "plain-get"
    assert res["status"] == "fetch-failed"
