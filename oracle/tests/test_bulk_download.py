"""Bulk download regression: manifest creation when scopes already exist."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_bulk_download as obd
import oracle_hunter as oh
import oracle_mindset_context as omc
import oracle_scan


def test_download_one_with_existing_scopes_writes_manifest(tmp_path, monkeypatch):
    class FakeWorkspace:
        def __init__(self, prog, base):
            self.base = tmp_path / "workspace"
            self.assets_dir = self.base / "assets"
            self.assets_dir.mkdir(parents=True)

        def save_program_json(self):
            (self.base / "program.json").write_text("{}")

        def save_program_brief(self, ctx):
            (self.base / "program_brief.md").write_text("brief")

    monkeypatch.setattr(omc, "ProgramWorkspace", FakeWorkspace)
    monkeypatch.setattr(omc, "OracleMindsetContext", lambda *a, **k: object())
    monkeypatch.setattr(oh, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(oh, "_extract_repo_urls", lambda *a, **k: [])
    monkeypatch.setattr(
        oracle_scan,
        "download_program_assets",
        lambda *a, **k: (
            ["asset.txt"],
            {"page_source": "test", "auth_session": False},
        ),
    )
    prog = {
        "name": "Acme",
        "platform": "TestPlat",
        "structured_scopes": [{"asset_identifier": "app.example.com"}],
    }
    out = obd.download_one(prog, cdp_port=9227, take_screenshot=False)
    assert out["status"] == "downloaded"
    manifest = json.loads((tmp_path / "workspace" / obd.MANIFEST).read_text())
    assert manifest["downloaded_at"]
    assert manifest["asset_count"] == 1


def _patched_download(monkeypatch, tmp_path, intake_result):
    captured = {}

    class FakeWorkspace:
        def __init__(self, prog, base):
            captured["prog"] = prog
            self.base = tmp_path / "workspace"
            self.assets_dir = self.base / "assets"
            self.assets_dir.mkdir(parents=True)

        def save_program_json(self):
            (self.base / "program.json").write_text("{}")

        def save_program_brief(self, ctx):
            (self.base / "program_brief.md").write_text("brief")

    monkeypatch.setattr(omc, "ProgramWorkspace", FakeWorkspace)
    monkeypatch.setattr(omc, "OracleMindsetContext", lambda *a, **k: object())
    monkeypatch.setattr(oh, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(oh, "_extract_repo_urls", lambda *a, **k: [])
    monkeypatch.setattr(obd, "intake_program_scopes", lambda prog: intake_result)
    monkeypatch.setattr(
        oracle_scan,
        "download_program_assets",
        lambda *a, **k: (["asset.txt"], {"page_source": "test", "auth_session": False}),
    )
    return captured


def test_download_one_refreshes_scope_from_source_even_when_present(
    tmp_path, monkeypatch
):
    # API/source intake must run even when the handoff already carries
    # DB scopes: fresh assets merge in, provenance is recorded.
    captured = _patched_download(
        monkeypatch,
        tmp_path,
        (
            [
                {"asset_identifier": "api.example.com"},
                {"asset_identifier": "app.example.com"},
            ],
            "ok",
        ),
    )
    prog = {
        "name": "Acme",
        "platform": "Intigriti",
        "structured_scopes": [{"asset_identifier": "app.example.com"}],
    }
    out = obd.download_one(prog, cdp_port=9227, take_screenshot=False)
    assert out["status"] == "downloaded"
    idents = {
        s["asset_identifier"] for s in captured["prog"]["structured_scopes"]
    }
    assert idents == {"app.example.com", "api.example.com"}
    assert captured["prog"]["scope_intake_status"] == "ok"
    assert captured["prog"]["scope_intake_new"] == 1
    assert captured["prog"]["scope_intake_fresh"] == 2
    assert captured["prog"]["scope_intake_missing"] == 0


def test_download_one_failed_intake_never_deletes_existing_scope(
    tmp_path, monkeypatch
):
    captured = _patched_download(monkeypatch, tmp_path, ([], "error"))
    prog = {
        "name": "Acme",
        "platform": "Intigriti",
        "structured_scopes": [{"asset_identifier": "app.example.com"}],
    }
    out = obd.download_one(prog, cdp_port=9227, take_screenshot=False)
    assert out["status"] == "downloaded"
    assert captured["prog"]["structured_scopes"] == [
        {"asset_identifier": "app.example.com"}
    ]
    assert captured["prog"]["scope_intake_status"] == "error"


def test_refresh_program_scopes_merges_and_stamps(monkeypatch):
    # G11 shared helper: hunt and download must refresh identically.
    monkeypatch.setattr(
        obd,
        "intake_program_scopes",
        lambda prog: (
            [
                {"asset_identifier": "api.example.com"},
                {"asset_identifier": "app.example.com"},
            ],
            "ok",
        ),
    )
    prog = {
        "name": "Acme",
        "platform": "Intigriti",
        "structured_scopes": [
            {"asset_identifier": "app.example.com"},
            {"asset_identifier": "old.example.com"},
        ],
    }
    out = obd.refresh_program_scopes(prog)
    idents = {s["asset_identifier"] for s in out["structured_scopes"]}
    # A successful non-empty fetch is authoritative: a revoked asset is
    # no longer current scope and can never be probed again by accident.
    assert idents == {"app.example.com", "api.example.com"}
    assert out["scope_intake_status"] == "ok"
    assert out["scope_intake_at"]
    assert out["scope_intake_new"] == 1
    assert out["scope_intake_fresh"] == 2
    assert out["scope_intake_missing"] == 1
    assert [s["asset_identifier"] for s in out["scope_intake_removed"]] == [
        "old.example.com"
    ]
    assert out["scope_intake_removed"][0]["removed_at"] == out["scope_intake_at"]
    # Input program is not mutated.
    assert "scope_intake_status" not in prog


def test_refresh_program_scopes_failed_intake_keeps_scope(monkeypatch):
    monkeypatch.setattr(
        obd, "intake_program_scopes", lambda prog: ([], "error")
    )
    prog = {
        "name": "Acme",
        "platform": "Intigriti",
        "structured_scopes": [{"asset_identifier": "app.example.com"}],
    }
    out = obd.refresh_program_scopes(prog)
    assert out["structured_scopes"] == [{"asset_identifier": "app.example.com"}]
    assert out["scope_intake_status"] == "error"


def _h1_prog():
    return {
        "name": "Acme",
        "platform": "HackerOne",
        "url": "https://hackerone.com/acme",
        "structured_scopes": [{"asset_identifier": "old.example.com"}],
    }


def test_hackerone_adapter_returns_fresh_out_of_scope_records(monkeypatch):
    import oracle_h1_api as h1

    monkeypatch.setattr(h1, "available", lambda: True)
    monkeypatch.setattr(
        h1,
        "fetch_program",
        lambda handle: {
            "structured_scopes": [
                {"asset_identifier": "app.example.com",
                 "eligible_for_bounty": True, "eligible_for_submission": True}
            ],
            "out_of_scope": ["old.example.com"],
            "out_of_scope_scopes": [
                {"asset_identifier": "old.example.com",
                 "eligible_for_bounty": False, "eligible_for_submission": True}
            ],
        },
    )
    scopes, status = obd.intake_program_scopes(_h1_prog())
    assert status == "ok"
    by_id = {s["asset_identifier"]: s for s in scopes}
    assert set(by_id) == {"app.example.com", "old.example.com"}
    assert by_id["old.example.com"]["eligible_for_bounty"] is False


def test_intake_reports_vanished_hackerone_program(monkeypatch):
    import oracle_h1_api as h1

    monkeypatch.setattr(h1, "available", lambda: True)
    monkeypatch.setattr(h1, "fetch_program", lambda handle: None)
    assert obd.intake_program_scopes(_h1_prog()) == ([], "vanished")


def test_intake_reports_hackerone_auth_error_distinctly(monkeypatch):
    import oracle_h1_api as h1

    monkeypatch.setattr(h1, "available", lambda: True)

    def reject(handle):
        raise h1.H1AuthError("rejected")

    monkeypatch.setattr(h1, "fetch_program", reject)
    assert obd.intake_program_scopes(_h1_prog()) == ([], "auth-error")


def test_refresh_vanished_program_clears_current_scope(monkeypatch):
    monkeypatch.setattr(
        obd, "intake_program_scopes", lambda prog: ([], "vanished")
    )
    out = obd.refresh_program_scopes(_h1_prog())
    assert out["structured_scopes"] == []
    assert out["scope_intake_status"] == "vanished"
    assert [s["asset_identifier"] for s in out["scope_intake_removed"]] == [
        "old.example.com"
    ]
