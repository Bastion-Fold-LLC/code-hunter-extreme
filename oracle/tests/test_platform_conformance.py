import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_bulk_download
import oracle_programs


def test_every_discovery_adapter_has_an_explicit_scope_outcome():
    """No listing adapter may silently appear scope-ready."""
    supported_scope = set(oracle_bulk_download._SCOPE_ADAPTERS)
    explicit_unsupported = {"bugbase", "hatsfinance"}

    assert supported_scope.isdisjoint(explicit_unsupported)
    assert set(oracle_programs.SCRAPERS) == supported_scope | explicit_unsupported


def test_scope_intake_reports_unsupported_platform_explicitly():
    scopes, status = oracle_bulk_download.intake_program_scopes({
        "platform": "bugbase",
        "name": "Example",
        "url": "https://bugbase.example/programs/example",
    })

    assert scopes == []
    assert status == "no-adapter"


def test_intigriti_scope_adapter_registered():
    assert "intigriti" in oracle_bulk_download._SCOPE_ADAPTERS
    scopes, status = oracle_bulk_download.intake_program_scopes({
        "platform": "intigriti",
        "handle": "nonexistent_mock_program_xyz",
    })
    # Nonexistent or unresolvable program safely returns empty ok
    assert isinstance(scopes, list)
    assert status == "empty"


def test_intake_distinguishes_error_from_empty(monkeypatch):
    """Transport failure is 'error' (not authoritative), genuine absence is 'empty'."""

    def _boom(prog):
        raise RuntimeError("transport down")

    def _void(prog):
        return []

    def _full(prog):
        return [{"asset_identifier": "example.com", "kind": "DOMAIN"}]

    monkeypatch.setitem(oracle_bulk_download._SCOPE_ADAPTERS, "t_err", _boom)
    monkeypatch.setitem(oracle_bulk_download._SCOPE_ADAPTERS, "t_mty", _void)
    monkeypatch.setitem(oracle_bulk_download._SCOPE_ADAPTERS, "t_ok", _full)

    scopes, status = oracle_bulk_download.intake_program_scopes({"platform": "t_err"})
    assert scopes == [] and status == "error"

    scopes, status = oracle_bulk_download.intake_program_scopes({"platform": "t_mty"})
    assert scopes == [] and status == "empty"

    scopes, status = oracle_bulk_download.intake_program_scopes({"platform": "t_ok"})
    assert len(scopes) == 1 and status == "ok"
