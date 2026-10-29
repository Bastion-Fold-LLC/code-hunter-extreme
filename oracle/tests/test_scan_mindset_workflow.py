import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_mindset_context as mindset
import oracle_programs
import oracle_scan


def test_scan_defaults_to_every_registered_platform(monkeypatch):
    captured = {}
    programs = [
        {"platform": "bugcrowd", "name": "B1"},
        {"platform": "bugcrowd", "name": "B2"},
        {"platform": "hackerone", "name": "H1"},
        {"platform": "hackerone", "name": "H2"},
    ]

    def _fake_fetch(platforms, return_errors=False):
        captured["platforms"] = platforms
        if return_errors:
            return programs, []
        return programs

    monkeypatch.setattr(oracle_programs, "_load_cache", lambda: [])
    monkeypatch.setattr(
        oracle_programs,
        "fetch_all_programs",
        _fake_fetch,
    )
    monkeypatch.setattr(
        oracle_programs, "_save_cache", lambda _programs, **_kwargs: None
    )
    monkeypatch.setattr(oracle_programs, "filter_programs", lambda values, **_kwargs: values)

    cfg = oracle_scan._default_config()
    cfg["filter"]["pick_per_platform"] = 1
    assert [p["name"] for p in oracle_scan.scan_platforms(cfg)] == ["B1", "H1"]
    assert captured["platforms"] is None


def test_pick_per_platform_selects_top_n_from_each_source():
    programs = [
        {"platform": "bugcrowd", "name": "B1"},
        {"platform": "bugcrowd", "name": "B2"},
        {"platform": "hackerone", "name": "H1"},
        {"platform": "hackerone", "name": "H2"},
    ]

    assert [p["name"] for p in oracle_scan.pick_per_platform(programs, 1)] == ["B1", "H1"]


def test_mindset_world_binds_scope_rules_and_both_seam_engines():
    program = {
        "name": "Example",
        "platform": "hackerone",
        "url": "https://example.test",
        "structured_scopes": [
            {
                "asset_identifier": "https://api.example.test",
                "asset_type": "URL",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            }
        ],
        "rules": "Do not test production payment flows.",
    }
    ctx = mindset.OracleMindsetContext(program=program, voice=False, ttp_mode="compact")
    ctx.inject_pending_seams(
        [
            {
                "n": 1,
                "origin": "invisible-seam",
                "claim_type": "contract",
                "reflex": "SPEC-AUDIT",
                "mitre": "CWE-285 / T1190",
                "assertion_a": "Authorization is enforced.",
                "assertion_b": "The code path omits the ownership check.",
                "impact": "Cross-account access.",
            },
            {
                "n": 2,
                "origin": "seam-template",
                "claim_type": "template",
                "reflex": "BINARY CONFLICT + ONE CHECK",
                "mitre": "CWE-20 / T1595",
                "assertion_a": "Input is validated.",
                "assertion_b": "A public route accepts the conflicting input.",
                "impact": "Unexpected state change.",
            },
        ]
    )

    prompt = ctx.system_prompt()

    assert "ACTIVE PROGRAM — SCOPE WALL" in prompt
    assert "https://api.example.test" in prompt
    assert "Do not test production payment flows." in prompt
    assert "ORACLE TTP REFERENCE (fused paradox+MITRE)" in prompt
    assert "PENDING SEAMS" in prompt
    assert "CWE-285 / T1190" in prompt
    assert "CWE-20 / T1595" in prompt


def test_asset_intake_uses_shared_firecrawl_aware_fetch(monkeypatch, tmp_path):
    calls = []

    monkeypatch.setattr(
        oracle_programs,
        "_fetch_with_via",
        lambda url, timeout, use_cdp, redirect_validator=None: calls.append(
            (url, timeout, use_cdp, redirect_validator is not None)
        )
        or ("rendered asset", "plain-get"),
    )
    workspace = mindset.ProgramWorkspace(
        {"name": "Example", "platform": "test"}, base=tmp_path
    )

    assert (
        workspace._fetch_asset("https://api.example.test/openapi.json", timeout=9)
        == "rendered asset"
    )
    # Scoped-asset contract (run-2 remediation): no CDP, redirect validator on.
    assert calls == [("https://api.example.test/openapi.json", 9, False, True)]


def test_asset_intake_accepts_concrete_web_scopes_without_a_repository(tmp_path):
    workspace = mindset.ProgramWorkspace(
        {
            "name": "Website-only",
            "platform": "test",
            "url": "https://program.example.test",
            "structured_scopes": [
                {"asset_identifier": "app.example.test", "asset_type": "DOMAIN"},
                {"asset_identifier": "*.wildcard.example.test", "asset_type": "WILDCARD"},
                {"asset_identifier": "com.example.mobile", "asset_type": "GOOGLE_PLAY_APP_ID"},
            ],
            "scope": "api.example.test\nhttps://docs.example.test",
        },
        base=tmp_path,
    )

    urls = workspace._collect_asset_urls()

    assert "https://app.example.test" in urls
    assert "https://api.example.test" in urls
    assert "https://docs.example.test" in urls
    assert all("*." not in url for url in urls)
    assert all("com.example.mobile" not in url for url in urls)


def test_asset_intake_records_explicit_no_assets_status(monkeypatch, tmp_path):
    monkeypatch.setattr(mindset.ProgramWorkspace, "_fetch_asset", lambda *_args, **_kwargs: "")
    workspace = mindset.ProgramWorkspace(
        {"name": "No assets", "platform": "test", "url": "https://example.test"},
        base=tmp_path,
    )

    assert workspace.download_assets(max_urls=1) == []
    assert workspace.program["asset_status"] == "no-assets"
    assert workspace.program["asset_count"] == 0
