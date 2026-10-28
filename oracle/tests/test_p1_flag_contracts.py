"""P1 flag/config contracts from the adversarial audit batch.

Each test pins a defect the audit reproduced: DNS TLD allowlist drops,
limit/top zero+negative semantics, silent overlay fallbacks, CLI
tracebacks instead of clean exits, and a dead --model on analyze.
"""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
import oracle_intake as oi
import oracle_llm
import oracle_scan4me as bridge


# ── DNS predicate ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "superbet.ro",
        "*.superbet.gr",
        "superbet.rs",
        "app.example.work",
        "x.gg",
        "a.nz",
        "bank.finance",
        "example.com",
        "sub.deep.example.co.uk",
        "127.0.0.1",
        "203.0.113.7",
    ],
)
def test_dns_target_accepts_real_hosts(host):
    assert oh._is_dns_target(host) is True
    assert oi._is_dns_target(host) is True  # one shared predicate


@pytest.mark.parametrize(
    "host",
    [
        "com.wolt.android",
        "com.acme.mobile",
        "com.acme.banking",
        "943905271",
        "01.2.3.4",
        "00.1.1.1",
        "a_b.example.com",
        "localhost",
        "example",
        "exa mple.com",
        "example.com/path",
        "-bad.example.com",
        "bad-.example.com",
        "999.1.1.1",
        "example.123",
        "",
    ],
)
def test_dns_target_rejects_non_hosts(host):
    assert oh._is_dns_target(host) is False
    assert oi._is_dns_target(host) is False


def test_extract_domains_keeps_new_tlds():
    out = oh._extract_domains("*.superbet.ro\nhttps://app.example.work/x\ncom.wolt.android\n")
    assert "superbet.ro" in out
    assert "app.example.work" in out
    assert "com.wolt.android" not in out


# ── limit semantics ──────────────────────────────────────────────────────────


def test_run_prescan_limit_matrix(tmp_path):
    fetch = lambda: [{"name": "A"}, {"name": "B"}, {"name": "C"}]  # noqa: E731
    r0 = oi.run_prescan(fetch_fn=fetch, limit=0, out_dir=tmp_path, stamp="l0")
    assert r0["count"] == 0
    r2 = oi.run_prescan(fetch_fn=fetch, limit=2, out_dir=tmp_path, stamp="l2")
    assert r2["count"] == 2
    with pytest.raises(ValueError):
        oi.run_prescan(fetch_fn=fetch, limit=-1, out_dir=tmp_path, stamp="ln")


def test_fetch_contests_limit_matrix():
    assert bridge.fetch_contests(limit=0) == []
    with pytest.raises(ValueError):
        bridge.fetch_contests(limit=-1)


@pytest.mark.parametrize("bad", [True, 2.0, -1, "2"])
def test_fetch_programs_limit_validation(bad):
    with pytest.raises(ValueError):
        bridge.fetch_programs(limit=bad)


@pytest.mark.parametrize("bad", [True, 2.0, -1, "2"])
def test_select_deep_dive_top_n_validation(bad):
    with pytest.raises(ValueError):
        oi.select_deep_dive({"verdicts": []}, top_n=bad)


def test_cmd_prescan_sync_no_cloud_dies_clean():
    args = types.SimpleNamespace(
        sync=True, cloud=False, limit=5, out_dir=None
    )
    with pytest.raises(SystemExit):
        oh.cmd_prescan(args)


def test_cmd_prescan_negative_limit_dies_clean():
    args = types.SimpleNamespace(sync=False, cloud=True, limit=-3, out_dir=None)
    with pytest.raises(SystemExit):
        oh.cmd_prescan(args)


# ── overlay contracts ────────────────────────────────────────────────────────


def test_overlay_all_zero_weights_fail_loud():
    tri = {
        "weights": {
            "asset_count": 0,
            "fast_triage": 0,
            "new_assets": 0,
            "recency": 0,
            "low_reports": 0,
            "payout": 0,
        }
    }
    with pytest.raises(ValueError):
        bridge.triage_prescan_overlay({"ranking_weights": {"payout_size": 9}}, tri)


def test_overlay_negative_weights_fail_loud():
    tri = {"weights": {"asset_count": 1, "payout": -2}}
    with pytest.raises(ValueError):
        bridge.triage_prescan_overlay({}, tri)


def test_triage_cfg_corrupt_fails_loud(monkeypatch):
    import oracle_triage

    def boom(path):
        raise ValueError("bad yaml")

    monkeypatch.setattr(oracle_triage, "load_config", boom)
    with pytest.raises(ValueError):
        bridge._triage_cfg_or_none()


# ── analyze --model reaches the router ───────────────────────────────────────


def test_config_hunt_cloud_false_pins_local(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"hunt": {"cloud": false}}')
    args = types.SimpleNamespace(cloud=None, config=str(cfg))
    oh._config_hunt_cloud(args)
    assert args.cloud is False
    # CLI always wins over config.
    args2 = types.SimpleNamespace(cloud=True, config=str(cfg))
    oh._config_hunt_cloud(args2)
    assert args2.cloud is True
    # Config true/absent leaves auto (None) untouched.
    cfg.write_text('{"hunt": {"cloud": true}}')
    args3 = types.SimpleNamespace(cloud=None, config=str(cfg))
    oh._config_hunt_cloud(args3)
    assert args3.cloud is None
    # Malformed hunt block must not crash cmd_hunt before it starts.
    cfg.write_text('{"hunt": "yes"}')
    args4 = types.SimpleNamespace(cloud=None, config=str(cfg))
    oh._config_hunt_cloud(args4)
    assert args4.cloud is None


def test_status_never_prints_key_fragments(monkeypatch, capsys):
    secret = "sk-live-abcdef0123456789tail"
    monkeypatch.setattr(
        oh, "_load_env", lambda: {"HACKERONE_API_KEY": secret, "RESEARCHER_HANDLE": "h"}
    )
    monkeypatch.setattr(oh, "_run", lambda *a, **k: (1, "", "down"))
    monkeypatch.setattr(oh, "_tool_ok", lambda t: False)
    monkeypatch.setattr(oracle_llm, "load_backend_config", lambda: {"routes": {}})
    oh.cmd_status()
    out = capsys.readouterr().out
    assert secret[:8] not in out and secret[-4:] not in out
    assert "HACKERONE_API_KEY set" in out


def test_cmd_analyze_model_reaches_router(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(
        oracle_llm, "set_preferred_local_model", lambda m: seen.setdefault("m", m)
    )
    monkeypatch.setattr(oh, "run_reflexes", lambda *a, **k: "TARGET CLEAN\n")
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    args = types.SimpleNamespace(cloud=False, model="pinned-model-1")
    oh.cmd_analyze(str(tmp_path), args)
    assert seen["m"] == "pinned-model-1"
