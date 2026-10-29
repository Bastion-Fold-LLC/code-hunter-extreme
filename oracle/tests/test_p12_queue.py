#!/usr/bin/env python3
"""P12: queue config + deterministic scheduler.

No network, no cloud: handoffs are fixture dicts (or files written by P11's
own ``write_handoff``), config comes from tmp files. Never touches the net.
"""

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_intake as intake
import oracle_queue as queue
from oracle_queue import QueueConfigError


# ── fixtures ──────────────────────────────────────────────────────────────────


def _prog(name, handle, platform, rank, score, payout=1000):
    return {
        "rank": rank,
        "name": name,
        "handle": handle,
        "platform": platform,
        "url": f"https://{platform}.example.com/{handle}",
        "score": float(score),
        "max_payout_usd": payout,
        "currency": "USD",
        "verdict": "verified",
        "checks": {},
        "oracle_rescan": {
            "source": "test-independent-adapter",
            "independent": True,
            "found": True,
        },
        "deep_dive": {
            "assets": [{"asset_identifier": f"app.{handle}.com"}],
            "company": {
                "name": name,
                "handle": handle,
                "platform": platform,
                "website": f"https://{handle}.com",
            },
            "resources": {"program_url": f"https://{platform}.example.com/{handle}"},
            "sources": ["scan4me:programs+assets"],
        },
    }


def _six_progs():
    # ranks interleave across sites so the two orders differ observably
    return [
        _prog("Alpha-1", "a1", "hackerone", 1, 90),
        _prog("Beta-1", "b1", "bugcrowd", 2, 80),
        _prog("Gamma-1", "c1", "intigriti", 3, 70),
        _prog("Alpha-2", "a2", "hackerone", 4, 60),
        _prog("Beta-2", "b2", "bugcrowd", 5, 50),
        _prog("Alpha-3", "a3", "hackerone", 6, 40),
    ]


def _handoff_dict(progs, **kw):
    return {
        "_schema": intake.HANDOFF_SCHEMA,
        "created_utc": "2026-10-12T00:00:00+00:00",
        "prescan_report": "p.json",
        "scan_report": "s.json",
        "no_cloud": kw.get("no_cloud", False),
        "selector": {"top_n": kw.get("top_n"), "sites": kw.get("sites")},
        "ranked_verified": list(progs),
        "excluded_named": [],
        "note": "unverified programs never appear here; see the scan report",
    }


def _names(items):
    return [i["company"]["name"] if "company" in i else i["name"] for i in items]


def _site_waves(sched):
    by_site = {}
    for it in sched["items"]:
        by_site.setdefault(it["site"], []).append(it["wave"])
    return by_site


# ── both orders on fixture ────────────────────────────────────────────────────


def test_finish_site_order_on_fixture():
    ordered = queue.order_programs(_six_progs(), "finish-site")
    assert _names(ordered) == [
        "Alpha-1",
        "Alpha-2",
        "Alpha-3",
        "Beta-1",
        "Beta-2",
        "Gamma-1",
    ]


def test_round_robin_order_on_fixture():
    ordered = queue.order_programs(_six_progs(), "round-robin")
    assert _names(ordered) == [
        "Alpha-1",
        "Beta-1",
        "Gamma-1",
        "Alpha-2",
        "Beta-2",
        "Alpha-3",
    ]


def test_order_ignores_input_permutation():
    progs = _six_progs()
    shuffled = [progs[5], progs[0], progs[3], progs[1], progs[4], progs[2]]
    assert _names(queue.order_programs(shuffled, "finish-site")) == [
        "Alpha-1",
        "Alpha-2",
        "Alpha-3",
        "Beta-1",
        "Beta-2",
        "Gamma-1",
    ]
    assert _names(queue.order_programs(shuffled, "round-robin")) == [
        "Alpha-1",
        "Beta-1",
        "Gamma-1",
        "Alpha-2",
        "Beta-2",
        "Alpha-3",
    ]


def test_bad_order_rejected():
    with pytest.raises(QueueConfigError, match="order"):
        queue.order_programs(_six_progs(), "bogus")


# ── waves: sequential-within-site always, cap respected ───────────────────────


def test_sequential_one_item_per_wave(tmp_path):
    sched = queue.build_schedule(
        _handoff_dict(_six_progs()), config={}, out_dir=tmp_path, stamp="seq1"
    )
    assert sched["queue"] == {
        "order": "finish-site",
        "concurrent": False,
        "cross_site_cap": 3,
        "effective_cap": 1,
    }
    assert sched["count"] == 6
    assert sched["waves"] == 6
    assert [it["wave"] for it in sched["items"]] == [0, 1, 2, 3, 4, 5]
    assert [it["position"] for it in sched["items"]] == [1, 2, 3, 4, 5, 6]


def test_concurrent_cap_respected_and_site_sequential(tmp_path):
    sched = queue.build_schedule(
        _handoff_dict(_six_progs()),
        order="round-robin",
        concurrent=True,
        cross_site_cap=2,
        config={},
        out_dir=tmp_path,
        stamp="cc1",
    )
    assert sched["queue"]["effective_cap"] == 2
    sizes = {}
    for it in sched["items"]:
        sizes[it["wave"]] = sizes.get(it["wave"], 0) + 1
    assert max(sizes.values()) <= 2
    assert sched["waves"] == 3  # [A1,B1] [C1,A2] [B2,A3]
    for site, waves in _site_waves(sched).items():
        assert waves == sorted(waves) and len(set(waves)) == len(waves), site


def test_site_sequential_also_when_concurrent_default_order(tmp_path):
    sched = queue.build_schedule(
        _handoff_dict(_six_progs()),
        concurrent=True,
        cross_site_cap=3,
        config={},
        out_dir=tmp_path,
        stamp="cc2",
    )
    for site, waves in _site_waves(sched).items():
        assert waves == sorted(waves) and len(set(waves)) == len(waves), site


def test_concurrent_cap_one_is_sequential(tmp_path):
    sched = queue.build_schedule(
        _handoff_dict(_six_progs()),
        concurrent=True,
        cross_site_cap=1,
        config={},
        out_dir=tmp_path,
        stamp="cc3",
    )
    assert sched["waves"] == 6


# ── precedence CLI > config > builtin ─────────────────────────────────────────


def test_cli_over_config_precedence():
    spec = queue.resolve_queue(
        cli={"order": "finish-site"},
        config={
            "order": "round-robin",
            "concurrent": True,
            "cross_site_cap": 2,
            "default_count": 7,
        },
    )
    assert spec.order == "finish-site"  # CLI wins
    assert spec.concurrent is True  # config fills the rest
    assert spec.cross_site_cap == 2
    assert spec.default_count == 7


def test_config_over_builtin():
    spec = queue.resolve_queue(config={"order": "round-robin"})
    assert spec.order == "round-robin"
    assert spec.concurrent is False
    assert spec.cross_site_cap == 3
    assert spec.default_count == 5


def test_builtin_defaults_when_nothing_specified():
    spec = queue.resolve_queue()
    assert (spec.order, spec.concurrent, spec.cross_site_cap, spec.default_count) == (
        "finish-site",
        False,
        3,
        5,
    )


def test_null_falls_through_to_next_layer():
    spec = queue.resolve_queue(
        cli={"order": None, "concurrent": None},
        config={"order": None, "concurrent": True},
    )
    assert spec.order == "finish-site"  # both null → builtin
    assert spec.concurrent is True  # CLI null → config


def test_comment_keys_ignored():
    spec = queue.resolve_queue(config={"_comment": "hi", "order": "round-robin"})
    assert spec.order == "round-robin"


# ── invalid config rejected (fail-closed) ─────────────────────────────────────


@pytest.mark.parametrize(
    "block",
    [
        {"order": "bogus"},
        {"order": 123},
        {"order": True},
        {"concurrent": "yes"},
        {"concurrent": 1},
        {"concurrent": 0},
        {"cross_site_cap": 0},
        {"cross_site_cap": -1},
        {"cross_site_cap": "3"},
        {"cross_site_cap": True},
        {"cross_site_cap": 2.0},
        {"default_count": -1},
        {"default_count": "5"},
        {"default_count": False},
        {"default_count": 2.5},
        {"bogus_key": 1},
        {"order": "finish-site", "extra": 0},
        "not-a-dict",
        ["order"],
    ],
)
def test_invalid_config_rejected(block):
    with pytest.raises(QueueConfigError):
        queue.validate_queue_block(block)
    if isinstance(block, dict):
        with pytest.raises(QueueConfigError):
            queue.resolve_queue(config=block)


def test_invalid_non_dict_config_rejected():
    with pytest.raises(QueueConfigError):
        queue.resolve_queue(config="nope")  # type: ignore[arg-type]


def test_invalid_cli_rejected():
    with pytest.raises(QueueConfigError):
        queue.resolve_queue(cli={"order": "bogus"})
    with pytest.raises(QueueConfigError):
        queue.resolve_queue(cli={"cross_site_cap": 0})


def test_bad_config_raises_even_when_cli_overrides():
    with pytest.raises(QueueConfigError):
        queue.resolve_queue(cli={"order": "finish-site"}, config={"order": "bogus"})


def test_load_queue_config_missing_file_is_unspecified(tmp_path):
    assert queue.load_queue_config(tmp_path / "nope.json") == {}


def test_load_queue_config_bad_file_fails_closed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(QueueConfigError, match="JSON"):
        queue.load_queue_config(bad)
    lst = tmp_path / "list.json"
    lst.write_text("[1,2]", encoding="utf-8")
    with pytest.raises(QueueConfigError, match="object"):
        queue.load_queue_config(lst)
    wrong = tmp_path / "wrong.json"
    wrong.write_text('{"queue": {"order": "bogus"}}', encoding="utf-8")
    with pytest.raises(QueueConfigError, match="order"):
        queue.load_queue_config(wrong)


def test_committed_config_carries_valid_queue_block():
    here = Path(__file__).resolve().parent.parent
    raw = json.loads((here / "oracle.config.json").read_text(encoding="utf-8"))
    assert "queue" in raw, "oracle.config.json must define the queue block (P12)"
    spec = queue.resolve_queue(config=queue.load_queue_config())
    assert spec.order == "finish-site"
    assert spec.concurrent is False
    assert spec.cross_site_cap == 3
    assert spec.default_count == 5


# ── determinism: run twice, identical ─────────────────────────────────────────


def test_determinism_run_twice_identical(tmp_path):
    first = queue.build_schedule(
        _handoff_dict(copy.deepcopy(_six_progs())),
        config={"order": "round-robin"},
        out_dir=tmp_path,
        stamp="det1",
    )
    second = queue.build_schedule(
        _handoff_dict(copy.deepcopy(_six_progs())),
        config={"order": "round-robin"},
        out_dir=tmp_path,
        stamp="det2",
    )

    def scrub(payload):
        payload = dict(payload)
        payload.pop("created_utc", None)
        payload.pop("_report_path", None)
        return payload

    assert scrub(first) == scrub(second)
    assert _names(first["items"]) == _names(second["items"])


# ── handoff consumption (P11 format, never redefined) ─────────────────────────


def test_handoff_schema_not_redefined():
    assert queue.HANDOFF_SCHEMA is intake.HANDOFF_SCHEMA


def test_wrong_schema_rejected(tmp_path):
    bad = _handoff_dict(_six_progs())
    bad["_schema"] = "oracle.intake.scan/v1"
    with pytest.raises(QueueConfigError, match="_schema"):
        queue.load_handoff(bad)
    with pytest.raises(QueueConfigError, match="_schema"):
        queue.build_schedule(bad, out_dir=tmp_path, stamp="x")


def test_malformed_handoff_rejected(tmp_path):
    with pytest.raises(QueueConfigError, match="ranked_verified"):
        queue.load_handoff({"_schema": intake.HANDOFF_SCHEMA})
    with pytest.raises(QueueConfigError, match="ranked_verified"):
        queue.load_handoff(
            {"_schema": intake.HANDOFF_SCHEMA, "ranked_verified": "nope"}
        )
    with pytest.raises(QueueConfigError, match="not found"):
        queue.load_handoff(tmp_path / "missing.json")
    with pytest.raises(QueueConfigError, match="no P11 handoff"):
        queue.load_handoff(None, out_dir=tmp_path)


def test_product_handoff_requires_oracle_independent_verification(tmp_path):
    handoff = _handoff_dict(_six_progs())
    # Fresh public Scan4Me discovery is raw, not a queue blocker by itself:
    # every ranked entry already carries independent Oracle verification.
    handoff["feed_trust"] = {
        "ok": False,
        "raw_candidate_ok": True,
        "issues": ["unauthenticated public-file rows: hackerone"],
    }
    sched = queue.build_schedule(
        handoff,
        out_dir=tmp_path,
        stamp="public-verified",
        require_trusted_handoff=True,
    )
    assert sched["feed_trust"]["ok"] is False
    assert sched["count"] == 6

    handoff["ranked_verified"][0]["oracle_rescan"] = {
        "source": "scan4me-db",
        "independent": False,
    }
    with pytest.raises(QueueConfigError, match="not independently verified"):
        queue.build_schedule(
            handoff,
            out_dir=tmp_path,
            stamp="bridge-only",
            require_trusted_handoff=True,
        )

    # An independent stamp cannot rescue a contradictory entry: the
    # product gate judges the whole scan-shaped record, not one flag.
    mutations = [
        lambda e: e.update({"verdict": "unverified"}),
        lambda e: e.update({"failed_checks": ["scope_live"]}),
        lambda e: e["oracle_rescan"].update({"found": False}),
        lambda e: e["oracle_rescan"].update(
            {"source": "scan4me-db", "independent": True, "found": True}
        ),
    ]
    for i, mutate in enumerate(mutations):
        bad = _handoff_dict(_six_progs())
        bad["feed_trust"] = {"ok": True, "issues": []}
        mutate(bad["ranked_verified"][0])
        with pytest.raises(
            QueueConfigError, match="not independently verified"
        ):
            queue.build_schedule(
                bad,
                out_dir=tmp_path,
                stamp=f"contradictory-{i}",
                require_trusted_handoff=True,
            )


def test_p11_writer_output_is_consumed_verbatim(tmp_path):
    sel = {
        "ranked_verified": _six_progs(),
        "excluded_named": [],
    }
    handoff = intake.write_handoff(sel, out_dir=tmp_path, stamp="real11")
    sched = queue.build_schedule(
        handoff["_report_path"], config={}, out_dir=tmp_path, stamp="q1"
    )
    assert sched["count"] == 6
    assert sched["handoff_report"] == handoff["_report_path"]
    assert _names(sched["items"])[:3] == ["Alpha-1", "Alpha-2", "Alpha-3"]


# ── schedule payload shape ────────────────────────────────────────────────────


def test_schedule_item_refs(tmp_path):
    sched = queue.build_schedule(
        _handoff_dict(_six_progs()), config={}, out_dir=tmp_path, stamp="refs1"
    )
    assert sched["_schema"] == queue.SCHEDULE_SCHEMA
    assert sched["count"] == 6 and sched["waves"] == 6
    assert "rate-limit" in sched["note"]
    path = Path(sched["_report_path"])
    assert path.exists()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["_schema"] == queue.SCHEDULE_SCHEMA
    first = sched["items"][0]
    assert first["site"] == "hackerone"
    assert first["company"] == {"name": "Alpha-1", "handle": "a1"}
    assert first["program_url"].endswith("/a1")
    assert first["score"] == 90.0
    assert first["handoff_rank"] == 1
    assert first["verdict"] == "verified"
    assert first["failed_checks"] == []
    assert first["deep_dive"] == {
        "asset_count": 1,
        "assets": [{"asset_identifier": "app.a1.com"}],
        "out_of_scope": [],
        "website": "https://a1.com",
        "sources": ["scan4me:programs+assets"],
    }
    # Workspace slot carried through for the executor (empty until scan
    # --download or queue --execute fills it).
    assert first["workspace"] == {"path": "", "status": ""}


def test_empty_handoff_writes_empty_schedule(tmp_path):
    sched = queue.build_schedule(
        _handoff_dict([]), config={}, out_dir=tmp_path, stamp="empty1"
    )
    assert sched["count"] == 0
    assert sched["waves"] == 0
    assert sched["items"] == []
    assert Path(sched["_report_path"]).exists()


# ── hunter wiring ─────────────────────────────────────────────────────────────


def _snap(name, handle, score):
    return {
        "name": name,
        "handle": handle,
        "platform": "hackerone",
        "url": f"https://hackerone.com/{handle}",
        "website": f"https://{handle}.com",
        "score": score,
        "max_payout_usd": 1000,
        "currency": "USD",
        "structured_scopes": [{"asset_identifier": f"app.{handle}.com"}],
    }


def _fake_report(snaps):
    return {
        "_schema": intake.SCAN_SCHEMA,
        "verified_count": len(snaps),
        "count": len(snaps),
        "_report_path": "scan_fake.json",
        "verdicts": [
            {
                "name": s["name"],
                "handle": s["handle"],
                "platform": s["platform"],
                "url": s["url"],
                "score": s["score"],
                "max_payout_usd": 1000,
                "currency": "USD",
                "verdict": "verified",
                "failed_checks": [],
                "checks": {},
                "oracle_rescan": {
                    "source": "test-independent-adapter",
                    "independent": True,
                    "found": True,
                },
                "_fresh": dict(s),
            }
            for s in snaps
        ],
    }


def _scan_args(tmp_path, **kw):
    snaps = [
        _snap("Acme", "acme", 90.0),
        _snap("Beta", "beta", 70.0),
        _snap("Gamma", "gamma", 50.0),
    ]
    prescan = tmp_path / "prescan_t.json"
    prescan.write_text(
        json.dumps({"_schema": intake.PRESCAN_SCHEMA, "programs": snaps}),
        encoding="utf-8",
    )
    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        json.dumps({"queue": {"default_count": kw.pop("default_count", 2)}}),
        encoding="utf-8",
    )
    base = {
        "prescan_file": str(prescan),
        "top_n": None,
        "sites": None,
        "probe_timeout": 8.0,
        "out_dir": str(tmp_path),
        "config": str(cfg),
    }
    base.update(kw)
    return SimpleNamespace(**base), snaps


def test_scan_applies_default_count_without_n_or_sites(tmp_path, monkeypatch):
    import oracle_hunter as oh

    args, snaps = _scan_args(tmp_path)
    monkeypatch.setattr(oh, "_apply_no_cloud", lambda _a: True)
    monkeypatch.setattr(intake, "run_scan", lambda *a, **k: _fake_report(snaps))
    _report, handoff = oh.cmd_scan(args)
    assert handoff["selector"]["top_n"] == 2
    assert [r["name"] for r in handoff["ranked_verified"]] == ["Acme", "Beta"]


def test_scan_explicit_n_beats_default_count(tmp_path, monkeypatch):
    import oracle_hunter as oh

    args, snaps = _scan_args(tmp_path, top_n=1)
    monkeypatch.setattr(oh, "_apply_no_cloud", lambda _a: True)
    monkeypatch.setattr(intake, "run_scan", lambda *a, **k: _fake_report(snaps))
    _report, handoff = oh.cmd_scan(args)
    assert handoff["selector"]["top_n"] == 1
    assert [r["name"] for r in handoff["ranked_verified"]] == ["Acme"]


def test_scan_named_sites_override_default_count(tmp_path, monkeypatch):
    import oracle_hunter as oh

    args, snaps = _scan_args(tmp_path, sites="gamma")
    monkeypatch.setattr(oh, "_apply_no_cloud", lambda _a: True)
    monkeypatch.setattr(intake, "run_scan", lambda *a, **k: _fake_report(snaps))
    _report, handoff = oh.cmd_scan(args)
    assert [r["name"] for r in handoff["ranked_verified"]] == ["Gamma"]


def test_scan_bad_queue_config_dies_loud(tmp_path, monkeypatch):
    import oracle_hunter as oh

    args, snaps = _scan_args(tmp_path)
    bad = tmp_path / "badcfg.json"
    bad.write_text('{"queue": {"default_count": -1}}', encoding="utf-8")
    args.config = str(bad)
    monkeypatch.setattr(oh, "_apply_no_cloud", lambda _a: True)
    monkeypatch.setattr(intake, "run_scan", lambda *a, **k: _fake_report(snaps))
    with pytest.raises(SystemExit, match="1"):
        oh.cmd_scan(args)


def test_queue_cli_wiring(monkeypatch):
    import oracle_hunter as oh

    seen = {}

    def fake_queue(args):
        seen.update(
            {
                "handoff": getattr(args, "handoff", "unset"),
                "order": getattr(args, "order", "unset"),
                "concurrent": getattr(args, "concurrent", "unset"),
                "cross_site_cap": getattr(args, "cross_site_cap", "unset"),
            }
        )

    monkeypatch.setattr(oh, "cmd_queue", fake_queue)

    monkeypatch.setattr(sys, "argv", ["oracle-hunter", "queue"])
    oh.main()
    assert seen == {
        "handoff": None,
        "order": None,
        "concurrent": None,
        "cross_site_cap": None,
    }

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "oracle-hunter",
            "queue",
            "--handoff",
            "h.json",
            "--order",
            "round-robin",
            "--concurrent",
            "--cross-site-cap",
            "2",
        ],
    )
    oh.main()
    assert seen == {
        "handoff": "h.json",
        "order": "round-robin",
        "concurrent": True,
        "cross_site_cap": 2,
    }

    monkeypatch.setattr(sys, "argv", ["oracle-hunter", "queue", "--sequential"])
    oh.main()
    assert seen["concurrent"] is False
