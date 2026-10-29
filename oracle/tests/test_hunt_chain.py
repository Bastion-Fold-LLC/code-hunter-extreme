#!/usr/bin/env python3
"""#19: intake→queue→hunt chain — cmd_hunt reads handoff/schedule artifacts."""

import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
import oracle_queue as queue
from oracle_intake import HANDOFF_SCHEMA


def _handoff(names=("Acme", "Beta")):
    return {
        "_schema": HANDOFF_SCHEMA,
        "_handoff_path": "/tmp/hand.json",
        "ranked_verified": [
            {
                "name": n,
                "handle": n.lower(),
                "platform": "hackerone",
                "url": f"https://h1/{n.lower()}",
                "score": 80.0,
                "rank": i + 1,
                "verdict": "verified",
                "failed_checks": [],
                "deep_dive": {
                    "assets": [
                        {"asset_identifier": f"app.{n.lower()}.example.com"}
                    ],
                    "out_of_scope": [f"status.{n.lower()}.example.com"],
                    "company": {"website": f"https://{n.lower()}.example.com"},
                },
            }
            for i, n in enumerate(names)
        ],
    }


def _schedule(names=("Acme", "Beta")):
    return {
        "_schema": queue.SCHEDULE_SCHEMA,
        "_schedule_path": "/tmp/sched.json",
        "count": len(names),
        "items": [
            {
                "position": i + 1,
                "wave": 0,
                "site": "hackerone",
                "company": {"name": n, "handle": n.lower()},
                "program_url": f"https://h1/{n.lower()}",
                "score": 80.0,
                "verdict": "verified",
                "failed_checks": [],
                "deep_dive": {
                    "assets": [
                        {"asset_identifier": f"app.{n.lower()}.example.com"}
                    ],
                    "out_of_scope": [f"status.{n.lower()}.example.com"],
                    "website": f"https://{n.lower()}.example.com",
                },
            }
            for i, n in enumerate(names)
        ],
    }


def test_load_schedule_validates_schema(tmp_path):
    bad = tmp_path / "s.json"
    bad.write_text(json.dumps({"_schema": "nope", "items": []}))
    with pytest.raises(queue.QueueConfigError):
        queue.load_schedule(bad)
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps(_schedule()))
    sched = queue.load_schedule(ok)
    assert len(sched["items"]) == 2


def test_pick_from_schedule_and_handoff():
    got = queue.pick_hunt_target(schedule=_schedule(), pick=2)
    assert (got["name"], got["position"], got["count"]) == ("Beta", 2, 2)
    assert got["origin"] == "/tmp/sched.json"
    got = queue.pick_hunt_target(handoff=_handoff(), pick=1)
    assert (got["name"], got["site"]) == ("Acme", "hackerone")
    # Schedule wins when both are given.
    got = queue.pick_hunt_target(
        handoff=_handoff(names=("H",)), schedule=_schedule(names=("S",))
    )
    assert got["name"] == "S"


def test_pick_fails_closed_on_empty_and_range():
    empty_sched = _schedule(names=())
    with pytest.raises(queue.QueueConfigError):
        queue.pick_hunt_target(schedule=empty_sched)
    with pytest.raises(queue.QueueConfigError):
        queue.pick_hunt_target(schedule=_schedule(), pick=9)
    with pytest.raises(queue.QueueConfigError):
        queue.pick_hunt_target(handoff=_handoff(names=()))
    with pytest.raises(queue.QueueConfigError):
        queue.pick_hunt_target(handoff=_handoff(), pick=0)


def _args(**kw):
    base = {"handoff": None, "schedule": None, "pick": 1}
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_hunt_helper_no_flags_and_explicit_name():
    assert oh._hunt_target_from_chain("__auto__", _args()) is None
    assert oh._hunt_target_from_chain("acme", _args(schedule=_schedule())) is None


def test_hunt_helper_resolves_chain_pick():
    got = oh._hunt_target_from_chain("__auto__", _args(schedule=_schedule(), pick=2))
    assert got["name"] == "Beta"
    got = oh._hunt_target_from_chain("", _args(handoff=_handoff()))
    assert got["name"] == "Acme"


def test_hunt_helper_dies_loud_on_empty_chain():
    with pytest.raises(SystemExit):
        oh._hunt_target_from_chain("__auto__", _args(schedule=_schedule(names=())))


def test_pick_carries_product_provenance():
    h = _handoff(names=("Acme",))
    h["feed_trust"] = {"ok": True, "issues": []}
    h["ranked_verified"][0]["oracle_rescan"] = {
        "mode": "independent",
        "source": "hackerone-api-authenticated",
        "independent": True,
    }
    got = queue.pick_hunt_target(handoff=h)
    assert got["feed_trust"]["ok"] is True
    assert got["oracle_rescan"]["independent"] is True

    s = _schedule(names=("Acme",))
    s["feed_trust"] = {"ok": True, "issues": []}
    s["items"][0]["oracle_rescan"] = {
        "source": "scan4me-db",
        "independent": False,
    }
    got = queue.pick_hunt_target(schedule=s)
    assert got["feed_trust"]["ok"] is True
    assert got["oracle_rescan"]["independent"] is False


def test_pick_carries_verified_deep_dive_scope():
    got = queue.pick_hunt_target(schedule=_schedule(), pick=2)
    assert got["verdict"] == "verified"
    assert got["failed_checks"] == []
    assert got["deep_dive"]["assets"] == [
        {"asset_identifier": "app.beta.example.com"}
    ]
    assert got["deep_dive"]["out_of_scope"] == ["status.beta.example.com"]
    got = queue.pick_hunt_target(handoff=_handoff(), pick=1)
    assert got["deep_dive"]["assets"] == [
        {"asset_identifier": "app.acme.example.com"}
    ]


def test_chain_scope_pins_scan_verified_assets_over_db_resolution():
    chain = queue.pick_hunt_target(schedule=_schedule(), pick=1)
    resolved = {
        "name": "Acme",
        "handle": "acme",
        "platform": "hackerone",
        "structured_scopes": [{"asset_identifier": "db-only.example.com"}],
        "out_of_scope": [],
    }
    prog = oh._chain_scope_prog(chain, resolved)
    assert prog["structured_scopes"] == [
        {"asset_identifier": "app.acme.example.com"}
    ]
    assert prog["out_of_scope"] == ["status.acme.example.com"]
    assert prog["_chain_scope"]["source"] == "scan-deep-dive"
    assert prog["_chain_scope"]["asset_count"] == 1
    assert len(prog["_chain_scope"]["sha256"]) == 64
    # The DB-resolved program is never mutated in place.
    assert resolved["structured_scopes"] == [
        {"asset_identifier": "db-only.example.com"}
    ]


def test_chain_scope_missing_assets_fails_closed():
    chain = queue.pick_hunt_target(schedule=_schedule(), pick=1)
    chain["deep_dive"] = {"assets": []}
    with pytest.raises(ValueError, match="chain scope"):
        oh._chain_scope_prog(chain, {"name": "Acme"})


def test_hunt_scope_stamp_records_chain_and_final_scope():
    chain_prog = {
        "structured_scopes": [{"asset_identifier": "app.acme.example.com"}],
        "_chain_scope": {"sha256": "a" * 64, "asset_count": 1},
    }
    final = {
        "structured_scopes": [{"asset_identifier": "app.acme.example.com"}],
        "scope_intake_status": "ok",
        "scope_intake_at": "2026-10-28T00:00:00+00:00",
        "scope_intake_fresh": 1,
    }
    stamp = oh._hunt_scope_stamp(chain_prog, final)
    assert stamp["chain_sha256"] == "a" * 64
    assert stamp["intake_status"] == "ok"
    assert stamp["final_asset_count"] == 1
    assert len(stamp["final_sha256"]) == 64
