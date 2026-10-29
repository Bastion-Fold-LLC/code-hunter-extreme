"""Workspace downloads + queue execution.

Locks the missing joins the adversarial audit found:
  - scan's verified selection can download exactly those workspaces
    (unverified/excluded never touched, per-program failure isolated);
  - schedule items preserve workspace + deep-dive scope;
  - execute_schedule honors wave order, the cross-site cap, failure
    isolation, resume, and max_items;
  - `queue --execute` runs hunts from the schedule with controlled,
    unattended args.
No network: downloader and hunt are faked at their real seams.
"""

import json
import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_bulk_download as obd
import oracle_hunter as oh
import oracle_intake as oi
import oracle_queue as oq


@pytest.fixture(autouse=True)
def _trusted_feed_for_handoffs(monkeypatch):
    """Queue tests exercise execution, not auth; stamp a trusted feed."""
    monkeypatch.setattr(
        oi,
        "feed_provenance_block",
        lambda: {
            "refresh_ok": True,
            "age_hours": 1.0,
            "stale": False,
            "platforms": {
                "hackerone": {
                    "count": 1,
                    "source": "authenticated",
                    "status": "ok",
                }
            },
        },
    )


def _entry(rank, name, platform="HackerOne", assets=None):
    return {
        "rank": rank,
        "name": name,
        "handle": name.lower().replace(" ", "-"),
        "platform": platform,
        "url": f"https://example.org/{name}",
        "score": 100.0 - rank,
        "max_payout_usd": 1000,
        "currency": "USD",
        "verdict": "verified",
        "checks": {},
        "oracle_rescan": {
            "source": "test-independent-adapter",
            "independent": True,
            "found": True,
        },
        "deep_dive": {
            "assets": (
                assets
                if assets is not None
                else [{"asset_identifier": "*.example.com", "asset_type": "WILDCARD"}]
            ),
            "out_of_scope": ["status.example.com"],
            "company": {
                "name": name,
                "handle": name.lower(),
                "platform": platform,
                "website": "https://example.com",
            },
            "sources": ["scan4me:programs+assets"],
            "checks": {},
        },
    }


# ── downloads ────────────────────────────────────────────────────────────────


def test_download_selected_exactly_the_ranked_verified(monkeypatch):
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: False)
    seen = []

    def fake(prog):
        seen.append(prog)
        return {"status": "downloaded", "detail": "3 asset(s)"}

    sel = {
        "ranked_verified": [_entry(1, "Acme One"), _entry(2, "Beta Two")],
        "excluded_named": [{"site": "Gamma", "reason": "unverified"}],
    }
    oi.download_selected_workspaces(sel, download_fn=fake)
    assert [p["name"] for p in seen] == ["Acme One", "Beta Two"]
    for prog in seen:  # handoff entry mapped to downloader shape
        assert prog["structured_scopes"]
        assert prog["out_of_scope"] == ["status.example.com"]
        assert prog["website"] == "https://example.com"
    for e in sel["ranked_verified"]:
        assert e["workspace"]["status"] == "downloaded"
        assert e["workspace"]["path"]


def test_download_selected_skips_bridge_only_entry(monkeypatch):
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: False)
    calls = []

    def fake(prog):
        calls.append(prog["name"])
        return {"status": "downloaded", "detail": "ok"}

    bridge = _entry(1, "Bridge Only")
    bridge["oracle_rescan"] = {"source": "scan4me-db", "independent": False}
    sel = {"ranked_verified": [bridge, _entry(2, "Verified Two")]}
    oi.download_selected_workspaces(sel, download_fn=fake)
    assert calls == ["Verified Two"]
    assert bridge["workspace"]["status"] == "skipped"
    assert "independent" in bridge["workspace"]["detail"]


def test_download_selected_present_skip_and_error_isolation(monkeypatch):
    monkeypatch.setattr(
        obd, "already_downloaded", lambda prog: prog["name"] == "Acme One"
    )
    calls = []

    def fake(prog):
        calls.append(prog["name"])
        if prog["name"] == "Beta Two":
            raise RuntimeError("cdp down")
        return {"status": "downloaded", "detail": "ok"}

    sel = {
        "ranked_verified": [
            _entry(1, "Acme One"),
            _entry(2, "Beta Two"),
            _entry(3, "Ceta Three"),
        ]
    }
    oi.download_selected_workspaces(sel, download_fn=fake)
    by_name = {e["name"]: e["workspace"]["status"] for e in sel["ranked_verified"]}
    assert by_name == {
        "Acme One": "present",
        "Beta Two": "error",
        "Ceta Three": "downloaded",
    }
    assert calls == ["Beta Two", "Ceta Three"]  # present one never downloaded


# ── schedule item metadata ───────────────────────────────────────────────────


def test_schedule_item_preserves_workspace_and_scope():
    e = _entry(1, "Acme One")
    e["workspace"] = {"path": "/tmp/ws/acme", "status": "downloaded", "detail": "x"}
    item = oq._schedule_item(e, position=1, wave=0)
    assert item["workspace"] == {"path": "/tmp/ws/acme", "status": "downloaded"}
    assert item["deep_dive"]["assets"] == e["deep_dive"]["assets"]
    assert item["deep_dive"]["out_of_scope"] == ["status.example.com"]


# ── executor ─────────────────────────────────────────────────────────────────


def _schedule(tmp_path, entries, **kw):
    handoff = {
        "_schema": oi.HANDOFF_SCHEMA,
        "ranked_verified": entries,
        "feed_trust": {"ok": True, "issues": []},
    }
    return oq.build_schedule(handoff, out_dir=tmp_path, **kw)


def test_executor_wave_barrier_and_cap(tmp_path):
    entries = [
        _entry(1, "A One", "HackerOne"),
        _entry(2, "B Two", "Bugcrowd"),
        _entry(3, "C Three", "Intigriti"),
        _entry(4, "D Four", "YesWeHack"),
    ]
    sched = _schedule(tmp_path, entries, concurrent=True, cross_site_cap=2)
    events = []
    lock = threading.Lock()
    running = {"now": 0, "max": 0}

    def hunt(item):
        with lock:
            running["now"] += 1
            running["max"] = max(running["max"], running["now"])
            events.append(("start", item["wave"], item["position"]))
        time.sleep(0.05)
        with lock:
            running["now"] -= 1
            events.append(("end", item["wave"], item["position"]))

    summary = oq.execute_schedule(sched["_report_path"], hunt_fn=hunt, out_dir=tmp_path)
    assert summary["done_total"] == 4 and summary["failed_total"] == 0
    assert running["max"] <= 2
    # Wave barrier: no wave N+1 start before every wave N end.
    wave_end_idx = {}
    wave_start_idx = {}
    for i, (kind, wave, _pos) in enumerate(events):
        if kind == "end":
            wave_end_idx[wave] = i
        else:
            wave_start_idx.setdefault(wave, i)
    for w in sorted(wave_start_idx):
        if w + 1 in wave_start_idx:
            assert wave_end_idx[w] < wave_start_idx[w + 1]
    assert Path(summary["state_path"]).exists()


def test_executor_sequential_within_site_and_failure_isolation(tmp_path):
    entries = [
        _entry(1, "A One", "HackerOne"),
        _entry(2, "A Two", "HackerOne"),
        _entry(3, "B Three", "Bugcrowd"),
    ]
    sched = _schedule(tmp_path, entries, concurrent=True, cross_site_cap=3)
    order = []

    def hunt(item):
        order.append(item["company"]["name"])
        if item["company"]["name"] == "A Two":
            raise SystemExit(2)

    summary = oq.execute_schedule(sched["_report_path"], hunt_fn=hunt, out_dir=tmp_path)
    assert summary["done_total"] == 2 and summary["failed_total"] == 1
    # Same-site pair sequential: A One strictly before A Two.
    assert order.index("A One") < order.index("A Two")
    state = json.loads(Path(summary["state_path"]).read_text())
    statuses = {r["name"]: r["status"] for r in state["items"].values()}
    assert statuses == {"A One": "done", "A Two": "failed", "B Three": "done"}


def test_executor_resume_and_max_items(tmp_path):
    entries = [_entry(i, f"P{i}", "HackerOne") for i in (1, 2, 3)]
    sched = _schedule(tmp_path, entries)
    hunted = []
    s1 = oq.execute_schedule(
        sched["_report_path"],
        hunt_fn=lambda it: hunted.append(it["position"]),
        out_dir=tmp_path,
        max_items=1,
    )
    assert hunted == [1] and s1["attempted_this_run"] == 1
    s2 = oq.execute_schedule(
        sched["_report_path"],
        hunt_fn=lambda it: hunted.append(it["position"]),
        out_dir=tmp_path,
    )
    assert hunted == [1, 2, 3]  # position 1 skipped as done, not re-hunted
    assert s2["skipped_done"] == 1 and s2["done_total"] == 3
    with pytest.raises(oq.QueueConfigError):
        oq.execute_schedule(
            sched["_report_path"], hunt_fn=lambda it: None, max_items=-1
        )


# ── cmd_queue --execute wiring ───────────────────────────────────────────────


def test_queue_hunt_args_carries_auth_material():
    # M4: queued hunts must inherit the operator's resolved auth material
    # instead of silently hunting unauthenticated.
    qargs = types.SimpleNamespace(
        cloud=False,
        model="m",
        researcher="r",
        mindset=None,
        controlled=True,
        config=None,
        auth="Bearer tok-a",
        cookie="sid=1",
        account_a="tokA",
        account_b="tokB",
    )
    hunt_args = oh._queue_hunt_args(qargs, "/tmp/sched.json", 2)
    assert hunt_args.auth == "Bearer tok-a"
    assert hunt_args.cookie == "sid=1"
    assert hunt_args.account_a == "tokA"
    assert hunt_args.account_b == "tokB"
    assert hunt_args.cloud is False
    assert hunt_args.model == "m"
    assert hunt_args.researcher == "r"
    assert hunt_args.controlled is True
    # Unattended invariants stay: no interactive login in queued hunts.
    assert hunt_args.prompt_login is False
    assert hunt_args.auto is True and hunt_args.pick == 2
    # Absent auth stays absent (getattr defaults, never invented).
    bare = oh._queue_hunt_args(types.SimpleNamespace(), "/tmp/s.json", 1)
    assert bare.auth is None and bare.account_a is None


def test_queue_hunt_args_carries_hunt_mode_flags():
    # Real hunt modes (testnet, local source) survive the queue boundary.
    # Integrity bypasses (seam invention, incomplete tactics) do not exist.
    qargs = types.SimpleNamespace(
        testnet=True,
        code="/tmp/src",
        code_only=True,
        seam_allow_new=True,
        allow_incomplete_tactics=True,
    )
    hunt_args = oh._queue_hunt_args(qargs, "/tmp/sched.json", 1)
    assert hunt_args.testnet is True
    assert hunt_args.code == "/tmp/src"
    assert hunt_args.code_only is True
    assert not hasattr(hunt_args, "seam_allow_new")
    assert not hasattr(hunt_args, "allow_incomplete_tactics")
    bare = oh._queue_hunt_args(types.SimpleNamespace(), "/tmp/s.json", 1)
    assert bare.testnet is False and bare.code is None
    assert bare.code_only is False


def test_pin_local_model_reaches_router():
    import oracle_llm

    try:
        model = oh._pin_local_model(types.SimpleNamespace(model="sentinel-model"))
        assert model == "sentinel-model"
        assert oracle_llm._PREFERRED_LOCAL_MODEL == "sentinel-model"
    finally:
        oracle_llm.set_preferred_local_model(None)


def test_verify_account_flags_refused_loudly():
    # Verify never consumed dual-account CLI values (silent drop); it
    # must refuse them loudly and point at hunt instead.
    ns = types.SimpleNamespace
    oh._reject_verify_account_flags(
        ns(account_a=None, account_b=None, prompt_login=False, researcher=None)
    )
    with pytest.raises(SystemExit):
        oh._reject_verify_account_flags(
            ns(account_a="tok", account_b=None, prompt_login=False, researcher=None)
        )


def test_effective_recon_auth_derives_from_account_a():
    # M4: recon must use Account A when only dual-account material is
    # given — previously it ran unauthenticated while the session gate
    # counted account_a as "auth present" and stayed silent.
    ns = types.SimpleNamespace
    assert oh._effective_recon_auth(ns(auth="Bearer x", account_a="tokA")) == "Bearer x"
    assert oh._effective_recon_auth(ns(auth=None, account_a="tokA")) == "Bearer tokA"
    assert (
        oh._effective_recon_auth(ns(auth=None, account_a="Bearer tokA"))
        == "Bearer tokA"
    )
    assert oh._effective_recon_auth(ns(auth=None, account_a=None)) is None
    assert oh._effective_recon_auth(ns()) is None


def test_cmd_queue_execute_runs_hunts_from_schedule(monkeypatch, tmp_path):
    sel = {"ranked_verified": [_entry(1, "Acme One"), _entry(2, "Beta Two")]}
    handoff = oi.write_handoff(sel, out_dir=tmp_path, stamp="testq")
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: False)
    monkeypatch.setattr(
        obd,
        "download_one",
        lambda prog, **k: {"status": "downloaded", "detail": "fake"},
    )
    hunts = []

    def fake_hunt(name, args):
        hunts.append(
            {
                "name": name,
                "pick": args.pick,
                "schedule": args.schedule,
                "controlled": args.controlled,
                "auto": args.auto,
            }
        )

    monkeypatch.setattr(oh, "cmd_hunt", fake_hunt)
    args = types.SimpleNamespace(
        handoff=handoff["_report_path"],
        order=None,
        concurrent=None,
        cross_site_cap=None,
        config=None,
        out_dir=str(tmp_path),
        execute=True,
        max_items=None,
        resume=True,
        skip_download=False,
        controlled=True,
        cloud=False,
        model="m",
        mindset=None,
        researcher=None,
        cdp_port=9227,
    )
    sched = oh.cmd_queue(args)
    assert [h["pick"] for h in hunts] == [1, 2]
    assert all(h["name"] == "" and h["controlled"] and h["auto"] for h in hunts)
    assert all(h["schedule"] == sched["_report_path"] for h in hunts)
    assert sched["_execution"]["done_total"] == 2
    assert sched["_execution"]["failed_total"] == 0
    assert Path(sched["_execution"]["state_path"]).exists()


def test_download_selected_malformed_entries_are_isolated(monkeypatch):
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: False)
    calls = []

    def fake(prog):
        calls.append(prog["name"])
        return {"status": "downloaded", "detail": "ok"}

    missing_platform = _entry(2, "No Platform")
    missing_platform["platform"] = ""
    missing_platform["deep_dive"]["company"]["platform"] = ""
    sel = {
        "ranked_verified": [
            _entry(1, "Good One"),
            "not-an-entry",
            missing_platform,
            _entry(3, "Good Three"),
        ]
    }
    oi.download_selected_workspaces(sel, download_fn=fake)
    assert calls == ["Good One", "Good Three"]
    assert sel["ranked_verified"][0]["workspace"]["status"] == "downloaded"
    assert sel["ranked_verified"][2]["workspace"]["status"] == "error"
    assert sel["ranked_verified"][3]["workspace"]["status"] == "downloaded"
    assert sel["download_errors"]
    assert oi.download_selected_workspaces(
        {"ranked_verified": None}, download_fn=fake
    ) == {"ranked_verified": None}


def test_executor_same_wave_same_site_is_sequential(tmp_path):
    sched = _schedule(
        tmp_path,
        [_entry(i, f"S{i}", "HackerOne") for i in (1, 2, 3)],
        concurrent=True,
        cross_site_cap=3,
    )
    # Hand-craft the unsafe shape assign_waves would never emit.
    for item in sched["items"]:
        item["wave"] = 0
    lock = threading.Lock()
    running = {"now": 0, "max": 0}

    def hunt(item):
        with lock:
            running["now"] += 1
            running["max"] = max(running["max"], running["now"])
        time.sleep(0.03)
        with lock:
            running["now"] -= 1

    summary = oq.execute_schedule(sched, hunt_fn=hunt, out_dir=tmp_path)
    assert summary["done_total"] == 3
    assert running["max"] == 1


def test_executor_ensure_systemexit_is_recorded_not_fatal(tmp_path):
    sched = _schedule(tmp_path, [_entry(1, "Acme One")])
    hunted = []

    def ensure(item):
        raise SystemExit(7)

    summary = oq.execute_schedule(
        sched,
        hunt_fn=lambda it: hunted.append(it["position"]),
        ensure_workspace_fn=ensure,
        out_dir=tmp_path,
    )
    assert hunted == [1]
    rec = next(iter(summary["records"].values()))
    assert rec["workspace"] == {"status": "error", "detail": "SystemExit(7)"}


def test_executor_explicit_state_reuse_does_not_skip_different_program(tmp_path):
    state_path = tmp_path / "shared-state.json"
    s1 = _schedule(tmp_path, [_entry(1, "First Prog", "HackerOne")], stamp="a")
    oq.execute_schedule(
        s1, hunt_fn=lambda it: None, out_dir=tmp_path, state_path=state_path
    )
    s2 = _schedule(tmp_path, [_entry(1, "Other Prog", "Bugcrowd")], stamp="b")
    hunted = []
    summary = oq.execute_schedule(
        s2,
        hunt_fn=lambda it: hunted.append(it["company"]["name"]),
        out_dir=tmp_path,
        state_path=state_path,
    )
    assert hunted == ["Other Prog"]
    assert summary["skipped_done"] == 0


def _queue_args(handoff_path, tmp_path, **over):
    base = dict(
        handoff=handoff_path,
        order=None,
        concurrent=None,
        cross_site_cap=None,
        config=None,
        out_dir=str(tmp_path),
        execute=True,
        max_items=None,
        resume=True,
        skip_download=False,
        controlled=True,
        cloud=False,
        model="m",
        mindset=None,
        researcher=None,
        cdp_port=9227,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def test_cmd_queue_execute_resumes_across_rebuilt_schedule(monkeypatch, tmp_path):
    sel = {"ranked_verified": [_entry(1, "Acme One"), _entry(2, "Beta Two")]}
    handoff = oi.write_handoff(sel, out_dir=tmp_path, stamp="resumeq")
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: True)
    hunts = []
    monkeypatch.setattr(oh, "cmd_hunt", lambda name, args: hunts.append(args.pick))
    stamps = iter(["run1", "run2"])
    monkeypatch.setattr(oq, "_stamp", lambda: next(stamps))

    s1 = oh.cmd_queue(_queue_args(handoff["_report_path"], tmp_path, max_items=1))
    s2 = oh.cmd_queue(_queue_args(handoff["_report_path"], tmp_path))
    assert s1["_report_path"] != s2["_report_path"]
    assert s1["_execution"]["state_path"] == s2["_execution"]["state_path"]
    assert hunts == [1, 2]
    assert s2["_execution"]["skipped_done"] == 1


def test_execute_queue_schedule_rejects_bridge_only_items(tmp_path):
    sched = _schedule(tmp_path, [_entry(1, "Acme One")])
    # Public discovery provenance alone is not the blocker; a bridge-only
    # (not independently Oracle-verified) schedule item is.
    sched["feed_trust"] = {
        "ok": False,
        "raw_candidate_ok": True,
        "issues": ["unauthenticated public-file rows: hackerone"],
    }
    sched["items"][0]["oracle_rescan"] = {
        "source": "scan4me-db",
        "independent": False,
    }
    with pytest.raises(oq.QueueConfigError, match="not independently verified"):
        oh._execute_queue_schedule(types.SimpleNamespace(), sched, tmp_path)


def test_execute_queue_schedule_rejects_unverified_item(tmp_path, monkeypatch):
    sched = _schedule(tmp_path, [_entry(1, "Acme One")])
    sched["items"][0]["verdict"] = "unverified"
    # Pre-fix this item reached ensure+hunt; fake both seams so the
    # fail-first run can never touch a real download or hunt.
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: True)
    monkeypatch.setattr(oh, "cmd_hunt", lambda name, args: None)
    with pytest.raises(oq.QueueConfigError, match="not independently verified"):
        oh._execute_queue_schedule(types.SimpleNamespace(), sched, tmp_path)


def test_execute_queue_schedule_rejects_rejoin_identity_mismatch(
    tmp_path, monkeypatch
):
    sched = _schedule(tmp_path, [_entry(1, "Right One", "HackerOne")], stamp="right2")
    wrong = oi.write_handoff(
        {"ranked_verified": [_entry(1, "Wrong One", "HackerOne")]},
        out_dir=tmp_path,
        stamp="wrong-rejoin",
    )
    sched["handoff_report"] = wrong["_report_path"]
    hunted = []
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: True)
    monkeypatch.setattr(oh, "cmd_hunt", lambda name, args: hunted.append(name))
    with pytest.raises(oq.QueueConfigError, match="does not match"):
        oh._execute_queue_schedule(types.SimpleNamespace(), sched, tmp_path)
    assert hunted == []


def test_cmd_queue_execute_bad_max_items_dies_before_schedule(tmp_path):
    sel = {"ranked_verified": [_entry(1, "Acme One")]}
    handoff = oi.write_handoff(sel, out_dir=tmp_path, stamp="badmax")
    before = set(tmp_path.glob("queue_schedule_*.json"))
    with pytest.raises(SystemExit):
        oh.cmd_queue(_queue_args(handoff["_report_path"], tmp_path, max_items=-1))
    assert set(tmp_path.glob("queue_schedule_*.json")) == before


def test_execute_queue_schedule_never_loads_latest_handoff(monkeypatch, tmp_path):
    right = _schedule(tmp_path, [_entry(1, "Right One", "HackerOne")], stamp="right")
    assert right["handoff_report"] == ""  # dict-built schedule: no handoff path
    wrong_sel = {"ranked_verified": [_entry(1, "Wrong Latest", "Bugcrowd")]}
    oi.write_handoff(wrong_sel, out_dir=tmp_path, stamp="zzzzwrong")
    downloaded = []
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: False)
    monkeypatch.setattr(
        obd,
        "download_one",
        lambda prog, **k: downloaded.append(prog["name"])
        or {"status": "downloaded", "detail": "fake"},
    )
    monkeypatch.setattr(oh, "cmd_hunt", lambda name, args: None)
    args = _queue_args(None, tmp_path)
    oh._execute_queue_schedule(args, right, str(tmp_path))
    assert downloaded == ["Right One"]


def test_executor_records_hunt_result_for_product_gate(tmp_path):
    sched = _schedule(tmp_path, [_entry(1, "Acme Product")])
    summary = oq.execute_schedule(
        sched,
        hunt_fn=lambda item: {
            "workspace": "/tmp/ws",
            "product": {"ready_for_submission": True, "status": "ready"},
        },
        out_dir=tmp_path,
    )
    rec = next(iter(summary["records"].values()))
    assert rec["status"] == "done"
    assert rec["result"]["product"]["ready_for_submission"] is True


def test_schedule_preserves_product_provenance(tmp_path):
    entry = _entry(1, "Acme Product")
    entry["oracle_rescan"] = {
        "mode": "independent",
        "source": "hackerone-api-authenticated",
        "independent": True,
        "found": True,
    }
    handoff = {
        "_schema": oi.HANDOFF_SCHEMA,
        "feed_trust": {"ok": True, "issues": []},
        "oracle_rescan": {
            "mode": "independent",
            "independent": True,
            "programs": 1,
            "independent_programs": 1,
        },
        "ranked_verified": [entry],
    }
    sched = oq.build_schedule(
        handoff,
        out_dir=tmp_path,
        stamp="provenance",
        require_trusted_handoff=True,
    )
    assert sched["feed_trust"]["ok"] is True
    assert sched["oracle_rescan"]["mode"] == "independent"
    item = sched["items"][0]
    assert item["oracle_rescan"]["independent"] is True
    picked = oq.pick_hunt_target(schedule=sched)
    assert picked["feed_trust"]["ok"] is True
    assert picked["oracle_rescan"]["source"] == "hackerone-api-authenticated"
