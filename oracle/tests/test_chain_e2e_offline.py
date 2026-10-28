"""Offline library-level canonical chain.

prescan → scan verify → deep-dive select (top 2 of 3) → workspace
downloads (exactly the selected 2) → handoff → schedule → execute
(fake hunt populates recon, as a real hunt does) → standalone analyze
of the hunted workspace resumes.

Only true externals are faked: the Scan4Me fetch, the liveness probe,
the program resolver, the per-program asset downloader, the hunt, and
the LLM completion. The CLI wrappers (cmd_scan/cmd_queue/cmd_hunt)
are covered separately in test_queue_execute.py; this test locks the
library joins, schemas, ordering, and file artifacts between them.
"""
import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_bulk_download as obd
import oracle_hunter as oh
import oracle_intake as oi
import oracle_llm
import oracle_queue as oq


def _prog(name, platform, score, host):
    return {
        "name": name,
        "handle": name.lower().replace(" ", "-"),
        "platform": platform,
        "url": f"https://platform.example/{name}",
        "website": f"https://{host}",
        "score": score,
        "max_payout_usd": 5000,
        "currency": "USD",
        "safe_harbor": "Standard",
        "managed_triage": True,
        "program_kind": "web2",
        "structured_scopes": [
            {
                "asset_identifier": host,
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "out_of_scope": [],
        "policy_text": f"{name} bounty policy v1",
    }


PROGRAMS = [
    _prog("Alpha One", "HackerOne", 90.0, "app.alpha.example.com"),
    _prog("Beta Two", "Bugcrowd", 80.0, "app.beta.example.com"),
    _prog("Gamma Three", "HackerOne", 70.0, "app.gamma.example.com"),
]
BY_KEY = {p["handle"]: p for p in PROGRAMS}


def test_full_chain_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    reports = tmp_path / "reports"

    # 1. prescan (Scan4Me fetch faked)
    prescan = oi.run_prescan(
        fetch_fn=lambda: PROGRAMS, limit=10, out_dir=reports, stamp="e2e"
    )
    assert prescan["count"] == 3

    # 2. scan verify (probe + resolver faked; all three verify)
    scan = oi.run_scan(
        prescan["_report_path"],
        resolve_fn=lambda key: BY_KEY.get(key),
        probe_fn=lambda host, timeout: {
            "host": host,
            "resolves": True,
            "live": True,
            "status": 200,
        },
        out_dir=reports,
        stamp="e2e",
    )
    assert scan["verified_count"] == 3

    # 3. deep-dive top 2 → download exactly those workspaces
    selection = oi.select_deep_dive(
        scan,
        prescan_programs=prescan["programs"],
        top_n=2,
        resolve_fn=lambda key: BY_KEY.get(key),
    )
    assert [e["name"] for e in selection["ranked_verified"]] == [
        "Alpha One",
        "Beta Two",
    ]
    downloads = []

    def fake_download(prog):
        # Mimic download_one's on-disk result at its real seam: program
        # metadata + assets + manifest and an EMPTY recon/. Real
        # downloads never write recon output; the hunt does (below).
        base = obd.workspace_base_for(prog)
        (base / "recon").mkdir(parents=True, exist_ok=True)
        (base / "assets").mkdir(exist_ok=True)
        (base / "program.json").write_text(json.dumps(prog))
        (base / ".oracle_bulk.json").write_text("{}")
        downloads.append(prog["name"])
        return {"status": "downloaded", "detail": "fake assets"}

    monkeypatch.setattr(oh, "TARGETS_DIR", tmp_path / "targets")
    monkeypatch.setattr(obd, "already_downloaded", lambda prog: False)
    oi.download_selected_workspaces(selection, download_fn=fake_download)
    assert downloads == ["Alpha One", "Beta Two"]  # Gamma (rank 3) untouched
    ws_dirs = sorted(
        p.name for p in (tmp_path / "targets").glob("*/*") if p.is_dir()
    )
    assert ws_dirs == ["alpha_one", "beta_two"]

    # 4. handoff → schedule (workspace metadata preserved)
    handoff = oi.write_handoff(
        selection,
        scan_report_path=scan["_report_path"],
        prescan_report_path=prescan["_report_path"],
        top_n=2,
        out_dir=reports,
        stamp="e2e",
    )
    sched = oq.build_schedule(
        handoff["_report_path"], config={}, out_dir=reports, stamp="e2e"
    )
    assert sched["count"] == 2
    for item in sched["items"]:
        assert item["workspace"]["status"] == "downloaded"
        assert item["workspace"]["path"]
        assert item["deep_dive"]["assets"]

    # 5. execute the queue (hunt faked at its seam; order + state real).
    # The fake hunt does the one on-disk thing a real hunt guarantees:
    # populate the workspace recon/ directory.
    hunted = []

    def fake_hunt(item):
        hunted.append(item["company"]["name"])
        base = Path(item["workspace"]["path"])
        host = item["deep_dive"]["assets"][0]["asset_identifier"]
        (base / "recon").mkdir(parents=True, exist_ok=True)
        (base / "recon" / "clean_live_hosts.txt").write_text(f"https://{host}\n")
        (base / "recon" / "known_urls.txt").write_text(
            f"https://{host}/api/users\nhttps://evil.example.org/x\n"
        )

    summary = oq.execute_schedule(
        sched["_report_path"],
        hunt_fn=fake_hunt,
        out_dir=reports,
    )
    assert hunted == ["Alpha One", "Beta Two"]  # finish-site by rank
    assert summary["done_total"] == 2 and summary["failed_total"] == 0
    state = json.loads(Path(summary["state_path"]).read_text())
    assert {r["status"] for r in state["items"].values()} == {"done"}

    # 6. standalone analyze resumes the hunted workspace (root input)
    alpha_ws = Path(sched["items"][0]["workspace"]["path"])
    prompts = {}

    def _fake_complete(task, system, **k):
        prompts["task"] = task
        return "TARGET CLEAN"

    monkeypatch.setattr(oracle_llm, "complete", _fake_complete)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    seams, raw = oh.cmd_analyze(
        str(alpha_ws), types.SimpleNamespace(cloud=False, model="m")
    )
    assert raw == "TARGET CLEAN"
    assert seams == []
    assert "/api/users" in prompts["task"]
    assert "evil.example.org" not in prompts["task"]
