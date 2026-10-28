import json
import sys

from oracle_runlog import RunLog, redact, redact_argv


def test_runlog_writes_events_summary_and_hashes(tmp_path):
    run = RunLog(
        "hunt",
        [
            "hunt",
            "example",
            "--auth",
            "Bearer super-secret",
            "--cookie",
            "session=also-secret",
        ],
        root=tmp_path,
    )
    run.event("stage", name="recon", status="ok")
    artifact = tmp_path / "report.md"
    artifact.write_text("finding\n", encoding="utf-8")
    run.artifact(artifact, "verify_results", confirmed=0)
    run.finish("ok")

    events = [
        json.loads(line)
        for line in run.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert events[0]["event"] == "run.start"
    assert events[-1]["event"] == "run.end"
    assert events[-1]["status"] == "ok"
    event_text = run.events_path.read_text(encoding="utf-8")
    assert "super-secret" not in event_text
    assert "also-secret" not in event_text
    assert events[0]["argv"].count("[REDACTED]") >= 2

    summary = json.loads(run.summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "ok"
    assert summary["exit_code"] == 0
    assert summary["command"] == "hunt"
    assert summary["artifacts"][0]["kind"] == "verify_results"
    assert len(summary["artifacts"][0]["sha256"]) == 64
    assert summary["event_counts"]["artifact"] == 1
    assert (tmp_path / "latest.json").exists()


def test_runlog_finish_is_idempotent(tmp_path):
    run = RunLog("scan", ["scan"], root=tmp_path)
    run.finish("ok")
    ended = run.finished_at
    run.finish("failed", "late failure")
    assert run.finished_at == ended
    assert run.status == "ok"


def test_failed_run_keeps_partial_status_and_error(tmp_path):
    run = RunLog("hunt", ["hunt", "example"], root=tmp_path)
    run.artifact(tmp_path / "partial.json", "partial")
    run.event("warning", message="lens produced no cards")
    run.finish("failed", "LENS-STARVED HUNT", exit_code=1)

    summary = json.loads(run.summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "failed"
    assert summary["exit_code"] == 1
    assert summary["error"] == "LENS-STARVED HUNT"
    assert summary["warnings"] == ["lens produced no cards"]
    assert summary["artifacts"][0]["exists"] is False


def test_main_writes_one_runlog_per_command(tmp_path, monkeypatch):
    import oracle_hunter

    monkeypatch.setenv("ORACLE_RUNLOG_DIR", str(tmp_path))
    monkeypatch.setattr(oracle_hunter, "cmd_list", lambda args: None)
    monkeypatch.setattr(sys, "argv", ["oracle-hunter", "list"])
    monkeypatch.setattr(oracle_hunter, "_ACTIVE_RUNLOG", None)
    try:
        oracle_hunter.main()
        latest = json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))
        summary = json.loads(
            (tmp_path / latest["run_id"] / "summary.json").read_text(encoding="utf-8")
        )
        events = (tmp_path / latest["run_id"] / "events.jsonl").read_text(
            encoding="utf-8"
        )
    finally:
        oracle_hunter._ACTIVE_RUNLOG = None

    assert summary["command"] == "list"
    assert summary["status"] == "ok"
    assert '"event": "console"' in events
    assert '"event": "run.end"' in events
    assert latest["run_id"] == summary["run_id"]


_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fw"


def test_runlog_redacts_unlisted_credential_key_variants():
    out = json.dumps(redact({
        "account_a": "raw-token-1",
        "account_b": "raw-token-2",
        "session": "sess-value-3",
        "credential": "cred-value-4",
        "jwt": _JWT,
        "signing_key": "raw-key-5",
        "status": "ok-status-stays",
    }))
    for leaked in ("raw-token-1", "raw-token-2", "sess-value-3",
                   "cred-value-4", _JWT, "raw-key-5"):
        assert leaked not in out
    assert "ok-status-stays" in out


def test_runlog_redacts_basic_cookie_pairs_and_bare_jwt_strings():
    out = redact({
        "message": "Authorization: Basic dXNlcjpwYXNzd29yZA== retrying",
        "headers": "Cookie: a=first-secret; b=second-secret",
        "note": f"captured {_JWT} from traffic",
    })
    text = json.dumps(out)
    assert "dXNlcjpwYXNzd29yZA==" not in text
    assert "first-secret" not in text
    assert "second-secret" not in text
    assert _JWT not in text


def test_runlog_redacts_values_after_unlisted_secret_flags():
    out = redact_argv(
        ["hunt", "acme", "--session", "sess-secret", "--credential", "cred-secret"]
    )
    assert "sess-secret" not in out
    assert "cred-secret" not in out
    assert out.count("[REDACTED]") >= 2


def test_warn_keeps_stdout_clean_in_json_mode(capsys, monkeypatch):
    import oracle_hunter as oh

    monkeypatch.setattr(oh, "_JSON_STDOUT", True)
    monkeypatch.setattr(oh, "_ACTIVE_RUNLOG", None)
    oh._warn("json-warn-marker")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "json-warn-marker" in captured.err


def test_die_marks_shared_runlog_failed_without_finishing_it(tmp_path, monkeypatch):
    import pytest

    import oracle_hunter as oh

    run = RunLog("queue", ["queue", "--execute"], root=tmp_path)
    monkeypatch.setattr(oh, "_ACTIVE_RUNLOG", run)
    try:
        with pytest.raises(SystemExit):
            oh._die("one queued hunt died")
        # Queue catches SystemExit per item and keeps going; the shared
        # runlog must stay open for the remaining items and final status.
        assert run.finished_at is None
        assert run.status == "failed"
        run.finish("ok", exit_code=0)
        summary = json.loads(run.summary_path.read_text(encoding="utf-8"))
        assert any("one queued hunt died" in e for e in summary["errors"])
    finally:
        oh._ACTIVE_RUNLOG = None
