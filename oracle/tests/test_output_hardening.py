"""Step-2 output hardening: persisted artifacts must never carry secrets.

Writers are the last trusted boundary before disk. Even when an upstream
caller forgets to redact, finding JSON on disk must not contain live
credential header values, and funnel counts must reconcile exactly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_foundation as foundation
from oracle_mindset_context import ProgramWorkspace, _local_credential_scrub

SENTINEL = "SENTINEL-SECRET-VALUE-123"


def test_save_finding_never_persists_credential_headers(tmp_path):
    ws = ProgramWorkspace(
        {"name": "Acme", "platform": "test", "url": "https://acme.example"},
        base=tmp_path,
    )
    seam = {
        "n": 7,
        "claim_type": "idor",
        "check": (
            f'curl -H "Authorization: Bearer {SENTINEL}" '
            f'-H "Cookie: sid={SENTINEL}" https://acme.example/api'
        ),
    }
    out = ws.save_finding(seam, evidence=f"reflected Authorization: Bearer {SENTINEL}")
    blob = out.read_text(encoding="utf-8")
    xref = (out.parent / "finding_007.xref.json").read_text(encoding="utf-8")
    assert SENTINEL not in blob
    assert SENTINEL not in xref
    assert "[REDACTED]" in blob


def test_funnel_counts_reconcile():
    confirmed = {
        1: {"det_verdict": "CONFIRMED", "confirmed": True},
        2: {"det_verdict": "CONFIRMED", "confirmed": False, "kill_gate": "6a"},
        3: {"det_verdict": "REJECTED", "confirmed": False},
        4: {"det_verdict": None, "confirmed": False, "inconclusive": True,
            "kill_gate": "pre1"},
        5: {"confirmed": True},  # static merge: no det_verdict -> det_other
    }
    out = foundation.build_funnel_counts(confirmed, mined_wave1=4, followups_queued=1)
    assert out["verify_attempted"] == 5
    assert (
        out["det_confirmed"] + out["det_rejected"] + out["det_other"]
        == out["verify_attempted"]
    )
    assert out["final_confirmed"] == 2
    assert out["final_inconclusive"] == 1
    assert out["postgate_killed"] == {"6a": 1}
    assert out["preverify_dropped"] == {"pre1": 1}
    assert out["mined_wave1"] + out["followups_queued"] == 5


def test_save_seam_snapshot_persists_pre_synthesis_candidates_redacted(tmp_path):
    import json

    ws = ProgramWorkspace(
        {"name": "Acme", "platform": "test", "url": "https://acme.example"},
        base=tmp_path,
    )
    seam = {
        "n": 7,
        "mindset": "seam",
        "origin": "seam-template",
        "assertion_a": "only owners can read records",
        "assertion_b": "another user can read records",
        "check": (
            f'curl -H "Authorization: Bearer {SENTINEL}" '
            f'-H "Cookie: sid={SENTINEL}" https://acme.example/api'
        ),
        "details": {"raw": f"Cookie: sid={SENTINEL}"},
    }

    out = ws.save_seam_snapshot(
        [seam],
        stage="pre_synthesis",
        meta={"target": "Acme", "note": f"Authorization: Bearer {SENTINEL}"},
    )

    assert out == ws.reports_dir / "seam_snapshot_pre_synthesis.json"
    blob = out.read_text(encoding="utf-8")
    data = json.loads(blob)
    assert SENTINEL not in blob
    assert data["stage"] == "pre_synthesis"
    assert data["seam_count"] == 1
    assert data["seams"][0]["n"] == 7
    assert data["seams"][0]["assertion_b"] == "another user can read records"
    assert data["program"]["name"] == "Acme"


def test_snapshot_seams_helper_is_best_effort(tmp_path):
    import oracle_hunter as oh

    ws = ProgramWorkspace({"name": "Acme", "platform": "test"}, base=tmp_path)
    out = oh._snapshot_seams(ws, [{"n": 1}], "wave1", target="Acme")
    assert out == ws.reports_dir / "seam_snapshot_wave1.json"

    class BrokenWorkspace:
        def save_seam_snapshot(self, *args, **kwargs):
            raise OSError("disk full")

    assert oh._snapshot_seams(BrokenWorkspace(), [{"n": 1}], "wave1") is None


def test_local_credential_scrub_mirrors_hunter_shapes():
    text = (
        f'curl -H "Authorization: Bearer {SENTINEL}" '
        f"-H 'Cookie: sid={SENTINEL}' "
        f"-u admin:{SENTINEL} https://acme.example/?api_key={SENTINEL}"
    )
    assert SENTINEL not in _local_credential_scrub(text)


def test_save_seam_snapshot_redacts_keys_bytes_and_sets(tmp_path):
    import json

    ws = ProgramWorkspace({"name": "Acme", "platform": "test"}, base=tmp_path)
    out = ws.save_seam_snapshot(
        [
            {
                "n": 3,
                f"Authorization: Bearer {SENTINEL}": "header-as-key",
                "raw_bytes": f"Bearer {SENTINEL}".encode(),
                "set_vals": {f"https://acme.example/?token={SENTINEL}"},
            },
            f"Cookie: sid={SENTINEL}",
            None,
        ],
        stage="pre_verify",
        meta={f"Cookie: sid={SENTINEL}": "meta-key"},
    )

    blob = out.read_text(encoding="utf-8")
    data = json.loads(blob)
    assert SENTINEL not in blob
    assert data["seam_count"] == 3
    assert data["seams"][0]["raw_bytes"] == "Bearer [REDACTED]"


def test_save_finding_redacts_nested_keys_and_bytes(tmp_path):
    import json

    ws = ProgramWorkspace({"name": "Acme", "platform": "test"}, base=tmp_path)
    out = ws.save_finding(
        {
            "n": 9,
            "details": {
                f"Authorization: Bearer {SENTINEL}": f"Bearer {SENTINEL}".encode()
            },
        }
    )

    blob = out.read_text(encoding="utf-8")
    data = json.loads(blob)
    assert SENTINEL not in blob
    assert list(data["details"].values()) == ["Bearer [REDACTED]"]


def test_save_seam_snapshot_scrubs_stage_before_slug_and_payload(tmp_path):
    ws = ProgramWorkspace({"name": "Acme", "platform": "test"}, base=tmp_path)

    out = ws.save_seam_snapshot([], stage=f"Bearer {SENTINEL}")

    assert SENTINEL not in out.name
    assert SENTINEL.lower() not in out.name
    assert SENTINEL not in out.read_text(encoding="utf-8")


def test_program_workspace_cannot_escape_base(tmp_path):
    ws = ProgramWorkspace(
        {"name": "..", "platform": "../../x"},
        base=tmp_path,
    )

    assert ws.base.is_relative_to(tmp_path)
    assert ".." not in ws.base.parts
