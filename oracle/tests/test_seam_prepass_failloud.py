"""Gap-plan Step 2 (G2): seam pre-pass fail-loud contract.

Step-2 invariant: missing source raises SeamPrepassUnavailableError;
clean-but-empty never raises. cmd_hunt dies loud (SystemExit naming the
seam lens) when 'seam' is requested and source was expected, instead
of hunting seam-blind.
"""

import http.server
import sys
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import bad_code_app  # noqa: E402
import oracle_hunter as oh  # noqa: E402
import oracle_llm  # noqa: E402
from oracle_code_seam import seam_engine_status  # noqa: E402
from oracle_mindset_context import ProgramWorkspace as PW  # noqa: E402

_SEAM_STATUS = seam_engine_status()
requires_seam_engine = pytest.mark.skipif(
    not _SEAM_STATUS["available"],
    reason=_SEAM_STATUS["reason"],
)


def test_seam_prepass_missing_source_raises(tmp_path):
    with pytest.raises(oh.SeamPrepassUnavailableError) as excinfo:
        oh.seam_prepass(
            repo_path=tmp_path / "nope_repo",
            recon_dir=tmp_path / "nope_recon",
            program=None,
            scope_gate=None,
        )
    assert isinstance(excinfo.value.__cause__, OSError)


@requires_seam_engine
def test_seam_prepass_clean_empty_never_raises(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    recon = tmp_path / "recon"
    recon.mkdir()
    for f in ("known_urls.txt", "fuzzed_paths.txt", "js_endpoints.txt",
              "js_secrets.txt", "api_specs.txt", "live_hosts.txt",
              "clean_live_hosts.txt"):
        (recon / f).write_text("")
    gate = oh.ProgramScopeGate({}, target_fallback="http://127.0.0.1:9")
    code, template, web3 = oh.seam_prepass(
        repo_path=repo, recon_dir=recon, program=None, scope_gate=gate
    )
    assert isinstance(code, list) and isinstance(template, list)
    assert isinstance(web3, list)


def _args(**over) -> types.SimpleNamespace:
    base = dict(
        cloud=True, model=None, verify=False, auto=True, fast_triage=False,
        min_payout=0, max_payout=0, auto_pick=False, testnet=True, code=None,
        auth=None, cookie=None, mindset="seam", from_scan4me=False,
        scan4me_top=1, seam_allow_new=False, handoff=None, schedule=None,
        pick=1, account_a=None, account_b=None, auto_provision=None,
        prompt_login=False, researcher=None,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def test_cmd_hunt_seam_requested_prepass_unavailable_dies(
    monkeypatch, tmp_path, capsys
):
    httpd = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), bad_code_app.VulnerableHandler
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()
    fake_prog = {
        "name": "prepass-testbed",
        "platform": "hackerone",
        "url": base,
        "max_payout_usd": 1000,
        "kind": "web2",
        "structured_scopes": [
            {
                "asset_identifier": base,
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "rules": "prepass test only.",
    }
    calls = []

    def _boom(*a, **k):
        raise oh.SeamPrepassUnavailableError("code lens: simulated outage")

    monkeypatch.setattr(oh, "seam_prepass", _boom)
    monkeypatch.setattr(oh, "recon", lambda *a, **k: recon_dir)
    monkeypatch.setattr(oh, "_scope_from_programs", lambda name: fake_prog)
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **k: tmp_path)
    monkeypatch.setattr(PW, "download_assets", lambda self, **kw: [])
    monkeypatch.setattr(
        PW, "recon_dir", property(lambda self: recon_dir), raising=False
    )
    monkeypatch.setattr(
        oracle_llm, "complete",
        lambda *a, **k: calls.append(1) or "TARGET CLEAN",
    )
    try:
        with pytest.raises(SystemExit):
            oh.cmd_hunt(base, _args(code=str(tmp_path)))
    finally:
        httpd.shutdown()
    out = capsys.readouterr()
    assert "seam pre-pass unavailable" in out.out + out.err
    assert calls == []  # died before any engine prompt was assembled
