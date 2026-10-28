import sys
import types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest
import oracle_hunter as oh
import oracle_llm
import oracle_mindsets


def _args(**over):
    # mindset="seam": these tests exercise the engine-independent
    # deterministic feed, so they request exactly that (#25 dies on drops).
    base = dict(cloud=False, model="m", verify=False, auto=True,
                fast_triage=False, min_payout=0, max_payout=0,
                auto_pick=False, testnet=False, code=None,
                auth=None, cookie=None, mindset="seam")
    base.update(over)
    return types.SimpleNamespace(**base)


def _patch_mindsets(monkeypatch):
    """Bypass the engine-availability gate — these tests exercise the code-lens
    path only and never reach the engine step. Effective mindsets are just
    ["seam"]: the LLM lenses are not selected here, so synthesis must not
    expect output objects from them."""
    monkeypatch.setattr(oracle_mindsets, "require_mindsets", lambda p, *a, **k: ["seam"])
    # These fixtures intentionally mint zero deterministic seams while
    # testing plumbing. Keep the production yield gate covered by
    # test_mindset_yield.py, but do not let that terminal gate mask the
    # calls/assertions under test when the local engine is unavailable.
    monkeypatch.setattr(oh, "_die_on_unserved_mindsets", lambda *_a, **_k: None)


@pytest.fixture(autouse=True)
def _restore_cloud_flags():
    # cmd_hunt flips the process-global no-cloud flags via _apply_no_cloud
    # — restore them so test order never leaks backend state.
    try:
        import oracle_programs as _op
    except Exception:
        _op = None
    prev_llm = oracle_llm.no_cloud_enabled()
    prev_op = _op.NO_CLOUD if _op is not None else None
    yield
    oracle_llm.set_no_cloud(prev_llm)
    if _op is not None:
        _op.NO_CLOUD = prev_op


def test_code_lens_merges_and_preconfirms(monkeypatch, tmp_path):
    _patch_mindsets(monkeypatch)
    monkeypatch.setattr(oh, "recon", lambda *a, **k: tmp_path)
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: ("TARGET CLEAN", "mock"))
    monkeypatch.setattr(oh, "_cloud_escalate", lambda *a, **k: "[poc]")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **_kwargs: tmp_path)
    code_seam = {"n": 1, "assertion_a": "claim", "assertion_b": "code says otherwise",
                 "check": "forge test X", "impact": "loss", "reflex": "SPEC-AUDIT",
                 "mitre": "N/A", "raw": "SEAM", "verdict": "CERTAIN",
                 "check_output": "verdict CERTAIN", "origin": "invisible-seam"}
    import oracle_code_seam
    monkeypatch.setattr(
        oracle_code_seam, "scan_repository_seams", lambda p, **_kwargs: [code_seam]
    )
    captured = {}
    monkeypatch.setattr(oh, "_write_report",
                        lambda name, rd, raw, seams, *a, **k: captured.setdefault("seams", seams) or Path("r.md"))
    oh.cmd_hunt("127.0.0.1:3000", _args())
    seams = captured["seams"]
    assert any(s["origin"] == "invisible-seam" for s in seams)


def test_code_lens_failure_is_soft(monkeypatch, tmp_path):
    _patch_mindsets(monkeypatch)
    monkeypatch.setattr(oh, "recon", lambda *a, **k: tmp_path)
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: ("TARGET CLEAN", "mock"))
    monkeypatch.setattr(oh, "_cloud_escalate", lambda *a, **k: "[poc]")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **_kwargs: tmp_path)
    import oracle_code_seam

    def boom(p, **_kwargs):
        raise ImportError("invisible_seam missing")

    monkeypatch.setattr(oracle_code_seam, "scan_repository_seams", boom)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    # Under fail-loud doctrine (Rule 2), scanner failure must exit loudly
    with pytest.raises(SystemExit):
        oh.cmd_hunt("127.0.0.1:3000", _args())


def test_deterministic_scans_run_once_per_hunt(monkeypatch, tmp_path):
    # #9: code lens + template + web3 scans run ONCE (pre-pass); §7/§7b
    # reuse the cached lists instead of re-scanning.
    _patch_mindsets(monkeypatch)
    monkeypatch.setattr(oh, "recon", lambda *a, **k: tmp_path)
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: ("TARGET CLEAN", "mock"))
    monkeypatch.setattr(oh, "_cloud_escalate", lambda *a, **k: "[poc]")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **_kwargs: tmp_path)
    calls = {"code": 0, "tpl": 0, "web3": 0}
    import oracle_code_seam
    import oracle_seam_templates
    import oracle_seam_templates_web3

    def _code(p, **kw):
        calls["code"] += 1
        return []

    def _tpl(**kw):
        calls["tpl"] += 1
        return []

    def _w3(**kw):
        calls["web3"] += 1
        return []

    monkeypatch.setattr(oracle_code_seam, "scan_repository_seams", _code)
    monkeypatch.setattr(oracle_seam_templates, "scan_template_seams", _tpl)
    monkeypatch.setattr(oracle_seam_templates_web3, "scan_web3_seams", _w3)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    oh.cmd_hunt("127.0.0.1:3000", _args())
    assert calls == {"code": 1, "tpl": 1, "web3": 1}


def test_cloud_mode_lens_drop_dies_loud(monkeypatch, tmp_path, capsys):
    # #25: default "all" request with no engine up must die naming the
    # dropped lenses — never proceed seam-only on a warning. Uses the
    # REAL require_mindsets (no mock): the drop is genuine.
    monkeypatch.setattr(oh, "recon", lambda *a, **k: tmp_path)
    monkeypatch.setattr(oracle_llm.OllamaBackend, "available", lambda self: False)
    # The honest cloud gate counts EVERY configured lane, including the
    # keyless OmniCLI tool lane — "no engine up" must take it down too.
    monkeypatch.setattr(oracle_llm.OmniCLIBackend, "available", lambda self: False)
    monkeypatch.setattr(oh, "_load_env", lambda: {})
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **_kwargs: None)
    with pytest.raises(SystemExit):
        # cloud=True (cloud MODE) but no keys in env + ollama down:
        # both engines down while mitre+paradox are requested.
        oh.cmd_hunt("127.0.0.1:3000", _args(mindset=None, cloud=True))
    out = capsys.readouterr()
    assert "mitre" in out.out + out.err and "paradox" in out.out + out.err


def test_unparseable_prose_counts_as_failed_pass():
    # Hunt7 diagnosis: Databricks returned OK (55k-token paradox prompt)
    # but zero cards parsed and no TARGET CLEAN verdict. That must be a
    # failed, ladder-retryable pass — not "lens ran" credit.
    assert oh.pass_failed("empty") is True
    assert oh.pass_failed("error") is True
    assert oh.pass_failed("clean") is False
    assert oh.pass_failed("seams") is False


def test_persist_raw_response_writes_sanitized_file(tmp_path):
    p = oh._persist_raw_response(tmp_path, "cloud-paradox", "RAW-TEXT-123")
    assert p is not None and p.read_text() == "RAW-TEXT-123"
    assert p.parent.name == "raw"


@pytest.mark.parametrize("controlled", [True, False])
def test_hunt_forwards_controlled_to_recon(monkeypatch, tmp_path, controlled):
    # Regression: hunt parsed --controlled/--no-controlled but never passed
    # it to recon(), so every hunt ran uncontrolled despite the flag/help.
    _patch_mindsets(monkeypatch)
    seen = {}

    def _recon(*a, **k):
        seen.update(k)
        return tmp_path

    monkeypatch.setattr(oh, "recon", _recon)
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: ("TARGET CLEAN", "mock"))
    monkeypatch.setattr(oh, "_cloud_escalate", lambda *a, **k: "[poc]")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    # No local source -> NOT code-only, so the live recon() call happens.
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **_kwargs: None)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    oh.cmd_hunt("127.0.0.1:3000", _args(controlled=controlled))
    assert seen.get("controlled") is controlled


def test_hunt_missing_controlled_attr_defaults_on(monkeypatch, tmp_path):
    # CLI contract is default-on; a programmatic args namespace without the
    # attribute must not silently get aggressive recon.
    _patch_mindsets(monkeypatch)
    seen = {}

    def _recon(*a, **k):
        seen.update(k)
        return tmp_path

    monkeypatch.setattr(oh, "recon", _recon)
    monkeypatch.setattr(oracle_llm, "complete", lambda *a, **k: ("TARGET CLEAN", "mock"))
    monkeypatch.setattr(oh, "_cloud_escalate", lambda *a, **k: "[poc]")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e, **_kwargs: None)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    args = _args()
    assert not hasattr(args, "controlled")
    oh.cmd_hunt("127.0.0.1:3000", args)
    assert seen.get("controlled") is True


def test_code_only_decision_forced():
    web = [{"asset_identifier": "x.example.com", "asset_type": "URL"}]
    forced = _args(code_only=True)
    plain = _args()
    # forced: source on disk wins even with web scope present
    assert oh._code_only_decision(forced, Path("/tmp"), web) is True
    # unforced: web scope means live recon path (legacy behavior)
    assert oh._code_only_decision(plain, Path("/tmp"), web) is False
    assert oh._code_only_decision(plain, Path("/tmp"), []) is True
    assert oh._code_only_decision(plain, None, []) is False
    # forced without source dies loud, never falls through to live recon
    with pytest.raises(SystemExit):
        oh._code_only_decision(forced, None, web)


def test_seed_hosts_skip_explicit_oos_but_keep_wildcard_apex():
    prog = {
        "name": "SeedTest",
        "structured_scopes": [
            {"asset_identifier": "plugins.example.org", "asset_type": "URL"},
            {"asset_identifier": "*.example.net", "asset_type": "WILDCARD"},
            # ineligible -> explicit out-of-scope apex (covers subdomains)
            {"asset_identifier": "example.org", "asset_type": "URL",
             "eligible_for_bounty": False},
        ],
    }
    gate = oh.ProgramScopeGate(prog, "")
    seeds = oh._seed_hosts(gate)
    assert "plugins.example.org" not in seeds
    assert "example.net" in seeds  # wildcard enumeration base survives


def test_queue_hunt_args_forwards_code_only():
    q = _args(code_only=True)
    ns = oh._queue_hunt_args(q, "sched.json", 1)
    assert ns.code_only is True
