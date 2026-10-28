> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Code-Lens Fusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `oracle-hunter hunt` run the Invisible Seam code lens when the target has source on disk, merge its cards with the recon cards, and route the merged set through the existing verify→chain→PoC→report pipeline.

**Architecture:** Both engines already emit the same seam-card dict. Add two pure helpers (`_norm`, `_merge_seams`), one filesystem helper (`_locate_target_source`), and wire the code lens + a verify-branch into `cmd_hunt`. Code seams are pre-proven (carry `verdict`) so they skip the curl-style `verify_seams`.

**Tech Stack:** Python 3.12, pytest. No new deps. Consumes existing `oracle_code_seam.scan_repository_seams`.

**Spec:** `docs/superpowers/specs/2026-09-27-code-lens-fusion-design.md`

## Global Constraints

- A lens error (ImportError, parse failure, anything) must NOT abort the hunt: `_warn` and continue recon-only. Fail-soft on the lens, never fail-open on findings (never auto-confirm an unproven card).
- A code seam is confirmed iff `verdict in ("RESOLVED", "CERTAIN")` — the same rule `cmd_audit` uses. Missing verdict → not confirmed.
- Code seams (`origin == "invisible-seam"`) must NOT be passed to `verify_seams` (its scope gate expects HTTP/curl).
- Surgical: do not change `oracle_code_seam.py`, the `invisible_seam` package, or the `audit` command.

## Review Focus

- **Target with no source on disk and no `--code`** → hunt runs recon-only, code lens skipped with an info line, no crash. (Task 3 test.)
- **`invisible_seam` package/scan raises mid-hunt** → caught, warned, hunt continues with recon seams. (Task 3 test.)
- **Same finding from both lenses** → dedupes to one card. (Task 1 test.)
- **Code seam with verdict `OPEN`/absent** → present in report but NOT marked confirmed. (Task 3 test.)
- **`--code` path that does not exist** → `_die` before any scanning. (Task 2 test.)

---

### Task 1: `_norm` + `_merge_seams`

**Files:**
- Modify: `oracle_hunter.py` (add both helpers near `_parse_seams`)
- Test: `tests/test_merge_seams.py`

**Interfaces:**
- Produces: `_norm(s: str) -> str` — lowercase, collapse whitespace, strip surrounding punctuation; used only for dedupe keys.
- Produces: `_merge_seams(recon_seams: List[Dict], code_seams: List[Dict]) -> List[Dict]` — tags recon seams `origin="recon-reflex"` when absent, concatenates recon+code, dedupes on `(_norm(assertion_a), _norm(assertion_b), _norm(check))` (first wins), renumbers `n` 1..N, returns merged list.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_merge_seams.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def _s(a, b, chk, **extra):
    return {"assertion_a": a, "assertion_b": b, "check": chk,
            "impact": "", "reflex": "r", "mitre": "N/A", "raw": "", **extra}


def test_concat_and_renumber():
    recon = [_s("a1", "b1", "curl x")]
    code = [_s("a2", "b2", "test y", origin="invisible-seam")]
    out = oh._merge_seams(recon, code)
    assert [s["n"] for s in out] == [1, 2]
    assert out[0]["origin"] == "recon-reflex"
    assert out[1]["origin"] == "invisible-seam"


def test_cross_lens_dedupe():
    recon = [_s("Same Claim", "Same Wire", "curl z")]
    code = [_s("same claim ", " same wire", "CURL z", origin="invisible-seam")]
    out = oh._merge_seams(recon, code)
    assert len(out) == 1  # deduped; first (recon) wins


def test_empty_code_lens():
    recon = [_s("a", "b", "c")]
    assert len(oh._merge_seams(recon, [])) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_merge_seams.py -v`
Expected: FAIL (`AttributeError: _merge_seams`).

- [ ] **Step 3: Implement in `oracle_hunter.py` (place directly after `_parse_seams`)**

```python
def _norm(s: str) -> str:
    """Normalizer for dedupe keys: lowercase, collapse whitespace, strip edges."""
    return re.sub(r"\s+", " ", (s or "").lower()).strip(" \t\n\r.-*`\"'")


def _merge_seams(recon_seams: List[Dict], code_seams: List[Dict]) -> List[Dict]:
    """Merge recon-lens and code-lens seam cards onto one list: tag origins,
    dedupe on (A,B,check), renumber n. First occurrence wins (recon before code)."""
    for s in recon_seams:
        s.setdefault("origin", "recon-reflex")
    merged: List[Dict] = []
    seen = set()
    for s in list(recon_seams) + list(code_seams):
        key = (_norm(s.get("assertion_a", "")), _norm(s.get("assertion_b", "")),
               _norm(s.get("check", "")))
        if key in seen:
            continue
        seen.add(key)
        merged.append(s)
    for i, s in enumerate(merged, 1):
        s["n"] = i
    return merged
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_merge_seams.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_hunter.py tests/test_merge_seams.py
git commit -m "feat(hunt): _merge_seams — one conveyor for recon + code seam cards"
```

---

### Task 2: `_locate_target_source`

**Files:**
- Modify: `oracle_hunter.py` (add helper near the other scope/program helpers)
- Test: `tests/test_locate_source.py`

**Interfaces:**
- Produces: `_locate_target_source(program: str, explicit: Optional[str]) -> Optional[Path]`. Explicit path (from `--code`) wins; a nonexistent explicit path calls `_die`. Else scans `targets/*/` for a subdir (excluding `screenshots`) containing source (`.sol/.rs/.py/.js/.ts`) or a `.git` dir, preferring a parent whose name shares a token with the program slug. Returns first match or `None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_locate_source.py
import sys, pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def test_explicit_path_returned(tmp_path):
    d = tmp_path / "src"; d.mkdir()
    assert oh._locate_target_source("prog", str(d)) == d.resolve()


def test_explicit_missing_dies(tmp_path):
    with pytest.raises(SystemExit):
        oh._locate_target_source("prog", str(tmp_path / "nope"))


def test_autodiscovers_repo_under_targets(tmp_path, monkeypatch):
    targets = tmp_path / "targets" / "sherlock_aave" / "aave-v4"
    targets.mkdir(parents=True)
    (targets / "Hub.sol").write_text("contract Hub {}")
    monkeypatch.setattr(oh, "_HERE", tmp_path)
    got = oh._locate_target_source("aave", None)
    assert got == targets.resolve()


def test_none_when_only_screenshots(tmp_path, monkeypatch):
    (tmp_path / "targets" / "prog" / "screenshots").mkdir(parents=True)
    monkeypatch.setattr(oh, "_HERE", tmp_path)
    assert oh._locate_target_source("prog", None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_locate_source.py -v`
Expected: FAIL (`AttributeError: _locate_target_source`).

- [ ] **Step 3: Implement in `oracle_hunter.py`**

```python
_SOURCE_EXTS = (".sol", ".rs", ".py", ".js", ".ts")


def _locate_target_source(program: str, explicit: Optional[str]) -> Optional[Path]:
    """Find the target's on-disk source tree. Explicit --code wins; else
    best-effort scan of targets/*/. Returns None when there is no code."""
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            _die(f"--code path not found or not a directory: {explicit}")
        return p

    targets_root = _HERE / "targets"
    if not targets_root.exists():
        return None
    slug_tokens = set(re.split(r"[^a-z0-9]+", program.lower())) - {""}

    def _has_source(d: Path) -> bool:
        if (d / ".git").exists():
            return True
        for f in d.rglob("*"):
            if f.is_file() and f.suffix.lower() in _SOURCE_EXTS:
                return True
        return False

    candidates = []
    for parent in sorted(targets_root.glob("*")):
        if not parent.is_dir():
            continue
        for sub in sorted(parent.glob("*")):
            if not sub.is_dir() or sub.name == "screenshots":
                continue
            if _has_source(sub):
                score = len(slug_tokens & set(re.split(r"[^a-z0-9]+", parent.name.lower())))
                candidates.append((score, sub))
    if not candidates:
        return None
    candidates.sort(key=lambda t: -t[0])
    return candidates[0][1].resolve()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_locate_source.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_hunter.py tests/test_locate_source.py
git commit -m "feat(hunt): _locate_target_source — find on-disk code for the code lens"
```

---

### Task 3: Wire the code lens into `cmd_hunt`

**Files:**
- Modify: `oracle_hunter.py` (`cmd_hunt` gather + verify branch + summary; `_write_report` origin line; `--code` argparse flag)
- Test: `tests/test_hunt_code_lens.py`

**Interfaces:**
- Consumes: `_merge_seams`, `_locate_target_source` (Tasks 1–2), `oracle_code_seam.scan_repository_seams`, existing `verify_seams`/`_write_report`.
- Produces: no new public API; `cmd_hunt` now merges a code lens and branches verify by `origin`; `hunt` accepts `--code PATH`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hunt_code_lens.py
import sys, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def _fake_recon(*a, **k):
    return Path("recon/_fake")


def test_code_lens_merges_and_preconfirms(monkeypatch, tmp_path):
    # recon lens yields nothing; code lens yields one CERTAIN seam
    monkeypatch.setattr(oh, "recon", lambda *a, **k: tmp_path)
    monkeypatch.setattr(oh, "run_reflexes", lambda *a, **k: "")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e: tmp_path)
    code_seam = {"n": 1, "assertion_a": "claim", "assertion_b": "code says otherwise",
                 "check": "forge test X", "impact": "loss", "reflex": "SPEC-AUDIT",
                 "mitre": "N/A", "raw": "SEAM", "verdict": "CERTAIN",
                 "check_output": "verdict CERTAIN", "origin": "invisible-seam"}
    import oracle_code_seam
    monkeypatch.setattr(oracle_code_seam, "scan_repository_seams", lambda p: [code_seam])
    captured = {}
    monkeypatch.setattr(oh, "_write_report",
                        lambda name, rd, raw, seams, *a, **k: captured.setdefault("seams", seams) or Path("r.md"))
    # no interactive verify, no cloud
    args = types.SimpleNamespace(cloud=False, model="m", verify=False, auto=True,
                                 fast_triage=False, min_payout=0, max_payout=0,
                                 auto_pick=False, testnet=False, code=None,
                                 auth=None, cookie=None)
    oh.cmd_hunt("127.0.0.1:3000", args)
    seams = captured["seams"]
    assert any(s["origin"] == "invisible-seam" for s in seams)


def test_code_lens_failure_is_soft(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "recon", lambda *a, **k: tmp_path)
    monkeypatch.setattr(oh, "run_reflexes", lambda *a, **k: "")
    monkeypatch.setattr(oh, "_parse_seams", lambda *a, **k: [])
    monkeypatch.setattr(oh, "_locate_target_source", lambda p, e: tmp_path)
    import oracle_code_seam

    def boom(p):
        raise ImportError("invisible_seam missing")

    monkeypatch.setattr(oracle_code_seam, "scan_repository_seams", boom)
    monkeypatch.setattr(oh, "_write_report", lambda *a, **k: Path("r.md"))
    args = types.SimpleNamespace(cloud=False, model="m", verify=False, auto=True,
                                 fast_triage=False, min_payout=0, max_payout=0,
                                 auto_pick=False, testnet=False, code=None,
                                 auth=None, cookie=None)
    # must not raise
    oh.cmd_hunt("127.0.0.1:3000", args)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_hunt_code_lens.py -v`
Expected: FAIL (code lens not wired; no `invisible-seam` origin in report seams / or `--code` attr unused).

- [ ] **Step 3: Wire the gather + merge into `cmd_hunt`**

After the recon-lens `seams = _parse_seams(raw, recon_dir=recon_dir)` line, insert:

```python
    # ── Code Lens (Invisible Seam) — fused into the hunt ──────────────────
    code_seams: List[Dict] = []
    src = _locate_target_source(name, getattr(args, "code", None))
    if src:
        _banner(f"Code Lens (Invisible Seam): {src.name}")
        try:
            from oracle_code_seam import scan_repository_seams
            code_seams = scan_repository_seams(src)
            _ok(f"code lens: {len(code_seams)} code seam(s)")
        except Exception as e:
            _warn(f"code lens failed on {src} — continuing recon-only: {e}")
    else:
        _info("no source on disk — code lens skipped (recon-only)")

    seams = _merge_seams(seams, code_seams)
    _ok(f"{len(seams)} total seam(s) after fusion")
```

- [ ] **Step 4: Add the verify branch (replace the current verify block)**

Replace the existing `if seams and verify:` verify block with a split that keeps recon verify and pre-confirms code seams:

```python
    verify = getattr(args, "verify", True)
    auto = getattr(args, "auto", False)
    confirmed_seams: Dict[int, Dict] = {}
    recon_only = [s for s in seams if s.get("origin") != "invisible-seam"]
    code_only = [s for s in seams if s.get("origin") == "invisible-seam"]

    if recon_only and verify:
        _banner("Interactive Verify (recon lens)")
        confirmed_seams = verify_seams(recon_only, name, recon_dir, model=model, auto=auto,
                                       scope_gate=scope_gate, is_testnet=is_testnet,
                                       auth=getattr(args, "auth", None),
                                       cookie=getattr(args, "cookie", None))
    for s in code_only:
        confirmed_seams[s["n"]] = {
            "seam": s, "check": s.get("check", ""),
            "output": s.get("check_output", ""),
            "verdict": s.get("verdict", ""),
            "confirmed": s.get("verdict") in ("RESOLVED", "CERTAIN"),
        }
```

- [ ] **Step 5: Add the `--code` flag + report origin**

In `main()` under the `hunt` subparser, add:

```python
    p_hunt.add_argument("--code", help="Path to the target's on-disk source tree (enables the code lens)")
```

In `_write_report`, in the per-seam block, add an origin line:

```python
                f"**Origin:** {s.get('origin', 'recon-reflex')}",
```

- [ ] **Step 6: Run test + full regression**

Run: `python3 -m pytest tests/test_hunt_code_lens.py -v && python3 -m pytest tests/ -q && python3 -m py_compile oracle_hunter.py`
Expected: new tests PASS, full suite green, compile clean.

- [ ] **Step 7: Commit**

```bash
git add oracle_hunter.py tests/test_hunt_code_lens.py
git commit -m "feat(hunt): fuse Invisible Seam code lens into hunt (auto on on-disk source; pre-proven seams skip curl-verify)"
```

---

## Notes for the executor

- Branch off current `master` (`456a086`): `feat/code-lens-fusion`.
- The `cmd_hunt` verify block currently lives around the "Interactive Verify" banner — read it before Step 4 and replace the whole block, don't append.
- After the plan, one manual smoke: `oracle-hunter hunt <name> --code targets/sherlock_aave_v4/aave-v4 --no-verify` should print code seams and write a report with `Origin: invisible-seam` cards (network/model may be slow — the code lens itself is deterministic).
