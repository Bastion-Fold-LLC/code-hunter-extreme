> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Code-Lens Fusion — Design Spec

*Date: 2026-09-27*
*Status: DRAFT — awaiting user review*
*Scope: `oracle_hunter.py` (hunt flow), consuming existing `oracle_code_seam.scan_repository_seams`*

---

## 1. Problem

Oracle has two hunting engines that never meet:

- **Recon lens** — `run_reflexes` reasons over recon + philosophy + TTP context → seam cards. Runs in every `hunt`.
- **Code lens** — `oracle_code_seam.scan_repository_seams` finds doc/config-claim vs actual-code (AST) mismatches → seam cards, already check-proven. **Only reachable via the standalone `audit` command.** On a normal `hunt` it never runs.

So a target with source on disk (Aave, Starknet, any cloned repo) gets only the recon lens; its code contradictions — Oracle's sharpest angle — are never surfaced during a hunt.

Verified (2026-09-27): `scan_repository_seams` already emits the **same seam-card shape** as `_parse_seams` (`assertion_a`, `assertion_b`, `reflex`, `mitre`, `check`, `impact`, `raw`, `n`) plus code-specific fields (`id`, `classification`, `source_a/line_a`, `source_b/line_b`, `verdict`, `question`, `check_output`, `origin="invisible-seam"`). The engines already speak one language.

## 2. Goal

`oracle-hunter hunt <target>` automatically runs the code lens when the target has source on disk, merges its cards with the recon-lens cards, and the merged set flows through the **existing** verify → chain → PoC → report pipeline. Invisible Seam becomes one of Oracle's eyes, not a side door.

## 3. Non-goals (YAGNI)

- **Not** the TTP-fusion re-wire (`oracle_ttps_fused.json`) — that is the next, separate spec.
- **Not** changing `oracle_code_seam.py` internals or the `invisible_seam` package.
- **Not** removing the `audit` command — it stays as a code-only entry point.
- No new model backends (router already handles LLM calls).

## 4. Design — one conveyor, the code lens added

### 4.1 Locating the target's source

New helper in `oracle_hunter.py`:

```
_locate_target_source(program: str, explicit: Optional[str]) -> Optional[Path]
```

- If `explicit` (from a new `--code PATH` flag) is given: resolve it; error out if it does not exist. Explicit always wins.
- Else best-effort auto-discovery: scan `targets/*/` for a subdirectory that (a) is not `screenshots`, and (b) contains source (`.sol`/`.rs`/`.py`/`.js`/`.ts`) or a `.git` dir, preferring one whose parent dir name shares a token with the program slug. Return the first match.
- No match → return `None` (a URL-only web2 target has no code; the code lens is simply skipped, logged via `_info`). This is fail-soft, not fail-open: a missing lens means fewer sources, never fabricated findings.

### 4.2 Running the code lens

In `cmd_hunt`, after the recon-lens seams are parsed (current step 4), add:

```
code_seams: List[Dict] = []
src = _locate_target_source(name, getattr(args, "code", None))
if src:
    _banner(f"Code Lens (Invisible Seam): {src.name}")
    try:
        from oracle_code_seam import scan_repository_seams
        code_seams = scan_repository_seams(src)
        _ok(f"code lens: {len(code_seams)} code seam(s)")
    except Exception as e:            # fail-soft: lens error != hunt failure
        _warn(f"code lens failed on {src} — continuing with recon seams only: {e}")
```

`ImportError` (invisible_seam package missing) is caught by the same guard and logged.

### 4.3 Merge + dedupe + renumber

New helper:

```
_merge_seams(recon_seams: List[Dict], code_seams: List[Dict]) -> List[Dict]
```

- Tag every recon seam `origin="recon-reflex"` if it has no `origin`.
- Concatenate recon + code seams.
- Dedupe on a normalized key `(_norm(assertion_a), _norm(assertion_b), _norm(check))` where `_norm` lowercases and strips whitespace/punctuation; first occurrence wins. (Cross-lens collisions are rare; this catches the case where both lenses flag the same thing.)
- Renumber `n` sequentially over the surviving list so downstream (`verify`, report) sees a clean 1..N.
- Return the merged list.

### 4.4 Verify branch — code seams are already proven

Code-lens seams carry a `verdict` from the invisible-seam check runner. They must **not** be pushed through `verify_seams` (which builds/validates *curl* commands against the scope gate — a code seam's `check` is a written test, not an HTTP probe; the scope gate would reject it).

In `cmd_hunt`, split before verify:

```
recon_only = [s for s in seams if s.get("origin") != "invisible-seam"]
code_only  = [s for s in seams if s.get("origin") == "invisible-seam"]

# recon seams: existing interactive/curl verify
confirmed = verify_seams(recon_only, name, recon_dir, ...) if recon_only and verify else {}

# code seams: already check-proven — confirmed iff verdict in the confirmed set
for s in code_only:
    is_conf = s.get("verdict") in ("RESOLVED", "CERTAIN")
    confirmed[s["n"]] = {"seam": s, "check": s.get("check", ""),
                         "output": s.get("check_output", ""),
                         "verdict": s.get("verdict", ""), "confirmed": is_conf}
```

(The confirmed set `("RESOLVED", "CERTAIN")` matches what `cmd_audit` already uses.)

Downstream PoC synthesis, compound chaining, and report writing already iterate `confirmed_seams` / `seams` and use only the shared keys, so they work unchanged on the merged set.

### 4.5 Report

`_write_report` already renders the shared keys. Add an `origin` line per seam card so a reader sees which lens found it. `cmd_hunt`'s end-of-run summary counts both lenses ("N recon + M code seams").

### 4.6 New CLI flag

`hunt` gains `--code PATH` (optional): explicit path to the target's source tree. Documented in the subcommand help.

## 5. Interfaces (for the plan)

- `_locate_target_source(program: str, explicit: Optional[str]) -> Optional[Path]`
- `_merge_seams(recon_seams: List[Dict], code_seams: List[Dict]) -> List[Dict]`
- `_norm(s: str) -> str` (dedupe-key normalizer)
- Existing, consumed unchanged: `oracle_code_seam.scan_repository_seams`, `verify_seams`, `_synthesize_poc`/`_cloud_escalate`, `_correlate_seams`, `_write_report`.

## 6. Error handling

- Code lens raising (ImportError, parse error, anything) → `_warn` + continue with recon seams. Never aborts the hunt.
- `--code` path that doesn't exist → `_die` (explicit user input must be valid).
- No source found and no `--code` → `_info("no source on disk — code lens skipped")`, recon-only hunt.
- A code seam missing `verdict` → treated as **not** confirmed (conservative; never auto-confirm an unproven card).

## 7. Testing

- `test_locate_source.py`: explicit path returned; nonexistent explicit path raises; auto-discovery finds a repo dir in a temp `targets/` tree; returns None when only `screenshots/` present.
- `test_merge_seams.py`: recon+code concat renumbers `n` 1..N; duplicate (same A/B/check across lenses) collapses to one; recon seams get `origin="recon-reflex"`.
- `test_hunt_code_lens.py`: with `scan_repository_seams` monkeypatched to return one CERTAIN code seam and `_locate_target_source` returning a path, the merged seam list contains the code seam and it is marked confirmed without going through `verify_seams`; with source path None, hunt proceeds recon-only. (Recon/network mocked.)
- All mocked — no live model/network/recon in CI.

## 8. Rollout

1. `_norm` + `_merge_seams` + tests.
2. `_locate_target_source` + tests.
3. Wire code lens + verify branch into `cmd_hunt`; add `--code` flag; report `origin`.
4. Full suite green; a manual `hunt` smoke against a target with a small on-disk repo.

## 9. Notes

- On a GPU-less box the recon lens' model call is the slow part; the code lens is deterministic (AST + written checks) and fast — it will often produce the first proven findings.
- This is committed on a feature branch off current `master` (`456a086`), same as the router work.
