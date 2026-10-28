# Oracle-System Plan

> **Status header (2026-10-20):** historical coordination plan, **not** the single
> source of truth and not a status board. Current truth: `STATUS.md`,
> `VERIFIED_STATE.md`, `IMPROVEMENTS_REPORT_2026-10-19.md`. PR-by-PR state below
> is a 2026-10-15 snapshot (superseded by direct-main commits since); checkboxes
> are not maintained.

_Scope: the three tools under GitHub org `code-hunter-extreme` — **oracle** (web hunter),
**scan4me** (scope/target DB), **omnicli** (red-team / LLM orchestration). Last updated 2026-10-15._

## Definition of done
1. Backlog of findings (Greptile + CodeRabbit + local security hook) fixed & merged.
2. Validation gate live on every PR (2 AI reviewers + deterministic CI + Snyk + Dependabot).
3. `omnicli test_qualifying_run_artifact_exists_and_validates` is **green** — i.e. a real
   end-to-end proving run has been done and recorded. (That test is red by design until then;
   it IS the finish line.)

## Phase A — Activate the gate (USER, ~15 min)
- [ ] Merge the 3 CI PRs: oracle #4, scan4me #5, omnicli #5 (validate stack + Dependabot + token-gated Snyk/Socket).
- [ ] Toggle Dependabot alerts on in each repo (Settings → Security).
- [ ] Rotate the Greptile API key and the Snyk token (both touched the chat transcript).

## Phase B — Close the backlog (ASSISTANT, through the gate)
Rule: *verify each flag first* — real bug → fix + regression test → PR → Greptile+CodeRabbit+CI → merge;
heuristic/already-defended → mark safe with proof (e.g. `_kill_squatter`, `substitute_probe_placeholders`).

Open fix PRs awaiting merge: oracle #1, #5, #6 · scan4me #4 · omnicli #6.

Remaining to verify/fix:
- [ ] oracle: `oracle_hunter` SSRF flag; `oracle_programs` session-hijack flag; `oracle_seam_templates:1412` XSS marker doesn't prove execution; optional auth-session hardening (strip `$`/backtick).
- [ ] omnicli: orchestrate resume ignores settings (:2386); KeyError on recovery (:1828); audit_state incomplete-looks-complete (:213); council history not persisted (chat.py:693).
- [ ] scan4me: stale-feed freshness (last_sync_ts after failed/offline); bugcrowd date strictness (#7); `_fetch_h1_authenticated` drops eligibility fields (#15). → closes scan4me 100%.

## Phase C — Proving run (makes the red test green)
- [ ] Run the full pipeline on oracle's LOCAL testbed (`vuln_testbed_full.py`): scan4me scope →
      oracle invisible-seam + mindset 1/2/3 + red-team passes + nuclei → verified finding → report,
      recorded as the qualifying artifact. LOCAL ONLY (doctrine).
- [ ] Final mindset-wiring confirmation on live output.

## Phase D — Repeat for vortex-system
- [ ] Stand up the gate FIRST, then port the same fix→verify→prove loop. Gate all AI agents (incl. codebuff) behind PRs.

## Status snapshot
- Merged: scan4me #2; omnicli #2, #3.
- Tests: scan4me 76/76; omnicli 401 pass (+52 subtests), 1 intentional-red gate; oracle 1004 collected.
- Tools proven on deliberately-bad code (bandit 10 / semgrep 4 → rectified to 0 real).
- Progress ≈ 86% of known work. See memory `greptile-fix-backlog` for live detail.

## Lessons (carry into vortex-system)
- The 3-mindset spine is sound; bugs lived in its *inputs* (seam/scope/red-team). Honest inputs > clever pipeline.
- Duplicated scope logic (scan4me vs oracle) drifts — one source of truth or parity tests.
- Dangerous failures were *silent wrongness*, not crashes — fail loud, no fallbacks.
- Confine every operator-behalf request to scope/origin explicitly.
- Validation must be a gate (CI + reviewers), not a habit; no AI agent pushes to main unreviewed.
