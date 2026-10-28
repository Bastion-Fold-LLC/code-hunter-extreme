> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle Gap-Fix Plan

Created 2026-10-13. Grounded in the adversarial gap pass of the same session
(evidence cited by `file:line`). Ordering rule: **trust fixes before
measurement** — a number taken through a silently-truncating or blind pipeline
is worthless, so the guards land before the LLM-layer measurement.

## Verified state at plan time
- Mindset wiring suite: 95 passed (S1–S6 wiring matches `docs/OWNER_MINDSET_SPEC.md`).
- Deterministic recall, fixtures: `test_p2_recall_bar` 1.0 (golden hunt 16/16, 0 FP).
- Deterministic recall, **live real targets**: `test_p14_bench_recall` **12/12 = 1.000**
  across juice-shop / DVWA / PyGoat at pinned commits (sqli 2/2, xss 2/2,
  auth-bypass 2/2, exposure 6/6; idor 0 planted — walled, documented).
- The live recall still exercises only the **deterministic** template→check→verify
  path; the three LLM mindsets have **no measured marginal recall** (G1 remainder).

## Goal
Close G1-remainder through G6 so the organism cannot silently miss, silently
degrade, or lie about its own state — then measure what the three mindsets
actually add, so a real-target run can be trusted.

## Success criteria
- Each code gap closed with a focused test that FAILS before the fix and PASSES
  after (G1: a measured number instead).
- No regression: mindset suite (~95) green, AND both recall gates stay green —
  `test_p2_recall_bar` (fixtures 1.0) + `test_p14_bench_recall` (live 1.0, benches up).
- Every fix fails loud — no new fallbacks.
- One file at a time; diff shown and approved before the next.

## Gaps (from the adversarial pass)
- **G1** — three LLM mindsets have no measured recall; only the deterministic
  floor is gated. `tests/test_golden_hunt.py:124`, `benchmarks/bench_recall.json`.
  (Live deterministic recall now proven 12/12; remainder = measure the LLM layer.)
- **G2** — invisible-seam pre-passes swallow exceptions and continue blind.
  `oracle_hunter.py:~6244 / ~6266 / ~6279`.
- **G3** — context-overflow guard is inert: all 12 cloud lanes have
  `context_tokens=None`, so `fits()` always returns True and oversized prompts
  can be silently truncated provider-side. `oracle_llm.py:181`, `oracle_backends.json`.
- **G4** — red-team "confirmed" never re-runs the check (rank-only); a "rejected"
  must not reorder verification. `oracle_mindsets.py:298`.
- **G5** — dead-target circuit breaker aborts verification after 10 consecutive
  transport failures, leaving seams unexecuted. `oracle_hunter.py:3029`.
- **G6** — duplicate branch in `effective_mindsets` (`oracle_mindsets.py:61-64`)
  + 3× `datetime.utcnow()` deprecations (`oracle_mindset_context.py:1471`,
  `oracle_hunter.py:4963`, `:4983`).

## Steps (ordered)

### Step 0 — snapshot
`git status` + diff stat of the already-dirty tree so every change is
attributable. No commit unless requested.

### Step 1 — G6 (warm-up, zero-risk)
- Change: collapse the duplicate paradox/mitre branch in `effective_mindsets`
  to one condition; replace 3× `datetime.utcnow()` with
  `datetime.now(datetime.UTC)`.
- Verify: mindset suite green; p14 runs with 0 DeprecationWarnings.
- Risk: none (pure refactor). Proves the red→green loop cheaply.

### Step 2 — G2 (seam can't vanish)
- Change: the three seam pre-passes — on EXCEPTION when `"seam" in _profiles`,
  `_die` instead of `_warn`. Keep clean-empty (no source on disk) as a
  legitimate empty feed.
- Sub-step: likely extract the pre-pass into a small helper so it is testable
  outside the ~300KB `cmd_hunt`.
- Test (new): `test_seam_prepass_failloud.py` — monkeypatch
  `scan_repository_seams` to raise → assert the hunt dies, not continues blind.
- Risk: medium — must not kill the valid "no source → empty feed" path. Only
  exceptions die.

### Step 3 — G3 (context guard real)
- Change (config): populate real `context_tokens` for all 12 lanes in
  `oracle_backends.json`. Lookup, not code — each provider's actual window.
- Change (code): `fits()` returns False on an unknown window; config loader
  fails loud if a configured lane has no `context_tokens`.
- Test (new): `test_llm_context_guard.py` — prompt > window ⇒ lane skipped;
  all-overflow ⇒ `RuntimeError`; unknown-window lane refused.
- Risk: medium — too-low a number wrongly skips a good lane. Mitigation:
  generous real values; `estimate_tokens` is already conservative (chars/4).

### Step 4 — G4 + G5 (verification integrity)
- G4: red-team `rejected` changes REPORT order only, never VERIFICATION order.
- G5: in `verify_seams` split transport failure (curl exit 7/28 → backoff,
  don't count) from target-dead (abort). Cap on consecutive confirmed-dead,
  not on demotion.
- Test (new): `test_verify_resilience.py` — transport fails interleaved with
  successes ⇒ no early abort, every seam attempted; a red-team-rejected-but-real
  card still gets wire-checked.
- Risk: medium — must still abort a genuinely dead target.

### Step 5 — G1 remainder (measure the LLM layer)
- Change (new): `test_p14_mindset_marginal.py` — run the real hunt/mindset
  passes against the live benches, collect LLM-origin confirmed seams, diff vs
  deterministic-only. Report marginal recall + any FPs.
- Reporting bench, NOT a hard 1.0 gate (models are stochastic): prints the
  number, skips without keys/ollama exactly as p14 skips without benches.
- Verify: produces a marginal-recall number on ≥1 bench.

### Capstone (not a fix — the money gate)
Point the hardened engine at one real in-scope target from `targets/`; measure
findings + FP rate + scope-compliance. Answers distance-to-money. Next action,
not part of "fix it all."

## Validation (per step)
`pytest tests/test_mindsets.py tests/test_mindset_profiles.py
tests/test_mindset_completeness.py tests/test_oracle_corpus.py -q`
+ that step's new test
+ `tests/test_p2_recall_bar.py`
+ `tests/test_p14_bench_recall.py` (benches up).
Red-before / green-after shown each time.

## Risks / open
- `cmd_hunt` is a monolith → G2/G4/G5 need minimal helper extraction to be
  testable (surgical, flagged before doing it).
- G3 needs real provider context windows (propose values; owner confirms).
- G5 must still abort a truly dead target.
- No commits/backups unless explicitly requested.

## Effort
~2 focused sessions for Steps 1–4; a few hours for Step 5.
