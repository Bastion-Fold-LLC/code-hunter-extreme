# Oracle 60-Case Gate Spec

Status: INITIAL — method is binding; numeric bars recalibrate after the first
full gate run (see Recalibration). The gate is confidence-only and explicitly
NON-BLOCKING for first money (user decision).

## Sources (grounding)

- `docs/BENCHMARK_EVALUATION.md` — ledger layers, scoring rule, onboarding policy.
- `benchmarks/registry.json` — 6 approved local benchmarks (juice-shop, pygoat and dvwa enabled (3 of 6)
  at pinned revision; rest disabled until reviewed onboarding).
- `tests/bad_code_app.py` + `tests/test_oracle_ground_truth.py` — flaw battery
  (≥7 flaws incl. Flaw 7) with reflex→parse→verify runner precedent.
- `STATUS.md` Proof6 rounds — blind-run precedent (XBEN-001-24) and the
  0-confirmed lesson: over-strict gates collapse recall.

## Case composition (INITIAL: 40 flaw + 20 clean = 60)

- Flaw cases: bad_code_app battery + pinned juice-shop challenge subset +
  `vuln_testbed_full.py` + blind holdout (XBEN-style; labels sealed until scoring).
- Clean cases: patched variants of flaw fixtures + benign endpoints whose wire
  behavior must close (401/403/530/404 per `test_scope_gate.py` precedent).
- All cases run loopback-only per registry onboarding policy.

## Ledger + scoring (binding, from BENCHMARK_EVALUATION.md)

One ledger row per case across the layers: scope gate, recon, seam, mindset,
MITRE, iPhone framing (sourced Assertion A, observed Assertion B, one decisive
check, impact), verification, chaining. A case passes iff:

```text
expected status == Oracle status
and
the stored evidence independently explains the status
```

## Metrics

- precision = true-confirmed / confirmed
- recall = true-confirmed / flaw-cases
- clean-FP = confirmed-on-clean / clean-cases

## Bars (INITIAL — machine values in `oracle.config.json` → `quality_gates`)

| Metric | Bar | Rationale (auditable) |
|---|---|---|
| precision | ≥ 0.70 | Above the only measured anchor (council F1 0.5714) |
| recall | = 1.0 | Locked zero-miss bar (P2-lock; machine value `gate_recall_min: 1.0` in `oracle.config.json`) |
| clean-FP | ≤ 0.10 | FP-resistance is the DVWA layer's purpose |

## Recalibration (binding)

After the first full 60-case run, each bar moves to measured±margin or stays
with a written justification committed alongside. Bars never move silently.

## Human-review exit stages (INITIAL)

- STAGE 0 (current): full human review of every verdict.
- STAGE 1 spot-check (1-in-3 + all high/critical): rolling precision ≥ 0.70
  over the last 30 live verdicts.
- STAGE 2 audit-sample (1-in-10): rolling precision ≥ 0.85 over the last 60
  live verdicts with zero false-CONFIRMED submissions.
- Measurement source: live-hunt verdict log (instrumented in Phase 4) + gate runs.
- Regression: two false-CONFIRMED submissions in any 30-verdict window drops
  one stage. No appeal, no delay.
