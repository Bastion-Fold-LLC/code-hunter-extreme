> Re-scoped 2026-10-20, then PARTIALLY EXECUTED same day (E0-1): the scoped
> fix #1 is now REAL — shared `parse_verdict(text)` lives in
> `oracle_foundation.py` (anchored first-token grammar; NEGATIONS/HEDGES —
> UNCONFIRMED, NOT CONFIRMED, POSSIBLY CONFIRMED... — classify UNKNOWN), and
> the sweep's inline substring gate (`"CONFIRMED" in v_upper`) was replaced
> by it (`oracle_hunter.py`, `_run_variant_sweep`). Fail-first receipts:
> UNCONFIRMED + POSSIBLY-CONFIRMED classified CONFIRMED pre-patch
> (tests/test_variant_sweep_verdict_gate.py), honest-contract shapes kept
> classifying post-patch (tests/test_parse_verdict.py, 12 cases; 6 sweep
> cases). Remaining deltas: INFORMATIONAL/NOT_A_BUG vocabulary, rollback
> tooling, and scoped fix #2/#3 (measure confirm-rate on live hunts; the
> route-sweep-through-verify_seam_card decision) — still **not fully
> implemented**, live validation owed at E1.

# Verdict-Tail Hardening — Scoped for Phase 4 (NOT implemented yet)

Source: deep-research verdict-path finding, scoped against code 2026-10-11.

## Findings (read, with refs)

1. `_assess_response` (`oracle_hunter.py:2658`) runs deterministic rules first
   (sensitive-data L2680, invariant L2687, 401/403/530 filters L2693+) then
   calls the LLM (L2776) with a strict prompt ("start with exactly one" of
   CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE, L2766-2769).
2. The variant sweep (`oracle_hunter.py:3314-3322`) checks
   `"CONFIRMED" in v_upper` with negation guards (FALSE_POSITIVE /
   INCONCLUSIVE / NOT CONFIRMED) but does NOT enforce startswith. Text like
   "POSSIBLY CONFIRMED IF…" passes. Worse: "UNCONFIRMED" contains
   "CONFIRMED" and matches NO negation guard → false CONFIRMED. The prompt's
   contract is unenforced.
3. The strict path (`verify_seams` → `verify_seam_card`,
   `oracle_deterministic.py:699`, Gates 1–5b) is bypassed by (2).

## Scoped fix (Phase 4, with live validation)

1. Add shared `parse_verdict(text)` enforcing startswith + negation guards;
   use it in the sweep (replacing the inline substring check) and anywhere
   else verdicts are substring-matched.
2. Measure confirm-rate before/after on gate cases. Rollback criterion: recall
   drops below the INITIAL bar (0.50) with no precision gain.
3. Decide during proving (not now): route sweep verdicts through
   `verify_seam_card` gates. Bigger change; needs live-wire evidence.

## Why not now

`STATUS.md` Proof6 R2: an over-strict change produced 0 confirmed
(GEAR FAILURE). Gate-strictness changes without live validation risk the same.
Implement during proving hunts where wire output validates behavior.
