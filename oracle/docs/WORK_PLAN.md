> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Work Plan (finishing the system)

How we finish Oracle: who does what, how bob is used, and the exact sequence.
Companion to `FINISHING_ROADMAP.md` (the phase detail) and
`SESSION_STATUS_2026-10-02.md` (where things stand).

## Status going in

The engine is proven: pointed at code with known planted bugs, the `mitre` and
`paradox` mindsets found all of them, the parser now captures them, and the
5-gate verifier confirms. The hard "does the method work?" risk is retired.
What remains is wiring, coverage, and speed.

## Division of labor

- **Claude (free) — the bulk.** All building (code), and all the *wide* hunting
  (recon + the free-model reflex sweep over many candidates). Zero bobcoins.
- **bob (IBM, used sparingly via an open CLI session) — the narrow, high-value
  steps only.** Two jobs, a handful of calls per hunt:
  1. **Red-team** a *confirmed* candidate (is it real, in scope, right severity?).
  2. **Write the PoC** for a confirmed bug.
  When a hunt reaches those, Claude hands over the exact candidate/prompt; bob
  runs it in the open session; the result comes back. Everything else is free.

## Bobcoin rules

- bob is **never** on the wide reflex sweep (`reflex` route stays free:
  `openrouter → nvidia → local`).
- bob is only ever invoked on the `poc` and `assess`/`correlate` steps, which
  are bounded to the top handful of confirmed candidates.
- Before relying on bob at all, spend exactly **one** bob call to verify it
  finds the planted flaws in `tests/bad_code_app.py`. One call, not a sweep.
- Target: ~2–5 bob calls per hunt, not dozens.

## Sequence

| # | Phase | Who | Bobcoins | Success criterion |
|---|-------|-----|----------|-------------------|
| A | Prove the full loop end-to-end on loopback Juice Shop | Claude | 0 | One CONFIRMED, agreement-ranked seam from a single command |
| B | Make full hunts fast (cap/parallelize the free-model cascade) | Claude | 0 | LLM passes complete within a bounded budget, same find rate |
| C | Scope-fetch + asset-download on a real program (the gate) | Claude | 0 | Scope + assets on disk, correctly scoped, for ≥1 real filtered program |
| D | First real hunt → submission | Claude + bob | ~2–5 | One real, in-scope, verified finding submitted (bob writes/red-teams the PoC) |
| E | Benchmark harness (runs alongside from A on) | Claude | 0 | One command prints "caught N of M known bugs" per target |

## Order of operations

1. **Phase A now** (free). Run the loop end-to-end; fix whatever it exposes.
2. **Phase B** (free). Speed.
3. **Phase C** (free). Real-program extract/download — the biggest remaining piece; gets its own short spec.
4. **Phase D**. Real hunt; bob enters here for PoC + red-team only.
5. **Phase E** runs in parallel from A onward.

Each phase: short spec where noted → TDD implementation → verify → commit.
Same loop used for the mindsets refactor.

## How bob is reached

- Default: the **`bob -p` CLI session you already have open** — Claude gives you
  the prompt, you paste the result back. No key in any file.
- bob touches nothing until Phase D's PoC/red-team step.

## Immediate next action

Phase A — Claude runs the full loop on loopback Juice Shop (free). No bobcoins.
