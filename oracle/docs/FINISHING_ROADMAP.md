> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Finishing Roadmap (from 2026-10-02)

Goal: take Oracle from "method proven on ground truth" to "runs a full hunt on a
real program and produces a submission-ready, verified finding."

Status going in: the analysis layer (3 mindsets) is proven to find bugs; parsing
is fixed; the 5-gate verifier exists. What remains is wiring, coverage, and
speed — not the core question of whether the method works.

Phases are ordered by the critical path to a first submission. Each phase ends
with a concrete, testable success criterion. The two large phases (A, C) each
get their own detailed spec→plan before implementation; the rest are bounded.

---

## Phase A — Prove the loop end-to-end on controlled ground truth

**Why first:** we have never run recon → 3 mindsets → cross-compare → verify →
report as one pass. Juice Shop on loopback is known-vulnerable with ground
truth, so any end-to-end wiring bug surfaces safely (exactly how the parser bug
surfaced).

**Work:**
- Stand up OWASP Juice Shop bound to loopback (already cloned, pinned revision).
- Run `oracle-hunter hunt <loopback>` through the full pipeline.
- Fix whatever the full path exposes (parser already fixed; expect more).
- Wire the deferred `sort_confirmed` into `_finalize_verify` so the report
  ranks by agreement.

**Success:** a written report with ≥1 **CONFIRMED** seam on Juice Shop,
agreement-ranked, produced by one command — no manual stitching.

**Size:** medium. Needs its own short spec (what "stand up Juice Shop loopback"
and the run invocation look like) before implementing.

---

## Phase B — Make full hunts fast enough to be practical

**Why:** the full `mitre` pass took 213s cascading through free models, and an
earlier run timed out at 5 min. A compact prompt against one capable model
returned in 64s. Real hunts can't churn the whole free-model list.

**Work:**
- Rank/select a small set of known-capable free models first (cap the cascade
  breadth); fail past dead models fast instead of 90s×retries each.
- Consider running the two LLM mindsets in parallel (the dual-engine already
  uses a thread pool).

**Success:** a full-mindset hunt's LLM passes complete within a bounded budget
(target: a few minutes, not open-ended) with the same find rate.

**Size:** bounded — a focused change in `oracle_llm` model selection + the
`cmd_hunt` submit loop. Chat-design + TDD, no separate spec.

---

## Phase C — Extract/download on a real program (the platform gate)

**Why:** this is the actual gate to a real target. Everything downstream is
proven; nothing matters if we can't reliably pull a real program's scope and
assets. Covers all 14 platforms in `platform_auth`, each a different format.

**Work:**
- For each platform (or a representative subset to start): verify
  `scope_scraper` fetches scope → `scope_config.json`, and the auth method
  cascade (api_key → cdp_session → public) falls through correctly on a
  missing/bad key.
- Verify asset download (repos, contracts, scope pages) lands on disk for a
  real in-scope program.
- Verify the config filters (`new_programs_only`, `recently_added_assets_only`,
  `max_resolved_reports`, payout) actually select as intended per platform.

**Success:** for at least one real filtered program, scope + assets are on disk,
correctly scoped, ready to hunt — demonstrated per platform we enable.

**Size:** large, and platform-by-platform. Needs its own spec→plan. This is the
single biggest remaining piece.

---

## Phase D — First real hunt → submission

**Work:** pick one filtered real program (fast-triage, low resolved-report
count, fresh per your filters), run the full hunt, confirm a seam, generate the
submission draft, submit.

**Success:** one real, in-scope, verified finding submitted.

**Size:** mostly execution once A–C land. The POST/state-mutation confirm path
(safe verifier is GET-only) gets handled here via `--testnet` or a human gate.

---

## Phase E — Continuous measurement (parallel, ongoing)

**Why:** your `BENCHMARK_EVALUATION.md` plan — measure before trusting, measure
before tuning.

**Work:** a repeatable benchmark harness that runs the pipeline across the
registry corpus (PyGoat, Juice Shop, NodeGoat, DVWA, WebGoat, Damn Vulnerable
DeFi) and scores candidates against each repo's ground truth (precision/recall).
Clone the Python + Solidity benchmarks (play to the lens's strongest matchers) —
your registry requires explicit per-repo consent to clone.

**Success:** a one-command benchmark that prints "caught N of M known bugs" per
target, so every change is measured, not guessed.

**Size:** medium; its own spec→plan. Highest leverage for turning "it found
things" into "its hit rate is X and rising."

---

## Suggested order

1. **Phase A** (prove the loop — do this next; it exposes real wiring bugs cheaply)
2. **Phase B** (speed — needed before real hunts are practical)
3. **Phase C** (extract/download — the real gate)
4. **Phase D** (first real submission)
5. **Phase E** runs alongside from Phase A onward (measure everything)

Each phase: short spec where noted → plan → TDD implementation → verify →
commit. Same loop we used for the mindsets refactor.
