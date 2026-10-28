# Oracle — Pipeline Validation / Test Plan

Goal: prove, per website and end-to-end, that (1) the filters select correctly,
(2) we download/extract correctly, (3) we scan/process all the information
correctly, and (4) the whole pipeline works. Written as layers — each with a
test method, a success criterion, and whether it's automatable or needs a live
check. Platforms in scope: the 14 keys in `oracle.config.json → platform_auth`
(hackerone, bugcrowd, intigriti, yeswehack, immunefi, hackenproof, cantina,
code4rena, sherlock, codehawks, patchstack, huntr, bugbase, hatsfinance).
Note (2026-10-20): `platform_auth` has **no production consumer** — it is read
only by a config test and docs; live platform coverage is defined by the
Scan4Me feeds + scope adapters (Hats excluded, Federacy off). Current
validation, for reference: Oracle pytest suite (1148 passed, 2026-10-20) +
`tests/run_all.py` (10 layers) + Scan4Me pytest (121 passed) + bench recall
bar 12/12 (`benchmarks/BENCH_RECALL.md`).

Grounded in what Phase A already exposed (see end): the loop had two unbounded
local-model waits (one fixed), and recon surfaced 0 endpoints on a bare target —
so these aren't hypothetical risks, they're the real failure modes.

---

## Layer 1 — Filters select correctly (per platform)

Every filter in `config.filter`, proven on each platform's data format.

**Filters to cover, each independently:** `min_payout_usd`, `max_payout_usd`,
`max_resolved_reports` (less-picked-over), `new_programs_only` + `new_program_days`,
`recently_added_assets_only`, `web2`/`web3`, `fast_triage_only`,
`pick_per_platform`, `top_n`.

**Method:**
- Capture one real program-list snapshot per platform (saved as a fixture).
- Unit-test `oracle_programs.filter_programs` / `oracle_hunt_filter` against each
  fixture: assert each filter includes/excludes exactly the right programs.
- Live spot-check: run the real fetch per platform once, eyeball the top N.

**Success:** for every platform, each filter provably selects the intended set;
a program failing a gate is excluded with a stated reason (fail-loud, no silent
pass). Automatable via fixtures; one live spot-check per platform.

---

## Layer 2 — Scope + download are correct (per platform)

**2a. Scope scraping.** `scope_scraper` → `scope_config.json` with correct
in-scope / out-of-scope assets, for each platform's page/API format.

**2b. Auth-method cascade.** `platform_auth.methods` = `api_key → cdp_session →
public`. Verify it **falls through** on a missing/bad key to the next method and
only fails loud when all methods are exhausted — never silently returns empty.

**2c. Asset download.** Repos clone, contracts download, scope pages fetch — land
on disk under the right workspace layout. `recently_added_assets_only` feeds
only the new assets forward.

**Method:** per platform, run scope scrape + download on one real program
(offline fixture of the platform's response where possible; live once per
platform). Assert `scope_config.json` contents and the files on disk.

**Success:** for ≥1 program per platform, scope is correct and assets are on
disk in the expected layout; the cascade demonstrably falls through; "new only"
forwards only new assets. Mostly live checks; cascade logic is unit-testable
with fake responses.

---

## Layer 3 — We scan/process all the information correctly

**3a. Recon coverage (critical — Phase A failure mode).** Recon must surface the
assets the analysis needs. Phase A fed the LLM **0 endpoints** on a live target,
so it found nothing. Verify endpoint/content-discovery actually finds a known
target's endpoints before trusting a "TARGET CLEAN."

**3b. Tool-output parsing.** The pipeline parses each tool's output → findings
via `intel_map.json` correctly (no dropped/garbled results).

**3c. Mindset injection.** recon + downloaded assets + scope wall are injected
into each mindset prompt (and nothing out-of-scope leaks in).

**3d. Seam parsing.** `_parse_seams` captures the model output across formats
(we fixed `SEAM CARD N` + fenced curls; keep a fixture per model/format and
assert non-zero parse on valid output — a 0-parse on real cards is a bug, as we
saw).

**3e. Verify correctness.** Checks run; CONFIRMED only on real wire match; no
false confirms; out-of-scope/unsafe checks rejected.

**Method:** ground-truth targets (`tests/bad_code_app.py`, Juice Shop) where we
know what *should* be found. Assert recon surfaces the vulnerable endpoints, the
mindsets emit candidates for them, parsing captures them, verify confirms the
verifiable ones. "Clean" on known-vulnerable input = a scan bug, by Reflex #6.

**Success:** on each known-vulnerable target, the vulnerable endpoints are
surfaced, candidates are produced and parsed (non-zero), and the verifiable ones
confirm. Automatable against the fixtures.

---

## Layer 4 — Whole pipeline, per target type

Run the full `hunt` and measure against ground truth, for each target shape:

- **web2 live** (Juice Shop on loopback): recon → mindsets → verify → report.
- **web3 / code** (Damn Vulnerable DeFi — Solidity): `--code` → code lens →
  verify.
- **code-only** (a Patchstack/PHP plugin): code lens direct, live recon skipped.

**Method:** the benchmark harness (roadmap Phase E) — one command per target
that runs the pipeline and scores candidates vs the repo's ground truth
(precision/recall). Clone the Python + Solidity benchmarks (registry requires
explicit per-repo consent).

**Success:** each target type produces a report with the expected confirmed
findings, and the harness prints "caught N of M known bugs" — so every future
change is measured, not guessed.

---

## Operational robustness (must hold for any of the above to finish)

- **Engine collection deadline** — FIXED this session (420s cap; proceed with
  whatever returned).
- **`collaborate()` deadline** — NOT yet fixed. Phase A hung here: its local
  private-reviewer has no timeout. Same fix needed (bounded wait, proceed with
  scout/adversary if local is slow).
- **Full-run speed** — bound/parallelize so a hunt completes in minutes; reduce
  or make Engine B's 14 local passes optional.

---

## Suggested execution order

1. Fix `collaborate()` deadline (unblocks any full-hunt test).
2. Layer 3 on ground truth (`bad_code_app` via `--code`, Juice Shop) — fastest,
   controlled, exposes scan bugs.
3. Build the Layer-4 benchmark harness (Phase E) — turns all of this into one
   measurable command.
4. Layers 1 & 2 per platform (the Phase-C work), platform by platform.

Each item: short spec where noted → TDD → verify → commit.
