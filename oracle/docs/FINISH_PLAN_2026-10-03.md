> **HISTORICAL (2026) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Finish Plan (2026-10-03)

Constraint model: agent-driven (user + Bob + me), not human-hours. Engineering
collapses to hours; the irreducibles are per-hunt wall-clock/$, hit-rate (probabilistic),
and the program's external triage clock.

RULE FOR EVERY VERIFY GATE: run the actual path (call _run_check, run the hunt, read the
findings JSON). A green pytest is NOT a gate — the 121 tests passed while Bug B was broken.

## Phase 0 — Coordination (avoid clobbering Bob)
Bob is editing oracle_seam_templates.py + oracle_hunter.py. One editor per file at a time.
Decide: Bob applies Phase 1 code (with the REAL Bug B fix), or he hands those files back.

## Phase 1 — Finish the engine (hours). GOAL: a TEMPLATE seam reaches CONFIRMED on the local app via the real wire path (never shown yet).
1. Bug B — REAL fix. Rewrite the 5 template checks to allow-listed flags only:
   - existence/body probes → `curl -i -s '{url}'`   (status read from included status line)
   - GraphQL (oracle_seam_templates.py:205) → GET form `curl -i -s '{url}?query=%7B__typename%7D'`
     AND fix the JSON regression `{"query":"{__typename}}` → `{"query":"{__typename}"}` (or drop POST)
   Lines: oracle_seam_templates.py ~205, 225, 317, 356, 402 (remove the `-m N` rewrites).
   VERIFY: `oh._run_check(<each check>)` returns non-[BLOCKED]. (Already proven: `curl -i -s URL` passes.)
2. Bug A (expected) + Bug C (mitre ctx): already fixed + verified. Leave.
3. Re-run: `python3 oracle_hunter.py hunt 127.0.0.1:3000 --auto` (cloud on, full 3 lenses).
   VERIFY (the real milestone): verify-results JSON shows >=1 CONFIRMED whose origin is a
   TEMPLATE seam (id like vacuum-/mirror-/observer-/spec-/single-token-), not only the
   header LLM cards. grep findings for template id + verdict CONFIRMED.

## Phase 2 — Mindset correctness (hours)
- Bug 2 (paradox cloud-only): add a local paradox pass OR log loudly "paradox lens skipped
  — cloud required" and make cross_compare count only lenses that actually ran.
- Bug 3 (downstream always paradox): per-seam mindset, or accept paradox default (low prio).
  VERIFY: a `--no-cloud` run's log names the lenses that executed; cross_compare agreement
  only counts those. No phantom "mitre" corroboration.

## Phase 3 — Real-target readiness (hours)
- Install ffuf + katana + nuclei into GO_BIN. VERIFY: `oracle_hunter.py status` shows all found.
  Add the missing-tool warnings Bob specced (name tool + install hint; no silent skips).
- Scope intake: `oracle_scan.py --pick N --download-only`. VERIFY: program.json has non-empty
  structured_scopes BEFORE hunt (else scope gate falls back to bare-name = over-broad).
- Filter/scraper hygiene (biases target selection; real but not a hard blocker):
  patchstack hardcoded $15k, codehawks ETH×3000, hardcoded fast_triage=True (5 platforms),
  max_resolved_reports no-op on 11/14, 2 thin scrapers (bugbase, hatsfinance).
  VERIFY: a dry `--scan` ranks targets sanely; recon on a JS-heavy target populates
  js_endpoints.txt / api_specs.txt / fuzzed_paths.txt (non-empty).

## Phase 4 — Fan out (the volume game)
- Pick a batch of real, in-scope, JS/API-heavy programs (>=$500, not picked-over). Run hunts
  in PARALLEL (this is the agent lever human estimates miss).
- Triage the CONFIRMED set: drop low-sev header-only; keep access-control / IDOR / logic /
  real info-disclosure. VERIFY: >=1 CONFIRMED of payable class with a clean PoC + submission_draft.

## Phase 5 — Submit + iterate
External triage/payout clock (days–weeks, not ours). Feed triage outcomes back into
target selection + seam templates.

## Honest status
- Engine (recon→mindsets→seam→5-gate verify→PoC→report): ~built, loop closes, verifier solid.
- NEVER YET SHOWN: a template seam confirming on real recon. Phase 1.3 is that proof.
- "Money": a volume + probability game once Phases 1–3 are done; not a schedule.
