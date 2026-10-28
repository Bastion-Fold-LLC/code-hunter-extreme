Follow-up to your readiness assessment. Read-only again — propose, don't edit (I'm making the code changes). Judge from code, not our docs.

New facts since you assessed (so your plan starts from current truth):
- The confirm path WORKS and has produced confirmed findings: the Oct-2 run on 127.0.0.1:3000 (bad-code app) has 3 cards with verdict CONFIRMED (missing CSP, HSTS, Referrer-Policy) + a "Confirmed: 3, Composite Severity: Critical" summary (reports/127.0.0.1_3000_20261002_094045.md). So the deterministic verifier can and does reach CONFIRMED. CAVEAT: those three are missing-security-header findings — low/informational severity that most programs will not pay for.
- Run 5 completed the FULL loop on 127.0.0.1:8765: recon → 3 mindsets → collaborate (3 candidates) → verify 6 seams → report written. 0/6 confirmed here. So "loop closes" is now PROVEN.
- Two located bugs caused run 5's 0 confirms (NOT a universal "nothing confirms" — the 3000 run confirmed 3): (1) every 8765 seam card's `expected` is empty/None → Gate 3 (oracle_deterministic.py:578) rejects; (2) the check sanitizer at oracle_hunter.py:1980 blocks checks that pipe `| head` ("shell metacharacters not allowed"). Open question for you: why did the 3000 header seams confirm while the 8765 seams didn't — seam-type specific, or a regression between the two runs?
- Confirmed dead: `platform_auth` in oracle.config.json has zero code consumers. Thin scrapers: bugbase, hatsfinance.
- Report-gen quirk to flag: that Oct-2 file concatenates 3 Summary blocks (Confirmed 0, then 3, then 0) — the top summary disagrees with the middle. Worth a look.

## Part A — per-subsystem operational plan
For EACH of the 9 subsystems from your assessment, give three things:
- **Gap**: what specifically stops it working on a REAL program (not the local test target), with file:line.
- **Improvement**: the concrete change(s) to close that gap, with file:line and a one-line "what good looks like."
- **Test**: a specific, runnable check (exact command + the assertion that must hold) that proves the subsystem works. Prefer deterministic tests; name the fixture or target to use. Where only an end-to-end test will do, say so and give the command.

## Part B — config wiring audit (they asked: "are the config options actually wired in?")
For EVERY key in oracle.config.json, cite the code line that reads/consumes it, or mark it DEAD (you already found platform_auth). Output a table: key | consumer file:line | effective? (yes / dead / partial). I need to know which configuration options are real controls vs. decoration.

## Part C — per-site filter behavior (they asked: "how do the filters actually work for each site?")
For each of the 14 platforms, given what its scraper ACTUALLY returns (does it populate payout? resolved-reports count? fast-triage flag? launch date?), trace how each filter key behaves for that platform: min_payout_usd, max_resolved_reports, fast_triage_only, new_programs_only/new_program_days. Output a table: platform | fields the scraper returns | which filters are effective vs. silent no-ops | where its programs land in ranking. Call out explicitly where a thin scraper (payout=0, no counts) slips through or gets buried.

## Part D — calibrated distance (they asked: "how close are we to money?")
Two numbers, each with ranges and the assumptions behind them:
1. To first CONFIRMED finding on the local known-broken target, AFTER the two bug fixes above.
2. To first VALID submission on a real program — list what gates it, ranked, with rough size each.
Do NOT anchor to our optimism. Priors: we HAVE confirmed findings (3 on the local bad-code app) but they are low-severity missing-header issues that likely won't pay. So the real question isn't "can it confirm anything" (it can) — it's "how far to a confirmed finding that a real program would actually PAY for." If we're far, say far, and say what would move the needle most. A number you can defend from the code beats a flattering one.

Rules: read-only — do not edit or run anything. Cite code, not our docs. If a subsystem/platform is too big to fully trace, say so and cite what you did read rather than guessing.
