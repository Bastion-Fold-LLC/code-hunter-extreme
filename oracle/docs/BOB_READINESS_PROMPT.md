Do an independent readiness assessment of the Oracle bug-bounty pipeline — read-only, one pass, no edits. Canonical repo: `/home/phantomcore/oracle` (ignore the other copies like `oracle-fresh/`).

Judge each subsystem from the **actual code**, not the docs — the docs (ARCHITECTURE.md, the *_PLAN.md files) are our *claims*; your job is to verify them and flag where they overclaim. For each subsystem give a verdict — **WORKS / PARTIAL / MISSING / BROKEN** — with a `file:line` citation as evidence. No verdict without a citation.

Subsystems to cover:

1. **Scope scraper, all 14 platforms** — `oracle.config.json → platform_auth` lists: hackerone, bugcrowd, intigriti, yeswehack, immunefi, hackenproof, cantina, code4rena, sherlock, codehawks, patchstack, huntr, bugbase, hatsfinance. For each, does `oracle_programs.py` actually resolve scope, or is it a stub/`NotImplemented`/TODO? Say which of the 14 are real vs. scaffolding.
2. **Config filters** (`config.filter`: min_payout_usd, max_resolved_reports, fast_triage_only, new_programs_only…) — do `oracle_hunt_filter.py` / `oracle_triage.py` actually read and apply each filter key, and does the behavior match the `_comment_*` descriptions?
3. **Asset/scope download + the `api_key → cdp_session → public` auth cascade** (`oracle_bulk_download.py`, `oracle_auth_session.py`) — on a bad/expired key, does it fall through to the next tier, or crash/hang? Cite the fall-through logic.
4. **Recon** (`oracle_deeprecon.py`, `oracle_scan.py`) — does it surface *endpoints/content*, or only live hosts? On our local test target recon fed the LLM **0 endpoints** — verify whether that's a target artifact or a real coverage gap in the recon code.
5. **The three mindsets + cross-compare** (`oracle_mindsets.py`, `oracle_mindset_context.py`, `oracle_hunter.py`) — are three distinct lenses actually built and run, and does cross-compare produce a real agreement signal (not a no-op)?
6. **Seam generation** (`oracle_seam_templates.py`, `oracle_code_seam.py`, `oracle_ttp_fuse.py`) — do templates produce machine-checkable seam cards (with a status-code expectation), or free text?
7. **The deterministic 5-gate verifier** (`oracle_deterministic.py`, `verify_seam_card`) — confirm there are genuinely 5 gates (grounding, scope, machine-readable expectation incl. status code, claim-source, wire-match) and that each one can actually REJECT. Cite each gate's line. Flag any gate that's vacuous (always passes).
8. **Collaborate / LLM layer** (`oracle_llm.py`) — are the role calls bounded (no unbounded hang on a slow local reviewer)? Cite the timeout/bound.
9. **Report generation + orchestration** (`oracle_hunter.py`, `main()` ~line 4036) — does a completed hunt actually write a report with a triaged finding end-to-end? Note: the last end-to-end run never finished (machine crashed mid-run), so the loop is **unproven**, not proven — treat "loop closes" as an open claim to test by reading the code path, not by trusting the docs.

Deliverable:
- One table: subsystem | verdict | file:line evidence | one-line note.
- Then the **top 3 blockers** to pointing this at a real program and getting one submission, ranked, each with why and a rough size (hours/days).
- Where a doc overclaims vs. the code, name the doc and the line.

Rules: read-only — do not edit, run, or scan anything. Don't echo our docs back as findings; cite code. If a subsystem is too big to fully trace, say so and cite what you did read rather than guessing.
