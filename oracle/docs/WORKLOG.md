> **HISTORICAL (2026-10-13 hunts) — superseded by `SYSTEM_WORKLOG.md`.** Wallet.md references below were already dead at writing.

# Oracle-System Worklog — what we're doing

_Live notes. Companion to `PLAN.md` (the finish plan) and the auto-memory at
`~/.claude/projects/-home-phantomcore-oracle/memory/`. Updated 2026-10-15._

## The system (grounded in your docs)
Three repos under GitHub org `code-hunter-extreme`:
- **oracle** — the hunter/brain. 3 mindsets (M1 MITRE, M2 philosophy/paradox, M3 synthesis)
  over the invisible seam, 5-gate wire verifier, chaining → report. (`ORACLE_DOCTRINE.md`,
  `docs/ORACLE_SYSTEM_EXPLAINED.md`, `oracle_mindsets.py`.)
- **omnicli** — the orchestration + red-team ENGINE oracle runs its lenses on
  (`oracle_llm.py` → `omnicli.orchestrate.run_orchestration`). No mindsets of its own.
- **scan4me** — the scope/target DB (scrapes bounty platforms → ranked scope/assets/rules).

## How we work (the review loop)
Every change: run the local deterministic stack → push → Greptile + CodeRabbit review the
diff + validate CI (when merged) → `scripts/review-harvest.py <repo> <pr>` unifies BOTH bots
+ CI into one checklist → verify each vs current code → fix/mark-safe + regression test →
merge only when both reviewers + CI are green. See `docs/TOOLING_INVENTORY.md`.

## Phases
- **Phase 1 — omnicli orchestration + red-teaming: DONE/verified.** Collaborate + red-team
  run live; red-team's 5-gate verifier rejected an ungrounded claim live; engine tests 43/44
  (1 = proving-run gate); found+fixed a live crash (swarm display KeyError, PR #8); docs
  corrected (providers 7→10, PR #7); config key-exposure window fixed (PR #6).
- **Phase 2 — scan4me (next):** verify it's solid; investigate parsing MORE from the bounty
  sites WITHOUT login (public program/policy pages often expose scope unauthenticated).
- **Phase 3 — oracle backlog + the end-to-end proving run** on `tests/vuln_testbed_full.py`
  (flips omnicli's red `test_qualifying_run` green = done).
- **Cross-cutting:** keep it easy to add API providers (omnicli `DEFAULT_PROVIDERS`, one entry)
  and bounty sites (scan4me fetchers + scrapers; oracle scrapers).

## Open PRs (merge when both reviewers + CI green)
- ALL OPEN PRs MERGED 100%:
  - oracle: #1 (seam/cred), #4 (validate CI), #5 (verify_in_scope parity), #6 (CSRF form-replay), #9 (docs/tooling), #10 (shell-expansion sanitization + reflected XSS raw tag).
  - scan4me: #2 (deleted-join/oos/CIDR), #4 (offline-no-API/schema migration/H1 eligibility), #5 (validate CI).
  - omnicli: #2 (model-sub/council), #3 (allow_localhost), #5 (validate CI), #6 (config 0600/deepcopy), #7 (docs), #8 (swarm KeyError).

## Proving Run Status
- Local Golden Hunt: PASS (`python3 tests/test_golden_hunt.py` -> 25 CONFIRMED, 16 planted vulns verified, 7 benign controls rejected, 67 chains formed / 39 Critical).
- Testbed Red-Team Pipeline: Verified live via `redteam_runner.sh` with 5-gate wire proof and compound threat models.
- omnicli Transition Gate (`test_qualifying_run_artifact_exists_and_validates`): Pending final qualifying run artifact.

## Reminders
- Rotate the Greptile API key AND the Snyk token — both were pasted into the earlier chat transcript.
