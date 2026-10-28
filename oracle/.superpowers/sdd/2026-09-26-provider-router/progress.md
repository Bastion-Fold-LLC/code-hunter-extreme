# SDD ledger — plan: docs/superpowers/plans/2026-09-26-provider-router.md

Setup: branch feat/provider-router (not a worktree).
Ruling: feature branch instead of git-worktree — fresh single-purpose local repo, solo inline build; branch gives the required "not on master" isolation without worktree overhead — cost if wrong: negligible, can move to worktree later.
Ruling: following plan's RED-GREEN steps as TDD without separate skill load — plan is already fully TDD-structured; conserves context given fragile streaming — cost if wrong: none, discipline is applied regardless.

Pre-flight (shared interfaces):
- Task2 consumes load_backend_config (Task1) — signature matches. ok
- Task3 base Backend/BackendError consumed by Task4,5 — names consistent. ok
- Task5 build_backends_for consumes OpenRouterBackend/OllamaBackend/CliBackend (T3,T4) — ctor sigs match brief. ok
- Task6 consumes oracle_llm.complete (T5) — signature complete(prompt,system,task_type) consistent. ok
- Task7 consumes build_backends_for + BackendError (T3,T5) — consistent. ok
Task 1: complete (commit 6e18a5f, tests: pytest tests/test_llm_config.py -> 3/3 pass)
Task 2: complete (commit 4008c37, tests: pytest tests/test_llm_discovery.py -> 3/3 pass)
Task 3: complete (commit 8d1dd17, tests: pytest tests/test_llm_http_backends.py -> 3/3 pass)

--- PAUSED (usage limit) 2026-09-26 ---
Task 4: IN PROGRESS — test_llm_cli_backend.py written and RED-confirmed (AttributeError: CliBackend). Implementation NOT yet written.
RESUME HERE: implement CliBackend in oracle_llm.py per plan Task 4 Step 3, then pytest tests/test_llm_cli_backend.py (expect 3/3), commit, ledger. Then Tasks 5-7 remain, then final review.

SECURITY REVIEW (background, on commits) — triage on resume:
1. command-injection oracle_hunter.py — PRE-EXISTING: _run_check uses subprocess shell=True on model-generated check cmds (guarded by ProgramScopeGate.validate_check, but shell=True is the risk). Not from router work. Assess hardening (shlex, shell=False).
2. credential-exposure test_keys.py — PRE-EXISTING test file, not part of router work. Review before it stays committed.
3. parser-differential oracle_hunter.py — LIKELY the _parse_seams regex change (bare-SEAM MULTILINE match). Verify the relaxed ^\s*...SEAM\d does not over-match line-start 'SEAM N' in prose/recon echoes. Add a differential test on resume.
4. (+1 more, unspecified in notification) — pull full review output on resume.
NOTE: findings are on already-committed code; none block Tasks 4-7 but #3 touches our parser fix and must be verified.
5. control-regression / fail-open state drift oracle_llm.py — ABOUT ROUTER CODE. MUST verify on resume: confirm complete() is fail-CLOSED (raises RuntimeError on exhaustion — it does by design), and check load_backend_config defaults (local_enabled default True, partial openrouter dict replace-vs-merge) and discover cache except:pass don't create a fail-open path (e.g. silently using stale/empty model list or bypassing allow_paid). Pull full review output; add regression test before proceeding to Task 5.
Task 4: complete (commit 16b2113, tests: pytest tests/test_llm_cli_backend.py -> 3/3 pass) [resumed after limit]
Task 5: complete (commit 224154f, tests: pytest tests/test_llm_router.py -> 5/5 pass; fail-closed exhaustion verified re: security finding 5)
Task 6: complete (commit 1ab0fc7, tests: pytest tests/ -> 42/42 pass; grep confirms free_models + bare OPENROUTER_API_KEY removed)
Task 7: complete (commit 8e626e4, tests: pytest tests/ -> 44/44 pass)

=== FINAL REVIEW (self + background security review; no fresh subagent per session policy) ===
Final: fixed #5 fail-open/cascade oracle_llm.py — test_router_cascades_past_non_backenderror + test_openrouter_discovery_failure_is_backenderror RED->GREEN, suite 48/48. Ruling: router catches Exception not just BackendError — a backend's internal error must cascade, exhaustion still raises RuntimeError — cost if wrong: could mask a backend bug as "failed", but reason string + RuntimeError preserve fail-closed.
Final: Ruling #3 parser-differential — VERIFIED NON-ISSUE: stray line-start 'SEAM N' with no card body is discarded (test_stray_seam_line_without_body_is_not_a_card passes). No fix — cost if wrong: none.
Final: Ruling #1 command-injection oracle_hunter.py _run_check(shell=True) — PRE-EXISTING, outside router scope, not introduced by this branch. NOT fixed here (surgical-changes rule). FLAG TO USER: model-generated check commands run via shell=True, mitigated by ProgramScopeGate.validate_check but should be hardened (shlex/shell=False) in a dedicated change — cost if wrong: RCE surface if scope gate is bypassed.
Final: Ruling #2 credential-exposure test_keys.py — PRE-EXISTING test file, outside router scope. FLAG TO USER for separate review — cost if wrong: test may expose key handling.
Final: #4 (unspecified in notification) — full background-review output not captured; FLAG TO USER to surface the 4th finding.
Workspace retained (not deleted): pre-existing security findings #1/#2/#4 remain open for user decision.
