# System Audit & Living Work Log

**Started:** 2026-10-16  
**Rule:** Only record what was actually inspected, executed, or changed. Do not overclaim.

---

## 1. Initial Read of the System (2026-10-16)

### Files Inspected
- [`ORACLE_DOCTRINE.md`](/home/phantomcore/oracle/ORACLE_DOCTRINE.md)
- [`docs/OWNER_MINDSET_SPEC.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_SPEC.md)
- [`docs/OWNER_MINDSET_FINISH_PLAN.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_FINISH_PLAN.md)
- [`docs/HOW_THE_SYSTEM_WORKS.md`](/home/phantomcore/oracle/docs/HOW_THE_SYSTEM_WORKS.md)
- [`docs/WORKLOG.md`](/home/phantomcore/oracle/docs/WORKLOG.md)
- [`ARCHITECTURE.md`](/home/phantomcore/oracle/ARCHITECTURE.md)
- [`oracle_mindsets.py`](/home/phantomcore/oracle/oracle_mindsets.py)
- [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py)
- [`oracle_corpus.py`](/home/phantomcore/oracle/oracle_corpus.py)
- [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py)
- [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py)
- [`oracle_seam_templates.py`](/home/phantomcore/oracle/oracle_seam_templates.py) (lines 1–250)
- [`oracle_hunter.py`](/home/phantomcore/oracle/oracle_hunter.py) (lines 600–1200, 5900–7450)
- [`tests/test_three_mindset_spec.py`](/home/phantomcore/oracle/tests/test_three_mindset_spec.py)
- `/home/phantomcore/invisible-seam/src/invisible_seam/extractors/` (`doc_extractor.py`, `python_security_extractor.py`, `php_security_extractor.py`)
- `/home/phantomcore/invisible-seam/src/invisible_seam/matchers/code_matcher.py`

---

## 2. How the Three-Mindset Architecture Actually Works in Code Right Now

### Mindset 1 (`mitre`)
- **What it is:** Full-weight MITRE ATT&CK lens (`oracle_ttps_fused.json`, 344 unique records) combined with the Invisible Seam candidate feed (`inject_pending_seams`) and full bug bounty context (`_program_brief`: in-scope assets, out-of-scope rules, policy/rules text, company info, downloaded assets).
- **Red Teaming:** Embedded with `_MITRE_REDTEAM_DIRECTIVE` during generation (`oracle_mindset_context.py:80-99`), and its output seam cards go through their own isolated pre-synthesis red-team gate (`redteam_challenge_by_lens` in `oracle_hunter.py:7056-7072` and `oracle_mindsets.py:388-410`).

### Mindset 2 (`paradox`)
- **What it is:** **ALL** philosophies, **ALL** paradoxes, and **ALL** impossible problems in iPhone-level framing (`ORACLE_SYSTEM_PROMPT.md` + `ORACLE_FRAMEWORK.md` + all 21 registered canonical documents in `corpus/` via `oracle_corpus.source_context(..., max_chars=320_000)`).
- **No Cherry-Pick Enforcement:** `oracle_corpus.py:256-298` validates that every file in `corpus/` is registered (`validate_registry()`) and loads all 21 documents verbatim; if `max_chars` cannot fit all documents, it raises `ValueError` naming the dropped documents rather than truncating or subsetting.
- **Combined with Invisible Seam + Bounty Context:** Receives the same `_program_brief()` and `inject_pending_seams()` feed as Mindset 1 (`oracle_hunter.py:6545-6572`).
- **Red Teaming:** Embedded with `_PARADOX_REDTEAM_DIRECTIVE` (`oracle_mindset_context.py:101-119`), and its output seam cards go through their own isolated pre-synthesis red-team gate (`redteam_challenge_by_lens`).

### Mindset 3 (`seam`)
- **What it is:** Takes the results from Mindset 1 and Mindset 2 (plus the deterministic seam feed) and runs a **second Invisible Seam pass** (`second_seam_pass` in `oracle_mindsets.py:417-470`) treating M1 and M2's cards themselves as the material—detecting whether lenses corroborate each other on a subject or expose a second-order contradiction (`m3_seam_state`: `corroborated`, `conflicted`, `single-lens`).
- **More Red Teaming:**
  1. Runs an LLM Adversarial Synthesis pass (`_SEAM_REDTEAM_DIRECTIVE`, `oracle_hunter.py:7096-7207`) over all candidate seams (with `corroborate_synth_seams` enforcing the no-invention rule by default).
  2. Runs `apply_mindset3_gates` (`oracle_mindsets.py:473-489`), which runs `second_seam_pass` followed by a fresh `redteam_challenge_by_lens` across all cards (revoking isolated confirmations if M1 and M2 contradicted each other on `assertion_b` or `expected`), and then `synthesize_seams` ranks everything into one unified list for the 5-gate wire verifier.

---

## 3. Where the Per-Language Adapter Drift Happened

 philosophies, impossible problems, paradoxes, iPhone-level framing, and MITRE are **language-agnostic**—they operate on claims vs. reality (`Assertion A` vs. `Assertion B` + a verifiable check).

However, in `/home/phantomcore/invisible-seam` and [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py) / [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py), the codebase started accumulating per-language extractors/adapters and per-language static predicates:
1. **`/home/phantomcore/invisible-seam/src/invisible_seam/extractors/`**:
   - `php_extractor.py`, `php_security_extractor.py` (untracked in `invisible-seam`, plus unstaged edits in `doc_extractor.py` and `code_matcher.py` on branch `feat/php-sql-extractor`)
   - `python_security_extractor.py` (commit `c9671f9`)
   - `js_extractor.py`, `go_extractor.py`, `rust_extractor.py`, `java_extractor.py`, `solidity_extractor.py`
2. **[`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py)**:
   - Hardcodes imports for `extract_php_claims`, `extract_js_claims`, `extract_solidity_claims`, `match_solidity_doc_claim` (lines 83–100, 421–448).
   - Hardcodes a 24-entry language/framework-specific `_CLAIM_TYPE_REFLEX` and `_SELF_CONFIRMING` table (`wp-nonce`, `py-sql-format`, `express-noauth`, etc., lines 151–272, 484–509).
3. **[`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py)**:
   - Hardcodes `claim_type == "py-sql-format"` with `"language": "python"` and imports `extract_python_security_claims` directly inside `_verify_static_ast` (lines 25–53, 99–153).

---

## 4. How the Vortex / Basilisk / CodeCrusher Confusion Happened

Inspected `/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/CLAUDE.md`, [`SYSTEM_VISION.md`](/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/SYSTEM_VISION.md), [`tests/test_file_headers.py`](/home/phantomcore/oracle/tests/test_file_headers.py), and git commits `731b6fe`, `2ec0a5a`, `98cf140`, and `94278cc`:

1. **Two Different Designs Were Conflated:**
   - **Vortex System (`/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM`):** Designed around three organs (`Basilisk` = deterministic NO-LLM per-chain/per-language detector packs; `CodeCrusher` = prove/judge/seal; `Vortex` = conductor where scope and bounty rules lived *outside* the hunter: *"Scope & bounty-rules filtering lives in VORTEX, not the hunter"*).
   - **Oracle (`/home/phantomcore/oracle`):** Your Three-Mindset system ([`ORACLE_DOCTRINE.md`](/home/phantomcore/oracle/ORACLE_DOCTRINE.md), [`docs/OWNER_MINDSET_SPEC.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_SPEC.md)), where:
     - **Mindset 1** = MITRE + Invisible Seam + **full bug bounty rules, assets, scope, and company info INSIDE the mindset** + Red Teaming.
     - **Mindset 2** = **ALL** philosophies, **ALL** paradoxes, **ALL** impossible problems in iPhone-level framing (never cherry-picked) + Invisible Seam + full bounty context + Red Teaming.
     - **Mindset 3** = **another Invisible Seam pass** over Mindset 1 + Mindset 2 results + **more Red Teaming** + synthesis.
2. **Why the Previous AI Built the Wrong Thing First:**
   - Commit `731b6fe` added [`tests/test_file_headers.py`](/home/phantomcore/oracle/tests/test_file_headers.py), enforcing `# LAYER: find|think|seal` and `# DEST: basilisk|codecrusher|vortex` headers at the top of every `oracle_*.py` file.
   - Instead of reading [`ORACLE_DOCTRINE.md`](/home/phantomcore/oracle/ORACLE_DOCTRINE.md), [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py), and [`oracle_corpus.py`](/home/phantomcore/oracle/oracle_corpus.py) first, the previous AI treated Oracle like Basilisk—a per-language static AST detector engine—and built:
     - [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) (commit `98cf140` / PR #12, tagged `# LAYER: seal / # DEST: basilisk`, hardcoding `py-sql-format` and `extract_python_security_claims`),
     - `/home/phantomcore/invisible-seam/src/invisible_seam/extractors/python_security_extractor.py` (commit `c9671f9` in `invisible-seam`),
     - `/home/phantomcore/invisible-seam/src/invisible_seam/extractors/php_security_extractor.py` (untracked on branch `feat/php-sql-extractor` in `invisible-seam`, plus uncommitted edits in `doc_extractor.py` and `code_matcher.py`).
3. **What the Uncommitted Diff in `/home/phantomcore/oracle` (`feat/three-mindset-spec`) Actually Contains:**
   - Inspected `git diff` across `oracle_mindsets.py`, `oracle_mindset_context.py`, `oracle_hunter.py`, `oracle_bulk_download.py`, and `tests/test_three_mindset_spec.py`:
     - [`oracle_mindsets.py`](/home/phantomcore/oracle/oracle_mindsets.py): Added `second_seam_pass()` and `apply_mindset3_gates()`, updated `_subject_key()` and `_challenge_one()` to use `source_a`/`source_b` and line numbers and to mark cross-lens `m3_seam_conflict` cards as `unreviewed` so isolated confirmations cannot bypass conflict resolution, and wired `second_seam_pass` into `synthesize_seams()`.
     - [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py): Added `update_program()`, made `inject_pending_seams([])` render an explicit `"Invisible Seam ran before this lens and produced no deterministic seam candidates"` block instead of silently omitting `PENDING SEAMS`, and added `Assertion A source`, `Behavior source`, `Check`, `Expected`, `Check output`, `Chain outputs`, `Chain preconditions`, and `Mindset-3 second seam` state to `_seam_block()`.
     - [`oracle_hunter.py`](/home/phantomcore/oracle/oracle_hunter.py): Preserved cross-mindset twin cards in `_merge_seams`, extracted downloaded policy/rules text into `prog["policy_text"]` and rebuilt both mindset contexts (`ctx.update_program`, `_mitre_ctx.update_program`), ran `seam_prepass` whenever any of `("mitre", "paradox", "seam")` is selected, and replaced the partial post-M3 challenge with `apply_mindset3_gates()` so all cards go through Mindset 3's second seam pass and fresh per-lens red-teaming.
     - [`oracle_bulk_download.py`](/home/phantomcore/oracle/oracle_bulk_download.py): Removed the length truncation cap on `_extract_section` / policy extraction so full program rules survive.

---

## 5. Work Log (Updated As Work Progresses)

- **2026-10-16 22:05 CDT:** Read core system files, git status, and recent commit history across `/home/phantomcore/oracle` and `/home/phantomcore/invisible-seam`. Created [`SYSTEM_WORKLOG.md`](/home/phantomcore/oracle/SYSTEM_WORKLOG.md) to track all findings and actions without overclaiming.
- **2026-10-16 22:10 CDT:** Inspected `/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/CLAUDE.md` and `SYSTEM_VISION.md`, [`tests/test_file_headers.py`](/home/phantomcore/oracle/tests/test_file_headers.py), commits `731b6fe` / `2ec0a5a` / `98cf140`, and the full uncommitted diff in `/home/phantomcore/oracle` (`feat/three-mindset-spec`). Documented how the Vortex/Basilisk/CodeCrusher architecture was conflated with Oracle's Three-Mindset architecture.
- **2026-10-16 22:37 CDT:** Ran `pytest tests/test_three_mindset_spec.py tests/test_oracle_corpus.py tests/test_mindset_completeness.py tests/test_mindset_profiles.py tests/test_mindsets.py -q` → **64 passed in 0.54s**. Inspected [`PLAN.md`](/home/phantomcore/oracle/PLAN.md), [`FINISH_PLAN.md`](/home/phantomcore/oracle/FINISH_PLAN.md), and `git log` in both `/home/phantomcore/oracle` and `/home/phantomcore/invisible-seam` to quantify the exact blast radius of the per-language / Vortex-fold drift.
- **2026-10-17 00:33 CDT:** Inspected [`oracle_llm.py`](/home/phantomcore/oracle/oracle_llm.py), [`oracle_backends.json`](/home/phantomcore/oracle/oracle_backends.json), [`oracle.py`](/home/phantomcore/oracle/oracle.py), [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py), [`tests/test_plan_gate_hooks.py`](/home/phantomcore/oracle/tests/test_plan_gate_hooks.py), and `/home/phantomcore/tools/omnicli/docs/TRANSITION_GATE_STATUS.md`. Measured exact built system prompt sizes via live Python probe:
  - **Mindset 1 (`mitre`, `full`):** `280,134 chars` (`~70,034 tokens`) — fits inside 128k cloud API lanes.
  - **Mindset 2 (`paradox`, `auto` with all 21 corpus docs verbatim):** `178,242 chars` (`~44,561 tokens`) — fits inside 128k cloud API lanes.
  - **Mindset 3 (`seam`, `auto`):** `39,148 chars` (`~9,787 tokens`) — fits inside both 128k cloud API lanes and 16k local models.
- **2026-10-17 01:19 CDT (Phase 1A Executed):** Cleaned PHP extractor drift out of `/home/phantomcore/invisible-seam` (reverted `doc_extractor.py` and `code_matcher.py`, removed `php_security_extractor.py` and `test_php_security_extractor.py`, switched back to `master`). Ran `pytest /home/phantomcore/invisible-seam/tests -q` → **71 passed in 4.77s**.
- **2026-10-17 01:21 CDT (Phase 1B Executed):** Refactored [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) and [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py) to be language-agnostic (`static_seam` verified via universal `scan_repository_seams`, removing hardcoded `py-sql-format` / `"language": "python"` / `extract_python_security_claims`). Ran `pytest tests/test_evidence.py tests/test_three_mindset_spec.py tests/test_file_headers.py -q` → **16 passed in 0.40s**.
- **2026-10-17 01:22 CDT (Phase 3 Executed):**
  - Ran `python3 tests/test_golden_hunt.py` → **`golden hunt: 25 CONFIRMED, 16 planted vulns expected, 7 benign controls, 67 chains (39 Critical) — RESULT: PASS`**.
  - Ran `python3 tests/run_all.py` → **All 8 layers PASS** (`card-structure smoke`, `injection templates`, `wordlist coverage`, `golden hunt`, `red-team verifier+chain`, `omnicli red-team gates`, `known-bug corpus 13/13`, `web3 contract layer`).
  - Completed full `pytest -q` suite across `/home/phantomcore/oracle` → **`959 passed, 22 skipped, 41 deselected, 1 warning, 32 subtests passed in 238.35s (0:03:58)`** (0 failures).
- **2026-10-17 01:54 CDT (Phase 2 Landed on `main`):** Committed the verified Three-Mindset pipeline and language-agnostic evidence spine (`bc68309`: `oracle_bulk_download.py`, `oracle_evidence.py`, `oracle_hunter.py`, `oracle_mindset_context.py`, `oracle_mindsets.py`, `tests/test_evidence.py`, `tests/test_three_mindset_spec.py`, `SYSTEM_WORKLOG.md`) and fast-forward merged `feat/three-mindset-spec` onto `main`.
- **2026-10-17 03:20 CDT (Independent Subagent Audit of `bc68309`):** Ran independent `research` subagent (`Independent Code Auditor`, `8bff6f62-7c67-479d-9a97-5b77f5dc91d6`) to audit `bc68309` and `/home/phantomcore/invisible-seam` without trusting prior claims. It verified the core pipeline flow and uncovered **6 real defects/gaps** that unit tests missed:
  1. **`second_seam_pass` false-conflict bug (`oracle_mindsets.py:448-458`):** `conflict = len(assertion_bs) > 1 or len(expected) > 1` compares exact normalized strings of free-text `assertion_b` across Mindset 1 and Mindset 2. In real hunts where M1 and M2 corroborate the same endpoint/check with different wording, `second_seam_pass` marks them `m3_seam_conflict = True` (`"conflicted"`), which then causes `_challenge_one()` (`oracle_mindsets.py:344-349`) to demote them to `"unreviewed"` and sort them behind single-lens findings.
  2. **`ttp_mode="auto"` default on `mindset="mitre"` (`oracle_mindset_context.py:171, 403-430, 952-958`, `oracle_hunter.py:6118, 7013`):** `OracleMindsetContext(mindset="mitre")` with default `ttp_mode="auto"` emits the compact (~33 TTP) block instead of all 344 TTPs, and L2 widen (`oracle_hunter.py:7013-7018`) passes `ttp_mode="full"` to `paradox` on cloud (stacking 344 TTPs onto the 320k corpus).
  3. **Premature policy cutoff & scope field caps (`oracle_bulk_download.py:178-186, 1430` & `oracle_mindset_context.py:521-534`):** `_extract_section` still stops at `stop_pattern` after 100 chars whenever a policy has normal subheadings (`Safe Harbor\n`, `Rewards\n`, `XSS\n`), and `_program_brief()` still caps `scope` (`500` chars), `targets` (`300` chars/line), and `out_of_scope` (`300` chars/line).
  4. **Subdirectory bug in `_verify_static_seam` (`oracle_evidence.py:56, 111`):** Scanning `file.parent` (`source_b`'s directory) misses `source_a` when `source_b` is in a subdirectory (`src/app.py`) and `source_a` is at repo root (`README.md`).
  5. **Remaining per-language extractors & ID-collision bug in `/home/phantomcore/invisible-seam` and `oracle_code_seam.py`:** `invisible-seam/src/invisible_seam/extractors/` still has 8 language-specific extractors (`python_security_extractor.py`, `php_extractor.py`, `js_extractor.py`, `go_extractor.py`, `java_extractor.py`, `rust_extractor.py`, `solidity_extractor.py`, `config_extractor_security.py`), `oracle_code_seam.py:417-426` runs them a second time after `doc_extractor.py:302-356`, and `doc_extractor.py:327-355` fails to increment `counter[0]` across extractors, causing `Claim.id` (`C001`) collisions that overwrite claims in `claim_map`.
  6. **Prompt rebuild ordering in `oracle_hunter.py:7551-7595` & standalone `cmd_analyze` (`oracle_hunter.py:5692-5747`):** `mindset_sys` is rebuilt at line 7592 *after* `_run_variant_sweep` (line 7551), and `mindset_sys_by_lens["mitre"]` is not refreshed at line 7594.
- **2026-10-17 04:11 CDT (Fixed All 6 Subagent-Discovered Defects):**
  1. [`oracle_mindsets.py`](/home/phantomcore/oracle/oracle_mindsets.py): Fixed `second_seam_pass()` to compare `_assertion_b_polarity` (`"violated"` vs `"enforced"`) and `_expected_polarity` (`status:<code/>` vs `"expected:denied"` vs `"expected:confirmed"`) instead of requiring character-identical prose strings across lenses.
  2. [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py): Made `mindset="mitre"` with default `ttp_mode="auto"` emit all 344 MITRE TTPs (`mode="full"`), and removed length truncation caps on flat `scope`, `targets`, and `out_of_scope` in `_program_brief()`.
  3. [`oracle_bulk_download.py`](/home/phantomcore/oracle/oracle_bulk_download.py): Stopped `_extract_section` from prematurely cutting off policy text at subheadings when `max_chars is None`, and removed `[:500]` cap on Intigriti scope `instruction`.
  4. [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) & [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py): Added `_resolve_scan_root()` using `os.path.commonpath` over `source_a` and `source_b` so subdirectory code files (`src/app.py`) still resolve root contract claims (`README.md`), and updated `test_evidence.py` to test universal doc-vs-code seams.
  5. `/home/phantomcore/invisible-seam` & [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py): Removed the 8 bolted-on per-language security extractors (`python_security_extractor.py`, `php_extractor.py`, `js_extractor.py`, `go_extractor.py`, `java_extractor.py`, `rust_extractor.py`, `solidity_extractor.py`, `config_extractor_security.py`), `_SELF_CONFIRMING_TYPES`, and `_CLAIM_TYPE_REFLEX`, eliminating the duplicate-extractor calls and `Claim.id` (`C001`) collisions. Verified `pytest` in `/home/phantomcore/invisible-seam` → **64 passed in 8.54s**.
  6. [`oracle_hunter.py`](/home/phantomcore/oracle/oracle_hunter.py) & [`tests/test_three_mindset_spec.py`](/home/phantomcore/oracle/tests/test_three_mindset_spec.py): Fixed L2 widen `ttp_mode` for `paradox`, wired `apply_mindset3_gates` into `cmd_analyze`, rebuilt `mindset_sys` and `mindset_sys_by_lens` (both `paradox` and `mitre`) before `_run_variant_sweep`, and added 4 regression tests in `tests/test_three_mindset_spec.py`.
  - Verified targeted Oracle suite (`pytest tests/test_three_mindset_spec.py tests/test_evidence.py tests/test_code_seam.py tests/test_hunt_code_lens.py tests/test_mindset_profiles.py tests/test_mindset_completeness.py tests/test_mindsets.py tests/test_hunt_mindset_wiring.py tests/test_analyze_synthesis.py tests/test_file_headers.py -q`) → **`89 passed in 17.80s`** (0 failures), and dispatched [`Independent Code Auditor`](conversation://8bff6f62-7c67-479d-9a97-5b77f5dc91d6) to re-verify all 6 fixes.
- **2026-10-17 04:21 CDT (Independent Subagent Re-Verification — 6/6 PASS):** [`Independent Code Auditor`](conversation://8bff6f62-7c67-479d-9a97-5b77f5dc91d6) re-audited all 6 fixed items directly against the source files in `/home/phantomcore/oracle` and `/home/phantomcore/invisible-seam` and returned **PASS on all 6 items**:
  1. `oracle_mindsets.py` (`_CHALLENGE_STATUS_RE`, `_assertion_b_polarity`, `_expected_polarity`, `second_seam_pass`) — **PASS**
  2. `oracle_mindset_context.py` (un-truncated flat `scope`/`targets`/`out_of_scope` & default 344 TTPs for `mindset="mitre"`) — **PASS**
  3. `oracle_bulk_download.py` (`_extract_section` preserving policy subheadings & un-truncated Intigriti `instruction`) — **PASS**
  4. `oracle_evidence.py` & `tests/test_evidence.py` (`_resolve_scan_root` via `os.path.commonpath` over `source_a`/`source_b` & universal doc-vs-code fixture) — **PASS**
  5. `/home/phantomcore/invisible-seam` & `oracle_code_seam.py` (all 8 per-language security extractors, `_SELF_CONFIRMING_TYPES`, `_CLAIM_TYPE_REFLEX`, duplicate calls, and `C001` ID-collision bugs removed) — **PASS**
  6. `oracle_hunter.py` & `tests/test_three_mindset_spec.py` (`cmd_analyze` `apply_mindset3_gates`, L2 widen `ttp_mode`, pre-M3 red-team coverage, downstream prompt rebuild order before `_run_variant_sweep`, and 4 new regression tests) — **PASS**
- **2026-10-17 05:13 CDT (Built Full Multi-Scenario Gauntlet & Caught `_merge_seams` Template Collision):**
  - Built [`tests/test_full_scenario_gauntlet.py`](/home/phantomcore/oracle/tests/test_full_scenario_gauntlet.py) to test the entire pipeline against **both** a multi-file "shit code" repository (README.md, `config.schema.json`, subdirectory Python modules, and Solidity smart contracts with missing NatSpec guards) **and** the live HTTP vulnerable testbed (`vuln_testbed_full.py`) across 6 scenarios (Invisible Seam + Evidence Spine, M1+M2 Full Prompt/Scope Wall, Cross-Mindset Corroboration with different phrasing, Cross-Mindset Conflict Resolution, Red-Team & 5-Gate Wire Rejection of noise/OOS/benign routes, and M3 No-Invention + Compound Exploit Chaining).
  - Running the gauntlet through `oh._merge_seams` exposed a real bug in [`oracle_hunter.py:4983`](/home/phantomcore/oracle/oracle_hunter.py#L4983): `_merge_seams` was deduplicating deterministic template cards by `(lens_key, _probe_key(s))` without `claim_type`, causing `_t_deathless` to swallow `_t_t1190_artifact` on `/.env` and drop its `expected` artifact markers. Fixed `url_key` in `_merge_seams` to include `claim_type`.
- **2026-10-17 06:12 CDT (Pushed Both Repositories to GitHub):**
  - Pushed `/home/phantomcore/invisible-seam` `master` (`8eb7607..d2c6008`) to `https://github.com/Alexander-Sorrell-IT/invisible-seam.git`.
  - Switched active `gh` account to `code-hunter-extreme` and pushed `/home/phantomcore/oracle` `main` (`94278cc..a6fa747`) to `https://github.com/code-hunter-extreme/oracle.git`.
- **2026-10-17 15:20 CDT (Cross-Audit Verification & `test_mistag_regression.py` Universal Mapper Lock):**
  - A second independent AI audited `a6fa747` (`oracle`) and `d2c6008` (`invisible-seam`), confirmed the Three-Mindset + Invisible Seam architecture and removal of the Basilisk-style per-language detectors, and updated [`tests/test_mistag_regression.py`](/home/phantomcore/oracle/tests/test_mistag_regression.py) so `test_code_seam_tags_corrected` and `test_no_code_seam_carries_t1078` test [`_map_seam_to_security_reflex`](/home/phantomcore/oracle/oracle_code_seam.py#L180-L244) via universal claim-vs-reality behavior rather than the deleted `_CLAIM_TYPE_REFLEX` table.
  - Added the remaining two branches (`config-fixable` and `default-generic`) to `_CODE_CASES` in [`tests/test_mistag_regression.py`](/home/phantomcore/oracle/tests/test_mistag_regression.py#L37-L92) so all 6 branches of `_map_seam_to_security_reflex` are locked.
- **2026-10-17 19:26 CDT (Added Scenario G: PoC Teardown, Workspace Persistence & Report Generation to Gauntlet):**
  - Expanded [`tests/test_full_scenario_gauntlet.py`](/home/phantomcore/oracle/tests/test_full_scenario_gauntlet.py) with **Scenario G** (`teardown_poc`, `ProgramWorkspace.save_program_json`, `save_program_brief`, `save_finding`, `_format_chain_report`, `save_report`) and explicit assertions that `M1_ADMIN`, `M2_ADMIN`, and `M3_SYNTH` each independently confirm on the wire (`("mitre", "/api/v1/admin/metrics")`, `("paradox", "/api/v1/admin/metrics")`, `("seam", "/api/v1/admin/metrics")`).
  - Adding `teardown_poc` caught that the synthetic `M1_ADMIN`/`M2_ADMIN`/`M3_SYNTH` cards in the gauntlet needed `assertion_a_source`, allow-listed `curl -i -s` flags, and `parse_expected`-compatible `expected` strings (`status 200, body contains "..."`) so the M1/M2/M3 cards themselves pass all 7 deterministic gates and 3x replay teardown.
  - Ran `python3 tests/run_all.py` → **All 9 layers PASS**.

---

## 6. Execution Plan to Finish Oracle (Before Any Future Fold Into Vortex)

### Phase 1: Clean Up the Per-Language / Basilisk Drift
1. **`/home/phantomcore/invisible-seam`:**
   - Remove the untracked `src/invisible_seam/extractors/php_security_extractor.py` and `tests/extractors/test_php_security_extractor.py`.
   - Revert the uncommitted `php-sql-format` edits in `src/invisible_seam/extractors/doc_extractor.py` and `src/invisible_seam/matchers/code_matcher.py`, and switch `/home/phantomcore/invisible-seam` back to `master`.
2. **`/home/phantomcore/oracle` ([`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) & [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py)):**
   - Make [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) language-agnostic: remove the hardcoded `claim_type == "py-sql-format"` / `"language": "python"` / `extract_python_security_claims` coupling so evidence normalization works universally on any seam card (`Assertion A` vs. `Assertion B` + check spec: `http`, `command`, or `static_seam` anchored to `source_a`/`source_b` existence and line).
   - Update [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py) to test universal claim-vs-reality evidence normalization rather than a single Python SQL extractor predicate.

### Phase 2: Verify & Lock In the Three-Mindset Wiring (`feat/three-mindset-spec`)
1. Verify all 6 owner-spec clauses ([`docs/OWNER_MINDSET_SPEC.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_SPEC.md)):
   - **S1:** Mindset 1 = full 344 MITRE TTPs + Invisible Seam + full bug bounty rules, assets, scope, and company info (including downloaded policy text via `ctx.update_program`).
   - **S2:** Mindset 2 = ALL 21 philosophies, paradoxes, and impossible problems in iPhone-level framing (never cherry-picked; `max_chars=320_000`, fails loud if anything cannot fit) + Invisible Seam + full bounty context.
   - **S3:** Mindset 1 and Mindset 2 each go through their own isolated red-team gate (`redteam_challenge_by_lens`) before synthesis, with cross-mindset twin cards preserved in `_merge_seams`.
   - **S4:** Mindset 1 and Mindset 2 outputs go to Mindset 3, which runs a second Invisible Seam pass (`second_seam_pass`), LLM adversarial synthesis (`_SEAM_REDTEAM_DIRECTIVE` over all candidates, no-invention enforced), and fresh per-lens red-teaming (`apply_mindset3_gates`) + ranking (`synthesize_seams`).
   - **S5 & S6:** Cloud APIs (`128k` context in `oracle_backends.json`) are primary generators for Mindset 1 (`~70k` tokens) and Mindset 2 (`~44.5k` tokens); local (`16k` context) runs as the post-synthesis second-vote verifier (`build_second_vote_packet` + `collaborate`).
2. Run the full Oracle test suite (`pytest` + `python3 tests/run_all.py`) and verify 0 regressions.
3. Commit the verified Three-Mindset changes on `feat/three-mindset-spec` and merge cleanly into `main`.

### Phase 3: End-to-End Local Proving Run (Golden Hunt + Testbed)
1. Run `python3 tests/test_golden_hunt.py` and the full 8-layer validation (`python3 tests/run_all.py`) against the local vulnerable testbed (`vuln_testbed_full.py`) to confirm:
   - All 16 planted vulnerabilities are confirmed on the wire by the 5-gate verifier.
   - All 7 benign controls are rejected (0 false positives).
   - Mindset 1, Mindset 2, and Mindset 3 synthesis + compound exploit chaining (`chain_seams`) + submission report generation run end-to-end.
2. Record the exact output and metrics in [`SYSTEM_WORKLOG.md`](/home/phantomcore/oracle/SYSTEM_WORKLOG.md).

### Phase 4: Live Bug Bounty Hunting (Make Money With Oracle First)
1. Run the intake & verification pipeline (`oracle-hunter prescan` → `oracle-hunter scan -N` → `oracle-hunter queue`) to select a verified, high-payout, fast-triage in-scope program.
2. Run `oracle-hunter hunt <program>` with the full Three-Mindset + Red-Team + 5-Gate Wire Verifier pipeline to produce a verified, submission-ready bug report.
3. *(Future only, after Oracle is paying out)*: Cut/export Oracle's proven modules into `VORTEX_SYSTEM`—never the reverse.


## 2026-10-19/20 — Production chain live gate + closeout (appended 2026-10-20)

- Live gate: Scan4Me sync (2,027 programs / 48,699 assets, Bugcrowd payout SQL
  crash fixed live) → prescan 24 → scan 10/24 verified → top-3 workspaces →
  queue schedule → 1 controlled queued hunt (Here Technologies). Recon OK
  (12 live hosts, ~37k crawl paths); hunt FAILED at engine analysis (lane
  starvation). Evidence retained in `reports/live_gate_20261019/`.
- Wired & hardened: scan `--download` workspaces, `queue --execute`
  (waves/resume/failure-isolation), analyze/seams/verify workspace resume,
  severity ladder law (one-step compounding, fail-closed), multi-path
  download verification (CDP authoritative + corroboration + `via`), scope
  always-refresh on download, engine lane health (breaker 600s, total
  budgets, Groq 8000-token cap), CDP tab PUT fix (was GET 405).
- Verified: Oracle pytest 1148 passed (2026-10-20 outside-sandbox run), `run_all.py` 10/10 layers, Scan4Me
  121 passed. Commits pushed: oracle `346373f` → `ca30ed3` → `25012a6` →
  `ffa9dcb`; scan4me `a77984e`. Full record: `IMPROVEMENTS_REPORT_2026-10-19.md`.
- Errata for §2 above (append-only file): its `oracle_brain.py` line ref is
  stale (logic now at `oracle_hunter._mindset_context`, oracle_hunter:3959ff).


## 2026-10-20/21 — E0 repair block: fake-verdict, lane-stall, starve-on-start (appended 2026-10-21)

Session: independent adversarial audit of ~30 documented claims (3 parallel
line-anchored reviewers: verify/gates/teardown/persistence · orchestration/
router/scope/downloads · deterministic/harvest/mindset feed), then the E0
fix block from the receipts.

- **E0-1 `fix` commit `1c199d6`** — shared `parse_verdict` (oracle_foundation):
  anchored first-token verdict grammar; `_run_variant_sweep`'s inline
  `"CONFIRMED" in v_upper` gate converted (the substring-CONFIRMED fake class
  from VERDICT_TAIL_SCOPE: `UNCONFIRMED`/`POSSIBLY CONFIRMED IF…` false-
  confirming sweep hits). Fail-first red captured pre-patch (2 classes
  CONFIRMED on unpatched code). Honesty receipts in same commit: STATUS.md
  + docs/VERDICT_TAIL_SCOPE.md now match code (previously two files claimed
  parse_verdict "landed" when it had not).
- **E0-2 `fix` commit `04f49b0`** — `oracle_llm._run_with_deadline`: the
  OmniCLI lane's long-acknowledged ignored-timeout defect is dead; a
  concrete deadline bounds `run_orchestration` in a daemon worker and
  overruns raise BackendError so lane breaker/health engage. Null keeps
  legacy free-running; `<=0` refuses dispatch. Fail-first: slow-swarm +
  timeout-0 RED pre-patch (unbounded 5s stalls), green post. Adjacent
  falsy-`or`-timeout pattern in CliBackend/Ollama pinned for a follow-up.
- **E0-3 `feat` commit `57381b2`** — `lane_preflight`/`enforce_lane_preflight`
  (oracle_llm) + cmd_hunt wiring: the 2026-10-19 death mode (hunt starting
  on a dead reflex fleet) now refuses loud before spend; floor cfg
  `preflight.min_alive_lanes` (ships 2); `--no-cloud` = declared local-only
  bypass. No network probes by design (preflight cannot hang a hunt).
  Verifier confirmed the gate is crossed on EVERY hunt path (CLI, queue
  --execute, scan4me) — no silent bypass.
- **Verification:** independent adversarial verifier per fix — E0-1 SHIP
  6/6 PASS; E0-2+E0-3 SHIP (deadlock/race check, contract completeness,
  key-parity incl. `_PREFERRED_LOCAL_MODEL`, wiring/env, concealment probe,
  test-meaningfulness). Full suite with E0-1: **1166 passed + 32 subtests**
  (+18 tests). Bandit parity held per file (no new findings). Two verifier-
  named design limits logged, NOT hidden: credential-dead lanes count as
  living (preflight is breaker-ledger-only by design); user-pinned 1-lane
  route refuses at floor 2 (sole-lane floor exemption recommended).
- **Logged, out of E0 scope:** pre-existing 16-lane concurrent env-merge
  race (OmniCLI env swap vs sibling lanes; bounded consequence), and
  `oracle_bounty.py` legacy bypass of the router (raw ollama subprocess).
- **Open for E0 closeout:** Databricks HTTP 400 diagnose-or-demote; ~20
  non-self-observing templates still alpha-sort `[:25]` (bury risk);
  0600 fuzz-cache perms; standalone confirm_form_replay GET leg scope
  gating; final full-suite closeout. Then E1 = target pick + policy fetch
  + first live end-to-end hunt (the proof owed).


## 2026-10-21 — E0 closeout: all five items + follow-ups landed (appended 2026-10-21)

- **Databricks 400 — diagnosed, lane HEALTHY, no demote:** live probes show
  `ORACLE_KEYS.env`'s token belongs to a different org (`403 Invalid access
  to Org`), while the repo `.env` token completes HTTP 200 on the configured
  `ai-gateway` base_url AND through the real `OpenAICompatBackend.complete`
  (content "ok") — loader precedence `ORACLE_KEYS.env < repo .env`
  (oracle_hunter.py:234-265) already routes the working token into hunts.
  The old ledger entry ("400 on all models") predates the working token:
  documented stale, corrected in STATUS same commit.
- **Falsy-zero timeout law (aef67d5):** verifier follow-up shipped —
  `_timeout_or` (oracle_llm) replaces `timeout or N` at all four remaining
  backend sites (OpenRouter :402, NVIDIA :484, CliBackend :637, openai-compat
  :775). Behavioral RED pre-patch: CliBackend succeeded at timeout=0.0 after
  burning 5.0s. Sole-lane floor exemption landed in the same commit (RED:
  pinned 1-lane route refused at fleet floor 2; now mirrors the breaker's
  sole-lane law).
- **Cap-cannot-bury law (5c36e11):** `_live_url_map`/`_cap_rank` shared law in
  oracle_seam_templates; `_t_self_observing` refactored onto it (byte-equal),
  `_t_deathless` converts (the one mixed-observation template left alpha-
  sorting), `_t_beautiful_liar` cross-source dedupe + UnboundLocalError crash
  fixed (RED receipts: order-bury, duplicate card, crash at :906). Uniform-
  evidence templates declared NO-CHANGE with reasons (no invented
  preferences). Verifier: writer-source receipt `fuzzed_paths.txt` emits
  absolute-only (oracle_deeprecon.py:594-608) — raw-key parity holds in
  practice. 33 passed across template/sweep/golden families.
- **Harvest hygiene legs (da7a10a):** id_fuzz.json cache now 0600 fd+chmod
  (RED: perms 664); `confirm_form_replay` standalone GET leg consults the
  scope gate — fail-closed on gate error, gate=None stays the declared
  ungated regime (legacy mutation-disabled test contract preserved).
  RED receipt: gate-deny let the GET fly its fetch. 15 passed across
  wash/csrf/chains suites.
- **Verification:** independent adversarial verifier (ses_ea2cf71c) on all
  three closeout commits: **3× SHIP** — checks A1-A4, B1-B4, C1-C4 PASS.
  Four surviving holes DECLARED, none hidden: (1) relative fuzzed lines
  (hand-written only; real writer emits absolute) → raw-keyed cards;
  (2) `_live_url_map` fuzzed branch lacks `_is_static` while `_t_deathless`'s
  build has it (static self-observability candidates nuance); (3) legacy
  0644 cache stays loose during the truncated-write window (
  `os.open` mode applies at creation; `os.chmod` follows — cosmetic race);
  (4) `--no-cloud` listed as preflight escape even with no local lane
  (honest fallback = complete()'s own exhaustion error).
- **Final suite (2026-10-21):** **1184 passed + 32 subtests, 22 env-skips,
  0 failures, 274.95s** — 1148 → 1184 across the session; zero regressions
  through all seven commits. Bandit parity held per file; mypy region-clean
  on every touched range; black/flake8 clean on authored lines.
- **E0: CLOSED.** Next owed proof: E1 — target pick (user, 2 min) + policy
  fetch + first complete live end-to-end hunt; the money gate per the
  MASTER_PLAN is ≥1 submitted finding with triage response.

## 2026-10-21 — E1 first live hunt: tinder (COMPLETE — honest zero, receipts)

- **Launch:** `hunt tinder --auto` (background sh_15da13d69001S0clqgoYkakyyN),
  NO_PROXY=127.0.0.1,localhost; preflight 13/13 reflex lanes living, floor 2.
- **Compliance before launch:** x-hackerone attribution header verified
  functioning in-flight (checks carry `-H "x-hackerone: <user>"`); policy +
  structured scope receipts committed (3f6a6aa).
- **Outcome:** `Verify complete — 0/1100 confirmed, 0 inconclusive` —
  funnel mined=146 followups=954 attempted=1100 det_reject=1100 postgate=0
  final=0; `Variant sweep: no confirmed phase-1 findings` (sweep gear
  skipped BY the zero, not around it); report written (5547 lines, report
  gitignored by design) + teardown; banner: `SYSTEM FAILURE: 0 confirmed,
  modes unpassed: recalled` — the pipeline's law, not a sugarcoat.
- **Wire truth:** 864/892 status-watched checks = 502 Bad Gateway from
  tinder's nginx edge (unauth regime against a session-gated data plane);
  18x404, 8x403. Zero real exceptions in runner code (31 grep hits were
  card TEXT describing hypothetical SQLi).
- **Self-audit receipts the flag-challenge demanded:** (1) dual-engine ran
  (both lenses submitted + clean, 0 minted), (2) all mined = ONE template
  class, (3) MITRE:"?" on every card front, (4) Engine B demoted by design,
  (5) funnel balanced (det_reject=postgate+final harmonics). The hunt did
  not paper a zero as success.
- **Follow-ups opened (E1.1, now unblocked by real funnel data):**
  det-reject rule IDs (A/S/B2 tagging in deterministic returns),
  auth-required premise filter at mint (kill 502-class predictions
  pre-wire), followup over-mint cap, LLM-lens card-yield audit (0/2).
  E2 (session-authed producer) named the real tinder path: user-provisioned
  2 accounts via --prompt-login/-auth-a; mass creation stays banned.
- **Post-run rectifications (2026-10-21, user-challenge driven):**
  (1) The analysis tier never swallowed the inventory — recon held 580 JS
  endpoints/86 subs/27 live hosts, but lens injection took 20 hosts + 30
  endpoints (distill caps, oracle_hunter.py:_distill_endpoints max_items=60
  + host cap; all 146 mined cards trace to that ~5% slice).
  (2) Mint monoculture: 146/146 seeded from ONE template family
  (router-spelling/auth); 954 followups expanded the same premise 6.5x.
  (3) Log-line ambiguity fixed by contract: "MITRE mapping: 12 techniques"
  is a SELECTION count (oracle_hunter.py:1834 prints len(selected)) — the
  per-tactic top slice of the local TTP corpus scored for web-relevance
  (:1800-1834), NOT the matrix; ATT&CK Enterprise is ~14 tactics / ~200
  techniques / ~424 sub-techniques. E1.1 receipt law: print "12 of N
  corpus techniques" and log selected T-code IDs per run.
- **Money gate: NOT met.** Submitted findings: 0. Triage: n/a. Next live
  spend on tinder only exits with the account regime; else roll to a
  fresh-program target where unauth machinery can bite (clear, #1 on the
  STATUS shortlist: launched 2026-03-02).

- **E1.1 fix list upgraded from audit to fix-now (2026-10-21, user
  challenge "mindsets misused" — accepted):** Carry-through failure
  named: the philosophy layer contributed ZERO artifact content in the
  tinder run — (a) paradox (320k corpus + impossible-problem framing,
  oracle_mindsets.py:30) is prompt-context only, never a card producer;
  (b) "iPhone" is a card-shape gate which gated cards that never minted;
  (c) MITRE techniques carry still not onto card fronts ("MITRE: ?"
  x1100); (d) SUBTLE MASK: paradox lens returned an explicit
  TARGET CLEAN verdict from the 5%-slice/no-session regime and
  lens_outcome() (oracle_hunter.py:4584) credits explicit verdicts as
  "clean" — a structurally unearned clean. Fix-now items (all red-first):
  1. qualified-clean law — TARGET CLEAN counts only with regime receipts
     (200-served endpoints + logged auth regime), else downgrades and
     Engine B second-vote un-demotes;
  2. carry-through tags — lens/L-seed/T-code onto card faces;
  3. mint-cap + auth-feasibility filter + slice-cap configs from prior
     block; 4. shape-gate observability line on zero-mint runs.
  No live credits until these land.

# System Audit & Living Work Log

**Started:** 2026-10-16  
**Rule:** Only record what was actually inspected, executed, or changed. Do not overclaim.

---

## 1. Initial Read of the System (2026-10-16)

### Files Inspected
- [`ORACLE_DOCTRINE.md`](/home/phantomcore/oracle/ORACLE_DOCTRINE.md)
- [`docs/OWNER_MINDSET_SPEC.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_SPEC.md)
- [`docs/OWNER_MINDSET_FINISH_PLAN.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_FINISH_PLAN.md)
- [`docs/HOW_THE_SYSTEM_WORKS.md`](/home/phantomcore/oracle/docs/HOW_THE_SYSTEM_WORKS.md)
- [`docs/WORKLOG.md`](/home/phantomcore/oracle/docs/WORKLOG.md)
- [`ARCHITECTURE.md`](/home/phantomcore/oracle/ARCHITECTURE.md)
- [`oracle_mindsets.py`](/home/phantomcore/oracle/oracle_mindsets.py)
- [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py)
- [`oracle_corpus.py`](/home/phantomcore/oracle/oracle_corpus.py)
- [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py)
- [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py)
- [`oracle_seam_templates.py`](/home/phantomcore/oracle/oracle_seam_templates.py) (lines 1–250)
- [`oracle_hunter.py`](/home/phantomcore/oracle/oracle_hunter.py) (lines 600–1200, 5900–7450)
- [`tests/test_three_mindset_spec.py`](/home/phantomcore/oracle/tests/test_three_mindset_spec.py)
- `/home/phantomcore/invisible-seam/src/invisible_seam/extractors/` (`doc_extractor.py`, `python_security_extractor.py`, `php_security_extractor.py`)
- `/home/phantomcore/invisible-seam/src/invisible_seam/matchers/code_matcher.py`

---

## 2. How the Three-Mindset Architecture Actually Works in Code Right Now

### Mindset 1 (`mitre`)
- **What it is:** Full-weight MITRE ATT&CK lens (`oracle_ttps_fused.json`, 344 unique records) combined with the Invisible Seam candidate feed (`inject_pending_seams`) and full bug bounty context (`_program_brief`: in-scope assets, out-of-scope rules, policy/rules text, company info, downloaded assets).
- **Red Teaming:** Embedded with `_MITRE_REDTEAM_DIRECTIVE` during generation (`oracle_mindset_context.py:80-99`), and its output seam cards go through their own isolated pre-synthesis red-team gate (`redteam_challenge_by_lens` in `oracle_hunter.py:7056-7072` and `oracle_mindsets.py:388-410`).

### Mindset 2 (`paradox`)
- **What it is:** **ALL** philosophies, **ALL** paradoxes, and **ALL** impossible problems in iPhone-level framing (`ORACLE_SYSTEM_PROMPT.md` + `ORACLE_FRAMEWORK.md` + all 21 registered canonical documents in `corpus/` via `oracle_corpus.source_context(..., max_chars=320_000)`).
- **No Cherry-Pick Enforcement:** `oracle_corpus.py:256-298` validates that every file in `corpus/` is registered (`validate_registry()`) and loads all 21 documents verbatim; if `max_chars` cannot fit all documents, it raises `ValueError` naming the dropped documents rather than truncating or subsetting.
- **Combined with Invisible Seam + Bounty Context:** Receives the same `_program_brief()` and `inject_pending_seams()` feed as Mindset 1 (`oracle_hunter.py:6545-6572`).
- **Red Teaming:** Embedded with `_PARADOX_REDTEAM_DIRECTIVE` (`oracle_mindset_context.py:101-119`), and its output seam cards go through their own isolated pre-synthesis red-team gate (`redteam_challenge_by_lens`).

### Mindset 3 (`seam`)
- **What it is:** Takes the results from Mindset 1 and Mindset 2 (plus the deterministic seam feed) and runs a **second Invisible Seam pass** (`second_seam_pass` in `oracle_mindsets.py:417-470`) treating M1 and M2's cards themselves as the material—detecting whether lenses corroborate each other on a subject or expose a second-order contradiction (`m3_seam_state`: `corroborated`, `conflicted`, `single-lens`).
- **More Red Teaming:**
  1. Runs an LLM Adversarial Synthesis pass (`_SEAM_REDTEAM_DIRECTIVE`, `oracle_hunter.py:7096-7207`) over all candidate seams (with `corroborate_synth_seams` enforcing the no-invention rule by default).
  2. Runs `apply_mindset3_gates` (`oracle_mindsets.py:473-489`), which runs `second_seam_pass` followed by a fresh `redteam_challenge_by_lens` across all cards (revoking isolated confirmations if M1 and M2 contradicted each other on `assertion_b` or `expected`), and then `synthesize_seams` ranks everything into one unified list for the 5-gate wire verifier.

---

## 3. Where the Per-Language Adapter Drift Happened

 philosophies, impossible problems, paradoxes, iPhone-level framing, and MITRE are **language-agnostic**—they operate on claims vs. reality (`Assertion A` vs. `Assertion B` + a verifiable check).

However, in `/home/phantomcore/invisible-seam` and [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py) / [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py), the codebase started accumulating per-language extractors/adapters and per-language static predicates:
1. **`/home/phantomcore/invisible-seam/src/invisible_seam/extractors/`**:
   - `php_extractor.py`, `php_security_extractor.py` (untracked in `invisible-seam`, plus unstaged edits in `doc_extractor.py` and `code_matcher.py` on branch `feat/php-sql-extractor`)
   - `python_security_extractor.py` (commit `c9671f9`)
   - `js_extractor.py`, `go_extractor.py`, `rust_extractor.py`, `java_extractor.py`, `solidity_extractor.py`
2. **[`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py)**:
   - Hardcodes imports for `extract_php_claims`, `extract_js_claims`, `extract_solidity_claims`, `match_solidity_doc_claim` (lines 83–100, 421–448).
   - Hardcodes a 24-entry language/framework-specific `_CLAIM_TYPE_REFLEX` and `_SELF_CONFIRMING` table (`wp-nonce`, `py-sql-format`, `express-noauth`, etc., lines 151–272, 484–509).
3. **[`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py)**:
   - Hardcodes `claim_type == "py-sql-format"` with `"language": "python"` and imports `extract_python_security_claims` directly inside `_verify_static_ast` (lines 25–53, 99–153).

---

## 4. How the Vortex / Basilisk / CodeCrusher Confusion Happened

Inspected `/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/CLAUDE.md`, [`SYSTEM_VISION.md`](/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/SYSTEM_VISION.md), [`tests/test_file_headers.py`](/home/phantomcore/oracle/tests/test_file_headers.py), and git commits `731b6fe`, `2ec0a5a`, `98cf140`, and `94278cc`:

1. **Two Different Designs Were Conflated:**
   - **Vortex System (`/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM`):** Designed around three organs (`Basilisk` = deterministic NO-LLM per-chain/per-language detector packs; `CodeCrusher` = prove/judge/seal; `Vortex` = conductor where scope and bounty rules lived *outside* the hunter: *"Scope & bounty-rules filtering lives in VORTEX, not the hunter"*).
   - **Oracle (`/home/phantomcore/oracle`):** Your Three-Mindset system ([`ORACLE_DOCTRINE.md`](/home/phantomcore/oracle/ORACLE_DOCTRINE.md), [`docs/OWNER_MINDSET_SPEC.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_SPEC.md)), where:
     - **Mindset 1** = MITRE + Invisible Seam + **full bug bounty rules, assets, scope, and company info INSIDE the mindset** + Red Teaming.
     - **Mindset 2** = **ALL** philosophies, **ALL** paradoxes, **ALL** impossible problems in iPhone-level framing (never cherry-picked) + Invisible Seam + full bounty context + Red Teaming.
     - **Mindset 3** = **another Invisible Seam pass** over Mindset 1 + Mindset 2 results + **more Red Teaming** + synthesis.
2. **Why the Previous AI Built the Wrong Thing First:**
   - Commit `731b6fe` added [`tests/test_file_headers.py`](/home/phantomcore/oracle/tests/test_file_headers.py), enforcing `# LAYER: find|think|seal` and `# DEST: basilisk|codecrusher|vortex` headers at the top of every `oracle_*.py` file.
   - Instead of reading [`ORACLE_DOCTRINE.md`](/home/phantomcore/oracle/ORACLE_DOCTRINE.md), [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py), and [`oracle_corpus.py`](/home/phantomcore/oracle/oracle_corpus.py) first, the previous AI treated Oracle like Basilisk—a per-language static AST detector engine—and built:
     - [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) (commit `98cf140` / PR #12, tagged `# LAYER: seal / # DEST: basilisk`, hardcoding `py-sql-format` and `extract_python_security_claims`),
     - `/home/phantomcore/invisible-seam/src/invisible_seam/extractors/python_security_extractor.py` (commit `c9671f9` in `invisible-seam`),
     - `/home/phantomcore/invisible-seam/src/invisible_seam/extractors/php_security_extractor.py` (untracked on branch `feat/php-sql-extractor` in `invisible-seam`, plus uncommitted edits in `doc_extractor.py` and `code_matcher.py`).
3. **What the Uncommitted Diff in `/home/phantomcore/oracle` (`feat/three-mindset-spec`) Actually Contains:**
   - Inspected `git diff` across `oracle_mindsets.py`, `oracle_mindset_context.py`, `oracle_hunter.py`, `oracle_bulk_download.py`, and `tests/test_three_mindset_spec.py`:
     - [`oracle_mindsets.py`](/home/phantomcore/oracle/oracle_mindsets.py): Added `second_seam_pass()` and `apply_mindset3_gates()`, updated `_subject_key()` and `_challenge_one()` to use `source_a`/`source_b` and line numbers and to mark cross-lens `m3_seam_conflict` cards as `unreviewed` so isolated confirmations cannot bypass conflict resolution, and wired `second_seam_pass` into `synthesize_seams()`.
     - [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py): Added `update_program()`, made `inject_pending_seams([])` render an explicit `"Invisible Seam ran before this lens and produced no deterministic seam candidates"` block instead of silently omitting `PENDING SEAMS`, and added `Assertion A source`, `Behavior source`, `Check`, `Expected`, `Check output`, `Chain outputs`, `Chain preconditions`, and `Mindset-3 second seam` state to `_seam_block()`.
     - [`oracle_hunter.py`](/home/phantomcore/oracle/oracle_hunter.py): Preserved cross-mindset twin cards in `_merge_seams`, extracted downloaded policy/rules text into `prog["policy_text"]` and rebuilt both mindset contexts (`ctx.update_program`, `_mitre_ctx.update_program`), ran `seam_prepass` whenever any of `("mitre", "paradox", "seam")` is selected, and replaced the partial post-M3 challenge with `apply_mindset3_gates()` so all cards go through Mindset 3's second seam pass and fresh per-lens red-teaming.
     - [`oracle_bulk_download.py`](/home/phantomcore/oracle/oracle_bulk_download.py): Removed the length truncation cap on `_extract_section` / policy extraction so full program rules survive.

---

## 5. Work Log (Updated As Work Progresses)

- **2026-10-16 22:05 CDT:** Read core system files, git status, and recent commit history across `/home/phantomcore/oracle` and `/home/phantomcore/invisible-seam`. Created [`SYSTEM_WORKLOG.md`](/home/phantomcore/oracle/SYSTEM_WORKLOG.md) to track all findings and actions without overclaiming.
- **2026-10-16 22:10 CDT:** Inspected `/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/CLAUDE.md` and `SYSTEM_VISION.md`, [`tests/test_file_headers.py`](/home/phantomcore/oracle/tests/test_file_headers.py), commits `731b6fe` / `2ec0a5a` / `98cf140`, and the full uncommitted diff in `/home/phantomcore/oracle` (`feat/three-mindset-spec`). Documented how the Vortex/Basilisk/CodeCrusher architecture was conflated with Oracle's Three-Mindset architecture.
- **2026-10-16 22:37 CDT:** Ran `pytest tests/test_three_mindset_spec.py tests/test_oracle_corpus.py tests/test_mindset_completeness.py tests/test_mindset_profiles.py tests/test_mindsets.py -q` → **64 passed in 0.54s**. Inspected [`PLAN.md`](/home/phantomcore/oracle/PLAN.md), [`FINISH_PLAN.md`](/home/phantomcore/oracle/FINISH_PLAN.md), and `git log` in both `/home/phantomcore/oracle` and `/home/phantomcore/invisible-seam` to quantify the exact blast radius of the per-language / Vortex-fold drift.
- **2026-10-17 00:33 CDT:** Inspected [`oracle_llm.py`](/home/phantomcore/oracle/oracle_llm.py), [`oracle_backends.json`](/home/phantomcore/oracle/oracle_backends.json), [`oracle.py`](/home/phantomcore/oracle/oracle.py), [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py), [`tests/test_plan_gate_hooks.py`](/home/phantomcore/oracle/tests/test_plan_gate_hooks.py), and `/home/phantomcore/tools/omnicli/docs/TRANSITION_GATE_STATUS.md`. Measured exact built system prompt sizes via live Python probe:
  - **Mindset 1 (`mitre`, `full`):** `280,134 chars` (`~70,034 tokens`) — fits inside 128k cloud API lanes.
  - **Mindset 2 (`paradox`, `auto` with all 21 corpus docs verbatim):** `178,242 chars` (`~44,561 tokens`) — fits inside 128k cloud API lanes.
  - **Mindset 3 (`seam`, `auto`):** `39,148 chars` (`~9,787 tokens`) — fits inside both 128k cloud API lanes and 16k local models.
- **2026-10-17 01:19 CDT (Phase 1A Executed):** Cleaned PHP extractor drift out of `/home/phantomcore/invisible-seam` (reverted `doc_extractor.py` and `code_matcher.py`, removed `php_security_extractor.py` and `test_php_security_extractor.py`, switched back to `master`). Ran `pytest /home/phantomcore/invisible-seam/tests -q` → **71 passed in 4.77s**.
- **2026-10-17 01:21 CDT (Phase 1B Executed):** Refactored [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) and [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py) to be language-agnostic (`static_seam` verified via universal `scan_repository_seams`, removing hardcoded `py-sql-format` / `"language": "python"` / `extract_python_security_claims`). Ran `pytest tests/test_evidence.py tests/test_three_mindset_spec.py tests/test_file_headers.py -q` → **16 passed in 0.40s**.
- **2026-10-17 01:22 CDT (Phase 3 Executed):**
  - Ran `python3 tests/test_golden_hunt.py` → **`golden hunt: 25 CONFIRMED, 16 planted vulns expected, 7 benign controls, 67 chains (39 Critical) — RESULT: PASS`**.
  - Ran `python3 tests/run_all.py` → **All 8 layers PASS** (`card-structure smoke`, `injection templates`, `wordlist coverage`, `golden hunt`, `red-team verifier+chain`, `omnicli red-team gates`, `known-bug corpus 13/13`, `web3 contract layer`).
  - Completed full `pytest -q` suite across `/home/phantomcore/oracle` → **`959 passed, 22 skipped, 41 deselected, 1 warning, 32 subtests passed in 238.35s (0:03:58)`** (0 failures).
- **2026-10-17 01:54 CDT (Phase 2 Landed on `main`):** Committed the verified Three-Mindset pipeline and language-agnostic evidence spine (`bc68309`: `oracle_bulk_download.py`, `oracle_evidence.py`, `oracle_hunter.py`, `oracle_mindset_context.py`, `oracle_mindsets.py`, `tests/test_evidence.py`, `tests/test_three_mindset_spec.py`, `SYSTEM_WORKLOG.md`) and fast-forward merged `feat/three-mindset-spec` onto `main`.
- **2026-10-17 03:20 CDT (Independent Subagent Audit of `bc68309`):** Ran independent `research` subagent (`Independent Code Auditor`, `8bff6f62-7c67-479d-9a97-5b77f5dc91d6`) to audit `bc68309` and `/home/phantomcore/invisible-seam` without trusting prior claims. It verified the core pipeline flow and uncovered **6 real defects/gaps** that unit tests missed:
  1. **`second_seam_pass` false-conflict bug (`oracle_mindsets.py:448-458`):** `conflict = len(assertion_bs) > 1 or len(expected) > 1` compares exact normalized strings of free-text `assertion_b` across Mindset 1 and Mindset 2. In real hunts where M1 and M2 corroborate the same endpoint/check with different wording, `second_seam_pass` marks them `m3_seam_conflict = True` (`"conflicted"`), which then causes `_challenge_one()` (`oracle_mindsets.py:344-349`) to demote them to `"unreviewed"` and sort them behind single-lens findings.
  2. **`ttp_mode="auto"` default on `mindset="mitre"` (`oracle_mindset_context.py:171, 403-430, 952-958`, `oracle_hunter.py:6118, 7013`):** `OracleMindsetContext(mindset="mitre")` with default `ttp_mode="auto"` emits the compact (~33 TTP) block instead of all 344 TTPs, and L2 widen (`oracle_hunter.py:7013-7018`) passes `ttp_mode="full"` to `paradox` on cloud (stacking 344 TTPs onto the 320k corpus).
  3. **Premature policy cutoff & scope field caps (`oracle_bulk_download.py:178-186, 1430` & `oracle_mindset_context.py:521-534`):** `_extract_section` still stops at `stop_pattern` after 100 chars whenever a policy has normal subheadings (`Safe Harbor\n`, `Rewards\n`, `XSS\n`), and `_program_brief()` still caps `scope` (`500` chars), `targets` (`300` chars/line), and `out_of_scope` (`300` chars/line).
  4. **Subdirectory bug in `_verify_static_seam` (`oracle_evidence.py:56, 111`):** Scanning `file.parent` (`source_b`'s directory) misses `source_a` when `source_b` is in a subdirectory (`src/app.py`) and `source_a` is at repo root (`README.md`).
  5. **Remaining per-language extractors & ID-collision bug in `/home/phantomcore/invisible-seam` and `oracle_code_seam.py`:** `invisible-seam/src/invisible_seam/extractors/` still has 8 language-specific extractors (`python_security_extractor.py`, `php_extractor.py`, `js_extractor.py`, `go_extractor.py`, `java_extractor.py`, `rust_extractor.py`, `solidity_extractor.py`, `config_extractor_security.py`), `oracle_code_seam.py:417-426` runs them a second time after `doc_extractor.py:302-356`, and `doc_extractor.py:327-355` fails to increment `counter[0]` across extractors, causing `Claim.id` (`C001`) collisions that overwrite claims in `claim_map`.
  6. **Prompt rebuild ordering in `oracle_hunter.py:7551-7595` & standalone `cmd_analyze` (`oracle_hunter.py:5692-5747`):** `mindset_sys` is rebuilt at line 7592 *after* `_run_variant_sweep` (line 7551), and `mindset_sys_by_lens["mitre"]` is not refreshed at line 7594.
- **2026-10-17 04:11 CDT (Fixed All 6 Subagent-Discovered Defects):**
  1. [`oracle_mindsets.py`](/home/phantomcore/oracle/oracle_mindsets.py): Fixed `second_seam_pass()` to compare `_assertion_b_polarity` (`"violated"` vs `"enforced"`) and `_expected_polarity` (`status:<code/>` vs `"expected:denied"` vs `"expected:confirmed"`) instead of requiring character-identical prose strings across lenses.
  2. [`oracle_mindset_context.py`](/home/phantomcore/oracle/oracle_mindset_context.py): Made `mindset="mitre"` with default `ttp_mode="auto"` emit all 344 MITRE TTPs (`mode="full"`), and removed length truncation caps on flat `scope`, `targets`, and `out_of_scope` in `_program_brief()`.
  3. [`oracle_bulk_download.py`](/home/phantomcore/oracle/oracle_bulk_download.py): Stopped `_extract_section` from prematurely cutting off policy text at subheadings when `max_chars is None`, and removed `[:500]` cap on Intigriti scope `instruction`.
  4. [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) & [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py): Added `_resolve_scan_root()` using `os.path.commonpath` over `source_a` and `source_b` so subdirectory code files (`src/app.py`) still resolve root contract claims (`README.md`), and updated `test_evidence.py` to test universal doc-vs-code seams.
  5. `/home/phantomcore/invisible-seam` & [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py): Removed the 8 bolted-on per-language security extractors (`python_security_extractor.py`, `php_extractor.py`, `js_extractor.py`, `go_extractor.py`, `java_extractor.py`, `rust_extractor.py`, `solidity_extractor.py`, `config_extractor_security.py`), `_SELF_CONFIRMING_TYPES`, and `_CLAIM_TYPE_REFLEX`, eliminating the duplicate-extractor calls and `Claim.id` (`C001`) collisions. Verified `pytest` in `/home/phantomcore/invisible-seam` → **64 passed in 8.54s**.
  6. [`oracle_hunter.py`](/home/phantomcore/oracle/oracle_hunter.py) & [`tests/test_three_mindset_spec.py`](/home/phantomcore/oracle/tests/test_three_mindset_spec.py): Fixed L2 widen `ttp_mode` for `paradox`, wired `apply_mindset3_gates` into `cmd_analyze`, rebuilt `mindset_sys` and `mindset_sys_by_lens` (both `paradox` and `mitre`) before `_run_variant_sweep`, and added 4 regression tests in `tests/test_three_mindset_spec.py`.
  - Verified targeted Oracle suite (`pytest tests/test_three_mindset_spec.py tests/test_evidence.py tests/test_code_seam.py tests/test_hunt_code_lens.py tests/test_mindset_profiles.py tests/test_mindset_completeness.py tests/test_mindsets.py tests/test_hunt_mindset_wiring.py tests/test_analyze_synthesis.py tests/test_file_headers.py -q`) → **`89 passed in 17.80s`** (0 failures), and dispatched [`Independent Code Auditor`](conversation://8bff6f62-7c67-479d-9a97-5b77f5dc91d6) to re-verify all 6 fixes.
- **2026-10-17 04:21 CDT (Independent Subagent Re-Verification — 6/6 PASS):** [`Independent Code Auditor`](conversation://8bff6f62-7c67-479d-9a97-5b77f5dc91d6) re-audited all 6 fixed items directly against the source files in `/home/phantomcore/oracle` and `/home/phantomcore/invisible-seam` and returned **PASS on all 6 items**:
  1. `oracle_mindsets.py` (`_CHALLENGE_STATUS_RE`, `_assertion_b_polarity`, `_expected_polarity`, `second_seam_pass`) — **PASS**
  2. `oracle_mindset_context.py` (un-truncated flat `scope`/`targets`/`out_of_scope` & default 344 TTPs for `mindset="mitre"`) — **PASS**
  3. `oracle_bulk_download.py` (`_extract_section` preserving policy subheadings & un-truncated Intigriti `instruction`) — **PASS**
  4. `oracle_evidence.py` & `tests/test_evidence.py` (`_resolve_scan_root` via `os.path.commonpath` over `source_a`/`source_b` & universal doc-vs-code fixture) — **PASS**
  5. `/home/phantomcore/invisible-seam` & `oracle_code_seam.py` (all 8 per-language security extractors, `_SELF_CONFIRMING_TYPES`, `_CLAIM_TYPE_REFLEX`, duplicate calls, and `C001` ID-collision bugs removed) — **PASS**
  6. `oracle_hunter.py` & `tests/test_three_mindset_spec.py` (`cmd_analyze` `apply_mindset3_gates`, L2 widen `ttp_mode`, pre-M3 red-team coverage, downstream prompt rebuild order before `_run_variant_sweep`, and 4 new regression tests) — **PASS**
- **2026-10-17 05:13 CDT (Built Full Multi-Scenario Gauntlet & Caught `_merge_seams` Template Collision):**
  - Built [`tests/test_full_scenario_gauntlet.py`](/home/phantomcore/oracle/tests/test_full_scenario_gauntlet.py) to test the entire pipeline against **both** a multi-file "shit code" repository (README.md, `config.schema.json`, subdirectory Python modules, and Solidity smart contracts with missing NatSpec guards) **and** the live HTTP vulnerable testbed (`vuln_testbed_full.py`) across 6 scenarios (Invisible Seam + Evidence Spine, M1+M2 Full Prompt/Scope Wall, Cross-Mindset Corroboration with different phrasing, Cross-Mindset Conflict Resolution, Red-Team & 5-Gate Wire Rejection of noise/OOS/benign routes, and M3 No-Invention + Compound Exploit Chaining).
  - Running the gauntlet through `oh._merge_seams` exposed a real bug in [`oracle_hunter.py:4983`](/home/phantomcore/oracle/oracle_hunter.py#L4983): `_merge_seams` was deduplicating deterministic template cards by `(lens_key, _probe_key(s))` without `claim_type`, causing `_t_deathless` to swallow `_t_t1190_artifact` on `/.env` and drop its `expected` artifact markers. Fixed `url_key` in `_merge_seams` to include `claim_type`.
- **2026-10-17 06:12 CDT (Pushed Both Repositories to GitHub):**
  - Pushed `/home/phantomcore/invisible-seam` `master` (`8eb7607..d2c6008`) to `https://github.com/Alexander-Sorrell-IT/invisible-seam.git`.
  - Switched active `gh` account to `code-hunter-extreme` and pushed `/home/phantomcore/oracle` `main` (`94278cc..a6fa747`) to `https://github.com/code-hunter-extreme/oracle.git`.
- **2026-10-17 15:20 CDT (Cross-Audit Verification & `test_mistag_regression.py` Universal Mapper Lock):**
  - A second independent AI audited `a6fa747` (`oracle`) and `d2c6008` (`invisible-seam`), confirmed the Three-Mindset + Invisible Seam architecture and removal of the Basilisk-style per-language detectors, and updated [`tests/test_mistag_regression.py`](/home/phantomcore/oracle/tests/test_mistag_regression.py) so `test_code_seam_tags_corrected` and `test_no_code_seam_carries_t1078` test [`_map_seam_to_security_reflex`](/home/phantomcore/oracle/oracle_code_seam.py#L180-L244) via universal claim-vs-reality behavior rather than the deleted `_CLAIM_TYPE_REFLEX` table.
  - Added the remaining two branches (`config-fixable` and `default-generic`) to `_CODE_CASES` in [`tests/test_mistag_regression.py`](/home/phantomcore/oracle/tests/test_mistag_regression.py#L37-L92) so all 6 branches of `_map_seam_to_security_reflex` are locked.
- **2026-10-17 19:26 CDT (Added Scenario G: PoC Teardown, Workspace Persistence & Report Generation to Gauntlet):**
  - Expanded [`tests/test_full_scenario_gauntlet.py`](/home/phantomcore/oracle/tests/test_full_scenario_gauntlet.py) with **Scenario G** (`teardown_poc`, `ProgramWorkspace.save_program_json`, `save_program_brief`, `save_finding`, `_format_chain_report`, `save_report`) and explicit assertions that `M1_ADMIN`, `M2_ADMIN`, and `M3_SYNTH` each independently confirm on the wire (`("mitre", "/api/v1/admin/metrics")`, `("paradox", "/api/v1/admin/metrics")`, `("seam", "/api/v1/admin/metrics")`).
  - Adding `teardown_poc` caught that the synthetic `M1_ADMIN`/`M2_ADMIN`/`M3_SYNTH` cards in the gauntlet needed `assertion_a_source`, allow-listed `curl -i -s` flags, and `parse_expected`-compatible `expected` strings (`status 200, body contains "..."`) so the M1/M2/M3 cards themselves pass all 7 deterministic gates and 3x replay teardown.
  - Ran `python3 tests/run_all.py` → **All 9 layers PASS**.

---

## 6. Execution Plan to Finish Oracle (Before Any Future Fold Into Vortex)

### Phase 1: Clean Up the Per-Language / Basilisk Drift
1. **`/home/phantomcore/invisible-seam`:**
   - Remove the untracked `src/invisible_seam/extractors/php_security_extractor.py` and `tests/extractors/test_php_security_extractor.py`.
   - Revert the uncommitted `php-sql-format` edits in `src/invisible_seam/extractors/doc_extractor.py` and `src/invisible_seam/matchers/code_matcher.py`, and switch `/home/phantomcore/invisible-seam` back to `master`.
2. **`/home/phantomcore/oracle` ([`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) & [`oracle_code_seam.py`](/home/phantomcore/oracle/oracle_code_seam.py)):**
   - Make [`oracle_evidence.py`](/home/phantomcore/oracle/oracle_evidence.py) language-agnostic: remove the hardcoded `claim_type == "py-sql-format"` / `"language": "python"` / `extract_python_security_claims` coupling so evidence normalization works universally on any seam card (`Assertion A` vs. `Assertion B` + check spec: `http`, `command`, or `static_seam` anchored to `source_a`/`source_b` existence and line).
   - Update [`tests/test_evidence.py`](/home/phantomcore/oracle/tests/test_evidence.py) to test universal claim-vs-reality evidence normalization rather than a single Python SQL extractor predicate.

### Phase 2: Verify & Lock In the Three-Mindset Wiring (`feat/three-mindset-spec`)
1. Verify all 6 owner-spec clauses ([`docs/OWNER_MINDSET_SPEC.md`](/home/phantomcore/oracle/docs/OWNER_MINDSET_SPEC.md)):
   - **S1:** Mindset 1 = full 344 MITRE TTPs + Invisible Seam + full bug bounty rules, assets, scope, and company info (including downloaded policy text via `ctx.update_program`).
   - **S2:** Mindset 2 = ALL 21 philosophies, paradoxes, and impossible problems in iPhone-level framing (never cherry-picked; `max_chars=320_000`, fails loud if anything cannot fit) + Invisible Seam + full bounty context.
   - **S3:** Mindset 1 and Mindset 2 each go through their own isolated red-team gate (`redteam_challenge_by_lens`) before synthesis, with cross-mindset twin cards preserved in `_merge_seams`.
   - **S4:** Mindset 1 and Mindset 2 outputs go to Mindset 3, which runs a second Invisible Seam pass (`second_seam_pass`), LLM adversarial synthesis (`_SEAM_REDTEAM_DIRECTIVE` over all candidates, no-invention enforced), and fresh per-lens red-teaming (`apply_mindset3_gates`) + ranking (`synthesize_seams`).
   - **S5 & S6:** Cloud APIs (`128k` context in `oracle_backends.json`) are primary generators for Mindset 1 (`~70k` tokens) and Mindset 2 (`~44.5k` tokens); local (`16k` context) runs as the post-synthesis second-vote verifier (`build_second_vote_packet` + `collaborate`).
2. Run the full Oracle test suite (`pytest` + `python3 tests/run_all.py`) and verify 0 regressions.
3. Commit the verified Three-Mindset changes on `feat/three-mindset-spec` and merge cleanly into `main`.

### Phase 3: End-to-End Local Proving Run (Golden Hunt + Testbed)
1. Run `python3 tests/test_golden_hunt.py` and the full 8-layer validation (`python3 tests/run_all.py`) against the local vulnerable testbed (`vuln_testbed_full.py`) to confirm:
   - All 16 planted vulnerabilities are confirmed on the wire by the 5-gate verifier.
   - All 7 benign controls are rejected (0 false positives).
   - Mindset 1, Mindset 2, and Mindset 3 synthesis + compound exploit chaining (`chain_seams`) + submission report generation run end-to-end.
2. Record the exact output and metrics in [`SYSTEM_WORKLOG.md`](/home/phantomcore/oracle/SYSTEM_WORKLOG.md).

### Phase 4: Live Bug Bounty Hunting (Make Money With Oracle First)
1. Run the intake & verification pipeline (`oracle-hunter prescan` → `oracle-hunter scan -N` → `oracle-hunter queue`) to select a verified, high-payout, fast-triage in-scope program.
2. Run `oracle-hunter hunt <program>` with the full Three-Mindset + Red-Team + 5-Gate Wire Verifier pipeline to produce a verified, submission-ready bug report.
3. *(Future only, after Oracle is paying out)*: Cut/export Oracle's proven modules into `VORTEX_SYSTEM`—never the reverse.


## 2026-10-19/20 — Production chain live gate + closeout (appended 2026-10-20)

- Live gate: Scan4Me sync (2,027 programs / 48,699 assets, Bugcrowd payout SQL
  crash fixed live) → prescan 24 → scan 10/24 verified → top-3 workspaces →
  queue schedule → 1 controlled queued hunt (Here Technologies). Recon OK
  (12 live hosts, ~37k crawl paths); hunt FAILED at engine analysis (lane
  starvation). Evidence retained in `reports/live_gate_20261019/`.
- Wired & hardened: scan `--download` workspaces, `queue --execute`
  (waves/resume/failure-isolation), analyze/seams/verify workspace resume,
  severity ladder law (one-step compounding, fail-closed), multi-path
  download verification (CDP authoritative + corroboration + `via`), scope
  always-refresh on download, engine lane health (breaker 600s, total
  budgets, Groq 8000-token cap), CDP tab PUT fix (was GET 405).
- Verified: Oracle pytest 1148 passed (2026-10-20 outside-sandbox run), `run_all.py` 10/10 layers, Scan4Me
  121 passed. Commits pushed: oracle `346373f` → `ca30ed3` → `25012a6` →
  `ffa9dcb`; scan4me `a77984e`. Full record: `IMPROVEMENTS_REPORT_2026-10-19.md`.
- Errata for §2 above (append-only file): its `oracle_brain.py` line ref is
  stale (logic now at `oracle_hunter._mindset_context`, oracle_hunter:3959ff).


## 2026-10-20/21 — E0 repair block: fake-verdict, lane-stall, starve-on-start (appended 2026-10-21)

Session: independent adversarial audit of ~30 documented claims (3 parallel
line-anchored reviewers: verify/gates/teardown/persistence · orchestration/
router/scope/downloads · deterministic/harvest/mindset feed), then the E0
fix block from the receipts.

- **E0-1 `fix` commit `1c199d6`** — shared `parse_verdict` (oracle_foundation):
  anchored first-token verdict grammar; `_run_variant_sweep`'s inline
  `"CONFIRMED" in v_upper` gate converted (the substring-CONFIRMED fake class
  from VERDICT_TAIL_SCOPE: `UNCONFIRMED`/`POSSIBLY CONFIRMED IF…` false-
  confirming sweep hits). Fail-first red captured pre-patch (2 classes
  CONFIRMED on unpatched code). Honesty receipts in same commit: STATUS.md
  + docs/VERDICT_TAIL_SCOPE.md now match code (previously two files claimed
  parse_verdict "landed" when it had not).
- **E0-2 `fix` commit `04f49b0`** — `oracle_llm._run_with_deadline`: the
  OmniCLI lane's long-acknowledged ignored-timeout defect is dead; a
  concrete deadline bounds `run_orchestration` in a daemon worker and
  overruns raise BackendError so lane breaker/health engage. Null keeps
  legacy free-running; `<=0` refuses dispatch. Fail-first: slow-swarm +
  timeout-0 RED pre-patch (unbounded 5s stalls), green post. Adjacent
  falsy-`or`-timeout pattern in CliBackend/Ollama pinned for a follow-up.
- **E0-3 `feat` commit `57381b2`** — `lane_preflight`/`enforce_lane_preflight`
  (oracle_llm) + cmd_hunt wiring: the 2026-10-19 death mode (hunt starting
  on a dead reflex fleet) now refuses loud before spend; floor cfg
  `preflight.min_alive_lanes` (ships 2); `--no-cloud` = declared local-only
  bypass. No network probes by design (preflight cannot hang a hunt).
  Verifier confirmed the gate is crossed on EVERY hunt path (CLI, queue
  --execute, scan4me) — no silent bypass.
- **Verification:** independent adversarial verifier per fix — E0-1 SHIP
  6/6 PASS; E0-2+E0-3 SHIP (deadlock/race check, contract completeness,
  key-parity incl. `_PREFERRED_LOCAL_MODEL`, wiring/env, concealment probe,
  test-meaningfulness). Full suite with E0-1: **1166 passed + 32 subtests**
  (+18 tests). Bandit parity held per file (no new findings). Two verifier-
  named design limits logged, NOT hidden: credential-dead lanes count as
  living (preflight is breaker-ledger-only by design); user-pinned 1-lane
  route refuses at floor 2 (sole-lane floor exemption recommended).
- **Logged, out of E0 scope:** pre-existing 16-lane concurrent env-merge
  race (OmniCLI env swap vs sibling lanes; bounded consequence), and
  `oracle_bounty.py` legacy bypass of the router (raw ollama subprocess).
- **Open for E0 closeout:** Databricks HTTP 400 diagnose-or-demote; ~20
  non-self-observing templates still alpha-sort `[:25]` (bury risk);
  0600 fuzz-cache perms; standalone confirm_form_replay GET leg scope
  gating; final full-suite closeout. Then E1 = target pick + policy fetch
  + first live end-to-end hunt (the proof owed).


## 2026-10-21 — E0 closeout: all five items + follow-ups landed (appended 2026-10-21)

- **Databricks 400 — diagnosed, lane HEALTHY, no demote:** live probes show
  `ORACLE_KEYS.env`'s token belongs to a different org (`403 Invalid access
  to Org`), while the repo `.env` token completes HTTP 200 on the configured
  `ai-gateway` base_url AND through the real `OpenAICompatBackend.complete`
  (content "ok") — loader precedence `ORACLE_KEYS.env < repo .env`
  (oracle_hunter.py:234-265) already routes the working token into hunts.
  The old ledger entry ("400 on all models") predates the working token:
  documented stale, corrected in STATUS same commit.
- **Falsy-zero timeout law (aef67d5):** verifier follow-up shipped —
  `_timeout_or` (oracle_llm) replaces `timeout or N` at all four remaining
  backend sites (OpenRouter :402, NVIDIA :484, CliBackend :637, openai-compat
  :775). Behavioral RED pre-patch: CliBackend succeeded at timeout=0.0 after
  burning 5.0s. Sole-lane floor exemption landed in the same commit (RED:
  pinned 1-lane route refused at fleet floor 2; now mirrors the breaker's
  sole-lane law).
- **Cap-cannot-bury law (5c36e11):** `_live_url_map`/`_cap_rank` shared law in
  oracle_seam_templates; `_t_self_observing` refactored onto it (byte-equal),
  `_t_deathless` converts (the one mixed-observation template left alpha-
  sorting), `_t_beautiful_liar` cross-source dedupe + UnboundLocalError crash
  fixed (RED receipts: order-bury, duplicate card, crash at :906). Uniform-
  evidence templates declared NO-CHANGE with reasons (no invented
  preferences). Verifier: writer-source receipt `fuzzed_paths.txt` emits
  absolute-only (oracle_deeprecon.py:594-608) — raw-key parity holds in
  practice. 33 passed across template/sweep/golden families.
- **Harvest hygiene legs (da7a10a):** id_fuzz.json cache now 0600 fd+chmod
  (RED: perms 664); `confirm_form_replay` standalone GET leg consults the
  scope gate — fail-closed on gate error, gate=None stays the declared
  ungated regime (legacy mutation-disabled test contract preserved).
  RED receipt: gate-deny let the GET fly its fetch. 15 passed across
  wash/csrf/chains suites.
- **Verification:** independent adversarial verifier (ses_ea2cf71c) on all
  three closeout commits: **3× SHIP** — checks A1-A4, B1-B4, C1-C4 PASS.
  Four surviving holes DECLARED, none hidden: (1) relative fuzzed lines
  (hand-written only; real writer emits absolute) → raw-keyed cards;
  (2) `_live_url_map` fuzzed branch lacks `_is_static` while `_t_deathless`'s
  build has it (static self-observability candidates nuance); (3) legacy
  0644 cache stays loose during the truncated-write window (
  `os.open` mode applies at creation; `os.chmod` follows — cosmetic race);
  (4) `--no-cloud` listed as preflight escape even with no local lane
  (honest fallback = complete()'s own exhaustion error).
- **Final suite (2026-10-21):** **1184 passed + 32 subtests, 22 env-skips,
  0 failures, 274.95s** — 1148 → 1184 across the session; zero regressions
  through all seven commits. Bandit parity held per file; mypy region-clean
  on every touched range; black/flake8 clean on authored lines.
- **E0: CLOSED.** Next owed proof: E1 — target pick (user, 2 min) + policy
  fetch + first complete live end-to-end hunt; the money gate per the
  MASTER_PLAN is ≥1 submitted finding with triage response.

## 2026-10-21 — E1 first live hunt: tinder (COMPLETE — honest zero, receipts)

- **Launch:** `hunt tinder --auto` (background sh_15da13d69001S0clqgoYkakyyN),
  NO_PROXY=127.0.0.1,localhost; preflight 13/13 reflex lanes living, floor 2.
- **Compliance before launch:** x-hackerone attribution header verified
  functioning in-flight (checks carry `-H "x-hackerone: <user>"`); policy +
  structured scope receipts committed (3f6a6aa).
- **Outcome:** `Verify complete — 0/1100 confirmed, 0 inconclusive` —
  funnel mined=146 followups=954 attempted=1100 det_reject=1100 postgate=0
  final=0; `Variant sweep: no confirmed phase-1 findings` (sweep gear
  skipped BY the zero, not around it); report written (5547 lines, report
  gitignored by design) + teardown; banner: `SYSTEM FAILURE: 0 confirmed,
  modes unpassed: recalled` — the pipeline's law, not a sugarcoat.
- **Wire truth:** 864/892 status-watched checks = 502 Bad Gateway from
  tinder's nginx edge (unauth regime against a session-gated data plane);
  18x404, 8x403. Zero real exceptions in runner code (31 grep hits were
  card TEXT describing hypothetical SQLi).
- **Self-audit receipts the flag-challenge demanded:** (1) dual-engine ran
  (both lenses submitted + clean, 0 minted), (2) all mined = ONE template
  class, (3) MITRE:"?" on every card front, (4) Engine B demoted by design,
  (5) funnel balanced (det_reject=postgate+final harmonics). The hunt did
  not paper a zero as success.
- **Follow-ups opened (E1.1, now unblocked by real funnel data):**
  det-reject rule IDs (A/S/B2 tagging in deterministic returns),
  auth-required premise filter at mint (kill 502-class predictions
  pre-wire), followup over-mint cap, LLM-lens card-yield audit (0/2).
  E2 (session-authed producer) named the real tinder path: user-provisioned
  2 accounts via --prompt-login/-auth-a; mass creation stays banned.
- **Post-run rectifications (2026-10-21, user-challenge driven):**
  (1) The analysis tier never swallowed the inventory — recon held 580 JS
  endpoints/86 subs/27 live hosts, but lens injection took 20 hosts + 30
  endpoints (distill caps, oracle_hunter.py:_distill_endpoints max_items=60
  + host cap; all 146 mined cards trace to that ~5% slice).
  (2) Mint monoculture: 146/146 seeded from ONE template family
  (router-spelling/auth); 954 followups expanded the same premise 6.5x.
  (3) Log-line ambiguity fixed by contract: "MITRE mapping: 12 techniques"
  is a SELECTION count (oracle_hunter.py:1834 prints len(selected)) — the
  per-tactic top slice of the local TTP corpus scored for web-relevance
  (:1800-1834), NOT the matrix; ATT&CK Enterprise is ~14 tactics / ~200
  techniques / ~424 sub-techniques. E1.1 receipt law: print "12 of N
  corpus techniques" and log selected T-code IDs per run.
- **Money gate: NOT met.** Submitted findings: 0. Triage: n/a. Next live
  spend on tinder only exits with the account regime; else roll to a
  fresh-program target where unauth machinery can bite (clear, #1 on the
  STATUS shortlist: launched 2026-03-02).

- **E1.1 fix list upgraded from audit to fix-now (2026-10-21, user
  challenge "mindsets misused" — accepted):** Carry-through failure
  named: the philosophy layer contributed ZERO artifact content in the
  tinder run — (a) paradox (320k corpus + impossible-problem framing,
  oracle_mindsets.py:30) is prompt-context only, never a card producer;
  (b) "iPhone" is a card-shape gate which gated cards that never minted;
  (c) MITRE techniques carry still not onto card fronts ("MITRE: ?"
  x1100); (d) SUBTLE MASK: paradox lens returned an explicit
  TARGET CLEAN verdict from the 5%-slice/no-session regime and
  lens_outcome() (oracle_hunter.py:4584) credits explicit verdicts as
  "clean" — a structurally unearned clean. Fix-now items (all red-first):
  1. qualified-clean law — TARGET CLEAN counts only with regime receipts
     (200-served endpoints + logged auth regime), else downgrades and
     Engine B second-vote un-demotes;
  2. carry-through tags — lens/L-seed/T-code onto card faces;
  3. mint-cap + auth-feasibility filter + slice-cap configs from prior
     block; 4. shape-gate observability line on zero-mint runs.
  No live credits until these land.

- **Full-service mindset law LANDED (2026-10-21, user decree):** every
  EFFECTIVE mindset is owed cards from the run; a zero-mint mindset is
  UNSERVED and the hunt banner FAILS causally — even when confirmations
  would read green (`oracle_hunter.py:8096-8109`). Lens TARGET CLEAN
  claims are only 'qualified-clean' with regime receipts (>=3 endpoints
  served 200 in a sessioned regime); engine origin tags
  (cloud-mitre/local-paradox) translate to mindset names before the
  cause chain; poisoned string receipts degrade to 0 (no crash).
  Yield lines print ALWAYS. RED-first: 6 then 9 pins
  (tests/test_mindset_yield.py); suite 1194 → **1197 passed** (2 runs:
  196s then 250s; 22 env-skips, 32 subtests, 0 failures). Bandit parity
  0/18 per file; flake HEAD-parity exactly 26 on mindsets; mypy clean in
  region (oracle_auth_session.py:691/694 = untouched-file pre-existing).
  Verifiers: ses_ea0e42ec9ffdLpf2CXR2z2cZCZ (4 holes found incl.
  unearned-clean + tag-translation dead branch) →
  ses_ea0d5f4beffeXEmTV8YX0SWyML (4/4 fixes verified, adversarial probes
  all PASS). DECLARED OPEN (accepted, not fixed): IDOR probes default
  credit the mitre lens (oracle_hunter.py:3128 default) — could mask a
  dead mitre lens; cmd_audit finalize has no yield accounting;
  local-tactic:X tags miss-credit mitre (fail-loud only).

- **E1.1-C cap regression fixed + E1.2a cage/pool contracts (2026-10-22,
  RED-first):** The E1.1-C mint cap shipped with an implicit 20-card
  family default and broke the pre-existing crawled-coverage contract
  (30 same-family crawled pages -> last-alpha page lost its primaries;
  full suite red at 115f74f). Fix: the cap is config-armed only —
  scan_template_seams defaults to no cap, program.hunt_config arms it,
  and cmd_hunt resolves prog > CLI arg > oracle.config.json hunt block
  (max_cards_per_family=20). RED pins: default preserves all 30 crawled
  pages, program config applies, resolver order incl. 0 = no cap, shipped
  config arms it; the pre-existing test_authed_recon budget test is green
  again. NEW oracle_mindset_cages.py (user law 2026-10-21: "mindsets can
  not be suggestion for OmniCLI, it has to be cages"): 
  validate_mindset_card enforces required fields, observation basis, wire
  prediction, rule compliance, mindset frame (T-code / paradox-frame /
  merged_from both parents) and the scope wall; resolve_mindset_pools
  assigns provider lanes in parallel (halves M1/M2, all lanes M3, config
  overrides, dedupe, empty pool = ValueError). Scope wall: a live
  ProgramScopeGate object delegates authoritatively; raw-list mode mirrors
  host rules and fails closed on hostile URL text, numeric-only IDs,
  malformed labels, IPv6 literals and path-scoped OOS. 23 cage/pool pins.
  Verifier rounds (same independent session): scope inversion, bool
  status, empty fields/headers, wildcard-apex semantics, path-scoped
  widening, numeric-ID acceptance and fail-open OOS were found and fixed;
  final delta = 138,612 differential candidates vs the real gate,
  0 cage-accepts/gate-rejects, A/B/C/D/E/F PASS. CONTRACT STATUS (E1.2a):
  UNWIRED — no production import, no live enforcement claim. Full suite
  1253 passed + 32 subtests, 22 env-skips, 0 failures (188s); flake8 clean
  on new files; bandit clean on the new module.
