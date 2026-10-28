# Oracle Verified State

Standing rule: a claim is listed here only with evidence (test/file:line/command).
Recall is not evidence. Verification-grade questions must consult this file first.

HEAD at last update: oracle `ffa9dcb`, scan4me `a77984e` (omnicli external — not re-verified here)
Last verified: 2026-10-20 (suite: oracle 1148 passed, full outside-sandbox run on working tree incl. in-flight prompt-hardening edits; Scan4Me 121 passed)

## DONE (evidence-backed)

| Claim | Evidence |
|---|---|
| Scope gate fail-closed (unknown program rejects all; 3rd-party blocked; prod safe-mode downgrade) | `tests/test_scope_gate.py` (esp. L402 `test_unknown_program_scope_gate_restrictive`); suite 1148 passed (2026-10-20; earlier snapshots: 372) |
| `save_program_json` scopeless-overwrite guard | 4 guard tests added with scope-wipe fix |
| Hunt CLI wired (`hunt`: recon → Oracle → verify → PoC; + verify/recon/scope/redteam/status) | `oracle_hunter.py:8486` (`p_hunt`), `main()` L8289 |
| Recon binaries present | `command -v`: subfinder, httpx, katana, nuclei all in `~/go/bin` |
| Scan4Me DB available | `/home/phantomcore/Scan4Me/scan4me.db` (9.1MB at 2026-10-20) |
| Target cache usable | `targets/`: 352 program.json, 217 with scope-ish content |
| Triage None-safe | `oracle_triage.py:175` (`lognorm` guards None); `score_programs` L181-294 |
| Payout-None handled at score layer | `oracle_programs.py:2458-2469` (None scores 0) |
| Corpus fold-in (18 mindset docs) | `test_oracle_corpus.py`; commit `26aa5fc`; byte-identical |
| OmniCLI council proven | 332 passed +53 subtests; proof 5e F1 0.5714; commits `fd3d018` `72fd42b` `fe9178e` |
| `scan4me_home()` (env→sibling→legacy + expanduser) | `tests/test_scan4me_home.py` (5 tests); `oracle_scan4me.py:45` |
| Shared K/M/B `parse_payout` wired into bugcrowd/immunefi/codehawks | `tests/test_payout_parse.py`; `oracle_programs.py:775`; immunefi uses `require_symbol=True` (reviewer-caught) |
| Payout 0→None at normalize + None-guards at all format sites | `normalize_program_record` `oracle_programs.py:2340`; guards `oracle_hunter.py:4944`, `oracle_mindset_context.py:378` |
| YWH page loop (20-page cap) | `tests/test_adapter_pagination.py`; `oracle_programs.py:1756` |
| Managed substring-clause dropped per audit | `audit/LOGIC_AUDIT.md:110`; `oracle_programs.py:1744` |
| 60-case gate spec (method binding, bars INITIAL) | `docs/GATE_SPEC.md`; bars in `oracle.config.json` → `quality_gates`; `tests/test_quality_gates.py` |
| Review-exit stages (0→1→2 + regression rule) | `docs/GATE_SPEC.md`; machine values in `quality_gates` |
| Verdict-tail hardening scoped for Phase 4 | `docs/VERDICT_TAIL_SCOPE.md` (shared parse_verdict + measure/rollback) |
| iPhone framing = card format (A/B/check/impact), load-bearing | `docs/BENCHMARK_EVALUATION.md:68`; prompt reflexes; `verify_seam_card` enforcement |
| Pipe-strip: `| head/tail -N` runs, hostile pipes still drop | `strip_safe_truncation` (`oracle_foundation.py`); call sites hunter:Op1/`_run_check`; `tests/test_safe_truncation.py` (11 tests) |
| Battery harness declares loopback benchmark | gate + `ORACLE_BATTERY_MODEL` override + `is_testnet` in `tests/test_oracle_ground_truth.py` |
| Verify path proven on wire: 4/4 flaws + clean reject | `tests/test_flaw_battery.py` (Flaws 1/3/4/7 + negative control) |
| Reflex comparison 3b vs 7b | 3b: 5 header-cards, 0/20. 7b: 9 parsed→36, real endpoints, 0/36 all honest wire rejects (`/tmp/battery_7b.log`) |
| ORDERS global pollution found + fixed | Flaw 7 POST dirtied `test_known_bugs` refund math; snapshot/restore in flaw-battery test |
| OOS exact-host now covers subdomains | `_compile_pattern(subdomains=True)` for OOS rules; `deep.secret` blocked |
| Non-http(s) schemes rejected at gate | `is_in_scope` scheme guard; `ftp:` no longer admitted |
| Fleet failover verified (cascade + fail-closed) | `oracle_llm.complete` L762-779; existing `test_all_fail_raises` et al |
| Prompt-injection exposure scoped (not yet fixed) | `docs/PROMPT_HARDENING_SCOPE.md`; blast radius bounded (no RCE path) |
| Juice-shop loopback provisioned (pinned rev) | image `juice-pinned:1618a611-local`, `127.0.0.1:3000`, checkout pristine |
| Hunt-1 diagnosis: --code skipped recon → 0/17 grounding rejects + exit hang | `/tmp/juice_hunt1.log`; hang = post-banner, 25 parked threads, idle Ollama |
| `_fetch` scheme normalization (crawl4ai ×127 root cause) | `oracle_programs.py:_fetch`; `tests/test_fetch_cascade.py` |
| Ollama streaming + 600s idle watchdog (hunt-1/2 hang root cause) | `oracle_llm.py:OllamaBackend.complete`; 3 new tests; live-verified vs 7b |
| Hunt-2 precision measured: ~0.03-0.09 vs 0.70 bar | 25 vacuous spoof + 7 SPA-fallback of 35 confirmed; only 044 solid |
| Gate 6a: variation differential (reframe vs recorded parent output) | hunter verify loop; `tests/test_confirm_gates.py` (3 tests) |
| Gate 6b: SPA-fallback control fetch | `build_spa_control` (foundation) + hunter check; 2 tests |
| Generic-marker stoplist in Gate 5 OR-lists | `_GENERIC_MARKERS` (deterministic); 2 pure tests; flaw-battery 4/4 preserved |
| Hunt-3 verify: 3/411 confirmed, exit 0, GEAR-TURN PARTIAL | `/tmp/juice_hunt3.log` L26616/L26670; report `reports/http___127.0.0.1_3000_20261011_132414.md` |
| Hunt-3 precision: 0.5/3 vs 0.70 bar (7 FP public-endpoint, 40 FP plumbing-fingerprint, 69 half real-exposure/false-mechanism) | audit vs juice source: `server.ts:391` (Challenges public), `:695` (metrics public), `exposedMetricsChallenge` in `challenges.yml`; served `main.js` has no literal |
| Gate 7 Rules A/S/B2 (prediction adequacy, web-only, web3 exempt) | `oracle_deterministic.py` Gate 7 block; `tests/test_gate7_adequacy.py` (11 verifier tests) |
| Gate 7 Rules B1/C (original-card header differential, spelling-twin differential) | hunter Gate 6 block extension + `build_variation_control`/`build_spelling_twin` (foundation); 4 hunt-path tests |
| Post-gate verdict print (Gate 6/7 flips no longer hide behind stale CONFIRMED) | hunter `_warn("Post-gate verdict...")`; capsys test |
| Miner F1: secret values must be quoted literals (plumbing killed at birth) | `_SECRET` (`oracle_deeprecon.py`); fingerprint `sha256("this.options.authToken")[:16]==7b6271b3ecfd3306` proven; plumbing test |
| B2 omission-frame exemption ("without auth" tested by sending none) | `_OMISSION_FRAME_RE`; caught by `test_omnicli_redteam` positive control pre-commit + regression test |
| Cloud per-address burn diagnosed (120s x 16 addrs) + fixed (IPv4-first, 8s connect fuse, per-host fail-fast) | SYN-SENT cycling proof; `_FastConnectHTTPSConnection`, `_prefer_ipv4`, `_CLOUD_HOST_DOWN`; 2 cloud tests |
| Gemini direct path 404s (stale `gemini-2.0-flash` ID) | `/tmp/juice_hunt3.log` L26626/L26631 |
| Hunt-4a void (infra): juice died mid-run, 319x curl exit 7, no abort | `/tmp/juice_hunt4.log` (all "no observation"); container absent at end |
| Hunt-4b: 0/396 with correct gates (388 honest + 8 rightful post-gate kills) | `/tmp/juice_hunt4b.log` L25764; seams 3 (C), 64 (B1), 88/89/221/222/335/336 (6a) |
| Recall miss proven (miner-side): live /metrics cut by template cap at rank 25 | fuzzed rank query; body hits token/version/config (non-generic); no 5b phrases |
| Self-observing ranks live-first + canonical-short-path-first | `_t_self_observing` rank key; `tests/test_phase2_fixes.py` burial test |
| Dead-target circuit breaker (10 consecutive transport fails abort) | `verify_seams` trip + reset; trip test (dead port) + 9+1+9 reset guard |
| Router honors hunt --model (override + cmd_hunt wiring + conftest isolation) | `set_preferred_local_model`; `tests/conftest.py` autouse reset |
| Hunt-4c: 1/392, seam 22 /metrics TRUE POSITIVE — precision 1.0 vs 0.70 bar | `/tmp/juice_hunt4c.log` L25463/L25486; card `finding_022.json`; markers token/version/config |
| PoC starvation root cause: 106KB system prompt vs 16k local model | measured `prompt_size()` voice=True; 600s zero-byte timeout; wrong "32k" comment fixed |
| Lean reporting prompt for router legs (direct-cloud unchanged) | `reporting_prompt()`; threaded finalize→synth/corr→escalate; live probe 58s/59s |
| Hunt-4d: 2/392 — seam 22 TP + real local PoC; seam 332 FP on float/NaN jitter | `/tmp/juice_hunt4d.log`; PoC panel L25469; `0` vs `0.5` + NaN diffs proven live |
| Differential normalization hardens floats + NaN/Inf (4 sites unified) | `normalize_wire_output()`; jitter replay test; 3/3 live pairs now identical |
| OPEN (deferred): Engine-B mining timeouts need evidence budgeting; severity calibration | 16x 600s in 4d, engine fully failed-over; exposure-class High/Critical generous |
| DVWA hunt-1: 0/24, all BLOCKED by blanket metachar scan (Cookie ';') | `/tmp/dvwa_hunt1.log` L573; 24x `[BLOCKED] shell metacharacters` |
| Token-position-aware runner gate (curl URL/value data passes; structural metachars blocked) | `oracle_hunter.py` `_run_check`; 5 tests in `tests/test_scope_gate.py`; suite 487 +32 subtests |
| Adversarial gate review PASS (~90 live candidates, zero bypasses) + 3 pre-existing findings closed | 6 tests (F1 @file narrow, F2 -K CR/LF sink, F3 _sub sanitize); `oracle_foundation.sanitize_header_val` |
| Bench pins committed: dvwa `068d9744`, pygoat `19d17cc8`, loopback images live | `benchmarks/registry.json`; `dvwa-pinned`/`pygoat-pinned` on 127.0.0.1 |
| `_split_path` fail-closed on recon garbage (nuclei `[CVE-*:version]` tag) | garbage regression test in `tests/test_scope_gate.py` |
| DVWA re-hunt: 4/12, exit 0, 0 BLOCKED; audit 4/4 TP, precision 1.0 | `/tmp/dvwa_hunt2.log` L569; live re-fetch config(262B)+phpinfo(86KB)+HEAD |
| No dedup (seams 1+6 same URL); seam-1 draft invents "/self-observe" | reports/; `oracle_hunter.py:4210-4213` prompt feeds jargon; zero `dedup` refs; logged |
| Pygoat hunt-1: 1/8, exit 0, 0 BLOCKED; /debug TP + 3 post-gate kills | `/tmp/pygoat_hunt1.log`; live 15.5KB dump (creds/tracebacks); clean seam report |
| Paradox never executes on --no-cloud (P0, workflow + self-verified) | Engine A `if _cloud_up` ~5740; Engine B mitre-only ~5773; log 5428 requested-not-effective |
| Disclose-fix: Requested vs Effective mindsets log + `effective_mindsets()` | `oracle_mindsets.py`; 4 tests; suite 491 +32; subagent PASS (gates/returns/rerun/consumers) |
| Phase 4 shortlist: clear / wealthsimple / tinder (h1, web2, fast) | scorer top-30 + 5-child workflow; spot-verified program.json; AUTO-policy gap OPEN |
| Juice funnel: det-REJECTED 1828/1896 (96.4%); post-gate 27/68; survivors 2.2% | 6-child workflow; grep re-verified 405/410, 388/396, 383/392 x2 |
| funnel.json per hunt (entry keys + kill tags + aggregation) | `build_funnel_counts`; 3 tests; suite 494 +32; subagent PASS (5/5, 7/7, probes) |
| Mindset audit: MITRE MIXED (T1078 mistags), paradox local-NO, iPhone gate REAL, red-team local mitre/seam only | 6-child workflow + self-verify (finding_001, cmd_redteam 6429-6505, Engine B sweep); recall gate precedes pick |

| Intake pipeline wired (prescan → scan select → download workspaces → queue --execute waves/resume/failure-isolation) | `oracle_intake.py`, `oracle_queue.py`; tests `test_queue_execute.py`, `test_chain_e2e_offline.py`; live gate 2026-10-19 (`reports/live_gate_20261019/`) |
| Severity ladder law (one compounding step, fail-closed unknown/negated, no count-to-Critical) | `oracle_mindset_context.chain_seams`; `tests/test_severity_ladder.py` (71 cases) |
| Multi-path download verification (CDP authoritative + corroboration render + `via` provenance; scope always refreshes) | `oracle_scan.py`, `oracle_bulk_download.py`; `tests/test_scan_download_multipath.py`, `test_bulk_download.py`; live fetch probes 2026-10-20 |
| Saved-session CDP page fetch works (PUT /json/new; was GET 405) | `oracle_scan.py:_cdp_page_text`; `tests/test_cdp_page_text.py`; live: HERE 11,146B / Spotify 16,412B via host browser |
| Engine lane health (breaker 600s, total budgets 360/170/360, Groq cap; 68k-token prompt answered live in 99.6s) | `oracle_llm.py`, `oracle_backends.json`; `tests/test_llm_lane_health.py` |
| Live gate 2026-10-19 (sync 2,027 → prescan 24 → scan 10 verified → 1 queued hunt FAILED at engines pre-fix; 0 live findings) | `reports/live_gate_20261019/` (logs + queue_state); `IMPROVEMENTS_REPORT_2026-10-19.md` |

## CLOSED (code — 2026-10-20)

| Item | Fix | Evidence |
|---|---|---|
| `run_reflexes` called router with `timeout=None` — circuit breaker never fired | `timeout=360` (same as Engine-A budget) | `oracle_hunter.py:2393`; commit `713ea5c` |
| `controlled=True` (queue default) skipped ALL deep recon (JS mining, API specs, listing harvest) | deep recon runs in controlled mode; only ffuf stays skipped | `oracle_hunter.py:1510`; commit `713ea5c` |
| `hakrawler` only ran against `clean_urls[0]` — 11 of 12 HERE hosts got zero JS extraction | loops all `clean_urls` | `oracle_hunter.py:1583`; commit `713ea5c` |
| Program listing header reached model before instruction hierarchy reminder | `[UNTRUSTED program-listing]` wrap + reminder moved first in `_build` | `oracle_mindset_context.py`; `tests/test_prompt_hardening.py`; commit `713ea5c` |
| ~~Router backend timeout audit + log winning backend~~ CLOSED 2026-10-20 | Total router/lane budgets + circuit breaker + request caps shipped (`25012a6`); `return_model` attributes the winning lane; groq too-large now pre-skipped by `max_request_tokens` (8000) | |

## OPEN (code)

| Item | Evidence |
|---|---|
| K/M rollout to remaining ~13 adapters (follow-up; boundary coercion covers correctness, per-adapter K-strings still unparsed) | `parse_payout` wired into 3 of 16 scrapers |
| Reflex quality: no identity variation, GET/POST confusion, hallucinated routes | 7b run: 0 X-Original-Role spoofs, bare `-X POST`, `/login` 404 (`/tmp/battery_7b.log`) |
| Router default model ignores `--model` (asked 30b 15x on a 7b hunt) | `/tmp/juice_hunt3.log` `qwen3-coder:30b` x15 |
| Gemini model-ID refresh (direct path 404s) | L26626/L26631; per-host fail-fast now bounds the cost |
| Hunt-4 `--no-cloud` to prove the local PoC path end-to-end | hunt-3 PoCs are error strings (GEAR-TURN incomplete on PoC leg) |
| Juice-shop loopback provisioning + hunt loop | checked out at pinned rev, not running (next) |
| Code+live combined mode missing | `--code` disables recon; no flag runs both (OPEN) |
| Exit-hang mechanism unproven (thread names not captured) | re-run will capture `/proc/PID/task/*/comm` if it recurs (OPEN) |

## ABSENT (spec — confirmed by empty regex search)

| Item | Evidence |
|---|---|
| Dual-reviewer adjudication | CONFIRMED ABSENT (workflow 2026-10-10): repo-wide `adjudicat` regex matches only this file. NOTE: superseded — review-exit stages in GATE_SPEC.md replace dual-review with measured precision bars |

## MUST BE PROVEN LIVE (unverifiable read-only)

- Full hunt end-to-end on a real target *(still open — 2026-10-19 gate reached recon, died at engines pre-fix)*
- Verdict quality on real wire output
- Measured cost/hunt + hit-rate
- Paid finding (submitted → accepted → paid): **none yet as of 2026-10-20**
