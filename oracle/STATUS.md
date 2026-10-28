# Oracle — Current Status (2026-10-21)

- **Oracle HEAD:** current tip = E0 closeout (see Suite line date; pushed after
  doc-truth commit) · **Scan4Me HEAD:** `a77984e` (pushed, verified).
- **Suite:** pytest **1184 passed + 32 subtests, 22 env-skips, 0 failures** (full
  outside-sandbox run, 2026-10-21, E0 complete — 1148 → 1184 across this session's
  fix set; inside the proxy sandbox, set `NO_PROXY=127.0.0.1,localhost` or loopback
  tests fail through the proxy). `tests/run_all.py`: **10/10 layers
  PASS** incl. severity ladder (71 cases). 125 test files / ~1,211 tests. Scan4Me: 121 passed.
- **Pipeline:** `sync → prescan → scan → download → queue --execute → hunt` is wired
  and live-exercised through recon (2026-10-19 gate: 2,027 programs, 24 prescan,
  10 verified, 1 queued hunt). That hunt died at engine analysis (lane starvation);
  since fixed (circuit breaker + total budgets + request caps) and a 68k-token hunt
  prompt has completed live since. No live hunt has yet completed end-to-end —
  that is the next proof owed.
- **Detection:** proven on planted-bug testbeds (golden hunt, known-bug 13/13).
  Live paid-target findings: none yet. Never merge those two statements.
- **Known degraded lanes:** ~~Databricks HTTP 400 on all models~~ — **diagnosed
  2026-10-21, lane HEALTHY, no demote:** root cause was the wrong-org token in
  `ORACLE_KEYS.env` (`403 Invalid access to Org`); loader precedence
  `ORACLE_KEYS.env < repo .env` (oracle_hunter.py:234-265) means the merged hunt
  env carries the working token, and the lane completes HTTP 200 through the
  actual adapter (`OpenAICompatBackend.complete`, live receipt "ok"). The old
  "400 on all models" ledger entry predates the working `.env` token.
  OmniCLI timeout arg now ENFORCED (E0-2, 2026-10-21: a concrete
  deadline bounds run_orchestration in a daemon worker; overruns raise
  BackendError so lane health/breaker engage — previously the arg was accepted
  and ignored, wedging the router on slow orchestrations). The falsy-zero bug
  class is dead repo-wide (E0 follow-up, 2026-10-21: `_timeout_or` law —
  `timeout or N` at ALL four other backend sites could map a spent deadline
  silently onto the large call default; behavioral RED receipt: a CliBackend
  call succeeded at timeout=0.0 after burning 5.0s).
- **Lane preflight (E0-3, 2026-10-21):** the 2026-10-19 death mode — a hunt
  starting on lanes already stamped dead — now refuses at start:
  `enforce_lane_preflight` (oracle_llm) counts living reflex lanes from the
  in-run breaker ledger, floor from cfg `preflight.min_alive_lanes` (ships 2),
  fail-loud RuntimeError with the dead-lane names; `--no-cloud` declares a
  local-only regime and bypasses; SOLE-LANE routes are exempt from a fleet
  floor (mirror of the breaker's sole-lane law — one declared lane is a
  regime, not a dying fleet). cmd_hunt calls it right after the mindset
  gate. No network probes by design: preflight cannot hang a hunt.
- **Cap law (E0, 2026-10-21):** the hunt-4b bury class (
  live `/metrics` ranked 25th alphabetically, cut by `[:25]`) now has a single
  shared home — `_live_url_map`/`_cap_rank` (oracle_seam_templates): observed-
  first, short-path, alpha. `_t_self_observing` refactored onto it (byte-equal),
  `_t_deathless` (the one mixed-observation template left alpha-sorting)
  converts, and `_t_beautiful_liar`'s cross-source dedupe + UnboundLocalError-
  on-empty-fuzzed crash are fixed. Uniform-evidence templates declared no-change
  (no invented preferences).
- **Harvest hygiene (E0, 2026-10-21):** fuzz probe cache written 0600 (was
  0644-umask); `confirm_form_replay`'s standalone GET leg now consults the
  scope gate (fail-closed on gate error; gate=None stays the declared ungated
  legacy regime).
- **E0 repair block: CLOSED** (2026-10-21) — all five items + follow-ups landed,
  each with fail-first RED receipts and an independent adversarial verifier
  SHIP verdict (seven commits total this session). Next owed proof: E1 — the
  target pick + policy fetch + first complete live end-to-end hunt.

Everything below is the **2026-10-08 repair history** — accurate as history,
superseded as current status by this section.

---

# Oracle — Repair Status (2026-10-08)

## Round 1: repair + harden + foundation-3 — DONE
Scope: F1–F9 hygiene + F10 paradox operators. 24 modules, ~42k lines.

### Fixes
1. F1: 6 stale tests updated to hardened engine behavior (suite was 239+6).
2. F2: `NameError` in `_looks_client_rendered` (missing `urllib` import,
   hidden by broad `except`); narrowed `except` + new regression test.
3. F3/F4: autoflake, dead stores, 19 ambiguous `l` renames.
4. F5 (redo): bandit 2 high + 39 medium → 0/0. Real fixes: `mktemp`→
   `mkstemp`, sha1→sha256 queue ID, scheme guards in `discovery._get`
   (raises) and `_looks_client_rendered` (fail-closed False); honest
   `nosec` on 37 audited hardcoded-scheme/localhost `urlopen` sites
   (each traced to its `Request`), Gmail tooltip bidi `nosec`, B104
   `nosec` moved onto flagged line. (Pre-compaction "0 mediums" claim
   was wrong; current numbers observed.)
5. F6: mypy 103 → 0 errors, 24 files (`mypy.ini`, `types-requests`,
   `Optional`/`Any` annotations, loop-var renames, `isinstance` narrows).
6. F7/F8: black all files; flake8 146 → 0 (autopep8 mechanical batch,
   52 `noqa: E501`, 9 prompt rewraps, 2 JS splits, 1 unused import).
7. F9: comment hygiene.
8. F10: `oracle_foundation.py` (new) — foundation-3 as literal operators:
   Op 1 iPhone card-shape validator wired into `verify_seam_card`;
   Op 2 frame-rewrite (5 curl transforms) wired into `verify_seams`
   REJECTED branch, one bounded generation; Op 3 `GearTurn` 4-mode
   escalator wired into `cmd_hunt` (0 confirmed = SYSTEM FAILURE).

### Verification (observed)
- `pytest tests/`: 266 passed + 32 subtests (was 239 passed + 6 failed).
- `black --check` clean; `flake8` clean; `bandit` 0 medium/0 high
  (88 lows: accepted recon-tool noise — try/except/pass, subprocess);
  `mypy` 0 errors in 24 files; new module pylint 9.90.
- New tests: `test_looks_client_rendered.py` (5), scheme guards (2),
  `test_foundation_operators.py` (15).

### Deferred (known, not this round)
- 88 bandit lows (B110/B404/B603/B607): accepted, revisit if policy changes.
- pylint `too-many-*` on hunter/deterministic; `datetime.utcnow()` warning.
- Producers don't use `build_seam_card` yet (validator enforces at choke).
- RECALLED mode = variant sweep only; no cross-program tracker recall yet.

### Snapshots
- BEFORE: `oracle_BEFORE_20261008.tar.gz`
- AFTER: `oracle_AFTER_20261008.tar.gz` (STALE — predates proof-hunt fixes below; re-snapshot at next milestone)

### Proof hunts (2026-10-08/09, post-snapshot — all fixed + tested)
Live fire on XBEN-001/002 found 10 defects: scope-gate localhost grants,
leak-rewrite vs lab URLs, echo-card (A==B) confirmations, vendored-code
noise, blank-line crash, code-only misclassification, recon seeded with
program names, Gate 2b discrimination floor, confirmation strength labels,
reframe variation exemption. Suite: 277. Phase-1 IDOR confirmation still
open — needs the credential/ID-harvest reframe engine (roadmapped).

## Phase A1: fold-ready file headers — DONE (2026-10-09)
25 modules stamped (LAYER/DEST/ENDPOINTS/TOPICS); roster is 25 not 24 —
`oracle_scan4me.py` (Scan4Me bridge) was unlisted. New `test_file_headers.py`
(2 tests) locks roster + header validity + endpoint resolution.
Suite: 279 passed + 32 subtests. New lines flake8/black clean (10 long
ENDPOINTS lines carry `# noqa: E501` per repo practice).

## Phase A2: report schema v2 — DONE (2026-10-09)
`save_finding` (sole writer) now emits schema v2: `schema_version: 2`,
`bug_key` (sha256 over host-normalized check + bug_type + assertion_b),
`site_log` pointer, `xref` pointer. Side effects per finding: xref skeleton
(`finding_NNN.xref.json`, arrays empty until checked), `site.log` JSONL event,
upward `_log_of_logs.jsonl` (real tree) with local fallback for custom bases.
Numbering fixed: xref files no longer inflate auto-`n` (max+1 over finding_*.json).
New `test_report_schema_v2.py` (8 tests). Suite: 287 passed + 32 subtests.
Gates: black/flake8-new/mypy/pylint-E/bandit(0M/0H) clean.

## Phase A3: PoC teardown stage (strict) — DONE (2026-10-09)
New `teardown_poc` (seal layer): attacks CONFIRMED proofs with replay x3,
evaluator-sanity (empty output must reject), id_swap 9-fill control
(hosts/ports untouched, scope-gated), fix_mutation SKIP (no fix producer).
Hooked at top of `_finalize_verify` (before persist/synth/chain/report);
FAIL demotes to candidate w/ notes, `poc_teardown` persisted per finding
(None when not run). `is_testnet` threaded from both callers. Real-wire
probe: golden-testbed vuln survives (3/3 live replays re-confirm).
New `test_teardown_poc.py` (8 tests). Suite: 295 passed + 32 subtests.
Golden script: PASS (18 CONFIRMED, 0 benign). Gates: black/flake8-new/
mypy/pylint-E clean; bandit B104 at hunter:4743 pre-existing (string
comparison, not a bind). Also zeroed pre-existing mypy error in triage:46
(verified identical at HEAD).

## Phase A4: harvest engine — BUILT, Proof6 round 1 failed on hang (2026-10-09)
New `oracle_harvest.py` (think/vortex): wire-body corpus (creds/IDs/cookies/
tokens/forms/links), two-step login walker (CookieJar, same-host redirects,
localhost-or-testnet POST rule, 0600 cache), authed re-fetch of known URLs,
bounded ID-range fuzz (±500, standalone-echo hits, cached, abort on dead
host), data-driven reframes (authed replay, IDOR-shaped ID/link cards with
echo expectations, basic/Bearer variants). Hooked into verify on REJECTED +
weak-CONFIRMED. Live probe: harvested test:test, walked login, captured
Flask session on :32768. New `test_harvest.py` (22 tests, stub server).
Proof6 round 1: timeout-1800s, 0 confirmed — died in collaborative review
(3 silent sequential LLM role calls, local backend slow), never reached
verify. Fixes (all tested, `test_proof6_fixes.py` 6 tests): per-seam review
deadline 300s (`_collaborate_bounded`, daemon worker) + progress logs;
flushed log helpers; origin-preserving spec-doc URLs (was https://host/,
dropping scheme+port); sanitized ffuf wordlist (comment lines were fuzzed
as paths); harness runs `python3 -u`. Suite: 323 passed + 32 subtests.
Proof6 round 2: timeout-1800s, 0 confirmed — gear SYSTEM FAILURE (40
seams verified, all REJECTED, 0 harvest lines). Root causes: rendered
asset stripped `test:test` comment; spec URLs dropped scheme/port; ffuf
fuzzed `#` comments; review hang; metachar cards executed. Fixes: `_raw_get`
verbatim companion; Op1 metachar early-drop (`SHELL_METACHARS`, parity
test); bounded review. Proof6 round 3 LAUNCHED (blind XBEN-001-24,
log `lab/hunt_xben_001_24_R3_20261009_164401.log`). Suite: 327 passed
(323 + 4 new Op1/raw tests) + 32 subtests. Scope-gate fixture updated
for Op1 `expected` requirement (contract predates the hook).
R3 scored: hunt COMPLETED (outer timeout ate the score record;
reconstructed: 2 CONFIRMED mentions, GEAR PARTIAL, 1 finding).
Harvest FIRED (0→firing). But: the 1 confirm was a FALSE positive
(Seam 5: B claimed access, expected 403, wire 403 → CONFIRMED —
inverted), and 21/26 rejects died on Gate 4 (no cited source).
R4 Fix 1: Gate 5b verdict direction in `verify_seam_card` — denial/
absence wire supports A, never confirms B; byte-mirror of
`_assess_response` rules 3-4 + parity test (`test_verdict_direction`,
5 tests). R4 Fix 2: reframe authors emit citations —
`reframe_a_source` (inherit parent source, else parent check URL),
wired into harvest + Op2 reframes (`test_reframe_citation`, 5 tests).
Suite: 337 passed + 32 subtests. Bench (ruff/pylint/mypy/black/
bandit/vulture/semgrep/coverage/gitleaks) clean on both fixes;
gitleaks flagged tracked scraped pages with expired AWS temp keys
(user decision pending).
Phase 1 punch (2026-10-11): closed all 5 VERIFIED_STATE.md code items.
scan4me_home() (env→sibling→legacy + expanduser); shared parse_payout
(K/M/B, require_symbol for card prose) wired into bugcrowd/immunefi/
codehawks (+_parse_codehawks_payout helper); payout 0→None coercion at
normalize_program_record + None-guards at hunter:4944/mindset:378;
YWH page loop (20-page cap); Managed substring-clause drop per
LOGIC_AUDIT.md:110. 3 new test files (40 tests). 2-reviewer workflow
caught the immunefi $-prefix regression pre-commit (require_symbol fix).
Suite: 412 passed + 32 subtests. black/mypy clean.
Phase 2 specs (2026-10-11): docs/GATE_SPEC.md (60-case method binding,
bars INITIAL: P≥0.70/R≥0.50/FP≤0.10, recalibration rule, non-blocking),
review-exit stages 0→1→2 + regression rule, bars mirrored to
oracle.config.json quality_gates + tests/test_quality_gates.py guard.
docs/VERDICT_TAIL_SCOPE.md scoped the Phase 4 parse_verdict fix — that
shared `parse_verdict` in `oracle_foundation.py` LANDED 2026-10-20 (E0-1):
anchored first-token grammar (CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE /
UNKNOWN; UNCONFIRMED and hedges are UNKNOWN), and the sweep's inline
substring gate was converted to it. Fail-first receipts captured the old
fake class red pre-patch. E1 live validation still owed; the remaining
delta (sweep verdicts routed through verify_seam_card) stays scoped there. iPhone framing resolved: card format
per BENCHMARK_EVALUATION.md:68, load-bearing via prompt + gates.
Break-it-locally round 1 (2026-10-11): battery ran 0/9 (gate blocked
loopback — harness never declared benchmark) then 0/5 (Op1 killed all
piped cards). Fixes: harness benchmark gate + MODEL override + is_testnet;
strip_safe_truncation (foundation + 2 hunter call sites, hostile pipes
still drop). Verify path PROVEN: test_flaw_battery 4/4 + clean reject.
Reflex compare: 3b header-only 0/20 vs 7b surface-finding 0/36, all honest
wire rejects (403 unvaried, 404 hallucinated, GET-vs-POST). Found+fixed
ORDERS-global pollution of test_known_bugs. Suite: 427 passed + 32
subtests. black/mypy clean (2 pre-existing-drift files untouched).
Break-it round 2 (2026-10-11): adversarial probes. Found REAL holes:
OOS children admitted (deep.secret via wildcard) + ftp: scheme admitted —
both fixed in gate (subdomains=True for OOS; scheme guard), pinned by
tests/test_gate_evasion.py (6 tests). Fleet failover verified in code
(cascade → RuntimeError; assess → INCONCLUSIVE). Prompt-injection exposure
confirmed at 3 points, blast radius bounded, scoped in
docs/PROMPT_HARDENING_SCOPE.md for its own change.
Break-it round 3 (2026-10-11): juice-shop pinned image built (sbom drift
skipped, Node 24 toolchain, loopback-only -p 127.0.0.1:3000, checkout
pristine) and serving 200. Hunt-1 ran code-only (--code skips recon —
my invocation error): 248 seams, 0/17 verified, all Gate-1 grounding
rejects on empty recon; then hung 30+ min post-banner (25 parked threads,
idle Ollama, 30b default loaded vs 7b requested). Fixed _fetch scheme
normalization (crawl4ai ×127 root cause) + tests/test_fetch_cascade.py.
OPEN: code+live combined mode, exit-hang mechanism (thread names next).
Break-it round 4 (2026-10-11): precision surgery for the 0.03-0.09
measurement. Gate 6a (reframe differential vs recorded parent output),
Gate 6b (SPA-fallback control fetch via build_spa_control), generic-marker
stoplist in Gate-5 OR-lists. 7 new tests in test_confirm_gates.py.
Recall guardrail holds: flaw-battery 4/4 + known-bugs green. Suite: 445
passed + 32 subtests. black/mypy clean.
Break-it round 5 (2026-10-11): hunt-3 live-path on fresh juice (7b):
verify 3/411 confirmed (Gate 6 killed the vacuous/spa classes; 2 more
CONFIRMED-then-flipped by 6a). Precision audit vs 0.70 bar: 0.5/3 —
seam 7 FP (public endpoint, bypass never tested), seam 40 FP (miner
fingerprinted `this.options.authToken` plumbing as a secret — sha256
match proven), seam 69 half (exposure real per exposedMetricsChallenge,
header-bypass mechanism fiction). Root cause class: verifier checked
prediction-MATCH, never prediction-ADEQUACY. Fixes: Gate 7 Rules
A/S/B2 (deterministic) + B1/C differentials (hunt path) + post-gate
verdict print (239/240-style flips were hidden behind stale CONFIRMED
lines) + miner quoted-literal requirement (F1). Cloud: PoC stage burned
~16 min/call — urlopen timeout is PER-ADDRESS (16 for Google); fix is
IPv4-first + 8s connect fuse + per-host fail-fast memory. Gemini 404s
(stale model ID) → error-string PoCs; router fell through to groq
(request-too-large) → silent next backend (winner unlogged — gap).
Exit 0, GEAR-TURN PARTIAL (modes unpassed: recalled), report written.
Compound rated the 3 vacuous findings Critical (GIGO — Gate 7 starves
it). Router asked qwen3-coder:30b 15× despite --model 7b (failover
noise — wire --model through). 20 new tests in
tests/test_gate7_adequacy.py (fail-first, incl.
omission-frame guard that caught a B2 over-reach pre-commit). Suite:
465 passed + 32 subtests. black/mypy clean. NEXT: hunt-4 --no-cloud
to prove the local PoC path end-to-end.
Phase 1 hunt-4a (2026-10-11): VOID — juice container died mid-run
(cause undetermined, --rm destroyed the corpse); all 319 checks curl
exit 7, 0 confirmed. Real find: no dead-target abort (20 min burned).
Phase 1 hunt-4b (2026-10-11): 0/396, exit 0, target healthy throughout.
Gates CORRECT: 388 honest wire rejects + 8 rightful post-gate kills
(C x1, B1 x1, 6a x6 — incl. exact hunt-3 FP patterns re-killed live).
Proven recall miss (miner-side, not gates): /metrics confirmable-TP
(200 + token/version/config markers, game-confirmed challenge) cut by
self-observing [:25] cap at alpha-rank 25. Router asked 30b 17x on the
7b hunt (failover noise + 20GB resident).
Phase 2 (2026-10-11): three fail-first fixes. (1) Self-observing ranks
candidates live-first, canonical-short-path-first (sort order can no
longer bury live endpoints; cap untouched). (2) Dead-target circuit
breaker: 10 consecutive transport failures (curl 6/7/28, timeouts)
aborts verify with TARGET UNREACHABLE banner. (3) Router honors the
hunt's --model via set_preferred_local_model (mirrors set_no_cloud),
wired in cmd_hunt; tests/conftest.py resets the process global between
tests (order-dependent router failure caught pre-commit). 5 new tests
in tests/test_phase2_fixes.py. Suite: 470 passed + 32 subtests.
black/mypy clean. NEXT: hunt-4c re-measure (expect /metrics confirm).
Hunt-4c (2026-10-11): 1/392 confirmed — seam 22, the /metrics
self-observing card Phase 2 was built to emit. TRUE POSITIVE (200 +
token/version/config markers, endpoint public per server.ts:695,
game-confirmed exposedMetricsChallenge). Precision 1/1 = 1.0 vs 0.70
bar: PHASE 1 GATE PASSED. The 8 vacuous patterns re-killed. BUT the
PoC leg failed new: local 7b hit the 600s idle timeout with zero
bytes. Root cause: mindset_system is 106KB (~26k tokens) against the
16k local model — the "32k context" sizing comment was wrong.
Phase 2b (2026-10-11): reporting_prompt() (2.3KB: directive + scope
wall + evidence discipline, no corpus/TTPs) threaded through finalize
→ synthesize/correlate → router leg; direct-cloud legs keep full
system (unchanged). Live probe: compact prompt → first byte 58s,
complete 59s (10x inside budget). 3 more fail-first tests. Suite: 473
passed + 32 subtests. black/mypy clean. NEXT: hunt-4d (expect /metrics
confirm + first real local PoC).
Hunt-4d (2026-10-11): 2/392 confirmed. Seam 22 /metrics TP re-confirmed
+ FIRST REAL LOCAL PoC (complete Title/Severity/Repro/PoC/Impact/
Remediation, written by 7b in ~1 min on the lean prompt — PoC LEG
PROVEN). Seam 332 = FALSE POSITIVE (method-override reframe): the
only wire difference was event-loop lag `0` vs `0.5` (float jitter)
plus NaN↔number gauge flips — a full Critical report written on
float noise. Precision 1/2 = 0.50, below bar.
Phase 2c (2026-10-11): normalize_wire_output() (floats collapse as a
unit, NaN/Inf collapse; replaces 4 inline digit-only lambdas across
Gate 6a/6b/B1/C). Unit test + hunt-path jitter replay test (stub
alternates "lag 0"/"lag 0.5" — CONFIRMED pre-fix, REJECTED post).
Live proof: 3/3 real 332-class pairs now IDENTICAL (would reject).
Suite: 475 passed + 32 subtests. black/mypy clean. OPEN (deferred,
not gate-blocking): Engine B dead on local (16x 600s mining timeouts
— needs evidence budgeting, bigger design); severity calibration
(High/Critical for exposure-class is generous).
Phase 3 gate hardening (2026-10-11): DVWA hunt-1 went 0/24 — every
authed check BLOCKED by the blanket metachar substring scan (Cookie
';', query-string '&', POST-body '&' are DATA, not shell CONTROL).
Fix: token-position-aware gate (curl URL/value tokens pass as inert
argv under shell=False; bare tokens still hit allow-list BLOCKED;
slither/forge/cast positionals keep an explicit tripwire).
Independent adversarial review (~90 live attack candidates): PASS,
zero bypasses introduced; its 3 pre-existing findings closed in the
same pass: --data-urlencode name@file read (narrow to that flag —
plain -d @ stays literal), CR/LF -K directive injection (sink raises,
runner BLOCKEDs), post-scope-gate _sub quote/newline breakout
(sanitize at source via new oracle_foundation.sanitize_header_val).
Fail-first: 7 red + 4 guards green; final 11/11. Suite: 487 passed +
32 subtests. black clean on touched lines (test_auth_session.py hunks
are pre-existing drift, verified at HEAD); mypy clean (3 files).
Bench pins committed (dvwa 068d9744, pygoat 19d17cc8) + _split_path
fail-closed on recon garbage. NEXT: DVWA re-hunt authed + precision
audit, pygoat hunt.
DVWA re-hunt (2026-10-11): 4/12 confirmed, exit 0, ZERO BLOCKED (gate
fix proven live). Precision audit (independent live re-fetch): 4/4 TRUE
— /.git/config (262B real git content, seams 1+6 SAME URL), /phpinfo.php
(86KB), /.git/HEAD (ref: master). Precision 1.0 vs 0.70 bar. Defects
logged (reporting layer, human-gated, not fixed): seam-list dedup exists
(`_merge_seams` on (A, B, check), oracle_hunter.py:4570-4572) but did not
collapse the seams 1/6 same-URL pair (3 unique of 4); seam-1 draft names "/self-observe endpoint" (model paraphrase
of template jargon fed by the report prompt, oracle_hunter.py:4210-4213)
while PoC correctly shows /.git/config.
Pygoat hunt-1 (2026-10-11): 1/8 confirmed, exit 0, 0 BLOCKED. Seam 1
/debug = TRUE (15.5KB live log dump: creds-in-URL pattern, tracebacks
with view paths, admin paths). 3 more deterministic matches correctly
post-gate killed (gates working as designed). Precision 1/1 = 1.0.
Seam report clean — the DVWA /self-observe invention is sporadic model
drift (1 of 5 reports), not systematic.
Deep-research workflow (mindset interrogation, 2026-10-11): 6 children.
Verdicts — mitre/seam/iPhone-gate REAL; fused paradox+TTP CUTE (string-
inclusion tests only, zero ablation); axiom framing CUTE (CLI-only,
zero pipeline callers); P0: paradox listed but NEVER executes on
--no-cloud (Engine A inside `if _cloud_up` ~5740; Engine B mitre-only
~5773; log line 5428 reports requested, not effective, profiles) —
self-verified by code read. Phase-3 proof scope corrected: the
deterministic + mitre/seam/template stack generalizes (5/5 TP across
DVWA+pygoat); the paradox lens is unproven locally. DECISION OPEN:
local paradox pass (design change) vs disclose-only log fix (cheap
honesty, recommended first).
Disclose-fix LANDED (2026-10-11): `effective_mindsets()` pure function
in oracle_mindsets.py (paradox⇐cloud, mitre⇐cloud-or-local,
seam⇐always) + hunt log split into Requested/Effective lines with a
warn on mismatch. 4 fail-first tests; suite 491 + 32 subtests;
independent subagent verify PASS (gates mirror exactly, no early
returns, 10/10 re-run, no old-string consumers).
Phase 4 shortlist (2026-10-11): triage scorer top-30 (web2) fed a
5-child research workflow (3 slices + critic + synthesis) re-ranked to
user criteria (new/small/fast over giants): 1. clear (h1, $6k,
2026-03-02, 101 reports, 17 web assets, fast) 2. wealthsimple (h1,
$20k, 262 reports, 6 web assets, fast) 3. tinder (h1, $20k, 128
reports, 8 web assets, fast). All three spot-verified against local
program.json. BLOCKING GAP: no local policy text proves automated
testing explicitly allowed for any pick — policy fetch required after
the user approves one.
**E1 pick made (2026-10-21): tinder** ". Policy gate PASSED live from H1
-graphQL (automated testing allowed, non-destructive; mandatory x-hackerone
header on all testing traffic — compliance landed commit e2704b5+; scope
15: *.tinder.com/*.gotinder.com wildcards + staging + app ids; explicit-outs
go./help./console.). Attribution law: oracle_hunter._attribution_curl_argv +
oracle_harvest._attribution_headers + deeprecon probe merge (tests
test_attribution_header.py, 4 RED-pre-patch receipts).

**First live hunt (2026-10-21): run COMPLETE, verdict = honest zero.**
Funnel: mined=146 followups=954 attempted=1100 det_reject=1100 postgate=0
final=0. Dual-engine: Engine A both lenses submitted+clean, 0 minted (model
databricks:system.ai.gpt-oss-120b); Engine B demoted by design (S6); all
146 mined cards = seam-class templates, MITRE tag unset on card fronts.
Wire regime: NO-CREDENTIAL (--account-a/--cookie never passed) against
session-gated tinder data plane -> 864/892 wire checks = HTTP 502 from
data.gotinder.com nginx edge (only 18x404/8x403). "modes unpassed:
recalled" = variant-sweep gear (:7996), post-confirmation-only —
consequence of zero, not an engine skip. Report: reports/
tinder_20261021_091536.md (gitignored; workspace preserved).
NAMED LESSONS -> (L1) unauth regime cannot dent session-gated APIs —
tinder needs the account regime (--account-a/--account-b/--prompt-login,
2 accounts = policy-legal researcher norm; mass creation banned);
(L2) followup over-mint 6.5x on ONE premise class (router-spelling) —
det-reject rule ids + auth-required premise filter = E1.1, unblocked;
(L3) mitre/paradox LLM lens cards minted 0/2 passes — card-yield
plumbing to audit; (L4) card fronts carry no MITRE tags — unset-field law pending."

**E1.1 rework + E1.2a contracts (2026-10-22).** E1.1-A..E landed
(carry-through tags, auth-feasibility filter, mint cap, slice caps,
scope-empty fail-closed) with regression pins. The mint cap's implicit
20-card default was itself a regression: it starved the pre-existing
crawled-coverage contract (last-alpha page lost its primaries). Cap is
now config-armed only — library default = no cap; live hunts read
oracle.config.json hunt.max_cards_per_family=20; resolver order
prog > CLI > shipped config; 0 = no cap. New oracle_mindset_cages.py
implements the user's law "mindsets are cages, not suggestions":
per-mindset card admission (required fields, T-code/frame/merged_from,
observation basis, wire prediction, rule compliance, scope wall) plus
parallel lane assignment (halves M1/M2, all lanes M3). CONTRACT STATUS:
UNWIRED — cmd_hunt does not import it yet; no live enforcement claim.
Scope wall delegates to the real ProgramScopeGate when passed one;
raw-list mode is never broader than the gate (138,612-case differential
fuzz: 0 cage-accepts/gate-rejects) and fails closed on path-scoped OOS.
Receipts: 23 cage pins + 4 cap pins; suite 1253 passed + 32 subtests,
22 env-skips, 0 failures (188s). Verifier sessions: e9e2e05 (6 holes) →
e9e109a (B1/B3 closure, PASS). Next: E1.2b wiring (cages into producers)
and E1.3 authenticated observation (session → HAR → endpoint/flow model).

Juice funnel dissection (2026-10-11): 6-child workflow counted all 5
juice hunts (headlines independently re-verified by grep): #1 killer
is deterministic-REJECTED, 1828/1896 = 96.4% (per-hunt 88-99%);
#2 post-gate kills, 27/68 det-CONF = 40%; #3 precision-floor 10;
#4 pre-verify drops 5; reflex/dedupe 0. Total survivors 41/1896 =
2.2%. Follow-up expansion explains verify>>mined (all downstream
equations BALANCED).
Funnel instrumentation LANDED (2026-10-11): verify_seams entries now
carry det_verdict + kill_gate (5 post-gate tags 6a/6b/7B1/7C + 6
pre-verify tags); oracle_foundation.build_funnel_counts aggregates;
_write_funnel_artifact writes funnel.json per hunt (both call sites)
plus a one-line Funnel: log summary. 3 fail-first tests; suite 494 +
32 subtests; subagent verify PASS (5/5 tagged, 7/7 keyed, adversarial
probe clean, 3/3 re-run). Notes (not failures): REJECTED+kill combo
unreachable today — a future path tagging one would lose the tag
silently; is_inconclusive never set True (pre-existing dead flag).
Follow-ups (scoped, not built): det-reject by rule A/S/B2 (needs rule
ids in deterministic returns), reflex keep/drop + cumulative
cards-built markers, cross-run nondeterminism (4b 396 vs 4c/4d 392).
Mindset correctness audit (2026-10-11): 6-child workflow + self-verify.
MITRE MIXED (plumbing real; systematic T1078-as-generic-auth-bypass
mistags incl. juice finding_001, T1190/CWE-1104 misfits; Engine B
sweeps all_tactics unfiltered). Paradox/impossible MIXED (real via
Engine A cloud, unwired locally — P0 stands). iPhone: card-shape gate
REAL (correction: workflow's UNWIRED confused the doc with an
undefined separate "level"). Red-team per mindset MIXED (local mitre
YES / paradox NO / seam YES; 10-model swarm + collaborate
cloud-only). User call: recall gate (Phase 3b) BEFORE target pick —
bench recall is exposure-class only, 0 planted app vulns anywhere.
