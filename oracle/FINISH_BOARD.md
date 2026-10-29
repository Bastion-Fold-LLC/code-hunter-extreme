# Finish Board — single source of truth

Last updated: 2026-10-28 (G2–G4, G6–G8, G10–G11 closed; G5 PUSHED and closed —
private `Bastion-Fold-LLC/invisible-seam` at `81e47b5`; G12 pipeline batch
closed). Audit batch committed
across Oracle + Scan4Me + OmniCLI under code-hunter-extreme. Nothing below
counts until it is committed — that rule is the point of this board.

## Rules (every agent and audit uses these, no private taxonomies)

- Two finish lines only: **Safety closure** and **Money**. Stages are fixed
  below; add a stage only by editing this file, never in a chat answer.
- Finding/stage states: `open` → `fixed` (in tree, tests pass) →
  `verified` (independent check) → `closed` (committed at HEAD).
  `partial` = some sub-parts fixed, named residuals remain.
- "% done" per finish line = stages at `verified` or `closed` / total stages.
  A second number, "in-tree", counts `fixed` + `partial` too. Both or neither.
- Every state change names its evidence (test run, probe, commit). No evidence,
  no state change. Prior audits live in `~/security-audit-skill/`; this board
  is the rollup, not a replacement for their detail.

## Safety closure — audit findings to closed (10 stages)

| ID | Stage | State | Evidence / residual |
|---|---|---|---|
| S1 | Scan4Me ingest rejects public-suffix wildcards + controls | closed | Tests fail-first then pass; suite 127 passed. Committed. Heuristic suffix subset (e.g. `*.github.io` passes). 6 live brand-TLD rows blocked (`*.aws` …) — owner decision: keep blocked fail-closed |
| S2 | Bridge match-time wildcard guard | closed | Bridge tests pass (61 with remediations). Committed |
| S3 | Execution gate (`ProgramScopeGate`) rejects `*.com` / apex | closed | Fail-first gate test, then guard in `_compile_pattern`; suites pass (gate set 90+47). Committed. Apex-of-registrable-base kept per existing gate contract; full apex parity stays in S4 |
| S4 | One scope matcher (kill 3-matcher desync) | closed | Gate judges normalized hosts: bridge strips outer padding then delegates to `is_host_in_scope` (mirror only names rule + OOS IP safety net); '*.base' = proper subdomains only; gate gained CIDR (IPv4+IPv6) + host verdicts + single-label glued wildcards. Parity vectors pinned (`test_scope_matcher_parity.py`). Eligibility = submission AND bounty via gate parse. Scan4Me keeps its own `scope_match` (Phase E tightened glued to single-label for parity). Verifier v2: no ALLOW-side escape; residuals fail-closed |
| S5 | Redirects never forward tokens (Scan4Me `_api_request`, OmniCLI quota) | closed | No-redirect openers both repos; loopback tests fail-first then pass (Scan4Me 127, quota 22). 3xx now surfaces as error. Committed |
| S6 | Credential containment (sweep redact, rendered, `_run_check`) | closed | Delta + writer scrub + variants (cookie-pair values incl. URL-encoded pair values) in Phase D commit `8658a19`. Residual accepted: arbitrary transforms (base64-of-combined, case, JSON escapes) out of exact-value reach, documented in `_redact_known_secrets` |
| S7 | Scoped fetch SSRF validator | closed | Residual-acceptance reclassification (no new code in Phase D diff): DNS rebind window is a single connect (per-hop revalidation bounds it; no IP pinning), credentialed rendering stays disabled fail-closed (auth DOM-XSS inconclusive), scoped assets plain GET only. Per-hop internals = needs_validation outside this diff |
| S8 | CI supply chain (pins, checksum blocks, frozen lock) | closed | Pins + blocking checksum + frozen `uv.lock` committed. Detect findings stay advisory by doctrine; download/verify is a hard gate |
| S9 | Key precedence + OmniCLI config perms | closed | Runtime env now beats `config.json` (config still beats env files, pinned); config dir 0700 create/heal; corrupt backup born 0600. Fail-first tests; OmniCLI 313 passed. Committed |
| S10 | Delta committed + full suite green at HEAD | closed | Readiness gate 2026-10-25: HEAD suite 1326 passed / 1 failed vs base `bcecc7d` 1210 passed / 3 failed — zero regressions from the batch (4 failures fixed, see gate-triage commit). Remaining failure `test_mutation_testing` is a pre-existing full-suite order flake (fails at base too, passes targeted at both) — tracked, not hunt-blocking |

**Safety: done 10/10 closed (100%) at `8658a19`; S6/S7 residuals accepted explicitly in their rows.**
Stress-test progress: Steps 1–5 done; Phase D (de-hardcode + S4/S6/S7) committed at `8658a19`, verifier-corrected (CDP env wiring, IPv6, glued, whitespace delegation, pair-encoded redaction). Full Oracle suite on Phase D tree: 1332 passed / 5 failed — all 5 fail identically at clean HEAD `07492a0` in this env (4× `test_hunt_code_lens` lens-starve env-dependence + mutation flake); zero Phase D regressions. Phase E closed at Scan4Me `259ab05` (spark-verifier AGREE, revert-pinning proven). Phase F trio smoke PASS at Oracle `dafc1a7` / Scan4Me `259ab05` / OmniCLI `988078d` via `scripts/trio_smoke.py` (real-host agreement + read-only bridge + glued parity).
(top drops fixed: queue modes, verify `--model`/account refusal; sibling
standalone CLIs ~78 flags deferred); output writer scrubs credential
headers at disk boundary + funnel reconciliation pinned.
Baseline controls (scope gate, `_run_check` allowlist, secret-header
committed controls (scope gate, `_run_check` allowlist, secret-header
extraction) predate this board and are the baseline these stages harden.

## Money — first paid finding (8 stages)

| ID | Stage | State | Evidence / blocker |
|---|---|---|---|
| M1 | Intake pipeline live (sync → prescan → scan → queue) | verified | 2,027 programs exercised 2026-10-19 (STATUS.md) |
| M2 | Detector proven on testbeds | verified | Golden hunt, known-bug corpus, cold benchmarks assert recall+precision. Proven detector |
| M3 | One complete live hunt end-to-end | verified | Tinder 2026-10-21 complete, honest zero (0/1,100). Unauth vs session-gated API |
| M4 | Auth plumbed through queue + recon | closed | Queue parser + `_queue_hunt_args` carry resolved auth/accounts; recon derives Bearer from Account A (`_effective_recon_auth`). Fail-first tests; queue/auth suites pass (66+36). Committed. Prompt-login stays direct-hunt only |
| M5 | Authenticated live hunt (2 accounts) | open | USER-ONLY inputs: target approval + 2 accounts via env/file/prompt. Owner decisions 2026-10-25: small/new program first; lens-zero hunts fail loud (`_die_on_unserved_mindsets`, report preserved) |
| M6 | Live confirmed finding ≥ medium, wire evidence | open | Count today: 0. Lens yield blocker (M1/M2 lenses minted 0 on Tinder). Matomo det run 2026-10-26: 22 template candidates, 0/9 manually sampled exploitable (identifier interpolation); code lens 0 claims on PHP. Rerun 2026-10-27 completed to report: 21 template candidates, 0 confirmed (all teardown-failed; sampled Cloud PoC judged bound params/internal identifiers). Post-G5/G6 probes on same tree: 9,928 PHP claims → 49 code-lens conflicts + 4 value-position SQLi payloads; no hunt rerun has consumed them yet |
| M7 | Submission-ready draft + manual submit | open | Submit is USER-ONLY by doctrine. Draft must let a triager reproduce alone |
| M8 | Accepted + paid | open | EXTERNAL: triage days–weeks, then platform payout |

**Money: done 4/8 (50%). In-tree 4/8.** Proven detector, unproven earner —
stages M5–M6 are the gap now, in that order.

## Audit register (rollup)

5 runs in `~/security-audit-skill/`: 46 records — 32 confirmed
(2 high, rest medium/low), 12 needs_validation, 2 rejected.
Run-2 (Oracle standard) artifacts incomplete; do not cite as full coverage.
Needs-validation backlog (no severity until settled): private-invite scope
marking, CDP loopback exposure, cookie behavior across redirects,
listing-href program URLs, verify_http Host override.

## Pipeline exercise — Matomo full run (2026-10-26; rerun 2026-10-27)

Scan4Me → bridge → Oracle code-only hunt → OmniCLI redteam, exercised live.
Worked: trio resolution, H1 record pick, 4-repo clone, `--code-only` policy
path (fixed `08b56f4`), deterministic templates, OmniCLI judge KILLed a
false CERTAIN (agrees with manual read). First runs did NOT complete: both
hunts (local-only, cloud) died at Mindset-3 synthesis; reports/findings
empty. After G2–G4, the 2026-10-27 rerun (`--mindset seam`, cloud) completed
mechanically to report: Scan4Me resolved the H1 Matomo record, snapshots
`wave1`/`pre_synthesis`/`pre_verify` held 21 candidates each, synthesis
completed on a later lane after 403/overflow/timeout slices, and the report
plus 21 finding JSONs + xrefs persisted under `targets/HackerOne/matomo/`.
Result was still 0 confirmed — all 21 template candidates teardown-failed —
and the seam-only run printed `SYSTEM FAILURE … modes unpassed: delayed,
breakthrough, recalled`, so this is not an all-mindset pass. G6 precision
has since closed — the same Matomo tree now mints 4 value-position
payloads instead of 21 CERTAIN cards — and G5 yield is fixed in the
local invisible-seam tree (verified, commit pending there), so a rerun
should now also produce PHP Type-1 code-lens seams (49 conflicts on
probe). Full three-mindset hunt 2026-10-27 (no `--mindset` selector,
cloud): Scan4Me resolved, effective mitre+paradox+seam, 53 candidates
(49 PHP Type-1 + 4 value SQLi), synthesis completed, cross-compare 0
corroborated, local second vote unavailable (Ollama models dir
permission), teardown demoted 53/53, final banner `LENS-STARVED …
SYSTEM FAILURE: 0 confirmed` because both LLM lenses minted 0 on
72–92k-token prompts (report `reports/Matomo_20261027_062048.md`).
That failure is G10, now closed by lens packing; no live hunt has
consumed the packing yet.

| Gap | State | Evidence |
|---|---|---|
| G1 No forced code-only on mixed-scope programs; OOS host in recon seeds | closed | `--code-only` + seed filter, `08b56f4`, fail-first tests |
| G2 Synthesis mega-prompt (~17.4k tok) exceeds groq 8k/local 16k; no per-lane repacking/chunking | closed | `5fe892f` + Spark residuals `e931bf4`: Mindset-3 batches to the smallest viable lane that fits the mandatory base, exact-once packing, oversized seam fails loud (never truncated). Spark re-verify AGREE. Rerun synthesis packing completed instead of dying (cloud: 1 batch, 125952tok budget @128k lane; small-lane packing pinned by `test_plan_synthesis_batches_covers_every_seam_within_budget`) |
| G3 Backend death loses all hunt artifacts (no report/funnel snapshot) | closed | `16c0fbd` + `e931bf4`: best-effort scrubbed atomic seam checkpoints at `wave1`/`pre_synthesis`/`pre_verify`. Spark re-verify AGREE. Rerun persisted all 3 snapshots (21 each) plus `report_full_20261027_041558.md`, verify results, and 21 finding JSONs + xrefs — artifacts survive a zero-confirmed outcome |
| G4 Router: one 110s lane timeout starves later lanes (omnicli/local never tried); status lists 403 lanes as live | closed | `cfe907d` + `e931bf4`: per-lane slices reserve a fair shot for later eligible lanes; down/unavailable/overflow lanes pre-classified out of shares; router-imposed deadlines never trip the breaker (generic provider timeouts still do). Spark re-verify AGREE. Rerun: databricks 403 → groq overflow skip → nvidia/dahl sliced → monkeycode completed synthesis; databricks later `down (cooldown) — skip`. Preflight stays a no-network configured/not-down census by design — first real 403 trips the breaker and can no longer starve the route |
| G5 Code lens extracts 0 claims on PHP (Python/Solidity matchers) | closed | PHP pair added in local invisible-seam tree (NOT yet committed there): `_extract_php_claims` (PHPDoc free-text/@throws with own-declaration binding; @return/native return types, nullable+void/mixed skipped) + `matchers/php_matcher.py` (never-null / throws / declared-type vs brace-matched bodies; strings/comments/nested closures blanked; generic+propagated @throws unjudged; bodiless own-declaration and ambiguous same-name never guessed; checker never builds Python checks for .php/.sol seams). Fail-first tests; invisible-seam suite 88 passed; mypy/ruff clean on changed files (pre-existing residuals in untouched files: mypy cli.py:59, 9 ruff hits). Matomo probe: 0 → 9,928 PHP claims (7,020 type + 2,908 doc), 49 conflicts (47 type + 2 doc), 0 cross-file; Oracle `scan_repository_seams` yields seam cards with zero Oracle code changes. Spark verify: first DISAGREE (name-first misattribution, 508→62 with 11 cross-file) → fixed → re-verify AGREE. Second verifier round 2026-10-27 DISAGREE again with 5 reproduced false-conflict classes (commented-out declarations judged, heredoc text judged, negated "never throws" inverted + lowercase generic @throws judged, spaced `string | null` truncated to non-nullable, same-line docblock misbound) → all fixed fail-closed (shared comment/string/heredoc code mask in extractor+matcher, clause-safe type capture, negation + engine-exception guards, same-line docblock fall-through, unique-only `find_php_function`) with 9 fail-first E2E regressions; seam suite 98 passed, ruff/mypy clean on changed files; Matomo re-probe after fixes unchanged: 9,928 claims, 49 conflicts. Seam now PUSHED 2026-10-28: private repo `Bastion-Fold-LLC/invisible-seam` created, deploy key `SHA256:3jJFdRQPZAfpnrAiZsum+ZO7jWp3ImgR6NRkc1HkT+c` registered with write access, commits `d90955c` + `81e47b5` live on `origin/master` (pushed over the `github-seam` SSH alias). Old Alexander-Sorrell-IT remote kept as `retired`. PHP lens is no longer local-only |
| G6 Template CERTAIN conflates identifier vs value interpolation (precision) | closed | This commit: `_t_code_sqli_sink` mints CERTAIN only when a dynamic site is in value position (WHERE/HAVING/VALUES/SET/comparison); identifier/fragment sites (backticked tables, prefix/quote helpers, SELECT-list, FROM/JOIN/ORDER BY, placeholder tails, whole-WHERE fragments) mint nothing — grep-card⇒CERTAIN contract preserved. Fail-first `tests/test_sqli_template_precision.py`; cold-benchmark oracle (DVWA/Juice/PyGoat) still passes; impacted suites 87 passed. Matomo sink: 21 hunt cards → 4 payloads (TableLogAction:63/:178, ReportInformational:60, Revenue:91), all value-position. Spark verify AGREE. Residual by design: unmodeled regex shapes keep legacy mint fallback; ORDER BY/dynamic-column injection needs taint proof from other lenses |
| G9 SQLi template regex recall gaps (pre-G6): no hit on LIKE `'%$x%'` or unquoted `= $x` inside double quotes | open | Spark G6 break-it probes V2/V6: `_CODE_SQLI_RE` tail alternatives miss both; classifier now guards precision, so widening is safer than before — separate change |
| G10 M1/M2 lens mega-prompts (72–92k tok) starve both LLM lenses | closed | Full hunt 2026-10-27: cloud-paradox/mitre unparseable/empty, both minted 0, hunt died LENS-STARVED. This commit: lens prompt packing — every TTP (342) / corpus document delivered exactly once across passes capped at 65536tok input (foundations repeat), skeleton mandatory, fail-loud never drop; Engine A + L2 widen both sliced. Fail-first tests (corpus chunks, slices, budget); probe Matomo-shaped: mitre 109612tok → 3 passes ≤63369, paradox 90196 → 3 ≤63037. Spark verify AGREE (byte-identical unsliced prompts 36/36 configs). Live re-hunt with packing not yet run |
| G11 Hunt trusts DB scope; API re-scan only when scope empty | closed | This commit: shared `oracle_bulk_download.refresh_program_scopes` (always intake; a successful non-empty refresh is authoritative: current scopes are replaced and revoked assets move to `scope_intake_removed` history; empty/failed intake keeps known scope stamped unverified); download_one refactored onto it byte-identically; hunt now refreshes every real-platform program. Fail-first tests in `tests/test_bulk_download.py`; impacted suites 36 passed. Spark verify AGREE. Verifier-round residuals closed in G12 batch: authoritative 404 now `vanished` (clears current scope) instead of empty, credential rejection is distinct `auth-error` and hunt refuses stale scope, fresh ineligible records keep OOS truth on the API path, missing eligibility fields fail closed |
| G7 Duplicate program records: PDPrograms mirror authorizes host the H1 record excludes (`matomo.org`) | closed | Scan4Me `8438ca2`: OOS authority unions across duplicate rows (same normalized URL, or same normalized name+handle; bare name never links) in `cmd_check` + export. Fail-first tests; Scan4Me suite 134 passed. Live-DB copy: `check matomo.org` now NOT IN KNOWN SCOPE (H1 id 338 exclusion beats PDPrograms id 7436 mirror), control `matomo.cloud` still AUTHORIZED. Spark verify AGREE |
| G8 Agent-instance XDG config empties OmniCLI keys (0/16) — env trap, fails closed | closed | OmniCLI `e1a9245`: `ConfigManager.key_preflight()` (counts only, no secrets) + `OmniClient._require_api_key` fails loud BEFORE any HTTP (chat_complete raises, chat_stream yields one error chunk) naming env var, configured N/total, config dir, and fix. Empty-dir live probe: exit 1 with `0/14 providers configured in /tmp/omni-empty…` instead of bare 401. OmniCLI suite 538 passed. Spark verify AGREE. Workaround `OMNICLI_CONFIG_DIR` no longer load-bearing for silence — wrong config now screams |
| G12 Canonical pipeline batch (prescan/scan/queue-only chain, feed-trust gate, H1 independent re-scan, product bundles, runlog, OmniCLI conductor) | closed | This commit series: operator mindset selector + integrity bypasses removed (every product hunt M1+M2→M3); `scan` sole verified-context producer, `queue --execute` sole pipeline runner; SHA-256 bundles with separate `ready_for_submission` gate (feed_trust.ok, Oracle re-scan provenance, independent H1 re-scan, per-seam PoC); per-run structured runlog that cannot break a hunt; OmniCLI `oracle-pipeline` conductor complete only with a ready product. Three independent verifiers DISAGREEd on the in-tree batch; every claim adjudicated against code (several verifier claims disproven: pyproject packaging, compound-PoC acceptance, conductor placeholder API). Real blockers fixed fail-first: H1 client redirect forwarded Authorization (S5-class regression) → no-redirect opener; feed trust accepted Scan4Me public listing sources (`live-board`/`live-api`/`pd-repo`/`live-listing`/unknown) → only `authenticated` counted rows trusted; runlog redaction passed unlisted credential variants (accounts/sessions/JWT/Basic/multi-pair cookies) → meaning-class redaction fail-closed; prose scope parser granted wildcards from exclusion clauses → per-clause negation, exclusion wins; `verify_bundle` trusted self-asserted manifest readiness → recomputed from bundled artifacts (+ stale-artifact stamp guard vs hunt mixing); conductor completed on integrity-broken bundles → integrity+exit-code gate; G11 residuals (see G11 row); `--json` stdout kept clean on warn/die; a queued hunt's `_die` no longer freezes the shared runlog. Suites after fixes: Oracle 1433 passed, invisible-seam 98, OmniCLI 545; ruff at HEAD baseline. Not yet exercised live: authenticated prescan→scan→queue chain (Next actions 2–3) |

## Candidate census — Matomo tree (2026-10-28)

`scripts/teardown_census.py` assigns every candidate one terminal stage
(first gate it failed, walking the hunt's own order), so the counts reconcile
to the candidate total. On the 2026-10-27 Matomo findings (53 cards):

| Terminal stage | Count | Share | Meaning |
|---|---|---|---|
| `runnable-check` | 49 | 92% | static PHP conflicts, `verdict=UNSOLVED`, no probe exists to run |
| `teardown` | 4 | 8% | reached teardown, PoC failed replay 0/3 |
| confirmed | 0 | 0% | — |

Accounting: 53/53. Per lens: `invisible-seam` 49 runnable-check,
`seam-template` 4 teardown.

**This corrects the M6 row's framing.** "Teardown demoted 53/53" was wrong:
only 4 candidates ever reached teardown. The actual blocker for 92% of
candidates is that the PHP code lens emits a *static* check (`grep`, file
inspection) with no observable probe, so nothing downstream can confirm it —
not a precision failure but a verification-form gap. The remaining 8% are a
replay failure in the template PoC, a separate fix.

Evidence: `python3 scripts/teardown_census.py targets/HackerOne/matomo`;
tests `tests/test_teardown_census.py` (9 passed).

## Next actions (ordered)

1. [x] DONE 2026-10-28 — `Bastion-Fold-LLC/invisible-seam` created (private),
   deploy key registered with write access, G5 pushed and `verified → closed`.
   Local tree now tracks `origin/master` via the `github-seam` alias.
2. [user] In Scan4Me config, disable the public supplemental platforms
   (immunefi `live-board`, sherlock `live-api`, pd_programs `pd-repo`,
   codehawks `live-listing`) for product syncs: since G12 the feed
   gate fails closed while any counted row is unauthenticated.
3. [agent] Live canonical proof: `prescan --sync` →
   `scan -N 1 --download` → `queue --execute`, then bundle
   `verify-download` + OmniCLI conductor to `complete`.
4. [agent] Rerun the full Matomo hunt with lens packing (G10) +
   scope refresh (G11) live; judge M1/M2 yield and survivors.
   Prerequisite for full dual-engine: local Ollama models dir
   permission (`/media/phantomcore` not traversable by ollama user).
5. [agent] G9 regex widening when next touching the SQLi template.
6. [user] Target + policy + 2 accounts → M5 authenticated hunt
   (Matomo self-host accounts we create, or Vinted real accounts via
   `env:`/`@file`/`prompt` — never a literal secret on argv).
7. [agent, later] Deferred flag-matrix tails
   (sibling CLIs, Scan4Me day-flags, OmniCLI chat temp/rotate).
   
   Ordered execution of actions 3–6, with exit criteria per package:
   `COMPLETION_PLAN.md` (P0–P5). P0 is the only one with a clock on it
   (invisible-seam PHP lens lives only in the local tree).

Update this file in the same commit as any stage change. If a chat answer
and this board disagree, the board is wrong or the commit is missing — fix
one of them before quoting a %.
