# Finish Board — single source of truth

Last updated: 2026-10-28 (G2–G4, G6–G8, G10–G11 closed; G5 PUSHED and closed —
private `Bastion-Fold-LLC/invisible-seam` at `81e47b5`; G12 pipeline batch
closed; G13 intake-boundary realignment verified; G14 download/
mindset completeness fixed, verification pending). Audit batch committed across Oracle +
Scan4Me + OmniCLI under code-hunter-extreme. Nothing below counts until
it is committed — that rule is the point of this board.

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
| G5 Code lens extracts 0 claims on PHP (Python/Solidity matchers) | closed | PHP pair added in the invisible-seam tree: `_extract_php_claims` (PHPDoc free-text/@throws with own-declaration binding; @return/native return types, nullable+void/mixed skipped) + `matchers/php_matcher.py` (never-null / throws / declared-type vs brace-matched bodies; strings/comments/nested closures blanked; generic+propagated @throws unjudged; bodiless own-declaration and ambiguous same-name never guessed; checker never builds Python checks for .php/.sol seams). Fail-first tests; invisible-seam suite 88 passed; mypy/ruff clean on changed files (pre-existing residuals in untouched files: mypy cli.py:59, 9 ruff hits). Matomo probe: 0 → 9,928 PHP claims (7,020 type + 2,908 doc), 49 conflicts (47 type + 2 doc), 0 cross-file; Oracle `scan_repository_seams` yields seam cards with zero Oracle code changes. Spark verify: first DISAGREE (name-first misattribution, 508→62 with 11 cross-file) → fixed → re-verify AGREE. Second verifier round 2026-10-27 DISAGREE again with 5 reproduced false-conflict classes (commented-out declarations judged, heredoc text judged, negated "never throws" inverted + lowercase generic @throws judged, spaced `string | null` truncated to non-nullable, same-line docblock misbound) → all fixed fail-closed (shared comment/string/heredoc code mask in extractor+matcher, clause-safe type capture, negation + engine-exception guards, same-line docblock fall-through, unique-only `find_php_function`) with 9 fail-first E2E regressions; seam suite 98 passed, ruff/mypy clean on changed files; Matomo re-probe after fixes unchanged: 9,928 claims, 49 conflicts. Seam now PUSHED 2026-10-28: private repo `Bastion-Fold-LLC/invisible-seam` created, deploy key `SHA256:3jJFdRQPZAfpnrAiZsum+ZO7jWp3ImgR6NRkc1HkT+c` registered with write access, commits `d90955c` + `81e47b5` live on `origin/master` (pushed over the `github-seam` SSH alias). Old Alexander-Sorrell-IT remote kept as `retired`. The PHP lens is no longer local-only |
| G6 Template CERTAIN conflates identifier vs value interpolation (precision) | closed | This commit: `_t_code_sqli_sink` mints CERTAIN only when a dynamic site is in value position (WHERE/HAVING/VALUES/SET/comparison); identifier/fragment sites (backticked tables, prefix/quote helpers, SELECT-list, FROM/JOIN/ORDER BY, placeholder tails, whole-WHERE fragments) mint nothing — grep-card⇒CERTAIN contract preserved. Fail-first `tests/test_sqli_template_precision.py`; cold-benchmark oracle (DVWA/Juice/PyGoat) still passes; impacted suites 87 passed. Matomo sink: 21 hunt cards → 4 payloads (TableLogAction:63/:178, ReportInformational:60, Revenue:91), all value-position. Spark verify AGREE. Residual by design: unmodeled regex shapes keep legacy mint fallback; ORDER BY/dynamic-column injection needs taint proof from other lenses |
| G9 SQLi template regex recall gaps (pre-G6): no hit on LIKE `'%$x%'` or unquoted `= $x` inside double quotes | open | Spark G6 break-it probes V2/V6: `_CODE_SQLI_RE` tail alternatives miss both; classifier now guards precision, so widening is safer than before — separate change |
| G10 M1/M2 lens mega-prompts (72–92k tok) starve both LLM lenses | closed | Full hunt 2026-10-27: cloud-paradox/mitre unparseable/empty, both minted 0, hunt died LENS-STARVED. This commit: lens prompt packing — every TTP (342) / corpus document delivered exactly once across passes capped at 65536tok input (foundations repeat), skeleton mandatory, fail-loud never drop; Engine A + L2 widen both sliced. Fail-first tests (corpus chunks, slices, budget); probe Matomo-shaped: mitre 109612tok → 3 passes ≤63369, paradox 90196 → 3 ≤63037. Spark verify AGREE (byte-identical unsliced prompts 36/36 configs). Live re-hunt with packing not yet run |
| G11 Hunt trusts DB scope; API re-scan only when scope empty | closed | This commit: shared `oracle_bulk_download.refresh_program_scopes` (always intake; a successful non-empty refresh is authoritative: current scopes are replaced and revoked assets move to `scope_intake_removed` history; empty/failed intake keeps known scope stamped unverified); download_one refactored onto it byte-identically; hunt now refreshes every real-platform program. Fail-first tests in `tests/test_bulk_download.py`; impacted suites 36 passed. Spark verify AGREE. Verifier-round residuals closed in G12 batch: authoritative 404 now `vanished` (clears current scope) instead of empty, credential rejection is distinct `auth-error` and hunt refuses stale scope, fresh ineligible records keep OOS truth on the API path, missing eligibility fields fail closed |
| G7 Duplicate program records: PDPrograms mirror authorizes host the H1 record excludes (`matomo.org`) | closed | Scan4Me `8438ca2`: OOS authority unions across duplicate rows (same normalized URL, or same normalized name+handle; bare name never links) in `cmd_check` + export. Fail-first tests; Scan4Me suite 134 passed. Live-DB copy: `check matomo.org` now NOT IN KNOWN SCOPE (H1 id 338 exclusion beats PDPrograms id 7436 mirror), control `matomo.cloud` still AUTHORIZED. Spark verify AGREE |
| G8 Agent-instance XDG config empties OmniCLI keys (0/16) — env trap, fails closed | closed | OmniCLI `e1a9245`: `ConfigManager.key_preflight()` (counts only, no secrets) + `OmniClient._require_api_key` fails loud BEFORE any HTTP (chat_complete raises, chat_stream yields one error chunk) naming env var, configured N/total, config dir, and fix. Empty-dir live probe: exit 1 with `0/14 providers configured in /tmp/omni-empty…` instead of bare 401. OmniCLI suite 538 passed. Spark verify AGREE. Workaround `OMNICLI_CONFIG_DIR` no longer load-bearing for silence — wrong config now screams |
| G12 Canonical pipeline batch (prescan/scan/queue-only chain, feed-trust gate, H1 independent re-scan, product bundles, runlog, OmniCLI conductor) | closed | This commit series: operator mindset selector + integrity bypasses removed (every product hunt M1+M2→M3); `scan` sole verified-context producer, `queue --execute` sole pipeline runner; SHA-256 bundles with separate `ready_for_submission` gate (feed_trust.ok, Oracle re-scan provenance, independent H1 re-scan, per-seam PoC); per-run structured runlog that cannot break a hunt; OmniCLI `oracle-pipeline` conductor complete only with a ready product. Three independent verifiers DISAGREEd on the in-tree batch; every claim adjudicated against code (several verifier claims disproven: pyproject packaging, compound-PoC acceptance, conductor placeholder API). Real blockers fixed fail-first: H1 client redirect forwarded Authorization (S5-class regression) → no-redirect opener; feed trust accepted Scan4Me public listing sources (`live-board`/`live-api`/`pd-repo`/`live-listing`/unknown) → only `authenticated` counted rows trusted; runlog redaction passed unlisted credential variants (accounts/sessions/JWT/Basic/multi-pair cookies) → meaning-class redaction fail-closed; prose scope parser granted wildcards from exclusion clauses → per-clause negation, exclusion wins; `verify_bundle` trusted self-asserted manifest readiness → recomputed from bundled artifacts (+ stale-artifact stamp guard vs hunt mixing); conductor completed on integrity-broken bundles → integrity+exit-code gate; G11 residuals (see G11 row); `--json` stdout kept clean on warn/die; a queued hunt's `_die` no longer freezes the shared runlog. Suites after fixes: Oracle 1433 passed, invisible-seam 98, OmniCLI 545; ruff at HEAD baseline. Not yet exercised live: authenticated prescan→scan→queue chain (Next actions 2–3) |
| G13 Intake boundary realignment (owner workflow: no-login Scan4Me discovery → Oracle independent verify) | verified | In tree, uncommitted. Governing doc `docs/OWNER_INTENDED_WORKFLOW.md` added; doctrine/architecture/P11 reconciled. `prescan --sync` calls Scan4Me `use_auth=False`; `feed_trust` splits authenticated `ok` from fresh `raw_candidate_ok`, malformed provenance (non-bool refresh/stale, non-numeric/NaN/negative age, malformed platforms/count) fails closed, stored prescan trust is always re-derived from provenance, and `allow_public_feed` can no longer mint `ok`. One shared strict record check (`is_independently_verified_entry`: verdict verified, no failed checks, independent+found re-scan, non-bridge source, handle-bound whenever the adapter stamps a handle) gates scan verdicts, deep-dive, download, schedule build, queue execution, and chain hunt; bundle readiness applies the same strict metadata check and additionally requires a present handle bound to `program.json`. Non-H1 `oracle_rescan` returns `no-oracle-adapter` without reading the bridge; product-mode `resolve_fn` and the bridge resolver can never verify; contradictory metadata contributes no `_fresh`. Deep-dive pins scan-fresh `structured_scopes` (no snapshot fall-through), handoff re-derives trust from copied scan provenance, schedule items carry verdict/failures, re-joined handoff entries are validated before download/hunt, and chain hunts pin pick deep-dive assets with chain-vs-final scope-hash stamps. Evidence: fresh-verifier DISAGREE bypasses fixed fail-first; focused set (`test_p11_intake`, `test_p12_queue`, `test_queue_execute`, `test_bundle`, `test_h1_api`, `test_chain_e2e_offline`, `test_hunt_chain`) 185 passed; `make test` 1478 passed, 2 skipped; scoped default ruff on touched Python files back to HEAD baseline (6 pre-existing hunter hits). Live 2026-10-28: `prescan --sync --limit 5` returned 5 raw candidates, exit 0 (artifact `feed_provenance.row_counts.programs=2026` is the synced DB total behind them), `trusted=false`, `ok=false`, `raw_candidate_ok=true`, age 0.0h (`/tmp/oracle-live-g13/prescan_20261028_122425.json`); its `scan -N 1 --download` reached Oracle H1 verify and failed exit 1 only on missing usable H1 credentials (`reports/runs/20261028T122425Z-21d01c3a/summary.json`); bounded non-H1 live scan 0/2 verified, `mode=no-oracle-adapter`, empty handoff, no download (`/tmp/oracle-live-g13-nonh1/scan_20261028_122435.json`, rerun `/tmp/oracle-live-g13b/`). Fresh re-verification round 3: AGREE (all prior bypasses replay-blocked, counts and doc claims corroborated). Adjudicated non-bypasses: explicit synthetic library seams (`require_*=False`, injected synthetic resolvers outside product mode, pick as a provenance-returning resolver) remain opt-outs the product CLI never uses; fully forged consistent local JSON has no signature anchor in the current design. Residuals: non-H1 Oracle API/browser adapters do not exist yet; no live independently verified program until a usable H1 token or a non-H1 adapter exists; download completeness + mindset firing are Stages 3–5 |
| G14 Download completeness + mindset feed/coverage accounting (Stages 3–6 honesty layer) | fixed | In tree, uncommitted. Fresh-verifier round 1 DISAGREE (9 falsifications) fixed fail-first: cascade renders named `rendered` not origin-`obtained`; empty/zero denominator never complete; `download_completeness` recomputes self-asserted fields; hunt download preserves prior missing entries + raw-page failure records; brief shows `status=unknown` with no workspace; regime receipts truthful (session regime only with real auth materials); minted+error slice = unserved; feed-manifest presence judged per feed (in-scope items>0, empty injected seams absent, OOS/downloaded feeds named); M3 src/code corroboration keys lens-neutral. Fresh-verifier round 2 DISAGREE (9 more) fixed fail-first: `_result_obtained` is via-first (cascade via never obtained at any status; rendered bucket via-aware); summarize emits `coverage_pct` and complete requires obtained≥denominator; `download_completeness` fully recomputes (lists required, entries origin-validated + filename flat + on disk in live mode, strict-int denominator, counts must match lists, counts-only never complete, malformed never raises; extracted-bundle mode drops only the on-disk check since bundles never pack asset bodies); scan+hunt cache hits require prior-report validated-obtained provenance (cascade leftovers re-fetch; cache-laundering closed); malformed prior report in hunt named `prior-report-unreadable`, blocks complete; brief shows recomputed verdict; regime receipts rebuilt on observed evidence (`build_regime_receipts`: [200]-tagged injected recon host lines; session regime = auth configured AND ≥1 observed 200; ledger demands `is True` + strict int); M3 non-URL corroboration keys claim content (normalized A/B/expected/check) so production `_parse_seams` restatements survive and rewrites drop, URL probe-bound restatement kept per gauntlet contract; correlation counts returned on every exit and persisted in saved/full/audit reports; bundle cross-checks `yield_ledger` against declared `unserved_mindsets`. Evidence: `make test` 1521 passed/2 skipped; golden hunt PASS; Stage-3 on-disk proof PASS; scoped ruff: only 6 pre-existing `oracle_hunter.py` hits. Fresh-verifier round 3 DISAGREE (Lens C all survived; A/B edges) fixed fail-first: via tokenization keeps digits (`crawl4ai` is cascade), compound/non-string/missing via = unknown provenance; entry shape (flat filename, never the report itself) required in bundle mode too; non-empty on-disk files; duplicate obtained deduped (summarize + completeness); present-but-malformed denominator poisons; rendered files hidden from obtained+missing count missing; scan program-page/corroboration/screenshot caches require prior-report proof; hunt malformed prior-missing named and carried (non-list = one marker), successful raw companions supersede prior raw failures, hunt fetch records real via (`_fetch_with_via`, operator-browser = `browser`); brief expected/methods recomputed; feed manifest counts brief-rendered assets (normalized `_scope_records`, non-empty idents, all scope fields) with brief-identical company/bounty predicates, `_ttp_score`/asset-URL collection normalized (string scopes no longer crash); regime receipts count strict status-token [200]s from tagged `live_hosts.txt` for injected hosts only, and the producers now carry hunt auth (httpx `-H`, direct-probe headers, no fabricated `[200]`); withheld failed slices completed at the accounting boundary (`complete_lens_outcomes` over futures+failed+escalation records) so they cannot vanish from yield aggregation; ledger fail-closes on unknown outcome tokens and non-dict receipts; bundle requires a present, non-empty, well-formed `yield_ledger` (normalized causes) cross-checked against `unserved_mindsets`. Evidence: `make test` 1533 passed/2 skipped; golden hunt PASS; Stage-3 proof PASS; round-3 verifier probes (`/tmp/probe_lensA*.py`, `probe_gap.py`, `probe_bundle.py`, `probe_lensb.py`) rerun all fail-closed; scoped ruff: only 6 pre-existing `oracle_hunter.py` hits. Fresh-verifier round 4 DISAGREE (Lens C all survived again; six A/B items) fixed fail-first: `validated_obtained_files` list-guards non-iterable obtained (no more TypeError crashes at scan/hunt cache sites; hunt prior-obtained iteration likewise guarded); hunt raw-companion cache requires prior-report `raw_companions` ok provenance (planted stale raw re-fetches); feed manifest buckets assets by brief eligibility exactly (submission-ineligible alone = SCOPE NOT LOADED parity, OOS deduped like the brief); bundle ledger must cover `effective_mindsets` exactly (subset/bogus/missing-effective all block); brief missing/not-enumerated detail lines come from the recomputed completeness verdict (`missing_entries`/`not_enumerated`, type-guarded — malformed report fields can no longer crash or char-render the brief); `downloaded_material` feed is completeness-backed, not a file glob; INFO edges closed too (summarize shape-guard, non-positive denominator poisons, ledger non-dict inputs). Evidence: `make test` 1538 passed/2 skipped; golden PASS; Stage-3 proof PASS; round-4 verifier probes (`probe_lensA2.py`, `probe_bundle_r4.py`, `probe_lensb_r4.py`, `probe_gap3.py`) rerun all fail-closed/correct; scoped ruff only 6 pre-existing `oracle_hunter.py` hits. Verifier round 5 pending. Canonical `download_report.json` (`oracle.download-report/v1`) written by BOTH scan/bulk and hunt download paths: expected/attempted/obtained/missing per file, serving sub-method (`cdp/crawl4ai/jina/firecrawl/plain-get/cached` via `oracle_programs._fetch_with_via`), screenshot/repo attempts, deferred lanes in `not_enumerated` (JS-bundle + authenticated app crawl = Stage 3b, named not hidden). `download_one` returns downloaded only when complete (else partial/empty); `already_downloaded` requires a complete report; program brief always shows DOWNLOAD COVERAGE; bundle packs the report and blocks proven-empty downloads. Mindset accounting: slice-aggregated yield outcomes (numbered cloud/local slice origins, any error/refusal poisons clean), origin-based minting, hunter wires real regime receipts, accounting failure = all unserved, bundle requires explicit `unserved_mindsets`. Local fit: paradox slices to the local window (corpus exactly-once, oversized docs split into named parts, foundations not repeated locally), per-tactic MITRE slices with fit checks, distinct `refusal` outcome, pre-submit failures recorded as failed passes. Coverage: per-TTP-code ledger (342 records, description-capping loss named) + per-slice paradox ledger + per-mindset feed manifests persisted per hunt. M3: content-bound corroboration (probe-bound URL subjects, exact candidate keys for src/code), budgeted correlation prompt with counted omissions, synthesis failure defers to wire+report then LENS-STARVED. Evidence: new `tests/test_stage3_completeness.py` + `tests/test_stage456_mindsets.py`; offline canonical chain extended to a ready, integrity-verified bundle; golden hunt PASS (24 confirmed, benign rejected); Stage-3 on-disk proof vs local testbed: partial report with NO_AUTH page named missing. Residuals: gate severity for partial/NO_AUTH downloads and unknown payouts/rules remain owner decisions; no live model hunt rerun this round; Stage 3b lanes unbuilt |

## Candidate census — Matomo tree (2026-10-28)

`scripts/teardown_census.py` assigns every candidate one terminal stage (the
first gate it failed, walking the hunt's own order), so the counts reconcile to
the candidate total. On the 2026-10-27 Matomo findings (53 cards):

| Terminal stage | Count | Share | Meaning |
|---|---|---|---|
| `runnable-check` | 49 | 92% | static PHP conflicts, `verdict=UNSOLVED`, no probe exists to run |
| `teardown` | 4 | 8% | reached teardown, PoC failed replay 0/3 |
| confirmed | 0 | 0% | — |

Accounting: 53/53. Per lens: `invisible-seam` 49 runnable-check,
`seam-template` 4 teardown.

**This corrects the M6 row's framing.** "Teardown demoted 53/53" was wrong:
only 4 candidates ever reached teardown. The blocker for 92% of candidates is
that the PHP code lens emits a *static* check (`grep`, file inspection) with no
observable probe, so nothing downstream can confirm it — a verification-form
gap, not a precision failure. The remaining 8% are a replay failure in the
template PoC, a separate fix.

Evidence: `python3 scripts/teardown_census.py targets/HackerOne/matomo`;
tests `tests/test_teardown_census.py` (9 passed).

## Next actions (ordered)

1. [x] DONE 2026-10-28 — `Bastion-Fold-LLC/invisible-seam` created (private),
   deploy key registered with write access, G5 pushed and `verified → closed`.
   The local tree now tracks `origin/master` via the `github-seam` alias.
2. [user] Provide a usable `HACKERONE_USERNAME` +
   `HACKERONE_API_TOKEN`/`HACKERONE_API_KEY` (via the layered key files,
   never literal argv), and settle the non-API verification *standard*
   (the owner workflow already lists API/Playwright/CDP/other fetch as
   methods; what browser evidence suffices to call a program verified,
   and whether unknown payouts/rules should block, is still open) so a
   non-H1 Oracle adapter can be built. Public Scan4Me platforms stay
   enabled: since G13 they are raw discovery only, and Oracle
   verification creates trust.
3. [agent] First live independently verified program (needs action 2),
   then the live canonical chain `prescan --sync` →
   `scan -N 1 --download` → `queue --execute`, then bundle
   `verify-download` + OmniCLI conductor to `complete`. The same chain
   to a ready bundle is proven offline in
   `tests/test_chain_e2e_offline.py`.
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

Update this file in the same commit as any stage change. If a chat answer
and this board disagree, the board is wrong or the commit is missing — fix
one of them before quoting a %.
