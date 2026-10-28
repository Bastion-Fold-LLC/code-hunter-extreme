# Improvements Report — Scan4Me + Oracle — 2026-10-19

## Bottom line first (four separate verdicts, do not merge them)

| Question | Verdict |
|---|---|
| Is the code improved and tested? | **Yes.** All test gates green (see §5). Two independent adversarial audits completed; the one blocking defect they found was fixed and re-tested (see §7). |
| Did the full live chain run end to end? | **Partly.** Sync → prescan → scan/verify → top-3 selection → queue build → one queued hunt all executed live. The hunt itself **failed** at the AI-engine analysis stage (see §6). |
| Is there a valid live vulnerability / submittable report? | **No.** The hunt produced 0 findings and 0 report files. |
| Is any money proven? | **No.** No report was submitted (by design, submission is manual), nothing was accepted, nothing was paid. |

## 1. How the system works (current, verified shape)

1. **Scan4Me** (`/home/phantomcore/Scan4Me`) is the discovery sensor. It syncs program
   listings from HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, ProjectDiscovery,
   Bugbase, HackenProof, Cantina, Patchstack, Huntr, Sherlock, and CodeHawks into a
   local SQLite DB. **Hats Finance is absent and Federacy is off by default**, per
   instruction (no accounts there).
2. **Shared triage config**: Oracle's `triage.yaml` is the single boss profile.
   `oracle_scan4me.py` (`triage_prescan_overlay`) maps it onto Scan4Me prescan ranking:
   payout is a **gate** (minimum floor), never a ranking weight; speed/recency windows
   come from the same file. One config governs both programs.
3. **Oracle prescan** reads the Scan4Me DB and emits a shortlist (raw, untrusted).
4. **Oracle scan** re-verifies each shortlisted program against live scope (signed-in /
   API-key / CDP paths where available), then selects top-N verified programs.
5. **`scan --download`** downloads exactly one workspace per selected verified program
   (assets, scope, program brief) under `targets/<Platform>/<program>/`.
6. **`queue`** builds a wave schedule from the handoff (same-site programs are sequenced,
   never run in parallel against one platform). **`queue --execute`** hunts in schedule
   order with `--max-items` cap, per-item state file, resume by stable target identity,
   and failure isolation (one failed hunt does not kill the queue).
7. **Hunt** = recon → dual-mindset AI analysis (MITRE + Paradox lenses) → invisible-seam
   synthesis → red-team verification → severity chaining → report drafting.
   Reports are **never auto-submitted**; a human reviews first.

## 2. Scan4Me improvements

Base: `078c37a` → this change set (`scan4me.py`, `config.example.json`, `tests/test_scan4me.py`).

- **Live-sync crash fixed**: Bugcrowd public-file upsert referenced `contests.max_payout`
  (wrong table) and crashed sync. Now `programs.max_payout` (`scan4me.py:2544`); the
  remaining `contests.max_payout` at `:2222` is correct (it inserts into `contests`).
- **Bad data fails safely instead of crashing**: `_safe_non_negative_float` (NaN/inf/negative/
  garbage payout → `0.0`) and `_coerce_bool` (`"false"/"0"/"off"` can never enable a flag)
  applied across listing sync, payout parsing, and `use_auth`. Filter/enrich/export reject
  non-int or negative limits. Non-dict filter/weight config coerces to `{}`.
- **No fabricated scope**: listing-only platforms (`Bugbase, HackenProof, Cantina, Patchstack,
  Huntr` in `LISTING_ONLY_PLATFORMS`, plus Sherlock bounties and CodeHawks contests) are
  recorded as listings/contests only — **zero invented assets/hosts** (verified in the live
  DB: 0 asset rows joined to those platforms). They get a neutral surface score, not fake scope.
- **Hats/Federacy**: no Hats fetcher exists; `federacy: false` in defaults and
  `config.example.json`, gated at sync. Live prescan provenance: `federacy: skipped, count 0`.
  (One stale pre-existing Federacy DB row, `okteto`, predates this work — leftover, not synced now.)
- **Tests**: suite grew to **121 tests, all passing**, including regression for the Bugcrowd
  payout upsert preserving a known payout.

## 3. Oracle improvements

Base: `b666049` → this change set (12 modified files + 6 new test files, ~1,600 new test lines).

- **`analyze` / `seams` / `verify` resume correctly** (`oracle_hunter.py`): a shared workspace
  resolver finds the hunt root from parent metadata and descends into `recon/`. Standalone
  resume on an existing workspace no longer dies with `[no recon data found]`.
- **`hunt --controlled` is real**: the flag now actually reaches recon (was parsed but dead).
- **`scan --download` wired**: downloads workspaces for exactly the selected verified
  programs via `oracle_intake.download_selected_workspaces`, mapping handoff entries to the
  downloader's program shape (`_prog_for_download`). Per-program failures are recorded as
  `workspace.status=error` and never abort the rest. Unverified programs are never touched.
- **`queue --execute` built and hardened** (`oracle_queue.py`): wave execution, same-site
  sequencing, `--max-items` validation (bad values rejected), resume keyed by stable target
  identity + schedule fingerprint, `SystemExit` inside a hunt is contained per-item, and
  only the schedule's own handoff can feed downloads (wrong-handoff downloads are refused).
- **Bulk-download crash fixed** (`oracle_bulk_download.py`): module-level
  `datetime, timezone` import. The live run exposed `UnboundLocalError: datetime` when
  writing manifests; assets had downloaded but manifests were missing. Regression-tested
  in `tests/test_bulk_download.py`. Note: the original live handoff JSON still honestly
  records those three workspaces as `error` — history was not rewritten.
- **Intake validation** (`oracle_intake.py`): prescan `--limit` and scan `-N` reject bools,
  non-ints, and negatives; the DNS-target predicate is now the single shared hunter
  implementation with **no divergent local fallback** (import failure fails closed), so
  mobile app IDs / store IDs can no longer slip through as "hostnames".
- **Flag contracts tested as contracts** (`tests/test_p1_flag_contracts.py`,
  `tests/test_chain_e2e_offline.py`): flags are exercised through real code paths offline,
  not merely checked for presence in `--help`.

## 4. Severity chaining (small → medium → high → critical → max critical)

Implemented in `oracle_mindset_context.py` (`chain_seams`, `_rank_entry`, `_parse_severity`)
and `oracle_mindsets.py`. Rules, all regression-tested in `tests/test_severity_ladder.py`
(**71 tests**):

- **Start at the highest verified level.** A chain's anchor is the strongest directly
  verified primitive in it. If a High is already proven, chaining starts from High.
- **One compounding step only.** A complete, verified chain (producer output demonstrably
  consumed by the sink, bound on exact observed wire values) adds exactly **one** severity
  step: Low→Medium, Medium→High, High→Critical. Critical is the cap ("max critical" =
  Critical anchored on a verified Critical/High primitive, ordered first).
- **Length never manufactures severity.** Six chained Lows still cap at Medium.
  Count-based promotion to Critical is impossible by construction (`min(max+1, 4)`).
- **Structured severity beats wording.** A recognized structured severity (critical/high/
  medium/low/info + aliases moderate/med/informational) decides the rank. Free-text impact
  is consulted only when no structured severity is present.
- **Unknown/negated severity fails closed.** Negated clauses ("not critical",
  "cannot lead to account takeover", mitigated phrasings like "prevents / blocks /
  patched / previously") are stripped before ranking; unknown impact text ranks info (0).
- **Unconfirmed findings never compose.** Explicit negative/candidate/pending verdicts on
  the wrapper, verify result, or nested seam block chaining. Duplicate copies of one
  finding are de-duplicated and cannot self-chain.
- **Chains sort highest-first** (combined severity, then depth), so the strongest chain is
  reviewed and reported first.

**Audit blocker found and fixed today (S1):** an independent auditor reproduced that a
*present but unparseable* structured severity (`"P4"`, `"bogus"`, `"9.8"`, `"not critical"`,
`"low (not high)"`) silently fell through to free-text impact ranking, so hot impact wording
("Critical account takeover") manufactured a **Critical** chain. Fixed: a present structured
severity now decides — unparseable/fully-negated values rank **0**, never fall through.
The negation lexicon also gained mitigated phrasings (prevents/blocks/patched/unlikely/
previously/formerly). Reproduced before the fix (11 failing cases in `/tmp/repro_s1.py`),
all pass after; durable regression cases added to `tests/test_severity_ladder.py`.
A second recheck then broke the first fix two more ways, both now fixed: negators stranded
across clause separators (`"patched: critical"` survived as `critical`) and container
severities (`["critical"]`, `{"note": "critical"}`) being string-scanned. Structured
severity now fails closed if any negation/mitigation marker appears anywhere in it, and
only plain strings are canonicalized. By established design, a blank severity means
"absent" (impact wording then ranks); homoglyph/fullwidth spellings under-rank
(fail-closed direction). Ladder suite is now **71 tests**.

## 5. Testing infrastructure — what was actually run

Run by the author in this session, after the S1 fix:

| Gate | Command | Result |
|---|---|---|
| Scan4Me suite | `python3 -m pytest -q tests/test_scan4me.py` (in Scan4Me) | **121 passed** |
| Oracle focused production set | `pytest` on severity ladder, analyze workspace, queue execute, chain e2e, flag contracts, bulk download, code lens, p12 queue, mindsets | **227 passed** |
| Oracle unified layers | `python3 tests/run_all.py` | **All 10 layers PASS** (card smoke, injection templates, wordlist, golden hunt, red-team verifier+chain, severity ladder 71, OmniCLI gates, known-bug corpus 13/13, web3 layer, 3-mindset gauntlet) |

Environment caveat, proven not assumed: the first `run_all.py` run failed 3 testbed layers
with `Connection refused` / `status None`. Cause was the sandbox proxy: `NO_PROXY` was empty,
so `127.0.0.1:8765` testbed traffic was routed to the proxy. With
`NO_PROXY=127.0.0.1,localhost` the identical code passes every layer. Local runs of
`run_all.py` should set `NO_PROXY=127.0.0.1,localhost`.

New test files added with this work: `tests/test_severity_ladder.py` (502 lines),
`tests/test_queue_execute.py` (430), `tests/test_analyze_workspace.py` (221),
`tests/test_p1_flag_contracts.py` (206), `tests/test_chain_e2e_offline.py` (181),
`tests/test_bulk_download.py` (48). `tests/run_all.py` now includes the severity-ladder layer.

## 6. Live gate run — 2026-10-19 (evidence: `reports/live_gate_20261019/`)

Canonical flow executed live, in order, with retained artifacts:

1. **DB backup** taken (`00_backup.txt`).
2. **Scan4Me sync** (`01_sync.log`): **2,027 programs / 48,699 assets** (3,618 wildcards,
   12,306 tombstoned; 303 Sherlock contests tracked separately). Per platform: HackerOne 449,
   Bugcrowd 298, Intigriti 145, YesWeHack 56, Immunefi 157, ProjectDiscovery 802, Bugbase 20,
   HackenProof 19, Cantina 10, Patchstack 28, Huntr 4, Sherlock bounties 39, CodeHawks 44.
3. **Prescan** (`02_prescan.log`): 24 programs, untrusted, `--no-cloud`.
4. **Scan/verify** (`03_scan.log`): **10/24 verified**. Top 3 selected: **Here Technologies**
   [Intigriti, 85.8, 18 assets], **WP Engine** [Intigriti, 85.8, 15], **Spotify**
   [PDPrograms, 85.3, 23].
5. **Queue build** (`04_queue_build.log`): 3 waves, one program per wave.
6. **One controlled queued hunt** (`05_queue_execute.log`, `--max-items 1 --controlled`):
   Here Technologies only. **Result: FAILED** (`attempted=1 done=0/3 failed=1`).

What the hunt proved: workspace download (18 assets; 19 ok / 83 failed fetches) and recon
worked — 18 scope seeds, 52 DNS records, **12 live hosts**, 36,990 katana paths, 9 template
seam candidates injected. What killed it: the AI backends. Degraded components, stated
plainly (these are **not** healthy outputs):

- **Databricks lane: exhausted** (all four models returned `None`).
- **Groq lane: request too large** for both `gpt-oss-120b` and `gpt-oss-20b` on this prompt.
- **OpenRouter mitre/paradox passes: dropped** at the 420 s engine-collection deadline,
  then the L1 retry hit the round budget. Zero engine responses for both lenses.
- **Mindset-3 synthesis** (NVIDIA lane) completed but produced no new cards.
- Terminal error, fail-closed by design: `synthesize input: lens(es) mitre, paradox
  produced no output object — refusing to unify short a lens` → `SystemExit(1)`,
  recorded per-item in `queue_state_a0f7dc36465965fe.json`.
- **CDP program-page render failed** (`CDP_RENDER_FAILED`) during downloads even though the
  CDP version endpoint was up; authenticated-page completeness is unproven.
- **Not all configured keys were exercised.** Prescan ran `--no-cloud` (an operator
  choice for that run; the default is cloud-on), which disables Firecrawl and cloud
  models for the prescan stage. Scan and hunt ran cloud-on. The shared fetch cascade is
  CDP → Crawl4AI → Jina → Firecrawl → plain GET, so Firecrawl only fires when the first
  three fail — and provider *success* is silent in logs, so the logs cannot prove how
  often Firecrawl actually served content (an observability gap, now partially closed:
  non-OK Firecrawl responses log a warning). AI lanes attempted: Databricks, Groq,
  OpenRouter, NVIDIA, local. No log evidence that Gemini, Anthropic, Tavily, or
  Cloudflare fired.
- **Scope was not re-verified against the source that run (design flaw, fixed after).**
  `download_one` only ran platform scope intake (API keys / signed-in adapters) when the
  program had *no* scopes yet; handoff entries always carry DB scopes, so in the
  canonical flow the keys never re-fetched scope. Scan verification that run was
  live-host probing (`check_scope_live`: a host must serve HTTP/S; contract scope can
  verify via `eth_getCode`/repo-URL existence). Fixed in this change set: download now
  always refreshes scope from the platform source, merges fresh assets into existing
  scope, and records `scope_intake_status`/`scope_intake_at`/`scope_intake_new` on the
  program; a failed intake never deletes known scope. Regression-tested in
  `tests/test_bulk_download.py`.
- Several in-scope HERE hosts simply do not resolve (`registry.service.api.platform.here.com`,
  `mobilitygraph.hereapi.com`, `listing.here.com` — DNS `ERR_NAME_NOT_RESOLVED`).
- **Listing-only platforms remain unverified end-to-end**: every Cantina / Immunefi /
  Sherlock / HackenProof / Patchstack / Huntr / Bugbase entry failed `scope_live` (they have
  no DNS/contract hosts to verify). Their discovery works; their hunt readiness does not yet.

**Findings: none.** `targets/Intigriti/here_technologies/findings/` and `reports/` are empty.
No report exists to review, nothing was submitted, no payout is claimed. The next live hunt
needs working engine capacity (smaller prompts or healthy Databricks/Groq/OpenRouter lanes)
before it can prove finding quality.

## 7. Independent audit results

Two adversarial subagent audits read the full uncommitted diffs and live evidence
(they were instructed to falsify, not confirm):

- **Scan4Me diff: SAFE TO COMMIT.** Payout SQL, fail-safe parsing, Hats/Federacy exclusion,
  no fabricated listing scope, and triage-overlay wiring all verified against code + live DB.
- **Oracle diff: NOT SAFE as written — one required fix (S1, §4), now fixed and re-tested.**
  Claims (1) workspace resume, (2) `--controlled`, (3) exact-selection downloads, and
  (4) queue waves/cap/failure-isolation held on their production paths.

Known follow-ups the audits reproduced but rated non-blocking (**not fixed in this change
set — listed so they are not forgotten**):

1. **Queue resume vs re-ranking (Q2):** item identity includes `handoff_rank` and the
   schedule fingerprint includes position/wave, so a fresh scan that reorders programs
   defeats resume and re-hunts completed items. Identical rebuilds resume correctly.
2. **Verify fast-path needle mismatch (A1):** existing-report lookup uses raw display
   names while report files are `_sanitize()`d, so `verify` usually re-runs full analysis.
   Correct results, wasted cost.
3. **Queue minors:** `max_items=0` writes no state file yet reports a `state_path`;
   corrupt state JSON is swallowed (silent full re-hunt); hand-crafted schedules with
   mixed-type `wave` or case-variant site names can crash or parallel-run (builder-emitted
   schedules are safe).
4. **Scan4Me residuals (pre-existing, outside this diff):** authenticated fetchers for
   Bugcrowd/Intigriti/YesWeHack and `_normalize_weights` still use bare `float()`.
5. **Stale DB row:** one pre-existing live Federacy row (`okteto`) predates the exclusion.

## 8. How the commit is updated (and how to do it next time)

Repositories (separate commits, separate pushes — never one mixed commit):

- Oracle: `https://github.com/code-hunter-extreme/oracle.git`, branch `main`,
  base `b6660496ff5c8694169fb05ddcc77b7b5509a818`.
- Scan4Me: `https://github.com/code-hunter-extreme/Scan4Me.git`, branch `main`,
  base `078c37a96b108aa9775c0b3ac0ee8345f0b8fcc0`.

**Deliberately excluded from both commits** (local-only state, not source):
Oracle `.mcp.json`, Oracle `targets/PDPrograms/` workspace, Scan4Me `scan4me.db.bak-*`
backups, and all `targets/` / `reports/` runtime output (already gitignored).

Exact update procedure used for this change set:

```bash
# Oracle
cd /home/phantomcore/oracle
git add oracle_bulk_download.py oracle_hunter.py oracle_intake.py \
  oracle_mindset_context.py oracle_mindsets.py oracle_programs.py \
  oracle_queue.py oracle_scan4me.py \
  tests/run_all.py tests/test_hunt_code_lens.py tests/test_mindsets.py \
  tests/test_p12_queue.py tests/test_analyze_workspace.py tests/test_bulk_download.py \
  tests/test_chain_e2e_offline.py tests/test_p1_flag_contracts.py \
  tests/test_queue_execute.py tests/test_severity_ladder.py \
  IMPROVEMENTS_REPORT_2026-10-19.md
git commit -m "feat(oracle): wire scan-download-queue production chain and harden severity ladder"
git push origin main

# Scan4Me
cd /home/phantomcore/Scan4Me
git add scan4me.py config.example.json tests/test_scan4me.py
git commit -m "fix(scan4me): repair Bugcrowd payout sync and fail safely on bad listing data"
git push origin main
```

Verify the push actually landed (do not trust exit 0 alone) — local `HEAD` must equal the
remote `main` SHA in **both** repos:

```bash
git -C /home/phantomcore/oracle  rev-parse HEAD
git -C /home/phantomcore/oracle  ls-remote origin refs/heads/main
git -C /home/phantomcore/Scan4Me rev-parse HEAD
git -C /home/phantomcore/Scan4Me ls-remote origin refs/heads/main
```

Rules for future updates: stage files by explicit name (never `git add -A` — it would sweep
in DB backups, target workspaces, and `.mcp.json`); run the §5 gates first; keep Oracle and
Scan4Me commits separate; never rewrite history to hide a bad live result — record it and
fix forward.

## Addendum (same day) — multi-path verification, and a framing correction

Correction to §6 wording: empty/placeholder platform API tokens are **not a system hole**.
The credential design is: platform API keys where they exist, otherwise the operator's
**saved signed-in CDP session**. And the multiple fetch paths are not a failover pecking
order to stop using — they exist so independent renders can **verify each other**. The
code did not fully live up to that: the fetch cascade returned the first success and
recorded nothing about which path served what. Fixed in this addendum's change set
(`oracle_scan.py`, `oracle_bulk_download.py`, `tests/test_scan_download_multipath.py`):

- **Program page corroboration.** The saved CDP session remains the only authoritative
  program-page source (existing platform rule; failure stays loud, nothing is faked).
  Every download now *also* fetches an independent render via Crawl4AI → Jina →
  Firecrawl → plain GET (CDP excluded, so agreement is genuine), saves it as
  `program_page_corroboration.txt`, and records agreement metrics in
  `download_report.json`: fetched/bytes, program-name match, and which in-scope hosts
  the independent render mentions. Corroboration cross-checks; it never substitutes.
- **Second path for target assets.** When plain GET fails on a renderable asset
  (homepage/HTML/text), the cascade tries to render it. Cascade content is saved for
  analysis with `via: "cascade"` but is **not** counted as a verified 2xx download, so
  multi-path data cannot inflate verified counts. Every download result now records its
  `via` path (`plain-get` / `cascade` / `cached`), closing the provenance gap.
- **Scope cross-check both directions.** Source scope refresh now also records
  `scope_intake_fresh` and `scope_intake_missing` (assets the source no longer lists),
  alongside `scope_intake_new`.

Live proof after the fix (real network, operator keys): Firecrawl returned 2,241 bytes
of raw HTML for a test URL in 6.7 s; Jina returned 1,081 bytes; the full cascade fell
through a sandbox-only Crawl4AI failure to Jina correctly; an end-to-end
`download_program_assets` run with no CDP session correctly reported
`page_source: NO_AUTH_SESSION` while corroboration independently fetched the page with
`name_match: true, scope_hits: 1`. Platform token state (for the operator, unchanged):
most platform tokens in `ORACLE_KEYS.env` are empty or placeholder notes and are rejected
as such; `INTIGRITI_SECRET` returned HTTP 401 against the researcher API (not a bearer
token); `HACKENPROOF_API_KEY` is present and well-formed. With no API tokens, the saved
CDP session is the credential path — by design.

## Addendum 2 (same day) — engine starvation fix

The HERE hunt died at analysis: passes are concurrent, but each pass walked its API
lanes/models strictly serially with no memory, so dead lanes (Databricks HTTP 400 on
every model, Groq TPM rejections) were re-walked from the top on every pass and ladder
round until the 420s/180s budgets died. Measured root sizes: mitre-full system prompt
~68k est. tokens, paradox-full ~106k (recon enters the task already prioritized to
~7.7k chars — the system corpora are the size, by design, and were not cut). Fixes in
`oracle_llm.py` / `oracle_hunter.py` / `oracle_backends.json`, all regression-tested in
`tests/test_llm_lane_health.py`:

- **Per-lane request caps** (`max_request_tokens`, Groq = 8000): lanes that would reject
  a request far below their context window are skipped fast by `fits()`, never called.
  Invalid/zero caps fail closed without raising.
- **Total time budgets, end to end**: router `timeout` is now the total across lanes
  (each lane gets only the time left); inside a lane it is the total across models
  (per-call caps preserved); transient retries survive but shrink to the deadline.
  Engine-A passes run at 360s (< 420s collect), ladder at 170s (< 180s round),
  Mindset-3 synthesis at 360s.
- **Per-run circuit breaker (600s cooldown)**: a lane that exhausts its models is
  skipped on later passes/rounds instead of re-walked. It never trips for the sole
  lane, budget-starved slices (<30s), our own lane-deadline cuts, or size rejections;
  light/heavy local models key separately so they cannot poison each other;
  `collaborate()` honors and feeds the same breaker. Success clears a lane instantly.

Live proof after the fix (real API lanes; the infrastructure is API-first, local is
only the floor/second vote): 9 of 13 reflex lanes answered a probe (nvidia, cloudflare,
llm7, xkiro, bynara, monkeycode, openrouter, dahl, omnicli); Databricks failed HTTP 400
on all models, Apinex HTTP 402 (daily check-in), Groq timed out through the sandbox
proxy, local Ollama was down. A real 68k-token mitre hunt prompt then completed through
the router in **99.6s** (Databricks failed fast, Groq skipped by cap with no API call,
NVIDIA served it). An adversarial recheck broke the first breaker version four ways
(budget-edge poisoning, name-only cross-talk, retry loss, cooldown shorter than the
collect window); all four are fixed above and its probe suite now passes. Still open:
OmniCLI's lane ignores its timeout argument (pre-existing), Databricks' HTTP 400 root
cause is undiagnosed (lane stays skipped while down), and no live hunt has yet run
end-to-end on healthy lanes — that is the next proof owed.

## Addendum 3 (same day) — saved-session retrieval bug, and the bug record

Record, stated correctly: this system has repeatedly found every planted bug in its
testbeds (golden hunt: every planted vuln confirmed, every benign control rejected;
known-bug corpus 13/13; full gauntlet PASS — re-verified in the 2026-10-20 full-suite green run (1148 passed)). That is proven detection ability on test code. It has not yet produced a live
paid-target finding, because the one full live hunt died at engine analysis (§6) and
its authoritative program page died even earlier, for the reason below. Those are two
different statements and must not be merged.

The HERE hunt's `CDP_RENDER_FAILED` was a code bug, not the browser: the saved-session
Chromium was up (`auth_session: True`), but `oracle_scan._cdp_page_text` created its
tab with `GET /json/new`, which Chrome ≥111 answers `405 Method Not Allowed`, and the
exception was swallowed silently. `oracle_programs` already used `PUT` (its CDP fetch
worked); the scan path was missed. Fixed: PUT, and failures now print their reason.
Live-verified against the operator's running browser: Intigriti HERE page 11,146 bytes
and HackerOne Spotify page 16,412 bytes of rendered program/scope text via the saved
session, where the old code returned 0 bytes instantly. Method comparison on the same
real pages: Firecrawl (592k/314k bytes), Crawl4AI (460k/301k), Jina (34k/0.8k), plain
GET (541k on largely-public Intigriti, 3.5k shell on HackerOne) — multiple independent
paths retrieve real website data, and the corroboration render (§Addendum) cross-checks
the authenticated page against them. Regression tests: `tests/test_cdp_page_text.py`.
