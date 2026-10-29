# Oracle Doctrine

Owner decisions, recorded 2026-10-12 (updated 2026-10-28). This doc is
the authority when code and docs disagree, together with
`docs/OWNER_INTENDED_WORKFLOW.md` for pipeline workflow and mindset
composition. Anything marked OPEN is a proposed default awaiting
correction.

## 1. Three mindsets, equal citizens

- **Mindset 1 = full-weight MITRE.** Real technique definitions, full tactic
  sweep. Nothing overlays or clobbers the ATT&CK text it reasons with.
- **Mindset 2 = philosophy + impossible problems + paradoxes + iPhone framing.**
- **Both lenses receive the same three feeds:** invisible-seam candidates,
  red-teaming, and bounty context (verified asset, verified in-scope and
  out-of-scope assets, company info, bounty rules). Bounty context is
  Oracle-verified material, never raw Scan4Me discovery output.
- The invisible seam is the shared object both lenses reason over and both
  red-team.
- **Mindset 3 = SYNTHESIS of Mindsets 1+2.** Takes both lenses' seam outputs
  plus the deterministic seam candidates plus red-team verdicts and produces
  the single unified ranked result. It runs its own adversarial pass (attack
  candidates, discard noise, chain compounds) and then unifies — it never
  invents seams that neither lens nor the deterministic feed produced.

## 2. Engines: API-first, local fallback

Oracle runs primarily on API engines (13 routed lanes per task in
`oracle_backends.json`: databricks → groq → nvidia → dahl → monkeycode →
bynara → openrouter → llm7 → cloudflare → xkiro → apinex → omnicli → local;
fixed route order (round-robin rotation exists but is OFF in shipped config, `round_robin: false`)). Local models remain supported as the floor/second-vote path,
not the main path. Bench hunts (`--no-cloud`) prove the fallback; real hunts
run the APIs.

Lane health is doctrine, not tuning: `oracle_llm.complete()` treats `timeout`
as the **total** budget across lanes (and inside a lane, across its models);
per-lane `max_request_tokens` caps keep oversized prompts off lanes that would
reject them (Groq: 8000); a per-run circuit breaker (600s) skips lanes that
have exhausted their models instead of re-walking them on every pass — it never
trips for the sole lane, budget-starved slices, our own deadline cuts, or size
rejections. Hunt passes run Engine-A 360s / ladder 170s / Mindset-3 360s.

## 3. Intake pipeline: prescan → scan → download → queue → hunt

> **BUILT (P11).** Implemented in `oracle_intake.py`, wired to
> `oracle-hunter prescan` / `--prescan` and `oracle-hunter scan -N/--top-n/
> --sites` (`oracle_hunter.py` `cmd_prescan` / `cmd_scan`). Intel comes from
> the `oracle_scan4me` bridge (local ranked DB; `--sync` refreshes first).

1. `--prescan` (`run_prescan`) — fast **no-login** Scan4Me sweep
   (`--sync` calls Scan4Me with `use_auth=False`). Produces a **prescan
   report**. Raw, untrusted candidate material; nothing downstream trusts
   it yet. Public provenance may proceed to verification, but an
   unavailable, stale, or failed-refresh feed may not supply candidates.
2. `scan` (`run_scan` → `verify_program`) — Oracle's independent
   verification pass over the prescan. Produces a **scan report** with a
   verdict per program. Trust is created here, per program, from
   Oracle's own platform API/browser re-fetch — never from Scan4Me's DB
   copy of the same listing. Only independently verified programs proceed.
3. `-N` (`select_deep_dive` + `write_handoff`) — deep-dive the top N
   **independently verified** programs: pull full asset, company info,
   and resources. Naming sites explicitly (`--sites`) overrides the
   count. Deep-dive assets come from the scan verdict's embedded fresh
   listing, never from the prescan snapshot and never re-resolved through
   the Scan4Me DB.
4. `--download` (`download_selected_workspaces`) — exactly one workspace per
   selected independently verified program (never unverified or
   bridge-only). Every download writes a canonical `download_report.json`
   (expected/attempted/obtained/missing per file, serving method per
   file, deferred lanes named in `not_enumerated`); partial says
   partial everywhere, and ``already_downloaded`` only accepts a
   complete report. Scope was established at `scan`; download/hunt refreshes
   from the platform source (API keys where they exist, saved signed-in
   CDP session otherwise) and records the outcome, but a failed or empty
   refresh never upgrades retained scope into verified truth. Downloads
   are multi-path: the saved-session CDP render is authoritative for
   authenticated platform pages (no anonymous substitute), an independent
   Crawl4AI/Jina/Firecrawl/GET render corroborates it, and every result
   records which path served it.
5. Pick a company → its full info loads into **all three** mindsets as
   bounty context. Then hunt. Each hunt persists per-mindset feed
   manifests (`reports/feed_manifests.json`: required feed → present,
   source, size, known loss such as TTP description capping) and
   coverage ledgers (`reports/lens_coverage_ledger.json`: per-TTP-code
   dispositions and per-slice paradox outcomes) behind its yield
   verdicts. Local lenses slice to the local window (corpus documents
   delivered exactly once, oversized documents split into named parts)
   or fail as explicit failed passes — never silently unsubmitted. A
   failed M3 synthesis pass defers like a dead lens: candidates still
   reach wire verification and the report, then the hunt fails
   LENS-STARVED. A chain (queued) hunt is pinned to the
   exact scan-verified deep-dive assets carried by its schedule pick:
   program resolution may supply metadata, but a Scan4Me DB re-resolution
   never supplies its scope. The hunt-time platform refresh may then
   authoritatively replace that set, and the hunt snapshot stamps both
   the chain scope hash and the final hunted scope hash/intake status.

### Verify-pass definition (BUILT — P11, `verify_program`)

A program is "accurate" iff Oracle independently re-fetched the fresh
program through its own adapter (`oracle_rescan.independent=true`,
`found=true`) and no verify leg blocks against that fresh listing:

- Scope URLs resolve / are live (fail-closed: must pass);
- Payouts match the platform listing (tri-state: only a proven
  mismatch/missing value blocks; unknown is recorded, not treated as a
  match);
- Bounty rules text is unchanged since prescan (advisory: only a proven
  change blocks; unavailable rules text is unknown, never faked).

Built today: the only Oracle verify adapter is HackerOne's authenticated
API. Other platforms have no Oracle API/browser verify adapter yet and
cannot verify. A Scan4Me DB copy, a missing platform adapter, or a
skipped re-scan can never satisfy the independent precondition, however
the three legs look. Whether unknown payouts/rules should eventually
block (the stronger reading of the owner workflow's Stage 2) is an open
owner decision — until settled, unknown stays explicit in the verdict
checks rather than silently upgraded to established truth.

## 4. Queue: order + concurrency, all in config

> **BUILT (P12).** Implemented in `oracle_queue.py` (`resolve_queue`,
> `build_schedule`), wired to `oracle-hunter queue` (`cmd_queue`) and to
> `oracle-hunter scan`'s default count (`cmd_scan` falls back to
> `queue.default_count` when neither `-N` nor `--sites` is given). The
> scheduler consumes the P11 handoff as-is (`oracle_intake.HANDOFF_SCHEMA`)
> and emits the ordered work list. **Execution is built**: `queue --execute`
> (`execute_schedule`) ensures each workspace, hunts in schedule waves with
> same-site sequencing, `--max-items` cap, resumable per-item state keyed by
> stable target identity, and per-item failure isolation (one failed hunt
> never kills the queue). Only the schedule's own handoff may feed downloads.

```json
"queue": {
  "order": "finish-site",
  "concurrent": false,
  "cross_site_cap": 3,
  "default_count": 5
}
```

- `order`: `finish-site` (exhaust every company on one website, then move on)
  or `round-robin` (first company per site in rotation). Default: `finish-site`.
- `concurrent`: cross-site parallelism on/off. Sequential within a site,
  always (one rate-limit bucket). Default: `false`.
- `cross_site_cap`: max parallel sites when concurrent. Default: 3.
- `default_count`: programs to deep-dive when `-N` is not given.

### Precedence

CLI flag > config file > built-in default. Unspecified CLI falls back to
config; unspecified config falls back to the defaults above.

## 5. Bar (Phase 3b recall gate)

**DECIDED (P2-lock, 2026-10-12).** Owner rejected "≥1 planted app vuln per
target" as too weak; direction is "find all." The bar is **zero misses in
covered classes**: every planted SQLi, XSS, auth bypass, IDOR, and exposure
across juice-shop / DVWA / PyGoat must be found. Machine value:
`gate_recall_min: 1.0` in `oracle.config.json` → `quality_gates`, enforced
by `tests/test_p2_recall_bar.py`. Anything outside the covered classes is
named explicitly as uncovered — never silently missed.

## 6. Severity chaining law

Chains start at the strongest directly verified primitive. A complete
verified chain (producer output demonstrably consumed by the sink, bound on
exact observed wire values) compounds severity by **exactly one step** in
total (Low→Medium, Medium→High, High→Critical), capped at Critical. Chain
length never manufactures severity; repeated Lows cap at Medium. Structured
severity beats free-form wording; unknown/negated/unparseable structured
severity fails closed at info rank and never falls through to impact text.
Explicitly unconfirmed findings never compose. Chains sort highest-first.
Enforced in `oracle_mindset_context.chain_seams`, tested by
`tests/test_severity_ladder.py`.

## 7. Retrieval truth

Scan4Me **discovery** is no-login public retrieval; it creates no trust.
Oracle **download/retrieval** uses API keys where they exist, otherwise
the operator's saved signed-in CDP session (hunts: Chromium on port
9227; email: Firefox CDP on 9222); for retrieval the saved session is a
first-class credential path. Oracle **scan verification** is narrower
today: the only built adapter is HackerOne's authenticated API, so
missing/unusable HackerOne credentials block HackerOne verification and
platforms without an adapter cannot verify at all — the saved session
does not currently substitute as a verify adapter.
Multiple fetch paths (CDP, Crawl4AI, Jina, Firecrawl, plain GET) exist to
**verify each other**, not merely to fail over: for authenticated
platform pages the authenticated render stays authoritative, independent
renders corroborate, and disagreements are recorded — never silently
merged. CLI
secrets are accepted only as `env:VAR`, `@FILE`, or `'prompt'`; literal
secrets on the command line are refused, and empty/whitespace-containing
credential values are rejected at load. Reports are never auto-submitted.
