# Oracle Doctrine

Owner decisions, recorded 2026-10-12 (updated 2026-10-20). This doc is the
authority when code and docs disagree. Anything marked OPEN is a proposed
default awaiting correction.

## 1. Three mindsets, equal citizens

- **Mindset 1 = full-weight MITRE.** Real technique definitions, full tactic
  sweep. Nothing overlays or clobbers the ATT&CK text it reasons with.
- **Mindset 2 = philosophy + impossible problems + paradoxes + iPhone framing.**
- **Both lenses receive the same three feeds:** invisible-seam candidates,
  red-teaming, and bounty context (asset, in-scope scope, company info,
  bounty rules).
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

1. `--prescan` (`run_prescan`) — fast Scan4Me sweep using saved credentials.
   Produces a **prescan report**. Raw output; nothing downstream trusts it yet.
2. `scan` (`run_scan` → `verify_program`) — Oracle's verification pass over
   the prescan. Produces a **scan report** with a verdict per program. Only
   verified programs proceed.
3. `-N` (`select_deep_dive` + `write_handoff`) — deep-dive the top N
   **verified** programs: pull full asset, company info, and resources.
   Naming sites explicitly (`--sites`) overrides the count. Deep-dive assets
   are re-resolved fresh at dive time, never taken from the prescan snapshot.
4. `--download` (`download_selected_workspaces`) — exactly one workspace per
   selected verified program (never unverified). Scope always refreshes from
   the platform source (API keys where they exist, saved signed-in CDP
   session otherwise) and merges into known scope; a failed intake never
   deletes known scope. Downloads are multi-path: the saved-session CDP
   render is authoritative for platform pages (no anonymous substitute), an
   independent Crawl4AI/Jina/Firecrawl/GET render corroborates it, and every
   result records which path served it.
5. Pick a company → its full info loads into **all three** mindsets as
   bounty context. Then hunt.

### Verify-pass definition (BUILT — P11, `verify_program`)

A program is "accurate" iff all three hold:

- Scope URLs resolve / are live;
- Payouts match the platform listing;
- Bounty rules text is unchanged since prescan.

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

Oracle uses API keys where they exist, otherwise the operator's saved
signed-in CDP session (hunts: Chromium on port 9227; email: Firefox CDP on
9222). Missing API tokens are not a system hole — the saved session is a
first-class credential path. Multiple fetch paths (CDP, Crawl4AI, Jina,
Firecrawl, plain GET) exist to **verify each other**, not merely to fail
over: the authenticated render stays authoritative, independent renders
corroborate, and disagreements are recorded — never silently merged. CLI
secrets are accepted only as `env:VAR`, `@FILE`, or `'prompt'`; literal
secrets on the command line are refused, and empty/whitespace-containing
credential values are rejected at load. Reports are never auto-submitted.
