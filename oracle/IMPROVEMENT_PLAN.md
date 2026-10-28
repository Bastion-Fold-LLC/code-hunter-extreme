> **HISTORICAL (2026-10-13) — partially acted on, then superseded.** Duplicates scanner-finding lists kept as findings history only.

# Oracle Improvement Plan — more bugs, no hallucination, chaining

Local model = base engine; cloud/CLI = optional escalation. Tasks ordered by leverage.
Each task has a pass/fail gate. Do one, verify, then next.

## Task 1 — Anti-hallucination gate (foundation) [ACTIVE]
Goal: a finding exists only if it is grounded and proof-backed. Model proposes, the
executed check owns the verdict (invisible-seam doctrine).
- 1a. Revert the TTP-enrichment parrot-bait in `_map_ttps_to_recon` (my edit that made
      devstral copy `Oracle reflex:` / `You never said:` labels). Remove the now-orphaned
      `_FUSED_TTPS` + `_load_fused_ttps` I added. (oracle_ttps_fused.json + generator stay.)
- 1b. `_parse_seams`: reject cards whose check is an ungrounded placeholder
      (`example.com`, `target-endpoint`, `<...>`, `TODO`). Keep the A+B+check bar.
- 1c. Reflex prompt (`run_reflexes`): require each assertion to cite a SOURCE, and the
      check to use a REAL path from the recon data; if it can't be grounded, emit no card.
- Gate: re-parse old devstral junk → 0 seams; a sourced A/B card with a real curl → 1;
  a card with an example.com/placeholder check → 0. `py_compile` clean.

## Task 2 — Fix apex-only recon crawl
- hunter line ~363: hakrawler crawls only the bare apex; point JS-endpoint extraction at
  the live subdomains (from live_hosts.txt) so the model gets endpoints, not hostnames.
- Gate: on a re-recon of a multi-subdomain target, js_endpoints/crawl non-empty and
  include a live subdomain's paths.

## Task 3 — Wire invisible-seam as a second engine
- For any target with source on disk, run `seam scan` (invisible-seam CLI, Python-only
  today) → doc↔code FIXABLE/PARADOX seams, each already check-proven. Merge into findings.
- Gate: `seam scan` output parsed into the same finding shape; zero unproven cards.

## Task 4 — Fresh / low-competition target selector
- `filter_programs` already has min_payout + fast_triage + max_reports; add a
  "recently launched" filter (launched_at is already captured for HackerOne).
- Gate: `list --new` ranks recently-launched, low-report, fast-triage, paying programs.

## Task 5 — Chaining (compose pass)
- After verify, take only CONFIRMED seams and run one reflex pass: "which chain into
  higher severity?" Build chains only from proven links. Output combined impact + the
  ordered sequence of proven checks.
- Gate: two confirmed seams that compose produce one chained finding; unproven seams
  are never chained.

## Invariants
- No finding without sourced Assertion A + Assertion B + a check that ran.
- The executed check owns the verdict, never model prose.
- Local is the base; Gemini/Copilot/Claude/Bob are optional, key/CLI-gated, local fallback.
- web2 today; Solidity/Type-2 architectural is reasoner-driven until invisible-seam gets
  Solidity extractors.
