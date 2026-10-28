> **HISTORICAL (2026-10-13) — scope landed or superseded.** Hunt timeouts, exposed-file fixes, and timeout defaults shipped; current truth in `ORACLE_DOCTRINE.md` + `STATUS.md`.

# Oracle — Finish Plan (path to a paid web2 finding)

Local model is the BASE engine (runs the reflex pass). Cloud providers
(Gemini / Copilot / OpenAI / Claude / Bob-watsonx) are OPTIONAL escalation —
key-gated, fall back to local when absent. Tasks, not time. Critical path = A → B → C.

## Phase A — Prove the local base engine
- A1. Run `oracle-hunter analyze` on devstral:24b to COMPLETION, read the cards.
      (Prior "junk" was qwen2.5:3b, not devstral — devstral never got a fair run.)
- A2. If devstral cards are weak: try qwen3-coder:30b, then tighten the reflex prompt.
- Gate: local model emits >=1 parseable card with real Assertion A + B + check + impact.

## Phase B — Deeper eyes (recon actually fires)
- B1. Fix the recon step so nuclei + crawl run (both produced 0 bytes on tstaging).
- Gate: nuclei.txt and crawl.txt non-empty on a fresh recon.

## Phase C — Prove the tail (verify -> PoC -> draft)
- C1. Run verify_seams against a real seam (Tinder public_meetup) — classify honestly.
- C2. Generate submission_draft.md from a confirmed seam (iPhone format, clean register).
- Gate: a draft a triager could reproduce from alone.

## Phase D — Optional escalation wiring (all key-gated, local fallback)
- D1. Unify the two .env loaders into one; fix stale `claude-opus-4-5` model id.
- D2. Add provider branches beside claude/gemini: openai, copilot, bob (IBM watsonx).
- Gate: `oracle-hunter status` lists which providers are live; each configured one
       returns text on a test seam; none configured -> silently uses local.

## Phase E — Tests (the missing spine)
- E1. Unit: _parse_seams (junk-drop), _map_ttps_to_recon (fusion injection), _load_fused_ttps.
- E2. Integration: recon dir -> analyze -> seams with a mocked model response.
- Gate: pytest green.

## Reality on money
- web2 programs only (HackerOne / Bugcrowd / YesWeHack web assets). web3 mega-payouts
  (Cantina/Immunefi/Code4rena contracts) are the Vortex/Basilisk/CodeCrusher system — later.
- A submitted valid finding is achievable once A+B+C hold. Payment is triage-gated (days-weeks),
  never same-day.
