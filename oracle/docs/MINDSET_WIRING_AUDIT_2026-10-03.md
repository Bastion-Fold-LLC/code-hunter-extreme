> **HISTORICAL (2026-10-03) — superseded.** The fusion defect it reports was fixed (`_close_one_glm_cache` removed).

# Mindset wiring audit — are mitre / paradox applied correctly? (2026-10-03)

User's suspicion confirmed: the mitre and paradox ("impossible problem" / philosophy)
frames are NOT cleanly applied. Three verified findings.

## The design (correct part)
- `OracleMindsetContext(mindset=...)` builds genuinely different system prompts:
  - `mitre`   → full TTP library, NO philosophy framework/corpus (oracle_mindset_context.py:583,596)
  - `paradox` → philosophy framework + verbatim corpus + compact TTP (same lines)
- Default is `mindset="paradox"` (oracle_mindset_context.py:89).
- Engine A (cloud/OpenRouter) DOES pass `mindset=_profile` per lens correctly
  (oracle_hunter.py:3659-3660) → a true mitre prompt AND a true paradox prompt.

## Finding 1 — the local "mitre" sweep actually runs on a PARADOX context
- `ctx = OracleMindsetContext(program=prog, voice=True, ttp_mode=_ttp_mode)` at
  oracle_hunter.py:3417 passes NO `mindset=` → ctx defaults to **paradox**.
- Engine B (local tactic sweep) is tagged `origin=local-tactic:*`, and
  `mindset_of_origin("local")` → **"mitre"** (oracle_mindsets.py:36-38).
- But Engine B calls `ctx.tactic_prompt(tactic)`, and `tactic_prompt` reuses
  `self.system_prompt()` (oracle_mindset_context.py:258) → inherits the instance
  mindset = **paradox**.
- NET: the pass counted/tagged as the "mitre" mindset runs with the paradox
  framework+corpus baked in. Label and content disagree. The local lens is not a
  clean mitre lens.

## Finding 2 — the paradox lens is CLOUD-ONLY; on --no-cloud it never runs
- Engine A (the only place the mitre/paradox split is real) runs only `if _cloud_up`
  = `not no_cloud and OPENROUTER_API_KEY` (oracle_hunter.py:~3640).
- Engine B (local) runs only the mitre-labeled tactic sweep (on paradox ctx, per Finding 1).
- NET on a `--no-cloud` hunt: NO Engine A → the paradox / "impossible problem" /
  philosophy lens is never applied as its own lens, and the true mitre-configured
  prompt also never runs. Only the local tactic sweep executes (mislabeled mitre,
  paradox-flavored ctx). "3 mindsets" collapses to ~1, silently.
- Run 5 (8765, WITH cloud) did submit both cloud lenses + local — so it's only clean
  when cloud is on. Any local-only run has not been exercising paradox at all.

## Finding 3 — downstream passes are always paradox-default, not mindset-aware
- `mindset_sys = ctx.system_prompt()` (oracle_hunter.py:3436) = paradox (default ctx).
- Collaborative review / verify uses `ctx.system_prompt()` (oracle_hunter.py:3828)
  = paradox, regardless of which lens produced the seam.
- So verification/refinement is always paradox-flavored; mitre never governs any
  downstream reasoning. (Arguably fine — paradox is richer — but it's not deliberate.)

## Consequence for cross_compare
`cross_compare` agreement (oracle_mindsets.py:78) counts distinct `mindset` tags at a
subject. Because the local sweep is tagged mitre but is paradox-context, and because
paradox-proper may not have run at all (no-cloud), the "agreement across mindsets"
signal can over-report corroboration. It is machinery that works, but fed mislabeled inputs.

## Fix direction (NOT yet implemented — awaiting go-ahead)
1. Engine B: build its OWN `OracleMindsetContext(..., mindset="mitre", ...)` for the
   tactic sweep instead of reusing the paradox-default `ctx`.
2. Decide paradox-on-local: either add a local paradox pass, or log LOUDLY when a
   selected mindset did not actually execute (e.g. "paradox lens requires cloud — SKIPPED").
3. Make the "Mindsets this hunt" line + cross_compare reflect lenses that ACTUALLY ran,
   not those merely selected.
4. Consider whether downstream verify/PoC should use a neutral or per-seam mindset.

## Note vs Bob
Bob rated subsystem 5 "WORKS" (three generators exist, cross_compare real) — correct as
far as it goes. He missed Findings 1-2 because they require tracing the `mindset=`
argument threading through ctx. User's suspicion + direct trace found what the readiness
pass did not. (Verify, don't assume — including Bob.)

---

## Corpus loading finding (the "real frames" question)
The paradox lens's corpus comes from `oracle_corpus.py`, which is a HARDCODED
whitelist of 16 `DOCUMENTS` (lines 33-130) — it does NOT scan the corpus/ folders.

- On disk (excl README/_TEMPLATE): 37 md/txt files. Registered: 16. Ignored: 21.
- No broken refs: all 16 registered files exist → the curated backbone (the 8
  reflexes' canonical sources) DOES load on the paradox lens. The method's core is used.
- Of the 21 ignored files, ~19 are DUPLICATE copies of already-loaded concepts in a
  different folder (e.g. impossible_problems/Self_Observing_Equation.md is ignored but
  paradoxes/Self_Observing_Equation.md is loaded). No concept lost there.
- `Phililo me 1.md` (both folders) = another copy of the "Build the World" speech
  (already loaded as build-the-world). Not a unique frame. RTF-dirty formatting.
- **GENUINELY MISSING:** `paradoxe and impssoble complee1.md` (42KB, 669 lines,
  "# Impossible Problems and Paradoxes — the empirical record ... live reasoning
  transcribed and analyzed") is a DISTINCT, substantial anthology — NOT a dup — and is
  registered nowhere, so the paradox lens never sees it. This is almost certainly the
  doc the user was pointing at.
- Both of those user-authored files are saved RTF-style (`\*`, `\'97` escapes); they'd
  need cleaning before being loaded verbatim or they pollute the prompt.

### Net answer to "are the frames used correctly"
- The 16 curated frames load correctly — but only on the CLOUD paradox lens (see Finding 2).
- The corpus is a manual whitelist decoupled from the folders: files dropped into
  corpus/ do nothing until added to DOCUMENTS. New frames are silently inert.
- One substantial frame doc ("Impossible Problems and Paradoxes", 42KB) is not wired in.

### Fix direction (corpus)
1. Register `paradoxe and impssoble complee1.md` in DOCUMENTS (after cleaning the RTF
   escapes + giving it a sane filename + keywords), OR
2. Switch oracle_corpus.py to SCAN corpus/<cat>/*.md|*.txt with a dedup-by-title rule,
   so adding a file to the folder wires it in automatically (and skip README/_TEMPLATE).
3. Clean the RTF-escaped source files (Phililo me 1, paradoxe and impssoble complee1).

---

## VERIFICATION of the parallel session's Bug A/B/C fixes (2026-10-03, this session)
- **Bug A (expected field): CORRECTLY FIXED.** _card() emits expected="status 200" default + body predicates. ✓
- **Bug C (mitre ctx): CORRECTLY FIXED.** Engine B now uses a separate mindset="mitre" ctx (mitre≈26.8K chars vs paradox≈86.6K). Label matches content. ✓
- **Bug B (check execution): NOT FIXED — verified empirically via _run_check.**
  Replacing `| head -c N` with `-m N` swapped a "shell metacharacters" block for an
  "unsafe curl argument '-m'" block: `-m` is NOT in _SAFE_CURL_VALUE_FLAGS (only the long
  form `--max-time` is). WORSE: the core existence-probe format
  `curl -s -o /dev/null -w "%{http_code}" URL` is ALSO blocked (`-o`,`-w` not allow-listed),
  and the GraphQL template uses `-X POST` which is blocked ("unsafe HTTP method":
  only GET/HEAD/OPTIONS allowed) AND has malformed JSON (`{"query":"{__typename}}` —
  the fix dropped the closing `\"`). Net: NO template-seam check can reach the wire.
  The 121 passing tests never call _run_check on these strings, so they can't catch it.
  The Oct-2 confirmed-3 used LLM cards with `curl -i -s URL` (only -i/-s, both allowed) —
  which is why that path worked and template seams still can't confirm.
- **Correct Bug B fix (verified passes sanitizer):** rewrite template checks to use only
  already-allow-listed flags — `curl -i -s URL` for existence/body probes (status read
  from the included status line; this is the exact format that confirmed 3 on Oct-2),
  `curl -I -s URL` for head-only. For GraphQL: either send as GET (`?query=%7B__typename%7D`)
  or make POST an explicit allow-list policy decision; and fix the JSON to `{"query":"{__typename}"}`.
- Consequence for the plan: BUILD_AND_REDTEAM_PLAN's "clear path to CONFIRMED for template
  seams" is NOT yet true — Bug B must actually be fixed first.

---

## Bug B — REAL fix applied + verified (this session, by me)
Converted ALL web template checks in oracle_seam_templates.py to `curl -i -s '{url}'`
(lines 161,185,204,224,256,286,316,355,379,401). Dropped inline `#` comments (they broke
shlex parsing too) and reduced the two multi-URL `;` checks to a single verifiable URL.
- WHY this form: extract_status_from_curl_output parses the `-i` status line (returns 200);
  a bare `%{http_code}` returns None → the old `-o /dev/null -w` probes were DOUBLY broken
  (sanitizer-blocked AND unparseable by the verifier). `-i -s` passes the sanitizer and
  gives status + headers + body.
- GATE PASSED: generated 7 template seams from a synthetic recon dir; 0/7 blocked by
  _run_check; all have an `expected` field. Verified empirically, not via pytest.
- Bug A (expected) + Bug C (mitre ctx): confirmed intact.

### Residual (NOT web-wire; separate follow-up)
- oracle_seam_templates.py:335 — `# confirm in page source...` secrets pseudo-check (manual, no URL).
- oracle_seam_templates.py:463,514 — code-lens `grep -rn` checks. grep is not in
  _ALLOWED_CHECK_BINS, so these BLOCK in _run_check. Only matters for repo-source seams,
  not the local web app. Fix later (allow-list grep for code seams, or verify them off the
  wire path).

### Still unproven (Phase 1.3 gate)
A template seam reaching CONFIRMED end-to-end still needs recon material
(js_endpoints/api_specs/fuzzed_paths) — which needs ffuf/katana (Phase 3) OR a synthetic
recon dir pointed at a live app. The mechanical path is now unblocked; the end-to-end
confirm has not yet been observed.
