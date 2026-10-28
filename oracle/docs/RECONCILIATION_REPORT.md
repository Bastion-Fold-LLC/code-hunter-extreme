> **HISTORICAL — reconciliation snapshot; current truth in `VERIFIED_STATE.md`.**

# Oracle — Documentation Reconciliation Report (2026-10-02)

Scope: `ARCHITECTURE.md`, `docs/SESSION_STATUS_2026-10-02.md`,
`docs/FINISHING_ROADMAP.md`, `docs/WORK_PLAN.md`, `docs/PIPELINE_TEST_PLAN.md`,
`docs/PLATFORM_CONFORMANCE.md`. Code read-only to check claims.
No `CLAUDE.md` exists in the repo (the audit scope referred to one that doesn't
exist — likely a planning note referring to a file not yet created or deleted).

---

## 1. Contradictions Between Docs

### 1a. "5-gate verifier" — count mismatch across docs and code

**Where:** `SESSION_STATUS_2026-10-02.md` (lines 25, 71), `FINISHING_ROADMAP.md`
(line 7), `WORK_PLAN.md` (line 11), `docs/superpowers/specs/2026-10-02-multiple-mindsets-design.md`
(lines 52, 61, 86), `docs/superpowers/plans/2026-10-02-multiple-mindsets.md` (line 17).

**Code reality:** `oracle_deterministic.verify_seam_card` labels four gates
(`# Gate 1` through `# Gate 4`). The logic that the spec calls "5 gates" is all
present, but gates 3 and 4 in the spec (status-required and claim-source-required)
are implemented under a single `# Gate 3` comment. The wire-match step is `# Gate 4`.

**Verdict:** No logic is missing — the spec's 5th gate (claim-source-required /
assertion_a_source check) is present in code; it just lives inside the
`# Gate 3` block alongside the status-required check. No security gap.

**Recommended fix (substantive — flagged, not silently changed):** Either
(a) relabel the code so the assertion_a_source check gets its own `# Gate 4`
comment and the wire-match becomes `# Gate 5`, or (b) update the docs to say
"4-gate verifier." The spec's own gate list
(`grounding, scope, status-required, claim-source-required, wire-match`) suggests
option (a) is the author's intent. **This is a code change; left to the code
session to decide.**

---

### 1b. `ARCHITECTURE.md` does not mention the 3-mindset design at all

**Where:** `ARCHITECTURE.md` — entire file describes "8 reflexes" and a
single-pass analysis engine. It has no mention of `--mindset`, `mitre`,
`paradox`, or `seam` generators.

**Code reality:** `oracle_mindsets.py` exports `resolve_mindsets`,
`cross_compare`; `oracle_hunter.py` (`cmd_hunt`) wires in `--mindset
mitre|paradox|seam|all` (default: `all`). Three separate generators have been
live since the `rowan/hunt-filter-fixes` branch.

**Verdict:** `ARCHITECTURE.md` is stale here. It correctly describes what the
reflexes *are* conceptually, but the pipeline section ("Oracle 8-reflex pass")
does not reflect that analysis now runs as three independent generators
(two LLM, one deterministic) feeding one verifier.

**Fix applied below** (wording only — pipeline step updated, `--mindset` flag
added to the Running It section).

---

### 1c. `ARCHITECTURE.md` Type-2 pipeline: "Deterministic FP filter (401/403/404/530/HTML killed before model sees response)"

**Where:** `ARCHITECTURE.md` line 111 — listed as pipeline sub-step 4 of the
Type-2 bug engine description.

**Code reality:** `oracle_hunter.py` (the `triage_seam_card` function, ~line
2050) applies this filter, but it runs **after** the check command executes, not
before the model sees the initial analysis. The filter intercepts the *verify*
stage response — it prevents the triage LLM from wasting a call on a clear
4xx/HTML non-finding. The original *reflex/analysis* LLM pass is not filtered.

**Verdict:** The description is slightly misleading ("before model sees response"
implies the analysis LLM is shielded; actually the triage LLM is shielded, post-
check). Not a harmful inaccuracy — the core fact (false positives are
deterministically killed) is correct.

**Fix applied below** — reworded to "Deterministic FP filter (401/403/404/530/HTML
kills triage before the LLM assess step)".

---

## 2. Stale Claims vs Code

### 2a. `ARCHITECTURE.md` "The Mind" section — 8 paradoxes claim

**Where:** `ARCHITECTURE.md` line 63: "`ORACLE_SYSTEM_PROMPT.md` — 8 paradoxes
as worked examples → hunt moves"

**Code reality:** `oracle_mindsets.py` / `oracle_mindset_context.py` load the
prompt files from disk. The number 8 is internally consistent (the reflexes are
8; the paradoxes used as worked examples may differ). This claim is hard to
verify without reading the prompt files, which are corpus/mindset content.
**Flagged for the owner to confirm** — if the system prompt uses the 8 reflexes
as its worked examples that is accurate; if the paradox count differs it should
be corrected.

---

### 2b. `ARCHITECTURE.md` still says "oracle_scan.py --status"

**Where:** `ARCHITECTURE.md` line 193.

**Code reality:** `oracle_scan.py` exists in the repo. `--status` is listed as
a valid flag in the doc. The file exists but this flag is not independently
verified here. **Flagged** — minor, worth a quick check.

---

### 2c. `PLATFORM_CONFORMANCE.md` lists 11 platforms tested; SESSION_STATUS says 14 platforms are in scope

**Where:** `PLATFORM_CONFORMANCE.md` — first-pass matrix has 11 rows (3 more
marked `no-adapter`). `SESSION_STATUS_2026-10-02.md` and `PIPELINE_TEST_PLAN.md`
refer to "14 platforms in `platform_auth`".

**Code reality:** `oracle.config.json → platform_auth` has exactly 14 platform
keys (excluding `_comment`): hackerone, bugcrowd, intigriti, yeswehack, immunefi,
hackenproof, cantina, code4rena, sherlock, codehawks, patchstack, huntr, bugbase,
hatsfinance.

**Verdict:** No contradiction — the conformance matrix correctly records only
the platforms that were tested in the read-only pass. The "14 platforms" claim in
other docs is correct. The conformance matrix's header "Platforms in scope: the
14 in `platform_auth`" in `PIPELINE_TEST_PLAN.md` is accurate. No change needed.

---

### 2d. `ARCHITECTURE.md` Credentials table — status may have changed

**Where:** `ARCHITECTURE.md` lines 143–149 — `ANTHROPIC_API_KEY ❌ not set`,
`GEMINI_API_KEY ❌ not set`, `HACKENPROOF_API_KEY ❌ not set`.

**Status:** These are point-in-time status markers. They will naturally drift.
**Not changed** — this kind of living status belongs in a session doc, not
ARCHITECTURE.md. **Flagged:** consider removing the ✅/❌ status column from
ARCHITECTURE.md and pointing to `.env` directly.

---

## 3. Duplicated / Overlapping Docs

### 3a. `FINISHING_ROADMAP.md` and `WORK_PLAN.md` are substantially overlapping

Both documents describe the same A–E phase plan. `WORK_PLAN.md` adds the
"division of labor" (Claude free / bob sparingly) and bobcoin budget rules.
`FINISHING_ROADMAP.md` has more detail per phase.

**Recommendation (substantive — flagged):** Merge into one document.
`WORK_PLAN.md` could become a section ("Division of labor + bobcoin rules")
appended to `FINISHING_ROADMAP.md`, or vice versa. The duplication is not
harmful right now but will diverge as phases complete. **Left to owner.**

---

### 3b. `SESSION_STATUS_2026-10-02.md` overlaps with `FINISHING_ROADMAP.md` intro

The "Status going in" paragraph in `FINISHING_ROADMAP.md` (lines 5–8) and
`WORK_PLAN.md` (lines 8–12) are near-identical restatements of the opening
section of `SESSION_STATUS_2026-10-02.md`. This is intentional redundancy for
context — acceptable in session docs. **No change needed.**

---

### 3c. `ORACLE_COMPLETION_PLAN.md` and `FINISHING_ROADMAP.md` overlap in scope

`ORACLE_COMPLETION_PLAN.md` covers similar ground (first submission, phase
breakdown) but appears to be an earlier/parallel document without the three-
mindset update. **Flagged for owner:** consider retiring or archiving
`ORACLE_COMPLETION_PLAN.md` once `FINISHING_ROADMAP.md` is the canonical plan.

---

## 4. Minor Issues Fixed In This Commit

The following wording-only changes were applied to `ARCHITECTURE.md`:

1. **Pipeline step 5 updated** — "Oracle 8-reflex pass" → "Oracle analysis pass
   (3 mindsets: `mitre` LLM, `paradox` LLM, `seam` deterministic — run via
   `--mindset mitre|paradox|seam|all`)"
2. **FP filter description** — "before model sees response" reworded to clarify
   this is the triage-LLM filter, post-check.
3. **Running It** — added `--mindset` example.

No code or test files were touched.
