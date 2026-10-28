> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Multiple Mindsets Refactor — Design Spec

**Date:** 2026-10-02
**Status:** Draft for review
**Scope:** `oracle/` (branch `rowan/hunt-filter-fixes`), the canonical working copy.

---

## 1. Problem

Today `OracleMindsetContext` (`oracle_mindset_context.py`) fuses *everything*
— the 8-reflex system prompt, the framework philosophy, voice layers, a
relevance-selected slice of `corpus/`, the MITRE TTP block, and the program
brief — into **one** system prompt (`system_prompt()` → `_build()`). One
prompt carries two different reasoning styles at once:

- **MITRE / technique** reasoning: "which known attack class does this surface invite?"
- **Paradox / philosophy** reasoning: "what unstated assumption breaks here?" ("you never said…")

Two problems follow:

1. **The styles dilute each other.** A single blended prompt makes the model
   average the two lenses instead of pushing hard on each.
2. **The philosophy is flattened twice.** The bundled `corpus/` (~10K tokens,
   16 files) is already a reduced subset of the real source material in
   `~/Documents/{Impossible Problems,Impossible Problems and Paradoxes,Paradoxes,Philosophies}`
   (~57K tokens, 48 real files). Then at runtime `_build()` truncates even that
   to `source_context(..., max_chars=12_000)` (~3K tokens). The reasoning
   patterns the corpus is meant to *teach* arrive as fragments.

This contradicts Oracle's own stated principle (module docstring + `ARCHITECTURE.md`):
the philosophies and paradoxes must be injected as **verbatim original source
that teaches a reasoning pattern**, not reduced to a replacement summary.

## 2. Goals

- Split the single mindset into **three mindset profiles**:
  - `mitre` — LLM generator, MITRE technique lens.
  - `paradox` — LLM generator, paradox/philosophy/iPhone lens, full corpus.
  - `seam` — **deterministic** generator (no LLM): the invisible-seam code lens
    reads the actual code/claims, *and* cross-compares its findings against the
    two LLM profiles to produce a corroboration (agreement) signal.
- All three share the **program brief** (in-scope assets, scope rules, payout,
  company info) and the same recon data.
- Give the `paradox` profile the **full un-flattened corpus**, bundled in the
  app (no external-folder runtime dependency).
- Default a hunt to run **all three** profiles, cross-compare, and feed every
  well-formed candidate to the one deterministic verifier. Expose a
  `--mindset mitre|paradox|seam|all` selector (default `all`).
- Agreement is a **ranking/confidence signal only** — it sorts and labels
  candidates; it never confirms a seam and never drops one before verification.
  The 5-gate verifier remains the sole arbiter of CONFIRMED/REJECTED.

## 3. Non-Goals (explicitly out of scope for this spec)

Each is its own future spec → plan → implementation cycle:

- Config/filter verification across all 14 platforms (extract + download).
- Alias / Account-A/B persistence document.
- Live traffic interception (extending `oracle_traffic.py` beyond HAR import).
- Any change to the verifier's gate logic. The 5 gates in
  `verify_seam_card` (grounding, scope, status-required, claim-source-required,
  wire-match) are **frozen** by this spec; mindsets only change what
  *candidates* are generated, never how they are *confirmed*.

## 4. Mental Model — two generators, one verifier

```
       ┌──────────────────── SHARED PROGRAM CONTEXT ────────────────────┐
       │  in-scope assets · scope rules · payout · company info          │
       │  recon data (live hosts, endpoints, downloaded assets, source)  │
       └──────┬───────────────────────┬────────────────────────┬────────┘
   ┌──────────▼─────────┐  ┌───────────▼──────────┐  ┌──────────▼───────────┐
   │ MINDSET: mitre (LLM)│ │ MINDSET: paradox (LLM)│ │ MINDSET: seam (NO LLM)│
   │ oracle_ttps_fused   │ │ full un-flattened     │ │ invisible-seam code   │
   │ (MITRE → 8 reflexes)│ │ corpus → 8 reflexes   │ │ lens: reads code/claim│
   └──────────┬──────────┘ └───────────┬───────────┘ └──────────┬───────────┘
              │ seam cards              │ seam cards             │ code seams
              └────────────┬───────────┴────────────────────────┘
                           ▼  CROSS-COMPARE: match candidates on shared subject
                           │  (URL, or file+function/claim-source).
                           │  matched set size = agreement score; tag
                           │  seam.corroborated_by = [profiles], seam.agreement = N
                           ▼
              ┌─────────── INVISIBLE SEAM VERIFIER (shared, UNCHANGED) ──────────┐
              │  verify_seam_card (5 gates) — verifies EVERY well-formed seam,    │
              │  regardless of agreement. Agreement never confirms or drops.      │
              └───────────────┬──────────────────────────────────────────────────┘
                              ▼
              chain engine → report (CONFIRMED only, ranked by agreement)
```

The two LLM profiles **speak the same 8 reflexes** and emit the **same seam-card
format**; they differ only in the *source material that teaches the moves*
(MITRE records vs. philosophy/paradox corpus). The `seam` profile is **not** an
LLM — it is the existing deterministic Type-1 code lens, promoted to a co-equal
generator whose extra job is to cross-compare against the two LLM result sets.

## 5. Component Design

### 5.1 `OracleMindsetContext` — add a `mindset` profile

Extend the constructor (mirrors the existing `ttp_mode` pattern):

```python
def __init__(self, program=None, voice=True, ttp_mode="auto",
             ttp_tactic=None, mindset="paradox"):
    # mindset: "mitre" | "paradox"  — which LLM generator this prompt is for
```

**Two different value sets, intentionally:** `OracleMindsetContext`'s `mindset`
takes only the two **LLM** profiles (`mitre` | `paradox`), because it builds a
system prompt. The **CLI** `--mindset` selector takes
`mitre | paradox | seam | all`, because `seam` is the deterministic code lens
dispatched in the hunt loop (§5.3 / §5.5), not an LLM prompt.

`_build()` becomes profile-aware. Shared layers are built for **both** LLM profiles;
profile-specific layers are gated:

| Layer | `mitre` | `paradox` |
|---|---|---|
| System prompt (8-reflex worked examples) | ✅ | ✅ |
| Voice layers (`ORACLE_VOICE`, `ALEX_VOICE`) | ✅ | ✅ |
| Framework philosophy (`ORACLE_FRAMEWORK`) | **omitted** | ✅ full |
| `corpus/` via `source_context` | **omitted** | ✅ **full** (cap lifted) |
| MITRE TTP block (`_ttp_block`) | ✅ full (`ttp_mode` as configured) | compact (`ttp_mode="compact"`, ~15 TTPs) |
| Program brief (`_program_brief`) | ✅ | ✅ |
| Recon context (`_recon_context_block`) | ✅ | ✅ |
| Type-1 seam block (`_seam_block`) | ✅ | ✅ |

**Rationale for the split:** the 8 reflexes are the shared move vocabulary, so
both profiles keep the system prompt that teaches them. The heavy *teaching
material* is what differs — `mitre` leans on the full TTP library and drops the
philosophy framework + corpus; `paradox` leans on the full framework + corpus
and keeps only a compact TTP reference so it still knows the MITRE vocabulary
exists. **This exact layer split is the most likely tuning point** — if you
want `mitre` to retain some framework, or `paradox` to carry the full TTP
library too, that is a one-line change to this table before the plan is written.

The corpus cap change is the one substantive edit inside `_build()`: today it
calls `source_context(selection_query, max_chars=12_000)`. For the `paradox`
profile, call it with a cap large enough to carry the full deduped corpus
(e.g. `max_chars=320_000`), keeping relevance ranking only as a tiebreaker for
ordering, not as a truncation knob. For the `mitre` profile, the corpus layer
is omitted entirely.

`system_prompt()` and the `_prompt` cache are unchanged (one instance builds
one profile's prompt; two profiles = two instances).

### 5.2 Corpus un-flattening (one-time build step, not a runtime dep)

- Import the real source files from `~/Documents/{Impossible Problems,
  Impossible Problems and Paradoxes, Paradoxes, Philosophies}` into the bundled
  `oracle/corpus/` tree, preserving the existing category folders
  (`impossible_problems/`, `paradoxes/`, `philosophies/`, `analysis/`).
- **Dedup** the overlap: `The_iPhone_Problem.md`, `The_Invisible_Architect.md`,
  etc. appear in both "Impossible Problems and Paradoxes" and "Philosophies".
  Keep one canonical copy per document.
- Convert the 4 `.rtf` files to markdown; drop macOS `._*` AppleDouble files
  and `.DS_Store`.
- This is a **build/import step** run once (a small `scripts/import_corpus.py`
  or a documented manual copy). The runtime only ever reads the bundled
  `corpus/` — **no runtime read of `~/Documents`** (portability rule).
- `oracle_corpus.py` needs no API change; `corpus_inventory()` /
  `source_context()` / `_rank_documents()` operate on whatever is in `corpus/`.

### 5.3 Hunt loop — run selected mindsets, cross-compare, verify

The hunter already threads the built prompt as a `mindset_system` string
through `run_reflexes` / triage / verify. The change:

- Resolve the selected profiles from `--mindset` / config (default
  `["mitre","paradox","seam"]`).
- **LLM profiles** (`mitre`, `paradox`): build
  `OracleMindsetContext(program, mindset=profile).system_prompt()`, run the
  reflex pass, parse seams (`_parse_seams`, which already extracts
  `assertion_a_source`), tag `seam["mindset"] = profile`.
- **Deterministic profile** (`seam`): run the invisible-seam Type-1 code lens
  (`oracle_code_seam` / `invisible_seam`) over the on-disk source, tag
  `seam["mindset"] = "seam"`. Skipped (not failed) when no source is on disk.
- **Cross-compare (the comparison step):** match candidates across profiles on a
  shared *subject identity* — normalized check URL for web seams, or
  `file+function` / `assertion_a_source` for code seams. For each matched group,
  record `seam["corroborated_by"] = [profiles]` and `seam["agreement"] = N`.
  Unmatched candidates keep `agreement = 1` and are **retained**, never dropped.
- Hand **every** well-formed candidate to the **existing** verify path,
  unchanged. Agreement rides along as metadata.
- Reporting sorts CONFIRMED seams by `(agreement desc, severity)` so
  multi-mindset corroborated findings surface first.

Passes run sequentially in v1 (simplest correct version). The deterministic
`seam` pass is cheap (no LLM, no network). Parallelizing the two LLM passes
across backends is a later optimization, out of scope here (YAGNI).

### 5.4 Config & CLI surface

- `oracle.config.json`: add under `hunt`:
  `"mindset": "all"` (values `mitre` | `paradox` | `seam` | `all`).
- `oracle-hunter hunt <target> --mindset mitre|paradox|seam|all` overrides config.
- `all` = run all three. A single value runs only that generator (and so emits
  no agreement signal, since there is nothing to cross-compare).
- Invalid value → **fail loud** with a `ValueError` naming the allowed set
  (no silent default — per the project error-handling philosophy).

### 5.5 The `seam` profile and the comparison step

The deterministic `seam` profile is **not new code to invent** — it is the
existing invisible-seam Type-1 lens (`oracle_code_seam.scan_repository_seams`)
promoted to a named, co-equal generator. Its two jobs:

1. **Generate** its own code seams from on-disk source (as it does today),
   tagged `mindset="seam"`.
2. **Cross-compare** — a new, small pure function (no LLM, no network):

   ```python
   def cross_compare(seam_sets: dict[str, list[dict]]) -> list[dict]:
       """Match candidates across mindsets on shared subject identity and
       annotate each with corroborated_by / agreement. Returns the union —
       nothing is dropped. Deterministic; unit-testable without a model."""
   ```

   Subject identity: normalized check URL for web seams; `file+function` or
   `assertion_a_source` for code seams. A match annotates both members with the
   shared `corroborated_by` set and `agreement = len(set)`.

**The `seam` profile is bound to the same shared program context as the two LLM
profiles.** It does not analyze raw source in a vacuum: it scopes its code
analysis to the **in-scope program assets**, drops out-of-scope findings through
the existing `_program_scope_gate` (`oracle_code_seam`), and carries the
**scope rules + payout + company information** as finding context (so a `seam`
finding reports the same program grounding as a `mitre`/`paradox` one). All
three mindsets stand on the identical program brief; only their *method* of
generating candidates differs.

Because the comparison is a pure function over already-produced seam lists, it
is fully deterministic and testable in isolation, and it cannot alter a verdict
— it only annotates. This keeps the "tools feed each other intelligence"
principle real while leaving the verifier untouched.

## 6. Error Handling

Follows the project's fail-fast philosophy (no silent fallbacks):

- Missing `corpus/` directory or empty corpus for the `paradox` profile →
  raise `RuntimeError`, do not silently run paradox with no source material.
- Unknown `--mindset` value → `ValueError` listing `{mitre, paradox, both}`.
- A mindset's reflex pass raising (router `RuntimeError: all backends failed`)
  aborts that profile with the real error surfaced; it does **not** silently
  skip to the other profile and claim success. If `both` was requested and one
  profile hard-fails, the hunt fails loudly (the operator chooses to re-run
  with the single working profile).
- The optional local model's 16K context cannot hold the full paradox corpus.
  Local is the optional final-check layer only; this spec does not route the
  paradox generator to local. (If local is later wanted for paradox, it needs a
  reduced corpus set or a raised context window — tracked as a note, not built
  here.)

## 7. Data / Token Budget

| | Words | ~Tokens |
|---|---|---|
| Current flattened bundled corpus | 7,890 | ~10K |
| Full un-flattened sources (deduped upper bound) | 43,598 | ~57K |

Paradox-profile prompt ≈ corpus (~57K) + reflexes/voice/framework (~10K) +
program brief (~5K) + recon (~5K) ≈ **~80K tokens**, inside the 128K+ context of
the mandatory cloud backends (OpenRouter, NVIDIA). The 16K local model is the
only context that cannot hold it; local is optional and not used for paradox.

## 8. Testing Strategy

- `OracleMindsetContext(mindset="mitre")` prompt **contains** the TTP block and
  **omits** the corpus section; `mindset="paradox"` is the inverse.
- Both LLM profiles' prompts contain the program brief (scope wall) and the
  seam-card format including the `Assertion A source` line.
- Paradox prompt length reflects the full corpus (not the 12K-char cap):
  assert corpus content beyond the old cap is present.
- Unknown `--mindset` value raises `ValueError`.
- `cross_compare` (pure function, no model needed):
  - a seam at the same subject from two profiles collapses to one with
    `agreement == 2` and both names in `corroborated_by`; all three → `3`.
  - a seam unique to one profile is **retained** with `agreement == 1`.
  - subject matching works for web (URL) and code (`file+function`) seams.
- **Agreement never confirms or drops:** a high-agreement seam that fails any
  of the 5 gates is still REJECTED; a lone-wolf (`agreement == 1`) seam is still
  verified. (Assert agreement is absent from the verdict path entirely.)
- `seam` profile is **skipped, not failed**, when no source is on disk.
- Regression: the full existing suite stays green (92 passing today); the
  verifier and its 5 gates are untouched.

## 9. Decisions Made (resolved during brainstorming)

- **Three** mindsets: `mitre` (LLM), `paradox` (LLM), `seam` (deterministic).
  Run all by default; `--mindset` selector for single runs.
- The `seam` mindset **cross-compares** against the two LLM result sets.
  Agreement is **ranking/confidence only** — it never confirms a seam and never
  drops one before verification.
- Paradox mindset carries the **full** un-flattened corpus; feasible on cloud
  backends (measured ~57K tokens).
- Corpus is **bundled** (imported once); no runtime read of `~/Documents`.
- The verifier is **frozen**; mindsets change candidate generation only.

## 10. Rough Implementation Order (for the plan phase)

1. Import + dedup the un-flattened corpus into `corpus/`; convert rtf; drop `._*`.
2. Add `mindset` to `OracleMindsetContext.__init__` and make `_build()` profile-aware (incl. lifting the corpus cap for paradox).
3. Add `--mindset` CLI flag + `hunt.mindset` config (`mitre|paradox|seam|all`), with fail-loud validation.
4. Promote the `seam` profile: run the Type-1 lens bound to the shared program context, tag `mindset="seam"`, skip (not fail) when no source on disk.
5. Add the pure `cross_compare` function; annotate `corroborated_by` / `agreement`; retain everything.
6. Hunt loop: run selected profiles, cross-compare, feed **all** well-formed seams to the existing verifier; sort report by `(agreement, severity)`.
7. Tests for all of the above (incl. agreement-never-confirms); confirm full suite green.
