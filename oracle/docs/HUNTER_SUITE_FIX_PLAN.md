> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Hunter-Suite Fix Plan (databricks-drafted, gate-verified)

Created 2026-10-13. Drafted by the databricks lane
(`databricks-meta-llama-3-3-70b-instruct`, 128k) from three findings that
survived verification, then **gated**: every step re-checked against the real
code before inclusion. Where databricks was wrong, the correction is marked
`[GATE OVERRIDE]`.

Scope: ONLY the three verified items below. The other ~41 databricks audit
findings were false positives — explicitly **out of scope, do not touch**.

Doctrine honored: one file at a time · fail loud, no silent fallbacks · surgical
· each step has a verification command + rollback · diff shown + approved before
the next file.

Working copies (decide before applying — see "Open decision" at end):
- oracle  → `/home/phantomcore/oracle` (this session's repo) **and** the monorepo's `oracle/`
- omnicli → `/home/phantomcore/tools/omnicli` **and** the monorepo's `omnicli/`
- monorepo → GitHub `code-hunter-extreme/hunter-suite`

---

## Step 1 — orchestrate.py: resolve the `-> Path` annotation  (real/latent, low risk)

**File:** `omnicli/omnicli/orchestrate.py`

**Defect:** `generate_redteam_report(...) -> Path` (sig return annotation). `Path`
is imported only inside three function bodies (930, 994, 1049), never at module
scope. Module imports and the function run fine (PEP 563 lazy annotations), but
`typing.get_type_hints(generate_redteam_report)` raises `NameError: name 'Path'`
— any introspection consumer (pydantic/FastAPI/typer/doc-gen) crashes, and a
strict type/lint pass fails.

**Change (minimal):** add one line to the stdlib import group (NOT jammed after
`from __future__`, per house style — group it with the other stdlib imports
around lines 22–27):
```python
from pathlib import Path
```
**[GATE ADD] recommended, same file:** the three in-body `from pathlib import Path`
at lines 930 / 994 / 1049 become strictly redundant once hoisted — remove them
in the same change (they are the only lines the hoist orphans). Minimal = add 1
line; recommended = add 1 + remove 3.

**Rationale:** one module-level import resolves the annotation for all consumers.

**Verify (FAILS before / PASSES after):**
```
python3 -c "import typing, omnicli.orchestrate as o; print(typing.get_type_hints(o.generate_redteam_report)['return'])"   # NameError before -> prints <class 'pathlib.Path'> after
python3 -m py_compile omnicli/omnicli/orchestrate.py
ruff check omnicli/omnicli/orchestrate.py --select F,E9
```
**Risk:** none (pure import hoist). **Rollback:** remove the line(s) re-added.

---

## Step 2 — oracle_mindsets.py `_challenge_one`: the silent `except`  (minor/doctrine, OWNER DECISION)

**File:** `oracle_mindsets.py` (function `_challenge_one`, ~line 292–296)

**Current:**
```python
if um and in_scope is not None:
    try:
        if not in_scope(um.group(0)):
            return "rejected"
    except Exception:
        pass  # scope oracle failed: cannot confirm, won't reject
```

**[GATE OVERRIDE]** Databricks proposed `except TypeError: pass`. **Rejected** —
that is backwards: `TypeError`/`AttributeError` are exactly the programming bugs
fail-loud wants surfaced, while a real "scope-indeterminate" error (URL-parse
`ValueError`, etc.) would then propagate and abort the whole batch red-team pass.
`in_scope` is an opaque caller-supplied lambda
(`lambda u: bool(scope_gate.is_in_scope(u)[0])`) run over many seams, so the
except cannot be a blind narrow.

This is a rank-only heuristic (the 5-gate verifier is the sole arbiter), so the
intent — "a scope-check failure must not reject the card, and must not crash the
batch" — is correct. The doctrine issue is only that it fails **silently**. Three
defensible fixes; owner picks:

- **(2A) Loud-but-non-fatal [recommended].** Keep broad catch, replace `pass`
  with a loud warning carrying the specific error + URL, then fall through
  (don't reject). Matches "no fallbacks — SCREAM LOUDLY" without aborting the
  batch. Needs a warn channel in this otherwise-pure module (confirm one exists
  or thread one in).
- **(2B) Narrow + re-raise unexpected.** Catch only the exceptions the scope
  lambda can legitimately raise for an unparseable URL (enumerate against
  `scope_gate.is_in_scope`), re-raise anything else. Most doctrine-pure; requires
  reading `is_in_scope`'s error contract first.
- **(2C) Leave as-is.** Lowest priority; operationally harmless for a rank-only
  heuristic. Accept the doctrine debt, note it.

**Verify:** `python3 -m py_compile oracle_mindsets.py` · `ruff check … --select F,E9`
· the mindset suite stays green · (2A/2B) add a test: `in_scope` raising →
assert card is NOT rejected AND the error is surfaced (2A) / re-raised (2B).
**Risk:** medium (must not change which cards get rejected). **Rollback:** restore the block.

---

## Step 3 — oracle_mindsets.py `effective_mindsets`: collapse duplicate branch  (cosmetic "G6", low risk)

**File:** `oracle_mindsets.py` (function `effective_mindsets`, ~line 61–64)

**Current:**
```python
if p == "paradox" and not (cloud_up or ollama_up):
    continue
if p == "mitre" and not (cloud_up or ollama_up):
    continue
```
**After [GATE refine — tuple, mitre-first to match codebase ordering]:**
```python
if p in ("mitre", "paradox") and not (cloud_up or ollama_up):
    continue
```
**Rationale:** two identical-condition branches → one membership test. Behavior
identical.

**Verify:** `python3 -m py_compile oracle_mindsets.py` · `ruff check … --select F,E9`
· mindset suite green (same selected profiles in/out).
**Risk:** none. **Rollback:** restore the two branches.

---

## Open decision (needed before applying)
Where do fixes land — in the individual working repos (`/home/phantomcore/oracle`,
`/home/phantomcore/tools/omnicli`) then re-sync to the monorepo, or directly in a
fresh `hunter-suite` checkout and push? The scratchpad clone is ephemeral — not a
place to edit.

## Suggested order
Step 1 (zero-risk, real impact) → Step 3 (zero-risk cosmetic) → Step 2 (owner
picks 2A/2B/2C). No commits/backups unless requested.
