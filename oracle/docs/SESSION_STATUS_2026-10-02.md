> **HISTORICAL (2026-10-02) — superseded by `STATUS.md`.** Browser-session facts below are dated snapshots.

# Oracle — Session Status (2026-10-02)

## What Oracle is (plain)

A bug-bounty hunting pipeline. It scrapes a program's scope, downloads its
assets, reasons over them with three independent "mindsets," proves candidate
bugs with a fail-closed verifier, and writes submission-ready reports. The whole
point: take many honest, *verified* shots at authorized programs, wasting zero
time on false positives, so the volume converts to paid findings.

## The three mindsets (this session's main work)

A hunt now runs three candidate **generators**, all feeding one **verifier**:

1. **`mitre`** (LLM) — MITRE ATT&CK technique lens, full 342-TTP prompt.
2. **`paradox`** (LLM) — impossible-problems / paradoxes / philosophies / iPhone
   framing, now carrying the **full un-flattened corpus** (was flattened to ~3K
   tokens; now the real source material).
3. **`seam`** (deterministic, no LLM) — the Invisible Seam code lens, which also
   cross-compares against the two LLM lenses.

They are selected with `--mindset mitre|paradox|seam|all` (default `all`). Their
candidates are **cross-compared** for an agreement signal (ranking/confidence
only — it never confirms or drops a seam) and every well-formed candidate goes
through the frozen 5-gate verifier. The verifier decides truth, not the models.

## Verified on ground truth (the important part)

We tested against code with **known** planted bugs (`tests/bad_code_app.py`) and
a real vulnerable app (OWASP Juice Shop source):

- The **`mitre` mindset found all 3 planted flaws** (header-trust auth bypass,
  state-invariant coupon bug, leaked `/debug/config` secret) with runnable repro
  commands.
- The **`paradox` mindset also found them** in the full run.
- The deterministic **code lens found 35 real candidates** on Juice Shop's
  TypeScript (JWT algorithm confusion, unauthenticated routes) in 0.3s.
- The deterministic **web engine** caught an open unauthenticated API object and
  (after a fix) a leaked credential in an API response body.

**Key principle confirmed (your Reflex #6):** on code we *know* is broken, a
"clean" result means we applied the method wrong — not that the code is clean.
Twice that principle paid off this session: the models found the bugs, and the
misses were *our pipeline's* fault, both now fixed (below).

## Fixes made this session

- Corpus un-flattened (14→39 files, 92K→324K) and the 12K runtime truncation cap
  removed for the paradox lens.
- `cross_compare` no longer drops a second finding at the same URL.
- Secret scanner now reads **all** response bodies, not just `.js` (caught the
  leaked key it previously walked past).
- **Parser robustness (biggest):** the full run exposed that `_parse_seams`
  returned **0 cards** on valid `**SEAM CARD N - ...**` output with fenced-block
  curls — silently discarding real findings. Now handles header and fence
  variation across models; verified the real run output 0→2 cards.
- Proof-first hardening committed (Assertion-A must cite a source; header
  predicates).

All committed on branch `rowan/hunt-filter-fixes`; 121 tests passing.

## How close are we to "done"?

The hardest technical risk — *does the method actually find bugs?* — is now
**retired. It does.** What remains is wiring and coverage, not the core question:

| Piece | State |
|---|---|
| Analysis (3 mindsets find bugs) | ✅ proven on ground truth |
| Parsing candidates reliably | ✅ fixed this session |
| Deterministic verifier (5 gates) | ✅ exists, frozen |
| **Extract/download across 14 platforms** | ❌ not verified — the real gate to a real target |
| One full recon→verify→report run on a real program | ❌ never run end-to-end |
| Full-run speed (cascade through free models is slow) | ⚠️ works but slow; needs smarter model selection |
| State-mutation (POST) auto-confirm | ⚠️ safe verifier is GET-only; needs testnet/human path |
| Report sort-by-agreement, aliases, traffic | minor / mostly done |

**Estimate:** the instrument is ~85–90% of the way to "runs a full hunt and
produces parsed, verified findings." The two substantive remaining pieces are
(1) proving scope extraction + asset download on a real program, and (2) one
clean end-to-end run. That's a focused session or two — not "done today," but
the make-or-break risk is behind us.

## Next actions (priority order)

1. Verify extract/download on one real filtered program (subsystem #2 — the gate).
2. One full end-to-end hunt on a real target → confirmed seam → submission draft.
3. Speed: bound/smart model selection so full hunts complete quickly.
4. Minor: report sort-by-agreement, POST-confirm path, assertion-text cleanup.
