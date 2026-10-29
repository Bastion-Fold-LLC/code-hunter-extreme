# Completion Plan — from "mechanically runs" to "paid"

Derived from `FINISH_BOARD.md` (2026-10-27). The board stays the source of truth
for stage state; this file is the ordered execution plan that closes the open
stages. If the two disagree, the board wins.

## Where we actually are

| Finish line | State | What that means |
|---|---|---|
| Safety closure | **10/10 closed** | Audit findings closed, committed, with accepted residuals named (S6/S7) |
| Money | **4/8** (M1–M4) | Intake, detector, one live hunt, auth plumbing all done |
| Money blocker | M5–M6 open | No authenticated hunt has run; **confirmed findings ≥ medium: 0** |

The architecture the operator asked for already exists end to end:

```
scan4me sync → scan4me prescan (unauth, triage.yaml shared with Oracle)
             → prescan_*.json report  ─┐
oracle-hunter scan --prescan-file ◄──────┘  verify (scope-live, payouts, rules)
             → -N / --sites  → --download  (CDP → Crawl4AI → Jina → Firecrawl → GET)
             → scan_*.json + handoff_*.json
oracle-hunter queue --handoff … --execute  (M1 ≥ M2 → M3, scope gate, teardown)
             → research/findings/*.json → bundle → verify-download
omni oracle-pipeline                       (conductor; complete only with a ready bundle)
```

So the gap is **not wiring**. Every stage in the operator's spec is implemented
and exercised. The single unsolved problem is **yield**: real hunts produce
candidate cards and then demote 100% of them at teardown.

## Diagnosis — why the money line is stuck

Evidence from the 2026-10-27 Matomo runs (board, "Pipeline exercise"):

1. **Lens starvation (G10, closed but unconsumed).** Both LLM lenses minted 0
   claims on 72–92k-token prompts. Packing now caps prompts at 65k and delivers
   every TTP/corpus document exactly once — but **no live hunt has run since**.
2. **Zero corroboration on a real target.** 53 candidates (49 PHP Type-1 + 4
   value SQLi), `cross_compare 0 corroborated`. The three-mindset corroboration
   machine has only ever been proven on the gauntlet, never on a real program.
3. **Teardown demotes everything.** 53/53 demoted. This is indistinguishable
   from a *correct* teardown gate, because there is no labeled live truth to
   score it against. That is the same methodological hole as the planted-bug
   critique, one layer up: the gauntlet proves the plumbing, not the judgment.
4. **Local second vote unavailable.** Ollama models dir not traversable by the
   ollama user, so dual-engine adjudication was single-engine.

Everything below follows from (1)–(4).

## Work packages, in order

### P0 — Stop the bleeding (today, <1h, agent)

| Item | Why now | Exit criteria |
|---|---|---|
| Push `invisible-seam` with the PHP code lens (G5) | It lives **only in the local tree**. Two verifier rounds and 9 fail-first regressions are one disk failure from gone | `invisible-seam` remote exists, seam commit pushed, board G5 `verified → closed` |
| Fix blind-eval DB path | `test_blind_evaluation` resolves `Scan4Me/scan4me.db` (capital S); tree has `scan4me/` and no DB | Test resolves the real DB path case-insensitively, skips with a clear reason when absent, and **passes** either way |
| Commit the working tree | Board rule: nothing counts until committed | HEAD clean, Oracle suite green at HEAD |

### P1 — Consume the two closed fixes (highest value per hour, agent)

One live hunt on the same Matomo tree, now with G10 packing + G11 scope refresh +
the G5 PHP lens. This is the first real test of the whole mindset machine.

```
python3 oracle_hunter.py hunt <matomo> --cloud        # no --mindset selector
```

**Exit criteria (recorded, not vibes):**
- M1 claims > 0 and M2 claims > 0 (parsed, not empty)
- `cross_compare` corroborated ≥ 1, *or* a documented reason none can exist
- teardown pass rate > 0 (≥1 survivor), or a named defect per demotion class
- a per-candidate funnel: minted → survived redteam → survived teardown, with
  the rejection reason for every drop

If M1/M2 still mint 0 with packing, the next suspect is the lane routing/model
choice for long prompts, not the corpus.

### P2 — Make teardown auditable (agent, ~1 day)

Cannot fix what cannot be scored. Add a rejection-reason census over the hunt's
finding JSONs (reason → count, per lens). Acceptance: on the Matomo rerun, the
census accounts for 100% of demotions, and at least one demotion class is
challenged by an independent verifier and overturned or upheld with evidence.

This is the honest replacement for "it demoted everything, so it works."

### P3 — M5 authenticated hunt (agent + user inputs)

User-provided and blocking: target approval, two accounts via `env:` / `@file` /
prompt (never argv). Prefer a small/new program. Prompt-login stays direct-hunt.

Exit criteria: both accounts used, `_effective_recon_auth` proves the bearer came
from Account A, zero lens-zero silent passes (`_die_on_unserved_mindsets` fires
loud and the report is preserved), and a funnel from P1/P2 exists for this target.

### P4 — M6: first confirmed finding ≥ medium with wire evidence

Depends entirely on P1–P3. Not schedulable before them, and not a coding task
until a candidate survives teardown.

Exit criteria: one finding whose card carries wire evidence (request/response),
scope-gate pass, teardown pass, per-seam PoC, and a proof packet that verifies
under `verify_proof_packet`.

### P5 — M7/M8 submission (user-only by doctrine)

Draft must let a triager reproduce alone. Submit and payout are external.

## Cross-cutting, not on the money path but needed before external claims

1. **OmniCLI transition gate** — needs a second independent reviewer on the
   60-case blinded packet, then `omni evaluate-security --quality-gate` across 3
   families × 2 reps with live keys. Until then omnicli's green suite is not the
   same as a passing gate.
2. **Unify the two proof-packet implementations** — `omnicli/proof_packet.py` and
   `oracle/oracle_foundation.py:681` are both HMAC but structurally independent.
   If a receipt is meant to travel from Oracle to omnicli, one of them must be
   canonical and the other must verify against it.

## Definition of finished

- **Safety:** already met (10/10 closed).
- **Money:** M1–M8 all `verified` or `closed`, i.e. one accepted, paid finding.
- Anything short of M6 is a good engineering artifact with an unproven product.

## What would falsify the current approach

If the P1 rerun still shows M1+M2 minting 0 and teardown demoting 100%, then the
bottleneck is generation, not verification, and no amount of gate hardening will
produce a paid finding. At that point the decision is between (a) seeding
hunting with a database of known CVE patterns per stack, or (b) narrowing
targets to stacks where the deterministic lenses already win (PHP value-position
SQLi, Solidity NatSpec seams) instead of hunting general web apps.
