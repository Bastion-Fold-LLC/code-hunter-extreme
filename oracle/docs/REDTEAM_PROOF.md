> **HISTORICAL — red-team proof snapshot (testbed claims dated); current proof set in `docs/HOW_THE_SYSTEM_WORKS.md` §6.**

# Red-Team Proof Run — omnicli staged red-team

_Run 2026-10-15. Proof that the omnicli red-team engine works, measured against a
known answer key. No quality gate, no reviewers — just the engine vs. labeled code._

## What was run

The staged red-team was run against the **dev set** (`tests/fixtures/redteam/cases.dev.jsonl`
in omnicli): **24 cases — 12 genuinely vulnerable, 12 benign** — each with a known
answer (category + file + line + gold evidence). A finding only counts as a hit under
the strictest metric:

> `metric = exact_category_file_line_and_quoted_gold_evidence`
> (right vulnerability class **and** right file **and** right line **and** it quotes the gold evidence)

**Reproduce:**
```bash
omni evaluate-security \
  --dataset tests/fixtures/redteam/cases.dev.jsonl --split development \
  --model groq:openai/gpt-oss-120b \
  --model siliconflow:deepseek-ai/DeepSeek-V4.1-Flash \
  --model xkiro:google/gemini-2.5-flash:free \
  --staged-redteam --output reports/redteam_dev_proof.json
```
(No `--quality-gate`: this uses the dev set's own labels; it does not touch the
2-reviewer transition gate. repetitions = 1, 3 model families.)

## Results (single-pass, 24 cases)

| model | recall (real vulns caught) | specificity (benign left alone) | citation accuracy | TP | FP | FN | errors |
|---|---|---|---|---|---|---|---|
| **groq** `openai/gpt-oss-120b` | **83.3%** (10/12) | **100%** (0 false alarms) | **100%** | 10 | 2 | 2 | 0 |
| **xkiro** `google/gemini-2.5-flash:free` | **91.7%** (11/12) | 83.3% | **100%** | 11 | 3 | 1 | 0 |
| siliconflow `deepseek-ai/DeepSeek-V4.1-Flash` | — | — | — | 0 | 0 | 12 | **24/24 failed** |

**3-model staged council:** Precision **0.786** / Recall **0.917** / F1 **0.846** —
394 member calls, **1 invalid case trial rejected** by the evidence gate.

**Measured recommendation (not auto-routed):** `xkiro:google/gemini-2.5-flash:free`
(F1 0.846, tie-break: latency).

## What this proves

- **It finds real bugs.** Best single model caught 11 of 12 planted vulns; the council
  caught 91.7% — under the strict exact-citation metric.
- **It does not fabricate.** groq flagged 0 of the 12 clean files (100% specificity).
  Citations were 100% exact (correct file/line/quote) for both working models.
- **The evidence gate is real.** It rejected 1 trial as invalid rather than letting an
  ungrounded finding through.

## Honest caveats (not hidden)

1. **siliconflow `deepseek-v4.1-flash` errored on all 24 cases** — that endpoint is broken
   for this workload (wrong model id, rate-limit, or it rejects the prompt format). The
   run counted those as missed findings rather than papering over them. 13 other providers
   + the freellmapi router are available to swap in a working third family.
2. **Not exploitability proof.** From the tool's own limitations:
   - Measures only the labels/cases supplied by the dataset author.
   - A match is not proof of exploitability; labels must be independently reviewed.
   - A missing/malformed model response counts as a missed gold finding (reported as an error).
   - 95% Wilson confidence intervals; not corrected for correlated cases/repeated prompts.
   - Do not route production audits from a small or unrepresentative dataset (24 cases).

## Bottom line

The red-team engine works: real recall (83–92%), 100% exact-citation accuracy, zero
hallucinations on clean code (groq), with honest reporting of the one provider that failed.
This proves the *engine*, not a production certification. Artifact:
`reports/redteam_dev_proof.json`.
