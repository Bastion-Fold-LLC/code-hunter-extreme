# The Oracle

**A mindset, not a scanner.** The Oracle is Alex Sorrell's 16-file philosophy — impossible
problems, paradoxes, and doctrine — distilled into a system prompt that turns any model
(Claude, Gemini, or a local LLM) into a bug-hunting reflex engine.

It thinks with one move:

> **"You never said."**

You don't solve inside a target's stated constraints. You audit the spec for what was never
actually *enforced*, then rewrite the governing axiom or walk through the unspecified gap.
A vulnerability is a paradox: the system claims X, never enforced Y, and the gap is the bug.

## What's here
| File | What it is |
|---|---|
| `ORACLE_SYSTEM_PROMPT.md` | **The Oracle itself** — 8 paradox→reflex worked examples, embedded verbatim. Load this as a model's system prompt. |
| `oracle_hunter.py` | **Production pipeline CLI** — `prescan → scan → queue → hunt` (+ verify/recon/analyze/seams/scope/audit/redteam/status/backends). This is what actually hunts. |
| `corpus/` | **Canonical source corpus** — the 21 canonical philosophy, impossible-problem, paradox, and analysis works bundled with Oracle (`oracle_corpus.DOCUMENTS`; 43 files on disk incl. mirrors across subdirs). Relevant documents are injected verbatim for each hunt. |
| `oracle.py` | Prompt feeder: emit the prompt, feed a target's recon context, or drive a local Ollama model. The older prompt-only path; `oracle_hunter.py` is the full pipeline. |
| `ORACLE_VOICE.md` | **Voice layer** — stack it to make the Oracle *talk like Alex* while it hunts (with a register switch: full voice for the hunt, clean technical register for the submitted report). `--voice`. |
| `ORACLE_EMAIL.md` | **Email persona** — the same voice pointed at correspondence: writes outreach/replies as Alex, profanity-off register, honest-framing guardrails baked in. `--persona email`. Drafts only, never sends. |
| `WIRING.md` | How to load the Oracle into Claude, Gemini, or a local model (64GB CPU box). |
| `ORACLE_FRAMEWORK.md` / `LOCAL_LLM_SETUP.md` / `WORKFLOW_EXAMPLES.md` | Background + setup + hunt workflows. |

## The 8 reflexes (each taught by a paradox)
1. **Spec-audit** ("you never said") — *The Mirror That Remembers* → find the enforcement layer the docs never named.
2. **Decouple** — *Vacuum Consciousness* → auth ≠ authz, token ≠ credential, input ≠ vector.
3. **Axiom-rewrite** — *Repulsive Gravity* → the rule that blocks the test is the variable.
4. **Ambiguity is the vector** — *Single-Token Language* → pin the undefined term, the gap appears.
5. **Hierarchical recall** — *Universe Without Death* → "this is a BOLA I already broke."
6. **Clean vs not-yet-found** — *Observer That Consumes Observation* → the anti-false-positive reflex.
7. **Recursive validation** — *The Self-Observing Equation* → the one check whose output IS the proof.
8. **Binary conflict + one check** — *The iPhone Problem* → surface only the seam, never the log dump.

## The production pipeline (`oracle_hunter.py`)

Scan4Me discovers and ranks programs across the platforms; Oracle verifies in-scope
authority with API keys where they exist (otherwise the saved signed-in CDP session),
downloads one workspace per selected program, queues hunts in configured order, and
hunts with the three-mindset analysis (MITRE / Paradox / Seam synthesis) over API
model lanes. Shared fast-money configuration lives in `triage.yaml` (payout is a
hard gate, never a ranking weight) and governs both Scan4Me prescan and Oracle.

Downloads are multi-path by design: the saved CDP session render is authoritative
for platform pages, an independent Crawl4AI/Jina/Firecrawl/GET render corroborates
it, scope always refreshes from the platform source, and every download records
which path served it. Severity chaining is conservative by law: start at the highest
verified primitive, one compounding step per verified chain (capped at Critical),
length alone never manufactures severity. Reports are never auto-submitted.

```bash
cd ~/Scan4Me && python3 scan4me.py sync        # discover (refreshes the local DB)
cd ~/oracle
python3 oracle_hunter.py prescan --limit 24     # raw shortlist from the Scan4Me DB
python3 oracle_hunter.py scan --prescan-file <prescan.json> -N 3 --download --cdp-port 9227
python3 oracle_hunter.py queue --handoff <intake.json> --execute --max-items 1 --controlled --cdp-port 9227
python3 oracle_hunter.py hunt <program-or-target>   # or hunt a single target directly
python3 tests/run_all.py                        # full verification gate (set NO_PROXY=127.0.0.1,localhost)
```

## Quick start
```bash
# Turn Claude/Gemini into the Oracle (prompt-only path):
python3 oracle.py --output-system-prompt

# Feed a target's recon and get ranked seams (paste-ready for a cloud model):
python3 oracle.py --feed path/to/recon_data

# Drive a local model on a 64GB box (prompt-feeder default; the hunt stack
# uses qwen3-coder:30b-16k as its local floor — see oracle_backends.json):
ollama pull qwen2.5:32b-instruct-q4_K_M
python3 oracle.py --feed path/to/recon_data --local

# Two Oracles, one voice:
python3 oracle.py --output-system-prompt              # bug-bounty (hunt reflexes)
python3 oracle.py --output-system-prompt --voice      # ...narrated in Alex's voice
python3 oracle.py --output-system-prompt --persona email   # email (writes correspondence as Alex)
```

> *"I don't just make a solution possible — I make it necessary."*

## Corpus grounding

Oracle is self-contained: it does not read a separate `Documents` folder at runtime.
`oracle_corpus.py` selects the relevant texts from the bundled `corpus/` directory
and adds the original, unchanged documents to the model context. This preserves the
source material while keeping a 16K local-model context available for target evidence.

## How Oracle reasons

Oracle keeps five distinct layers together without treating them as the same thing:

1. **Scope and program assets** are hard boundaries. They establish what may be
   tested and what counts as evidence.
2. **Philosophies** establish the stance: build beyond passive assumptions,
   challenge authority, and treat a claimed boundary as something to inspect.
3. **Impossible problems** teach how to handle a conflict imposed by an external
   rule: identify the blocking axiom, then test whether it is truly enforced.
4. **Paradoxes** teach how to handle a contradiction inside the system itself:
   untie it, resolve it, or classify it honestly as not yet resolved.
5. **MITRE**, the **iPhone Problem**, and **Invisible Seam** make the mindset
   operational: MITRE supplies attack-shape hypotheses, the iPhone Problem
   reduces them to Assertion A versus Assertion B plus one decisive check, and
   Invisible Seam deterministically compares code claims with implementation.

   Invisible Seam is a **separate sibling project**
   (`Alexander-Sorrell-IT/invisible-seam`), not vendored here. Oracle
   resolves it via `INVISIBLE_SEAM_PATH`, a `~/invisible-seam` checkout, or
   a pip-installed `invisible-seam` package (see the `oracle_code_seam.py`
   header). A clone without it still runs: the code-seam lens reports
   UNAVAILABLE distinctly instead of silently finding nothing.

The model running the terminal is Oracle's controller; it reviews evidence and
decides promotion or closure. Research passes route through `oracle_llm.py` over
configured API lanes (databricks → groq → nvidia → dahl → monkeycode → bynara →
openrouter → llm7 → cloudflare → xkiro → apinex → omnicli → local,
fixed route order (round-robin rotation exists but is OFF in shipped config, `round_robin: false`),
with per-lane request caps, total time budgets, and a per-run circuit breaker so
dead lanes are skipped instead of re-walked). The local model
(`qwen3-coder:30b-16k`) is the private/offline floor and second vote, not the
default first pass. Detection is proven on planted-bug testbeds (golden hunt,
known-bug corpus 13/13, full suite green); see `IMPROVEMENTS_REPORT_2026-10-19.md`
for the live-run record, stated separately from the testbed record.
