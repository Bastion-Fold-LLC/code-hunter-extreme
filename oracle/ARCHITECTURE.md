# Oracle — Architecture & Interface Guide

## What Oracle Is

Oracle is a bug bounty hunting pipeline. It runs recon, applies 8 security reflexes
via an LLM, verifies candidate findings deterministically, and produces submission-ready
reports. It runs from inside any AI shell interface.

---

## Starting Point — The Interface

Oracle is launched from whichever AI shell you are already in:

| Interface | How to launch oracle |
|---|---|
| **Bob shell** | `oracle-hunter prescan` → `scan` → `queue --execute` (pipeline) or `oracle-hunter hunt <target>` (one-off) |
| **Claude Code** | same |
| **Gemini Antigravity** | same |
| **Copilot** | same |
| **ChatGPT** | same |

Oracle does NOT call back into the interface you launched it from.
It uses its configured API lanes (and local Ollama as floor) for its own LLM passes.
The interface you started from is just the shell — you reason over the output directly.

---

## The Backend Stack

```
Starting interface (bob / claude / gemini / copilot / chatgpt)
        ↓
   oracle-hunter hunt <target>
        ↓
   Automated passes via oracle_llm.complete (13 lanes, fixed route order (round-robin rotation exists but is OFF in shipped config, `round_robin: false`)):
     - API lanes (primary): databricks, groq, nvidia, dahl, monkeycode,
       bynara, openrouter, llm7, cloudflare, xkiro, apinex, omnicli
     - Local Ollama             (qwen3-coder:30b-16k floor / second vote)
     - copilot -p               (subprocess, works in any context)
     - bob / claude / gemini -p (subprocess, only from terminal — not from inside themselves)
   Lane health: per-lane request caps (Groq 8000tok), TOTAL time budgets
   (Engine-A 360s / ladder 170s / Mindset-3 360s), 600s circuit breaker
   that skips dead lanes instead of re-walking them every pass.
        ↓
   Output: seam cards + verified findings
        ↓
   You reason over confirmed seams in your current interface
```

### Session detection

When running inside bob/claude/gemini, `BOB_SESSION=1` (or equivalent) is set.
Oracle detects this and skips subprocess calls to those same CLIs automatically.
Routes go to the API lanes + local floor. No configuration needed.

---

## The Mind — What Drives the Analysis

Oracle's analysis is not a prompt. It is a cognitive operating system loaded into every
LLM call. Its operational documents are concatenated, then the relevant original source
texts are selected verbatim from the bundled corpus:

| Document | What it is |
|---|---|
| `ORACLE_SYSTEM_PROMPT.md` | 8 paradoxes as worked examples → hunt moves |
| `ORACLE_FRAMEWORK.md` | 16-file philosophy — the cognitive OS |
| `ORACLE_VOICE.md` | Register + output discipline |
| `ALEX_VOICE.md` | One-move structure, named moves, rhythm |
| `corpus/` | The 21 canonical source documents (`oracle_corpus.DOCUMENTS`), selected verbatim by target context |

Plus per-hunt:
- `oracle_ttps_fused.json` — MITRE ATT&CK fused with the 8 reflexes + "you never said" seeds
- Program brief — scope wall, in-scope assets, rules of engagement

**The philosophies, paradoxes, and impossible problems are not decoration.**
They are packaged with Oracle and injected as original source text, not reduced to a
replacement summary. They teach the model a reasoning pattern, not a vocabulary.
"You never said the server checks it, only the UI hides it" is a move, not a sentence.

---

## The 8 Reflexes

Every analysis runs these in order:

1. **SPEC-AUDIT** — what layer actually enforces the claim?
2. **DECOUPLE** — authentication ≠ authorization, identity ≠ ownership
3. **AXIOM-REWRITE** — the blocking rule is a variable, not a wall
4. **AMBIGUITY IS THE VECTOR** — the undefined term is the door
5. **HIERARCHICAL RECALL** — map to a class already broken
6. **CLEAN vs NOT-YET-FOUND** — honest state: actually clean, or not found yet?
7. **RECURSIVE VALIDATION** — one command's output IS the proof
8. **BINARY CONFLICT + ONE CHECK** — two assertions, one curl, nothing else

---

## Two Bug Engines

### Type-1 — Code bugs (Invisible Seam)
Deterministic. No model in the loop.
1. Extracts behavioral claims from: Python docstrings/type hints, Solidity NatSpec + `require()`, Cairo `///` docs
2. Matches claims against implementation
3. Runs a check, gets a verdict: CONFIRMED or CLOSED
4. Zero false positives from hallucination

The evidence spine is language-agnostic (doc + config extractors; the
per-language security extractors were removed 2026-10-17). Solidity/Cairo
claim extraction survives inside the doc extractor; there are no
per-language detector modules.

### Type-2 — Logic bugs (Oracle 8-Reflex)
LLM-driven. Finds business logic flaws, auth bypasses, IDOR, race conditions.
1. Recon → signal extraction (up to 20,000 chars)
2. MITRE TTP mapping → aimed reflexes
3. Seam cards parsed → verify gate
4. Deterministic FP filter (401/403/404/530/HTML kills the triage-LLM assess step post-check — not a pre-analysis filter)
5. Confirmed seams → PoC synthesis

---

## Intake Pipeline (Scan4Me → Oracle)

```
scan4me sync            discover: 13+ platform feeds into the local DB
  → oracle-hunter prescan   fast sweep (triage.yaml overlay; raw, untrusted)
  → oracle-hunter scan      verify per program; -N/--sites select; --download
                            writes one workspace per VERIFIED program + handoff
  → oracle-hunter queue --execute   waves in config order, same-site sequential,
                            --max-items cap, resumable state, failure isolation
  → oracle-hunter hunt      the per-program pipeline below
```

Scan4Me discovery is no-login: `prescan --sync` calls Scan4Me with
`use_auth=False`. Its report is raw candidate material
(`trusted=false`, `feed_trust.raw_candidate_ok`); public provenance is
never product truth, and `feed_trust.ok` remains only the separate
authenticated-feed verdict. Prescan/scan hard-fail when the feed is
unavailable, stale (including age over Scan4Me's 48h bound), or its last
refresh failed. `prescan` preserves the rejected report on disk and the
runlog records the failure; there is no operator bypass flag.

Trust is created in `scan`, per program. HackerOne scope is re-fetched
from HackerOne's own authenticated Hacker API with Oracle's
`HACKERONE_USERNAME` + `HACKERONE_API_TOKEN`/`HACKERONE_API_KEY`; an
auth/transport failure fails the scan instead of reusing Scan4Me's DB
copy. A 404 is rendered as a vanished program, never as stale scope.
Other platforms have no Oracle API/browser adapter yet: they are stamped
`oracle_rescan={source: no-oracle-adapter, independent: false}` and
cannot verify, download, queue, or become submission-ready. The Scan4Me
bridge is never used to corroborate its own DB copy, deep-dive consumes
the scan verdict's embedded fresh listing, and the handoff copies the
scan's discovery provenance verbatim (trust verdicts re-derived from it,
never copied). Every downstream entry gate — scan verdict, deep-dive,
download, schedule build, queue execution, chain hunt — uses one
strict record check: `verdict=verified`, no failed checks, and re-scan
metadata with `independent=true`, `found=true`, a real adapter source,
and (whenever the adapter stamps one; HackerOne always does) a handle
bound to the program. Bundle readiness uses the same strict metadata
check and additionally requires the handle stamp to be present and
bound to the workspace `program.json`. Malformed feed
provenance fails closed, stored prescan trust blocks are always
re-derived from provenance, and a queued hunt pins the scan-verified
deep-dive assets from its pick (stamping chain vs final scope hashes)
instead of re-resolving scope from the DB.

Every completed `queue --execute` hunt is packaged into
`reports/product_<stamp>.zip` with `manifest.json` + `manifest.sha256`.
`verify-download` checks the manifest offline. Integrity and readiness are
separate: `ready_for_submission` requires matching confirmed results and
finding JSONs, a full report, a non-empty PoC per confirmed finding,
explicit mindset yield accounting with no unserved mindset,
`oracle_rescan.independent=true` (handle-bound) for the hunted
program (every platform), a non-empty download report when one exists
(it is packed and recorded in readiness checks either way), and clean
manifest verification. Scan4Me
`feed_trust` is carried as discovery provenance only; its public rows
neither create readiness nor block an independently verified product.
A zero-confirmed or direct/non-queue workspace gets a valid,
explicitly non-ready bundle — never a green gate.
OmniCLI's `omni oracle-pipeline` conductor runs the same three commands and
returns `complete` only when at least one verified bundle is submission-ready.

## Pipeline Steps (oracle-hunter hunt)

```
1. Resolve program + build unified mindset context
2. Create workspace: targets/<platform>/<slug>/
3. Download assets: program page, JS, OpenAPI specs, repos (git clone)
   └─ Scope always refreshes from the platform source first (API keys where
      they exist, saved signed-in CDP session otherwise). Platform pages:
      saved-session CDP render is authoritative (no anonymous substitute);
      an independent Crawl4AI → Jina → Firecrawl → GET render corroborates
      it (page-source agreement metrics). Target assets: plain GET, renderable
      failures get the cascade as a second path. Every result records `via`.
4. Recon: subfinder → httpx → gau → katana → nuclei → hakrawler → dnsx
5. Oracle analysis pass — 3 mindsets, all feeding one verifier:
   - `mitre`   (LLM) — Mindset 1, MITRE ATT&CK technique lens
   - `paradox` (LLM) — Mindset 2, impossible-problems / philosophy corpus
   - `seam`    (synthesis) — Mindset 3, unifies both lenses' outputs +
     deterministic seam candidates + red-team verdicts into one ranked result
   Both LLM lenses reason WITH invisible-seam candidates + bounty context +
   red-teaming. The deterministic code lens + template engine are the shared
   candidate feed, not a fourth lens.
   The operator CLI always runs all three; there is no mindset selector.
   `--no-cloud` runs all three locally; a lens with no local engine is a
   hard error, never a silent drop. Embedded callers/tests may request a
   subset through the internal API, but that is not a product run.
6. Mindset-3 synthesis: unify + rank all candidates (agreement signal); parse + classify (Type-1 vs Type-2)
7. Invisible Seam code lens (if source on disk)
8. Dual-account IDOR probes (if --account-a / --account-b provided)
9. Verify: gate ladder (shape pre-gate + Op1; Gates 1/2/2b/3/4/5/5b/7 in
   `verify_seam_card`; post-gates 6a/6b/7-B1/7-C in the hunter verify loop)
10. Bug chain engine: compose confirmed seams (one compounding severity step
    total, capped at Critical; unconfirmed findings never compose — Doctrine §6)
11. PoC synthesis for confirmed seams
12. Write report: targets/<platform>/<slug>/reports/
```

### Run logs

Every CLI invocation creates `reports/runs/<run_id>/`:

- `events.jsonl` — append-only JSONL: `run.start`, console output, warnings,
  errors, stage/artifact events, `run.exception`, `run.end`
- `summary.json` — final status (`ok`, `failed`, `incomplete`), command,
  duration, event counts, warnings/errors, artifact paths + SHA-256
- `latest.json` — pointer to the newest run

This is deliberately a log, not a completeness gate. Parts of the pipeline
are allowed to fail; they are not allowed to fail silently or to make a
partial run look complete. A failed run keeps its partial artifacts.

---

## Credentials

Loaded (layered, later wins) from `~/.config/trio/keys.env`, `ORACLE_KEYS.env`, `.env`, then process environment:

| Key | Used for |
|---|---|
| `HACKERONE_API_KEY` (+ username) | H1 program list / scopes |
| `HACKERONE_USERNAME` + `HACKERONE_API_TOKEN`/`HACKERONE_API_KEY` | Oracle's independent H1 verify re-scan (`scan`) |
| `INTIGRITI_TOKEN` | Intigriti researcher API (Bearer) |
| `HACKENPROOF_API_KEY` | HackenProof programs |
| `OPENROUTER_API_KEY` | One of 13 routed LLM lanes |
| `FIRECRAWL_API_KEY` / `JINA_API_KEY` | Corroboration renders |
| `RESEARCHER_HANDLE` | Compliance headers |

Status column intentionally removed: presence in a file ≠ usable (placeholder
values are rejected at load — precisely: empty or whitespace-containing credential-suffixed values). Run `python3 oracle_hunter.py status` for live state. Key naming follows code: adapters accept `INTIGRITI_TOKEN` **or** `INTIGRITI_JWT` (Bearer); the `status` probe currently checks only `INTIGRITI_JWT` (known inconsistency).
Model lanes use one key per lane in `oracle_backends.json` (`DATABRICKS_TOKEN`,
`GROQ_API_KEY`, `NVIDIA_API_KEY`, `OPENROUTER_API_KEY`, …); retrieval uses
`FIRECRAWL_API_KEY` / `JINA_API_KEY`. Where no platform key exists, the saved
signed-in session is the credential path, by design.

CDP sessions: hunt Chromium on port **9227** (logged-in browser for platform
pages; tab creation requires PUT on modern Chrome); email Firefox CDP on
**9222** — different browser, different job.

---

## Dual-Account IDOR

Pass two session tokens at hunt time. Literal secrets on the command line
are **refused** — use an env reference, a file, or an interactive prompt:

```bash
oracle-hunter hunt <target> \
  --account-a "env:ACCOUNT_A_TOKEN" \
  --account-b "@~/.oracle/account_b.txt" \
  --researcher codehunterextreme
# or: --account-a 'prompt'  (typed at runtime, never stored in argv/history)
```

Oracle will:
1. Inject Account A token into all verify probes
2. Extract resource-bearing URLs from seam cards (numeric IDs, UUIDs, prefixed IDs)
3. Generate Account B curl probes with compliance headers for each
4. Run cross-account IDOR checks automatically

---

## Running It

```bash
# Supported pipeline: signed-in Scan4Me sweep → Oracle re-scan + handoff → hunt
oracle-hunter prescan --sync
oracle-hunter scan -N 1 --download
oracle-hunter queue --execute

# Package one finished hunt into a SHA-256 product bundle and verify it offline
oracle-hunter bundle targets/HackerOne/<slug>
oracle-hunter verify-download targets/HackerOne/<slug>/reports/product_<stamp>.zip

# One-off hunt for a specific program (no Scan4Me/handoff/selection flags)
oracle-hunter hunt "shopify"

# One-off hunt with cloud escalation
oracle-hunter hunt "shopify" --cloud

# Hunt with authenticated sessions (IDOR mode; literal tokens are refused)
oracle-hunter hunt "shopify" --account-a "env:ACCOUNT_A_TOKEN" --account-b "env:ACCOUNT_B_TOKEN"

# Audit a Web3 repo (Type-1 code lens only)
oracle-hunter audit targets/sherlock_aave_v4/aave-v4

# Status check
oracle-hunter status
```

---

## What Is Not Done Yet

1. **A live paid-target finding.** Detection is proven on planted-bug
   testbeds (golden hunt, known-bug corpus, full suite green). The one full
   live hunt (2026-10-19) died at engine analysis before the lane-health
   fix; engines have since answered hunt-scale prompts live, but no
   end-to-end live hunt has completed on healthy lanes yet. That run is
   the next proof owed (`IMPROVEMENTS_REPORT_2026-10-19.md`).
2. **Databricks lane** returns HTTP 400 on all configured models (root
   cause undiagnosed); the breaker keeps it skipped while down.
3. **Authenticated recon on a real target** — pass `--account-a` (env/file/
   prompt form) with a real session token.
4. PoC synthesis runs through the router lanes; there is no separate
   direct-Anthropic/Gemini path to wire (older versions of this list were
   obsolete on that point).
