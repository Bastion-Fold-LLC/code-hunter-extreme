# How the Oracle System Works

_A complete, grounded explanation of the three-organ bug-bounty system. Written
2026-10-15, updated 2026-10-20 against the production pipeline and the
2026-10-19 live gate. Where something is optional, external, or not-yet-done
it says so plainly._

---

## 1. What it is

The Oracle System is **one organism for authorized bug-bounty hunting**, built from
three repositories (linked by the `oracle-system` super-repo as git submodules):

| Organ | Repo | Role |
|---|---|---|
| **The brain** | `oracle` | The hunter. Decides what to look at, turns target recon into candidate findings, **proves them on the wire**, chains them, and writes reports. |
| **The engine** | `omnicli` | Multi-provider AI orchestration **and** the red-team engine. Fans reasoning across many model families; has no mindsets of its own. |
| **The eyes** | `scan4me` | Scope / target intelligence. Ingests bug-bounty platforms and produces ranked, in-scope targets. |

The governing principle across all three:

> **AI proposes, deterministic code proves.**
> Models suggest where a bug might be. Nothing is called a finding until deterministic
> code confirms it against the live target (an HTTP/wire check), or a deterministic
> gate rejects it. No model opinion is trusted on its own.

Hard constraints (doctrine): **local/authorized targets only**, the hunting core is
**deterministic (no LLM guessing)**, and there are **no silent fallbacks** — anything
unproven is dropped loudly, never defaulted.

---

## 2. The end-to-end flow

```
scan4me                         oracle (brain)                              omnicli (engine)
────────         ┌────────────────────────────────────────────┐           ───────────────
platforms  ──►   │ acquire → recon → template seams (candidates)│           fan AI lenses /
→ ranked scope   │     → WIRE VERIFY gate ladder 1–7 (curl the target)   │ ◄──────►  red-team across
(scope_config)   │     → chain confirmed seams → report         │   via     many providers,
                 └────────────────────────────────────────────┘ oracle_llm  evidence-gated
                                      │
                                      ▼
                        verified, chained findings → BUG reports
```

1. **scan4me** syncs 13+ platform feeds into a local DB and ranks programs. Oracle's
   prescan reads that DB under the shared `triage.yaml` profile (payout is a hard
   gate, never a rank weight); `scan` verifies each shortlisted program, `-N` selects,
   and `--download` writes exactly one workspace per verified program — scope always
   refreshed from the platform source (API keys where they exist, saved signed-in
   CDP session otherwise), downloads corroborated across independent fetch paths.
2. **oracle** queues hunts (`queue --execute`: config order/waves, same-site
   sequencing, resumable state), acquires the target, runs recon, and applies its
   **seam templates** plus the MITRE/Paradox lens passes over the router's API lanes
   to produce *candidate* seams (claims of the form "assertion A vs. assertion B").
3. Every candidate is run through the **wire verifier**: the candidate's `check`
   (a `curl`/`grep` command) is executed against the live target, the response is parsed,
   and only candidates that survive the verification ladder become **CONFIRMED**.
4. Confirmed seams are **chained** into compound findings (and scored for severity).
5. Optionally, **omnicli** fans AI "lenses" / a red-team swarm across many model families
   to reason about the target — but their output is itself evidence-gated.
6. oracle writes the **reports** (description, proof, solution, PoC, submission draft).

---

## 3. oracle — the brain

**Entry point:** `oracle_hunter.py` (15 subcommands: prescan, scan, queue, hunt,
verify, recon, analyze, seams, scope, audit, redteam, …). `oracle.py` is the older
535-line prompt feeder (`oracle.py --feed <recon_dir>`), kept for prompt-only use.

### The three mindsets
oracle applies three cognitive modes (see `oracle_mindsets.py`, `oracle_mindset_context.py`):

- **M1 — MITRE:** full ATT&CK / CWE coverage; the systematic checklist view.
- **M2 — philosophy / paradox / impossible-problems:** the "no cherry-pick" creative view
  that looks for contract and assumption violations (the *invisible seam* — the thing you
  "never said" was true but the system assumes).
- **M3 — synthesis:** fuses M1 + M2 over the invisible seam.

### Seam templates (the candidate generators)
`oracle_seam_templates.py` holds **23 web templates** (plus a web3 layer in
`oracle_seam_templates_web3.py`). Each template encodes a conflict — e.g.
`mirror-remembered-vs-live` (stale API version still routable),
`repulsive-gravity-axiom-rewrite` (two spellings of one route, auth bound to one),
`state-invariant-violation` (terminal-state resource still accepts mutations),
`beautiful-liar`, `vacuum-identity-decoupling`, etc. Each carries a MITRE mapping
(CWE / T-code), a reflex class, and a classification (PARADOX / etc.).

A template reads recon material and emits candidate **cards**. A card states
`assertion_a` vs `assertion_b`, cites its source, and ships a deterministic `check`
(a `curl`/`grep` with an `expected` status/body) — the thing that will prove or kill it.

### The wire verifier (the proof)
`oracle_deterministic.py` implements Gates 1 (grounding), 2 (scope),
2b (discrimination), 3 (expectation), 4 (claim source), 5 (wire execution),
5b (verdict direction), 7 (adequacy) in `verify_seam_card`, behind a shape
pre-gate; the hunter's verify loop adds the Op1 metachar kill and post-gates
6a/6b/7-B1/7-C — backed by the enforce tests (`test_enforce_ladder`,
`test_confirm_gates`, `test_enforce_clean_signal`, `test_enforce_m3_gate`,
`test_enforce_redteam`). A candidate is only **CONFIRMED** when its `check` is run against
the live target and the response passes every gate. Anything else dies at
verify. This is where "AI proposes, deterministic code proves" is enforced.

### Chaining and reporting
Confirmed seams are composed into chains (`oracle_mindset_context.chain_seams`) under
the severity ladder law: start at the strongest verified primitive, **one compounding
step in total** (capped at Critical) — chain length alone can never manufacture
Critical, and unconfirmed findings never compose. Reports are written per bug (description,
on-the-wire proof, a fix, a stress-tested PoC, and a submission draft). Reports are
never auto-submitted.

---

## 4. omnicli — the engine

**It has no mindsets.** oracle calls it (`oracle_llm.py` → `omnicli.orchestrate.run_orchestration`)
to fan reasoning across providers. Two things live here:

### a) Orchestration
`run_swarm` / `run_orchestration`: fan a prompt across many model families, merge, and
synthesize. Used as oracle's "AI lenses."

### b) The red-team engine (`omnicli/redteam.py`)
This is the adversarial core, and it needs **no reviewers and no gate** to run:

- A **pinned 6-category taxonomy** (sql_injection, command_injection, path_traversal,
  unsafe_deserialization, authentication_authorization, sensitive_data_exposure) so
  findings are measurable.
- An **orthogonal payload-transform layer** (case-flip, URL-encode, HTML-entity,
  comment-break…) to probe evasion.
- An **evidence gate**: any ungrounded / hallucinated finding fails *globally*
  (unsupported_citation → FAIL → invalid trial). This is the anti-fabrication core.
- A **council-as-judge** stage with reasoning-chain validation + **deterministic
  cross-check**, then **ballots/votes** tallied to a verdict.
- A **spend ledger** (token budgets, retries).

Two ways to run it:
- **`omni swarm --redteam "<goal>"`** — fan all providers at a target/code; adversarial
  prompts; evidence gate rejects fabrications; votes tallied.
- **`omni agent --redteam "<goal>"`** — one autonomous adversary with real `verify_*`
  tools (`--allow-local`, `--allowed-host`, `--allow-mutating-http`) that actively probes
  a running target and proves findings on the wire.

### Providers & keys
(External-system claims — omnicli lives in its own checkout and is not verifiable from
this repo.) 14 providers, keys stored **uniformly** in `~/.config/omnicli/config.json` → `keys` dict
(0600). A **FreeLLMAPI** router is wired as one provider (`freellmapi`, self-hosted at
`127.0.0.1:3001`) that fans out to ~34 upstream providers with failover. `omni credits`
shows per-provider quota/usage in each provider's native unit (account balance,
rate-window, or a documented cap), honest `n/a` where none exists. From Oracle's side,
omnicli is simply one of 13 routed lanes in `oracle_backends.json`.

### The optional quality gate (NOT red-teaming)
Separate from the engine: `evaluate-security --quality-gate` / the Transition Gate
(`test_p4_council_rulings`). It is an **exam that grades** the red-team's accuracy against
a held-out answer key, and it requires that answer key to be labeled by **two independent
reviewers** (so the grade is trustworthy). This is optional certification — it is not the
red-team, and the engine works without it.

---

## 5. scan4me — the eyes

Scope / target intelligence: multi-platform ingestion (HackerOne, Bugcrowd, Intigriti,
YesWeHack, Immunefi, Sherlock, PDPrograms + listing-only Bugbase/HackenProof/Cantina/
Patchstack/Huntr/CodeHawks; Federacy off by default, Hats excluded) → scope, eligibility,
and composite ranking. Listing-only platforms carry zero fabricated assets. Output feeds
oracle via the `oracle_scan4me` bridge, under the shared `triage.yaml` overlay.

---

## 6. How we know it works (testbed record; live record stated separately)

- **oracle full suite: all 10 layers green** (`python3 tests/run_all.py`, re-verified
  2026-10-20 alongside the full pytest suite, 1148 passed): card-structure
  (23 web templates), injection templates, wordlist coverage, golden hunt, red-team
  verifier+chain, severity ladder, omnicli gates, known-bug corpus (13/13), web3,
  3-mindset gauntlet. Detection on planted-bug testbeds is proven and repeated.
- **Live record:** the 2026-10-19 live gate ran sync → prescan → scan → download →
  queue → recon against a real target, then died at engine analysis (lane starvation,
  since fixed: circuit breaker + total budgets; a 68k-token hunt prompt has since
  completed live in 99.6s). Live paid-target findings: none yet. The testbed record
  above must never be read as live-hunt recall.
- **Golden hunt:** `25 CONFIRMED / 16 planted vulns all confirmed / 7 benign all rejected /
  67 chains (39 Critical)` against the local testbed.
- **Red-team engine proof** (24 labeled dev cases, strict exact-citation metric): best
  model **91.7% recall**, **100% exact citation**, groq **100% specificity** (zero
  hallucinations on clean code); 3-model council **F1 0.846**. See
  [`REDTEAM_PROOF.md`](REDTEAM_PROOF.md).

---

## 7. How to run it

```bash
# oracle — full production chain (see README for the prescan/scan/queue flow)
python3 oracle_hunter.py hunt <program-or-target>
python3 oracle_hunter.py analyze targets/<platform>/<slug>   # resume on existing recon

# oracle — surface candidate seams from a recon dir (prompt-feeder path)
python3 oracle.py --feed <recon_dir>

# oracle — full self-test (spins the local testbed, proves the whole hunt path)
NO_PROXY=127.0.0.1,localhost python3 tests/run_all.py

# omnicli — red-team a target/code with the full provider swarm (no gate)
omni swarm --redteam "<goal>"
omni agent --redteam "<goal>" --allow-local --allowed-host <host>

# omnicli — provider health + quota
omni credits
```

---

## 8. What is and isn't finished

- **oracle (brain):** suite green, golden hunt + hardening in place; intake→download→
  queue execution wired and live-exercised through recon. ✅
- **omnicli (engine):** orchestration + red-team work and are proven; `omni credits` added. ✅
- **scan4me (eyes):** works across 13+ feeds; authenticated feed shapes remain unverified
  (no platform keys needed where the saved CDP session covers retrieval).
- **Next proof owed:** one end-to-end live hunt completing on healthy API lanes.
- **Optional quality-gate certification:** red until a human does the 2nd independent
  review of the held-out set — by design, and not required for the engine to run.

> This document describes the system as verified on 2026-10-20 (testbed claims
> reproducible via `tests/run_all.py`; live claims from the 2026-10-19 gate in
> `IMPROVEMENTS_REPORT_2026-10-19.md`).
