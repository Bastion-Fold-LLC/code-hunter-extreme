# Oracle Bug-Bounty Machine — Full System Reference
**Last verified: 2026-10-27 against Oracle working tree (1413 passed, 23 skipped, 41 deselected; 32 subtests passed) and OmniCLI `oracle-pipeline` conductor (543 passed, 1 skipped). Scan4Me `8438ca2`.**

---

## What this is

Three tools that work together as one automated bug-bounty hunting pipeline:

```
Scan4Me  ──►  Oracle  ──►  OmniCLI
(pick target)  (hunt it)  (red-team the system itself)
```

The goal: find real security bugs in real bug-bounty programs, prove them
with live wire evidence, write submission-ready reports, get paid.

---

## The three tools

### Scan4Me (`~/Scan4Me/`)

A program intelligence database. Latest live sync (2026-10-19): **2,027
programs, 48,699 assets** (counts churn per sync). Pulls from HackerOne,
Bugcrowd, Intigriti, YesWeHack, Immunefi, PDPrograms, Sherlock (bounties +
contests), plus listing-only discovery feeds (Bugbase, HackenProof, Cantina,
Patchstack, Huntr, CodeHawks) that carry zero fabricated assets. Federacy is
off by default; Hats excluded. Under Oracle, `triage.yaml` overlays Scan4Me's
config and payout becomes a hard gate, not a rank weight.

Ranks programs by a composite fast-money score (shipped `DEFAULT_CONFIG`):
- **Payout 35%** — maximum bounty
- **Surface 30%** — how many in-scope web assets
- **Freshness 20%** — how recently was scope updated
- **Speed 15%** — how fast do they pay (response-time signals)

Scope gate (`scope_match`) is fail-closed: `*.dropbox.com` matches
`api.dropbox.com` but never `evildropbox.com`. Lookalikes, OOS children,
`ftp:` schemes, `javascript:` schemes — all blocked.

Oracle reads Scan4Me via the bridge in `oracle_scan4me.py`. The bridge
resolves a program name to its live scope list so every recon probe is
scope-gated against the exact DB.

---

### Oracle (`~/oracle/`)

The main engine. Takes a program, hunts it end to end.

#### The pipeline

```
1. Prescan        Scan4Me sweep (triage.yaml overlay) → ranked raw shortlist.
                  Hard-fails on stale/refresh-failed/public-file/no-auth feeds;
                  the rejected report is preserved and the run is logged.
2. Scan/verify    Check scope live, payouts match, rules unchanged; -N/--sites
                  select; --download writes one workspace per verified program.
                  HackerOne scope is re-fetched from HackerOne's authenticated
                  Hacker API with Oracle's own credentials; auth failure is a
                  scan failure, 404 is a vanished program, never stale scope.
3. Queue          Order verified programs; --execute hunts them in waves
                  (same-site sequential, --max-items, resumable, failure-isolated)
4. Hunt           Full pipeline (steps 5–12 below)
5. Recon          subfinder → httpx → gau → katana → nuclei → hakrawler → dnsx
                  + mine_crawled_pages (inline JS navigation handlers)
6. Mindset 1      MITRE ATT&CK lens (344 techniques, cloud + local)
7. Mindset 2      Philosophy / paradox / impossible-problems lens (cloud)
8. Invisible seam Code lens (AST) + template engine (deterministic)
   (feeds both 1+2 before they run)
9. Mindset 3      Synthesis: unify 1+2+seam, attack candidates, chain finds
10. Verify        gate-ladder verifier against live wire (1/2/2b/Op1/5/5b/6a/6b/7)
11. PoC           Routed model lanes write the report draft (manual review; never auto-submitted)
12. Report        finding_NNN.json + funnel.json per hunt
13. Product gate  queue --execute packages each completed hunt; bundle /
                  verify-download check the SHA-256 manifest and separately
                  gate ready_for_submission (confirmed + PoC + full report
                  + trusted feed + Oracle re-scan provenance; H1 independent)
```

#### The three mindsets in detail

**Mindset 1 — MITRE (technique-indexed)**
System prompt: all 344 ATT&CK techniques (full definitions, relevance-sorted
per program). Red-team directive: weaponized probes, WAF bypasses, header
spoofing, verb tunneling. Runs 14 tactic-focused passes on local (Engine B)
or one full shot on cloud (Engine A).

**Mindset 2 — Paradox / Philosophy (contradiction-indexed)**
System prompt: 16 philosophy documents + 20 verbatim corpus documents +
8 paradox→reflex worked examples. Red-team directive: hunt broken axioms,
attack state machines, exploit contradiction between what the system claims
and what the wire does. Cloud-only (106KB prompt, too large for 16k local).

**Mindset 3 — Synthesis (adversarial unifier)**
Takes every candidate from Mindsets 1+2 plus the invisible seam feed.
Attacks each candidate (tries to break it), discards noise, chains survivors
into compound findings. Never invents seams that no feed produced.
Runs on cloud or local.

**The invisible seam (shared feed, runs before all three)**
Two sub-engines:
- `oracle_code_seam.py`: static AST analysis of source on disk. Extracts
  behavioral claims from docstrings, type hints, Solidity `require()`. Zero
  LLM, zero hallucination.
- `oracle_seam_templates.py`: 23 deterministic templates (`TEMPLATES`) matching recon
  patterns to known bug shapes (stale API, unguarded path, role header trusted,
  SQLi surface, XSS surface, IDOR surface, debug endpoint, etc.).

Both inject candidates into Mindsets 1 and 2 before they run, so both lenses
reason with the candidates rather than blind.

#### The seam card format (iPhone framing)

Every finding must be exactly:
```
Assertion A:  what the system claims (with source citation)
Assertion B:  what the wire actually does
Check:        one curl command, nothing else
Expected:     exact wire result that proves B (must include status code)
```

Malformed cards are rejected at construction (`validate_card_shape`).
The gate is token-position-aware: `&` inside a single-quoted URL query string
is inert data under `shell=False`, not a shell operator. Bare metacharacters
outside quoted strings still block (`SHELL_METACHARS`).

#### The gate-ladder verifier

Every seam card hits every gate in `verify_candidate`. Wire or die —
nothing confirms without a live HTTP response that matches.

```
Gate 1    Shape gate (validate_card_shape) before the wire
Gate 2    Scope gate (check host must be in scope)
Gate 2b   Discrimination (bare GET→200 proves nothing about auth)
Op1       Shell metachar kill (;  |  `  $(  &  && — bare only, token-aware)
Gate 5    Wire execution (live HTTP response)
Gate 5b   Verdict direction (violated vs enforced must read correctly)
Gate 6a   Reframe differential (variation must have observable effect)
Gate 6b   SPA control (server 200s everything? = app shell, not a finding)
Gate 7    Adequacy (prediction must be adequate, not just technically matching)
```

Severity chaining over confirmed seams (`chain_seams`): start at the
strongest verified primitive, **one compounding step in total** capped at
Critical; chain length alone never manufactures severity (repeated Lows
cap at Medium); unconfirmed findings never compose; chains sort
highest-first.

Additional precision machinery:
- `normalize_wire_output()`: collapses floats/NaN/Inf before differential
  comparison (hunt-4d seam 332: float jitter 0 vs 0.5 confirmed a Critical
  on noise — fixed)
- `SQLI_200_MARKERS` (broad, for discovery) vs `SQLI_ERROR_MARKERS` (strict,
  for proof under teardown): bare "mysql" matches DVWA page footers so a
  strict list keeps only error-shaped forms
- `LOGOUT_PATH_PATTERN`: blocks `/logout.php` etc. from injection targets —
  fetching one with a session cookie destroys it (DVWA `session_destroy()`)

#### The 8 reflexes (applied by every LLM pass)

1. SPEC-AUDIT — what layer actually enforces the claim?
2. DECOUPLE — authentication ≠ authorization, identity ≠ ownership
3. AXIOM-REWRITE — the blocking rule is a variable, not a wall
4. AMBIGUITY IS THE VECTOR — the undefined term is the door
5. HIERARCHICAL RECALL — map to a class already broken
6. CLEAN vs NOT-YET-FOUND — honest state: actually clean, or not found yet?
7. RECURSIVE VALIDATION — one command's output IS the proof
8. BINARY CONFLICT + ONE CHECK — two assertions, one curl, nothing else

#### Op2: reframe transforms (follow-up cards from rejected seams)

When a check is rejected, 5 transforms fire to generate follow-up cards:
- `strip-auth`: drop credential headers — is the gate server-side?
- `method-swap`: GET→POST→PUT→DELETE→GET cycle
- `header-spoof`: add `X-Forwarded-For: 127.0.0.1`
- `param-tamper`: numeric → -1, role-ish → escalated
- `method-override`: add `X-HTTP-Method-Override: PUT`

Each transform that changes the check emits exactly one follow-up card.
Already-reframed cards produce nothing (bounded: one round, ≤5 cards).

#### Op3: GearTurn (hunt completion tracking)

Four cognitive modes must all run before a hunt ends:
- `instant`: deterministic producers ran (code lens + templates)
- `delayed`: LLM lenses ran (mitre/paradox passes)
- `breakthrough`: reframe follow-ups ran on rejected checks
- `recalled`: prior constructs re-applied (variant sweep)

Zero confirmed findings = **SYSTEM FAILURE** regardless of modes passed.
The target always has bugs; zero means the hunt failed, not the target is clean.

---

### OmniCLI (`~/tools/omnicli/`)

Red-teams Oracle and Scan4Me's own code. Does not hunt targets.

Fans the same adversarial question to models from different families
simultaneously (Groq, NVIDIA, OpenRouter, local Ollama — all at once).
Four scenarios per run:
1. Authorization boundaries — can an attacker bypass a gate?
2. Taint-to-sink — does user input reach a dangerous function?
3. Sensitive data exposure — do secrets leak?
4. State and resilience — race conditions, resource exhaustion?

Evidence gate: a finding only survives if it cites exact file + line number
+ verbatim quote from the actual source. Models that hallucinate line numbers
or invent code paths are killed by the gate.

**Three real bugs found by OmniCLI swarm and fixed:**
1. `&` and `&&` missing from `SHELL_METACHARS` in `oracle_foundation.py`
2. `CliBackend` prompt injection surface in `oracle_llm.py`
3. `scan4me.py` accepted keys from `config.json` without warning

---

## Proven results (live wire **against testbeds** — not paid-target proof)

The hunts below ran against local training apps (DVWA/PyGoat/Juice Shop)
and the planted-bug testbed. They prove detection precision on controlled
code — repeatedly, including the 2026-10-20 full-suite green run (1148 passed). They are
**not** live bug-bounty findings: as of 2026-10-20, no finding has been
submitted, accepted, or paid.

| Target | Hunt | Confirmed | Precision | Notes |
|---|---|---|---|---|
| DVWA | re-hunt | 4/12 | 1.0 | `.git/config`, `/phpinfo.php`, `/.git/HEAD` — all TP |
| PyGoat | hunt-1 | 1/8 | 1.0 | `/debug` 15.5KB live log dump with credentials |
| Juice Shop | hunt-4c | 1/392 | 1.0 | `/metrics` Prometheus endpoint with tokens/config |
| Juice Shop | hunt-4d | 2/392 | 0.5 | seam 22 TP + seam 332 FP (float jitter) → fixed |
| Golden testbed | recall bar | 15/15 | 1.0 | all 5 bug classes confirmed, 0 misses |

**Funnel numbers (Juice Shop, 5 hunts, 1896 total seams):**
- 96.4% killed by deterministic REJECTED (expected — most endpoints are clean)
- 40% of det-CONFIRMED killed by post-gate checks
- 2.2% survive to final CONFIRMED
- This is correct behaviour, not a bug

---

## Test suite

**643 tests passing** (as of 2026-10-13).

10 pre-existing failures — all `omnicli` import errors (omnicli not on the
oracle test path, requires `PYTHONPATH=/home/phantomcore/tools`) or Ollama
offline. Zero new failures introduced.

Key test files:
- `test_p2_recall_bar.py` — zero-miss recall bar (machine-enforced)
- `test_p14_bench_recall.py` — per-bench recall mapping (juice/DVWA/pygoat)
- `test_golden_hunt.py` — full template→check→verify against live testbed
- `test_pressure.py` — 6 gap tests (Op1↔Op2, synthesis ranking, prompt
  injection, intake pipeline, evidence gate, cloud failure modes)
- `test_issue_pressure.py` — 7 issue tests (SQLi markers, logout guard,
  DOM XSS wall, IDOR wall, CSRF wall, Engine B timeout, MITRE mistag)
- `test_gate_evasion.py` — adversarial scope gate probes
- `test_gate7_adequacy.py` — verifier adequacy rules A/S/B2/B1/C
- `test_known_bugs.py` — 9 real CWE classes, regression corpus

---

## Known issues and walls

### Fixed

| Issue | Fix |
|---|---|
| `validate_card_shape` blocked `&` in quoted URL query strings | `_check_bare_metachars()` strips single-quoted content before scanning |
| Float jitter (0 vs 0.5) confirmed a Critical on noise | `normalize_wire_output()` collapses floats as a unit before differential |
| Broad `"mysql"` marker matched DVWA page footers | `SQLI_ERROR_MARKERS` strict subset keeps only error-shaped forms |
| Fetching `/logout.php` destroyed the session mid-hunt | `LOGOUT_PATH_PATTERN` excludes logout paths from injection targets |
| `&` and `&&` not in `SHELL_METACHARS` | Added to both `oracle_foundation.py` and `oracle_hunter.py` |
| Scan4Me `load_credentials()` silently accepted keys from `config.json` | Warning emitted when key comes from config.json |
| Paradox lens silently dropped on `--no-cloud` | `effective_mindsets()` reports it honestly in the log |
| Deepest-first crawl sort ranked katana junk ahead of real app routes | Reverted to shallow-first (depth ASC) within api/page split |
| Inline JS navigation handlers (`onclick`) not mined by katana | `mine_crawled_pages()` in `oracle_deeprecon.py` refetches crawled pages |

### Open walls (documented, not fixable without new capability)

**DOM XSS — needs browser rendering**
Curl gets raw HTML. DOM XSS only appears after JavaScript executes in a
browser. Fix direction: Playwright/crawl4ai rendered-DOM differential.
Test: `test_issue_pressure.py::TestDOMXSSWall` proves the wall and documents it.

**IDOR — needs two accounts**
Cross-account object reads need two registered sessions. DualAccountHarness
exists and wires correctly when given tokens. Needs: auto-registration via
the program's registration endpoint.
Test: `test_issue_pressure.py::TestIDORWall` proves the 401 wall and the
harness wiring.

**CSRF SQLi — needs two-step form replay**
Django/Flask CSRF protection rejects bare POST without the token. Fix
direction: fetch form → extract csrfmiddlewaretoken → replay POST.
Test: `test_issue_pressure.py::TestCSRFWall` proves the wall and proves
the two-step approach works in principle.

**Engine B local stall — needs evidence budgeting**
30b model × 14 tactic passes × 16k context = 600s stall per pass. The
420s `_COLLECT_BUDGET_S` deadline fires and hunt continues with whatever
Engine A (cloud) returned. Cloud is the primary engine — this is slowness,
not a blocking failure.

**MITRE T1078 mistag**
Auth-bypass findings (missing auth, CWE-306) get tagged T1078 (Valid
Accounts — using stolen credentials). Semantically wrong. Correct:
T1190 (Exploit Public-Facing Application) + CWE-306 or T1556.
Cosmetic — doesn't affect whether the finding is real.
Test: `test_issue_pressure.py::TestMITREMistag` pins the current tags.

---

## What it finds reliably today

**At precision 1.0 on every completed hunt:**

- Exposed files: `.git/config`, `.env`, `phpinfo.php`, `package.json`, `.git/HEAD`
- Debug endpoints: `/debug/config`, `/debug`, admin dashboards returning 200
- Missing auth on internal paths: privileged routes with no auth check
- Stale API versions: `/api/v1/` still live when `/api/v3/` is current
- Role header trust: `X-Original-Role: admin` escalates privilege
- Info disclosure: 500 stack traces, SQL errors in responses
- Infrastructure artifacts: `openapi.json`, GraphQL introspection open
- Security header misconfigs: no CSP, HSTS, X-Frame-Options

**What it misses today:**
- DOM XSS (needs browser)
- IDOR without pre-provisioned accounts
- CSRF-gated form injection (needs two-step fetch)
- Blind/time-based SQLi (needs inference loop)

---

## How to run a hunt

```bash
# Check everything is working
oracle-hunter status

# See ranked programs from the database
oracle-hunter list --web2 --min-payout 500

# Hunt a specific program (full pipeline, cloud + local)
oracle-hunter hunt "Dropbox Bug Bounty" --auto

# Prescan → scan → queue flow (the only supported pipeline)
oracle-hunter prescan --sync --limit 24
oracle-hunter scan --prescan-file <prescan.json> -N 3 --download --cdp-port 9227
oracle-hunter queue --execute --max-items 1 --controlled --cdp-port 9227

# Product gate after a hunt (queue --execute also bundles each completed hunt)
oracle-hunter bundle targets/HackerOne/<slug>
oracle-hunter verify-download targets/HackerOne/<slug>/reports/product_<stamp>.zip

# OmniCLI conductor: same three stages + product verification
omni oracle-pipeline --oracle-root ~/oracle --limit 24 --count 1
```

Output per hunt:
- `recon/<target>/` — all recon artifacts
- `reports/finding_NNN.json` — confirmed findings with PoC
- `reports/funnel.json` — funnel counts (mined/verified/confirmed)
- `lab/hunt_<target>_<timestamp>.log` — full hunt log
- `reports/product_<stamp>/` + `.zip` — product bundle with SHA-256 manifest
  (`manifest.json`, `manifest.sha256`); `verify-download` is integrity-clean
  separately from `ready_for_submission`, which requires confirmed findings,
  matching finding JSONs, a full report, a non-empty PoC per finding,
  `feed_trust.ok=true`, and Oracle re-scan provenance; HackerOne additionally
  requires an independent re-scan

Every CLI run also writes an append-only machine record:
- `reports/runs/<run_id>/events.jsonl` — one JSON object per console line,
  warning, artifact, exception, and command lifecycle event
- `reports/runs/<run_id>/summary.json` — command, start/end time, status,
  event counts, errors/warnings, and artifact SHA-256 hashes
- `reports/runs/latest.json` — pointer to the newest run

Logging is observability, not a gate. A stage may fail or be skipped; the
run is then recorded as `failed`/`incomplete` and its partial artifacts stay
on disk. Secrets are redacted at the logging boundary. A broken log directory
never takes down a hunt.

---

## Credentials needed

Loaded (layered, later wins) from `~/.config/trio/keys.env`, `oracle/ORACLE_KEYS.env`, `oracle/.env`, then process environment:

Presence in a file ≠ usable (empty or whitespace-containing credential values are rejected at load).
Run `oracle-hunter status` for live state. Key naming follows code:
`INTIGRITI_TOKEN` **or** `INTIGRITI_JWT` (Bearer; adapters accept both, the `status` probe checks only `INTIGRITI_JWT` — known inconsistency). There is no separate
direct-Anthropic/Gemini PoC path — synthesis routes through the 13 lanes.

| Key | Used for |
|---|---|
| Lane keys (`DATABRICKS_TOKEN`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, `OPENROUTER_API_KEY`, …) | Model lanes in `oracle_backends.json` |
| `HACKERONE_API_KEY` (+ username) | H1 program list / scopes (authenticated) |
| `HACKERONE_USERNAME` + `HACKERONE_API_TOKEN`/`HACKERONE_API_KEY` | Oracle's independent H1 verify re-scan (`scan`) |
| `INTIGRITI_TOKEN` | Intigriti researcher API |
| `FIRECRAWL_API_KEY` / `JINA_API_KEY` | Download corroboration renders |
| Local Ollama | `qwen3-coder:30b-16k` (heavy floor), `qwen2.5-coder:14b-16k` (light) |

---

## Next step — first paid finding

Stated honestly (2026-10-20): machinery is ready, live proof is owed.
The 2026-10-19 live gate ran sync → prescan → scan → download → queue →
recon against Here Technologies, then died at engine analysis (lane
starvation — since fixed; hunt-scale prompts have since completed live).
No live finding exists yet, and "nothing blocking" was wrong when an
earlier version of this doc said it.

Steps (unchanged in shape):
1. Pick a small-scope program from a fresh prescan/scan run
2. Fetch the policy page and confirm automated testing is allowed
3. Run `oracle-hunter hunt "<program>" --auto`
4. Read `reports/finding_NNN.json`, verify each PoC once manually
5. Submit manually — Oracle never auto-submits
