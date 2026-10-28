# Oracle — The System, Explained (hand this to Bob to finish it)
_Canonical as of 2026-10-04; facts refreshed 2026-10-20 (production pipeline, lane health, live gate). Doctrine lives in `ORACLE_DOCTRINE.md` when they disagree._

## 1. What Oracle IS (one paragraph)
Oracle is a **deterministic-core bug-bounty engine**. It pulls a program's scope, does recon,
analyzes the surface through two LLM lenses **and** a deterministic template engine (the
philosophy), then **proves every candidate on the wire with the gate-ladder verifier
(Gates 1/2/2b/Op1/5/5b/6/7)** — nothing is
"confirmed" unless a binary conflict is proven against real HTTP behavior. Confirmed findings
are then **chained** into compounded exploits and written as a submission-ready report.
~36,600 lines of Python, web2 today (HTTP), with a web3 contract layer tested in-suite. The
core bet: **the AI proposes, deterministic code proves.** The LLM can be wrong; the verifier
cannot be talked into a false confirm.

## 2. How BUGS work here (the philosophy — this is the point)
- **A bug is one of two things:** (1) **shit code** — a defect, the contradiction between what
  the code/docs *claim* and what the behavior *does* (the "seam"); or (2) **exploitable code**
  — something you can actually abuse.
- **ALL code has bugs.** Therefore: **"found nothing" NEVER means the code is clean — it means
  our tools weren't sharp enough.** A miss is always the tool's failure, never the target's
  innocence. This is the governing principle for everything, especially testing.
- **How we surface them — the "you never said" inversion.** Every template is an
  impossible-problem / paradox move that finds the unchallenged claim and tests whether the
  wire contradicts it:
  - *Vacuum* — "you never said the path NAME is the enforcement."
  - *Beautiful Liar* — "you never said the server VALIDATED the role, only that it trusts it."
  - *Mirror* — "you never said the old version stopped answering with the old rules."
  - *Cliff & Current* — "you never said auth runs on the ALTERNATE path."
  - *Repulsive* — "you never said the router binds every spelling of the route."
  - *Self-Observing / Artifact / Spec* — "you never said internals/files/specs weren't served."
- **Money is NOT in finding a bug** (trivial — all code has them). It is in two things:
  1. **Which seams are EXPLOITABLE** (reach data/auth/logic you shouldn't) — not benign noise.
  2. **CHAINING — compose little bugs into a bigger one and submit ONE compounded report.**
     The ladder law (Doctrine §6): start at the strongest verified primitive; a verified
     chain compounds severity by **one step in total** (capped Critical) — small→medium,
     medium→high, high→critical. Length alone never manufactures Critical (repeated Lows
     cap at Medium), and unconfirmed findings never compose. Ten scattered low findings = nothing.
- **What a bug is NOT (precision floor):** mere reachability or a missing header, alone, is not
  a payable bug. Only confirmed, exploitable, ideally-chained findings get a submission draft.

## 3. How each PART works (the pipeline, in order)
1. **Scope acquisition** — 13 routed platform feeds/listing sources in Scan4Me → ranked program list under shared `triage.yaml`. **Scope intake**
   (auto, pre-hunt) populates `structured_scopes` so the gate has real in-scope assets.
2. **Targeting** (`triage.yaml`) — new company / new assets / low resolved-reports. Deliberately
   gets us to **fresh, under-audited surface first**. This stacks the odds — it is NOT a numbers
   game; it is a reasoning method aimed at where unfound bugs are dense.
3. **Recon** — subfinder/httpx/katana/ffuf/gau surface hosts, endpoints, paths, JS secrets.
4. **Analysis** — two LLM lenses (**mitre** = full MITRE technique library; **paradox** =
   philosophy corpus + impossible-problems), the **deterministic template engine** (the paradox
   moves as machine-checkable seam cards), and the **invisible-seam code lens** (spec-vs-code on
   source). Both lenses carry the scope wall AND the invisible-seam candidates.
5. **Verification — the gate ladder** (deterministic, code-only, `verify_seam_card`):
   shape pre-gate (+ hunter Op1), then (1) grounding in recon data, (2) scope,
   (2b) discrimination, (3) machine-readable expectation, (4) cited claim source,
   (5) wire execution, (5b) verdict direction, (7) adequacy — plus hunter post-gates
   6a/6b/7-B1/7-C. Nothing confirms otherwise. THIS is the skeptical core; it refuses
   junk, which is the whole value.
6. **Chaining** — compose CONFIRMED seams on proven output→precondition edges; severity
   compounds **exactly one step total** from the strongest verified primitive (capped Critical).
   Chains sort highest-first.
7. **Report** — PoC synthesis + Compound Threat Analysis → one submission-ready report.

## 4. How we TEST every part (the methodology — built on §2's principle)
Because "found nothing = dull tool," the only honest test is **recall against code where a bug
is KNOWN to exist.** A miss is a sharpening task, never a pass.
- **Tier 1 — planted testbed (we own the answers).** `tests/vuln_testbed_full.py` plants one
  live vuln per template class + benign twins. `tests/test_golden_hunt.py` asserts BOTH ways:
  every planted vuln CONFIRMS (recall), every benign control REJECTS (precision). One command:
  `python3 tests/run_all.py`. **BUILT — passing (13 classes, 7 controls).**
- **Tier 2 — known-vulnerable REAL code (the sharpening engine).** Run Oracle on software with a
  *documented* bug (a CVE, a disclosed bounty report, a known-vulnerable plugin version, OWASP
  Juice Shop). Every known bug it misses → sharpen the template/recon → lock in as a test. A
  growing **regression corpus of known bugs** is how sharpness is proven. **BUILT in-suite**:
  `tests/test_known_bugs.py` (13/13 known-bug assertions, run in `run_all.py`).
- **Tier 3 — chain recall.** Plant a multi-level chain (leak → access → data = Critical); assert
  the engine composes it into one compound finding. **BUILT**: `tests/test_severity_ladder.py`
  (71 cases incl. planted chains, count-to-Critical denials, fail-closed severity).
- **Tier 4 — live-platform smoke.** Scrapers return real programs with real payouts; the full
  chain ran live 2026-10-19 (sync → prescan → scan → download → queue → recon) and died at
  engine analysis pre-lane-fix. **PARTIAL — live end-to-end completion still owed.**
- **The loop:** known bug → miss → sharpen template/recon → catch → add as a permanent test → next.

## 5. How much WORK is left (honest)
**Done + verified:** the web2 engine end-to-end (scrape→recon→2 lenses+templates+invisible seam
→gate-ladder verify→PoC), all **23 web templates** verified both-ways on live wire, credentialed
auth-bypass (Beautiful Liar), scope intake that always refreshes from source, chain composition
under the one-step ladder law, intake→download→queue execution wired and live-exercised, the
golden harness + card-structure + wordlist-coverage tests (full suite: 1148 passed, 2026-10-20),
and security hardening (session/cookie files 0600).

**Remaining, in priority order (2026-10-20):**
1. **One live hunt completed end-to-end** on healthy API lanes (the 2026-10-19 gate died at
   engines; lane health since fixed and hunt-scale prompts since answered live).
2. **Databricks HTTP 400** root-cause (lane skipped while down); OmniCLI lane ignores timeout.
3. **Recon discovery breadth** — keep proving ffuf/katana FIND planted routes live.
4. **Web3 live proof** — contract layer is tested in-suite; a live contract-program hunt is unproven.
5. **Minor:** queue resume vs re-ranking; `verify` fast-path needle mismatch (wasted re-runs).

**Bottom line:** the engine is built and *verified against known-bad code*; the money edge
(exploitable + chained findings on fresh surface) is wired. The front edge is one clean live
hunt — then findings, manual review, submit. (HatsFinance was removed from scope by choice;
Bugbase is a listing-only discovery feed, not a thin scraper awaiting depth.)
