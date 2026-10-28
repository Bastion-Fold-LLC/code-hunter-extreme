> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle: Execution Plan to First Accepted Submission

## Reality Check

Oracle is not being rebuilt. The core personal-hunter system is substantially
built:

- target ranking now prioritizes fresh assets, verified fast triage, surface
  size, and lower report volume;
- scope-gated website-only intake works without a repository;
- the philosophy, impossible-problem, paradox, MITRE, iPhone, and Invisible
  Seam layers are bundled into analysis;
- HAR traffic evidence is redacted and scope-gated before entering model
  context;
- controlled recon now limits pressure and stops when the target is unhealthy;
- a pinned, loopback-only Juice Shop benchmark is available for rehearsal.

This is approximately **75% build-complete for a personal hunter**, but
**0% revenue-proven**. Revenue proof begins only with an accepted, non-duplicate,
in-scope report. The purpose of this plan is to close that proof gap without
building unrelated product features.

## Target Architecture

| Role | Responsibility |
|---|---|
| Active interface model | Controller and final judge. Creates the evidence packet, chooses the next permitted check, and promotes or closes the candidate. |
| OpenRouter | Primary seam/hypothesis scout while allowed credits or models are available. |
| NVIDIA | Independent adversary. Tries to falsify each high-value scout candidate, identify missing preconditions, and expose false positives. |
| Local Qwen | Private collaborator for source/evidence analysis and offline continuation. |
| Deterministic tools | Fact judge. Scope gate, captured traffic, executed requests, source checks, and artifacts decide the verdict. |

OpenRouter and NVIDIA must not be treated as ordinary failover providers for
high-value work. The controller receives their separate outputs and records why
one decisive check was selected. Local continuation remains available when
cloud capacity is unavailable.

## Two-Lens Candidate Pipeline

Every hunt begins with the same non-negotiable foundation:

```text
Program rules + in-scope assets + company/product context
+ account roles + authorized traffic + recon/code evidence
```

That foundation is a hard boundary. No lens may invent an asset, bypass a
program rule, or treat an external host as evidence.

From the same foundation, Oracle runs two candidate lenses in parallel:

| Lens | Question | Inputs | Output |
|---|---|---|---|
| **MITRE × Invisible Seam** | Which known attack shape matches a real code or wire contradiction? | Relevant MITRE technique, implementation/spec mismatch, endpoints, HAR/recon evidence | Candidate with a named attack shape and sourced A/B contradiction |
| **Mindset × Invisible Seam** | Which claimed rule is only assumed, externally blocked, or internally contradictory? | Philosophy, impossible problem, paradox, iPhone framing, implementation/wire seam | Candidate with the blocking axiom, contradiction, and one decisive check |

Invisible Seam is the shared anchor, not a separate optional scanner. It turns
source contracts, UI claims, API behavior, and observed traffic into a specific
Assertion A versus Assertion B. MITRE supplies known attack-shape context; the
mindset layers supply novel assumption and contradiction moves. The iPhone
frame forces both lenses into the same final form:

```text
Assertion A → Assertion B → one permitted decisive check → observed output → impact
```

Both lenses write the same candidate-node schema. Deterministic verification
promotes or closes nodes. Only confirmed nodes may reach the chain graph.

## Proof-Only Chain Graph

Chains are how a small bug becomes a larger impact—or a large bug becomes a
critical one—but they cannot be keyword associations.

For a valid edge `A → B`, Oracle must store:

1. **Confirmed source node A** and its raw executed output.
2. **Declared precondition of B**, such as a credential, object ID, role,
   state transition, or signed value.
3. **Binding proof** that A's observed output is exactly the value/state B
   requires.
4. **Sequential reproduction** of A, then B using that output.
5. **Combined impact evidence** that remains in scope and permitted by program
   rules.

The current chain engine is a useful hypothesis generator, but it must be
upgraded from keyword linking to these evidence-carrying edges. A chain with
any missing edge is `CANDIDATE`, never `CHAINED` or submission-ready.

## Milestone 1: Controlled Local Proof Loop

**Goal:** prove that website-only evidence becomes a correct confirmed or closed
result without destabilizing the target.

1. Start the pinned Juice Shop benchmark on `127.0.0.1` only.
2. Capture normal browser traffic through ZAP and export a HAR.
3. Import the HAR through Oracle's scope-gated redaction path.
4. Run controlled recon: low request rates, no broad content fuzzing, target
   health checks between phases.
5. Run the mindset analysis on recon plus HAR evidence.
6. Select one candidate and execute only its minimal local decisive check.
7. Store the result as `CONFIRMED` or `CLOSED`, with the exact evidence and
   reason.

**Exit condition:** at least one known Juice Shop condition is classified
correctly with an iPhone-format A/B/check/output/impact card, and at least one
non-finding is closed rather than reported.

### Tests Required Before a Real Campaign

1. **Known-vulnerable tests:** Oracle confirms deliberately vulnerable local
   conditions with a real check, not a guessed explanation.
2. **Known-clean tests:** Oracle closes lookalike endpoints and rejected
   hypotheses instead of inflating finding count.
3. **Chain tests:** Oracle builds a known valid small-to-large chain only after
   every output-to-precondition edge reproduces; it rejects a keyword-similar
   but non-composable pair.
4. **Scope/account tests:** Oracle refuses an out-of-scope host, a prohibited
   action, or a request missing required program identification headers.
5. **Model ablation:** compare scout-only, scout-plus-adversary, and
   scout-plus-adversary-plus-local runs on the same evidence packet. Keep the
   collaboration only if it improves confirmation quality or false-positive
   closure.
6. **Operational tests:** controlled mode keeps a local target healthy and
   records all rate/health-stop decisions.

## Milestone 2: Collaborative Candidate Review

**Goal:** make the mindset layers measurable rather than prompt decoration.

1. OpenRouter produces bounded candidate cards from a single evidence packet.
2. NVIDIA reviews high-value cards as an adversary, not as a replacement scout.
3. Local Qwen independently reviews source or private evidence when available.
4. The controller records the selected philosophy/impossible-problem/paradox
   move, MITRE mapping, adversarial objection, and final decisive check.
5. The candidate ledger records the proposing/reviewing model roles and
   promoted/closed outcome.

**Exit condition:** every high-value candidate has scout evidence, adversarial
review, controller decision, and deterministic result. No model prose alone can
create a finding.

## Milestone 3: Real-Program Readiness

**Goal:** make one authorized website program safe and operationally complete.

1. Finish platform intake contracts: scope availability, normalized metadata,
   explicit asset-intake status, and API/session/public fallback results.
2. Add a program testing profile with:
   - in-scope assets and prohibited actions;
   - mandatory identification headers;
   - required researcher alias format;
   - Account A and Account B roles;
   - allowed login/session method and MFA notes.
3. Prompt for credentials without echoing or persisting passwords. Keep
   session values out of prompts, reports, and logs.
4. Capture the two authenticated sessions through the approved program flow.
5. Verify that every generated request carries required headers and stays
   inside declared scope.

**Exit condition:** Oracle can prepare a two-account, policy-compliant,
website-only research workspace without silently missing scope, headers, or
authentication requirements.

## Milestone 4: First Authorized Submission Campaign

**Goal:** turn the validated loop into a real triage decision.

1. Select one fresh-asset or new-program target using the existing ranker.
2. Read the program profile and scope before sending requests.
3. Run controlled recon and HAR intake.
4. Use collaborative review for only the highest-value candidates.
5. Execute minimal permitted verification checks.
6. Search for duplicates before writing a report.
7. Submit only an evidence-backed, reproducible, in-scope finding.
8. Record triage result: accepted, informative, duplicate, out-of-scope, or
   rejected, with the reason.

**Exit condition:** one triager-reproducible submission has a recorded outcome.
An accepted finding is revenue proof; every other outcome is still valuable
selection/model/verification feedback.

## What Not to Build Yet

Do not delay the first campaign for multi-tenant SaaS packaging, billing,
marketing dashboards, broad fine-tuning, or a massive scanner expansion. Those
become worthwhile only after the candidate-to-triage data shows that Oracle's
edge produces confirmed, accepted findings.

## Scoreboard

Track these numbers from the first benchmark onward:

| Metric | Why it matters |
|---|---|
| Candidates per target | Measures research focus. |
| Candidate to confirmed rate | Measures hypothesis quality. |
| Candidate to closed rate | Measures false-positive control. |
| Confirmed to submitted rate | Measures proof/report completeness. |
| Submitted to accepted rate | Measures actual money readiness. |
| Duplicate rate | Measures target selection and novelty. |
| Target health failures | Measures operational restraint. |
| Result by mindset move/model role | Proves which Oracle mechanisms create value. |
