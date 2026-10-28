> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Proof-First Oracle Roadmap

## Purpose

Oracle becomes valuable when it produces reproducible, in-scope findings that
survive triage. It is not a scanner that emits ideas and it is not a model that
is trusted because it sounds certain.

The system operates by one rule:

> A model proposes. Evidence decides.

Every component exists to move a candidate from an observation to an executed,
scope-compliant proof. Anything short of that remains a research lead.

---

## The Mindset Is an Operating System

The philosophy, impossible problems, paradoxes, MITRE data, and iPhone framing
do different jobs. They must stay distinct, then combine at the point of
evidence.

| Layer | Question it answers | Oracle behavior |
|---|---|---|
| Program scope and assets | What may be tested, and what is real? | Reject out-of-scope assets and unsupported claims before a request is sent. |
| Philosophy | What stance should the system take toward a claimed limit? | Challenge inherited assumptions, passive authority, and "that is just how it works." |
| Impossible problems | Is an external rule actually enforced? | Identify the blocking axiom, name its enforcement layer, and test the boundary. |
| Paradoxes | Does the system contradict itself internally? | Untie the conflict, resolve it with an observed state transition, or classify it as not yet resolved. |
| MITRE ATT&CK | Which known attack shape is relevant here? | Generate bounded, target-specific hypotheses from recon and code evidence. |
| Invisible Seam | Does implementation contradict its stated contract? | Extract code-versus-claim mismatches and create deterministic candidate nodes. |
| iPhone framing | What is the minimum useful output? | Reduce a result to Assertion A, Assertion B, one decisive check, observed output, and impact. |
| Verification | Is the claim true in the permitted target? | Execute the check, record the result, and promote or close the candidate. |

The original Oracle corpus is bundled under `corpus/`. Its documents are source
material, not slogans. Relevant documents are loaded verbatim for the active
target so the model can apply the original move without replacing it with a
new summary.

---

## The Four Reasoning Motions

### 1. Philosophy: refuse passive framing

Philosophy provides the posture. A policy statement, UI behavior, or apparent
technical limit is not proof of server-side enforcement.

This does **not** mean ignoring scope, policy, authorization, or safety. Scope
is a hard axiom. The system challenges a target's technical assumptions, never
the authorization boundary that permits the test.

### 2. Impossible problems: rewrite an external rule

An impossible problem has a blocker outside the object being analyzed: a WAF,
rate limit, UI restriction, one-account test limitation, or presumed system
law.

Oracle asks:

1. What exact rule appears to block the test?
2. Which layer enforces it?
3. Is that layer server-side, client-side, keyed to the right identity, and
   applied to the relevant state transition?
4. What minimal permitted check distinguishes enforcement from assumption?

Example: "The admin route is hidden" is not authorization. The question is
whether the server checks the caller before performing the privileged action.

### 3. Paradoxes: resolve an internal contradiction

A paradox is different. The contradiction lives inside the system:

- an object is deleted but remains readable,
- a token identifies a user but does not authorize that user's object,
- a price is server-calculated in one flow but client-controlled in another,
- a system claims one shared state while different routes produce incompatible
  states.

Oracle does not report the contradiction until one in-scope check identifies
which assertion fails in reality.

### 4. iPhone framing: remove everything except the seam

The iPhone Problem is the output discipline:

```text
Assertion A: what the target claims, documents, or exposes in its UI
Assertion B: what code or wire behavior actually permits
Decisive check: one minimal, permitted command or test
Observed output: the executed result
Impact: the concrete user or asset harm
```

Recon logs, model prose, and source snippets are evidence attachments. They
are not the finding.

---

## Finding Classes

Bad code is not automatically a bounty. Oracle must classify it honestly.

| Class | Definition | Allowed outcome |
|---|---|---|
| `SMELL` | Weak design, dead code, missing validation, or unsafe pattern without demonstrated security impact. | Retain as a lead. Never submit. |
| `CANDIDATE` | A code path or observed behavior could violate an authorization, integrity, confidentiality, availability, or money invariant. | Produce a bounded verification plan. |
| `CONFIRMED` | An in-scope check executed and produced the prohibited behavior. | Generate a submission-ready report. |
| `CLOSED` | The check disproved the candidate, the condition is unreachable, or scope does not permit testing. | Record the reason. Do not recycle it as a finding. |
| `CHAINED` | Two or more independently confirmed findings compose into greater impact. | Produce a combined proof only after every edge is reproduced. |

---

## Invisible Seam as the First Engine

Invisible Seam is Oracle's deterministic code engine. It is not an optional
report embellishment.

For every target with source code available, Oracle should:

1. Extract behavioral claims from documentation, type contracts, comments,
   API specifications, and authorization annotations.
2. Extract implementation behavior from handlers, state transitions, access
   checks, data-flow edges, and persistence boundaries.
3. Identify claim-versus-code mismatches.
4. Emit an evidence-backed candidate node.
5. Run a repository-local test, controlled reproduction, or permitted live
   verification when available.
6. Feed only confirmed nodes to the chain engine.

Each node must use a common schema:

```json
{
  "id": "stable-candidate-id",
  "class": "SMELL | CANDIDATE | CONFIRMED | CLOSED | CHAINED",
  "target": "program and in-scope asset",
  "invariant": "the rule that must hold",
  "assertion_a": "claimed behavior",
  "assertion_b": "observed code or wire behavior",
  "source_evidence": ["file:line", "spec URL or path"],
  "preconditions": ["authenticated role", "existing object", "test account"],
  "check": "minimal reproducible action",
  "observed_output": "captured result or artifact reference",
  "impact": "concrete harm",
  "status_reason": "why it was promoted or closed"
}
```

---

## Multi-Model Collaboration

The interface model is the controller. It may be Copilot, Bob, Claude Code,
Gemini Antigravity, Codex, or another approved interface.

The controller is not merely the first model in a failover list. It owns the
research state and delegates bounded jobs:

| Role | Default provider | Required output |
|---|---|---|
| Controller and final judge | Active interface model | Research plan, evidence review, promotion/closure decision |
| Independent seam scout | OpenRouter | Candidate cards tied to supplied evidence |
| Adversarial reviewer | NVIDIA | Counterexamples, missing preconditions, and false-positive attacks |
| Private/offline continuation | Local Qwen3-Coder 30B | Local source analysis and fallback candidate cards |
| Fact judge | Deterministic tools and executed checks | Raw output and verdict |

For high-value candidates, providers work in conjunction:

1. The controller creates a narrow evidence packet.
2. The scout proposes a candidate and its required preconditions.
3. The adversarial reviewer attempts to falsify it.
4. The controller selects one permitted decisive check.
5. The verifier executes it.
6. The controller promotes it only when the evidence supports the claim.

The current router is a failover mechanism. It must evolve into this
role-based orchestration while preserving failover for unavailable providers.

---

## Proof-Only Chaining

Chains are a graph of confirmed nodes, not a list of interesting ideas.

An edge is valid only when:

1. Both nodes are individually `CONFIRMED`.
2. The first node's output satisfies a declared precondition of the second.
3. The combined sequence remains within program scope and testing rules.
4. The combined impact is reproduced or otherwise directly evidenced.
5. The report can explain every step without relying on model inference.

Example:

```text
Node A: A user-controlled organization identifier is accepted.
Node B: The billing mutation does not verify organization membership.
Node C: The mutation changes a payout destination.

A → B → C: a low-privilege user redirects another organization's payout.
```

If Node B rejects the foreign identifier, the chain is `CLOSED` even if A and
C are individually interesting.

---

## Finding Ledger and Evaluation

Oracle needs a durable ledger before it needs a customer-facing product.

Every candidate records:

- program, asset, and source of scope permission;
- original recon/code evidence;
- applied Oracle reflex and MITRE technique;
- models that proposed, challenged, or reviewed it;
- check command or test identifier;
- raw result/artifact hash;
- status transitions;
- duplicate-search result;
- submission identifier and triage outcome, if submitted.

The required performance metrics are:

| Metric | Why it matters |
|---|---|
| Candidate → confirmed rate | Measures hypothesis quality. |
| Confirmed → submitted rate | Measures report completeness and policy fit. |
| Submitted → accepted rate | Measures real bounty value. |
| Duplicate rate | Measures target selection and novelty. |
| False-positive rate by engine/model/reflex/MITRE technique | Shows which parts of the system are trustworthy. |
| Time to decisive check | Measures whether the system reduces research effort. |

Use a benchmark containing intentionally vulnerable applications, known-clean
examples, historical rejected ideas, and confirmed findings. A model output is
not a benchmark result until the expected verification status is recorded.
The approved local benchmark registry and onboarding protocol live in
[`BENCHMARK_EVALUATION.md`](BENCHMARK_EVALUATION.md) and
`../benchmarks/registry.json`.

---

## Delivery Sequence

### Phase 1 — Close the proof loop

1. Run the complete pipeline against known-vulnerable and known-clean local
   fixtures.
2. Make the full test suite hermetic: browser/credential tests must be marked
   integration tests and excluded from the default unit suite.
3. Run Invisible Seam automatically for every target with code.
4. Store candidate nodes and execution receipts in the finding ledger.
5. Add hard promotion rules: no sourced A/B, no real path, no executed check,
   no finding.

**Exit condition:** the system correctly confirms known flaws and closes known
clean candidates without manual prompt repair.

### Phase 2 — Prove a real bounty loop

1. Select one clearly authorized, lower-competition program with narrow scope.
2. Capture scope and policy before recon.
3. Run recon, code/asset analysis, model collaboration, and verification.
4. Submit only a confirmed, minimally reproducible finding.
5. Record triage outcome in the ledger, including a rejection or duplicate.

**Exit condition:** one submission whose report can be reproduced from the
stored evidence alone.

### Phase 3 — Improve repeatability

1. Compare models and reflexes using ledger metrics.
2. Remove or tighten techniques that create false positives.
3. Add source-language support only after the current extractors have measured
   precision.
4. Improve fresh-target and duplicate-risk ranking from historical outcomes.
5. Build proof-only chain generation on top of confirmed nodes.

**Exit condition:** repeatable confirmed findings with measured quality, not
one lucky result.

### Phase 4 — Productize only after proof

After the system demonstrates repeatable value, add:

- packaged dependencies and reproducible setup;
- persistent jobs, artifact storage, and resumable runs;
- structured database and audit trail;
- approval gates and role-based access;
- operational metrics and evaluation dashboard;
- tenant isolation, secret handling, billing, and deployment.

Do not build a polished subscription product around unmeasured candidate
generation. First prove that the evidence loop survives triage.

---

## Non-Negotiable Invariants

1. Scope is a hard boundary.
2. The model never owns the verdict.
3. A code smell is not a vulnerability without impact and proof.
4. A chain is not valid unless each link is confirmed.
5. A report contains the smallest decisive evidence, not the largest log.
6. A rejected, duplicate, or closed candidate is valuable evaluation data and
   must remain in the ledger.
