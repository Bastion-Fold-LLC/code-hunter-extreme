> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle Completion Plan: Proof Before Payout

## 1. Objective

Oracle is a personal bug-bounty research system. Its purpose is not to maximize
scanner output or model prose. Its purpose is to produce **in-scope,
triager-reproducible, non-duplicate security findings**.

The first business milestone is one accepted report. That does not guarantee
future revenue, but it proves the complete system:

```text
target selection → authorized evidence → hypothesis → decisive check
→ reproducible report → triage outcome
```

## 2. Current Position

Oracle is substantially built for a personal hunter. It has target ranking,
platform intake, scope gates, website/code asset intake, recon, bundled source
corpus, MITRE mapping, Invisible Seam, deterministic verification, reports,
dual-account scaffolding, and a first chain engine.

Recent proof:

- target selection now gives priority to fresh assets, verified fast triage,
  surface size, and lower report volume;
- bare-domain website scope is actionable without requiring a repository;
- HAR traffic can be imported only through a scope gate and is redacted before
  it enters artifacts or model context;
- controlled recon caps pressure and skips broad content fuzzing;
- a pinned, loopback-only Juice Shop run proved live website discovery works
  and exposed an operational limit that was then fixed with controlled mode.

This is approximately **75% build-complete as a personal hunter**. It is
**not revenue-proven** until triage accepts a report.

## 3. Non-Negotiable Invariants

1. **Authorization is absolute.** Scope, program rules, rate limits, and
   prohibited actions are never “impossible problems” to bypass.
2. **Evidence decides.** A model can propose a candidate; only scoped observed
   evidence can promote it.
3. **No credential leakage.** Passwords, session values, cookies, API keys,
   and authorization headers never enter model prompts, reports, logs, or
   ordinary workspace JSON.
4. **No out-of-scope discovery laundering.** A discovered URL is not valid
   merely because an in-scope page linked to it.
5. **No severity inflation.** A chain needs reproduced output-to-precondition
   edges. Interesting keywords do not increase severity.
6. **No silent widening.** Missing payout, triage, scope, intake, or
   authentication metadata must be explicit, never treated as success.

## 4. Oracle Research Pipeline

### 4.1 Shared evidence foundation

Every run starts with:

```text
Program rules + in-scope assets + company/product information
+ account roles + permitted headers/aliases + recon + HAR + source/assets
```

This is the hard boundary and the evidence packet available to every engine.

### 4.2 Two candidate lenses

| Lens | Purpose | Inputs | Candidate output |
|---|---|---|---|
| MITRE × Invisible Seam | Apply known attack shapes to a real code/wire/UI contradiction. | Relevant MITRE techniques, source/spec mismatch, observed endpoint or traffic behavior. | Sourced Assertion A/B plus attack-shape rationale. |
| Mindset × Invisible Seam | Test an assumption, external blocker, or internal contradiction that other hunters may accept. | Philosophy, impossible problems, paradoxes, iPhone framing, source/wire/UI seam. | Blocking axiom/contradiction, sourced Assertion A/B, decisive check. |

Invisible Seam is the shared anchor. It makes both lenses evidence-grounded:
the claim, code behavior, UI behavior, or observed wire behavior must conflict.

### 4.3 Candidate lifecycle

```text
SMELL → CANDIDATE → CONFIRMED | CLOSED | INCONCLUSIVE
                                  ↓
                           proof-only CHAINED
```

Only `CONFIRMED` nodes can enter a chain or a final report.

### 4.4 Output discipline

Every candidate uses iPhone framing:

```text
Assertion A: what the system claims or appears to enforce
Assertion B: what source or observed wire behavior permits
Decisive check: one minimal permitted action
Observed output: captured, redacted result
Impact: concrete harm to a real user, asset, or money flow
```

## 5. Model Architecture

| Role | Provider | Job |
|---|---|---|
| Controller | Active interface model | Plans work, selects evidence packets/checks, decides promotion or closure. |
| Primary scout | OpenRouter | Produces bounded seam candidates while usable model credits/capacity remain. |
| Adversary | NVIDIA | Attempts to falsify high-value scout candidates, identify missing preconditions, and expose false positives. |
| Private collaborator | Local Qwen | Independently reviews private source/evidence and continues when cloud capacity is unavailable. |
| Fact judge | Deterministic tools | Enforces scope and executes/checks actual behavior. |

The current router still uses failover behavior. It must become an explicit
collaborative path for high-value candidates:

```text
scout output → adversarial review → local private review when useful
→ controller decision → deterministic check
```

OpenRouter and NVIDIA are not ordinary backups in that path. NVIDIA’s
40-requests-per-minute capacity is reserved for candidate-quality review rather
than raw URL scanning.

## 6. Proof-Only Chaining

Small bugs can produce large impact; large bugs can compose into critical
impact. A valid chain edge `A → B` requires:

1. A is independently confirmed with raw execution evidence.
2. B declares a concrete precondition: object ID, credential, role, state,
   signed value, or other typed input.
3. A’s observed output is bound to that precondition.
4. A then B reproduce sequentially in the permitted target.
5. The combined impact is observed or directly evidenced.

The existing keyword-link chain engine is retained only as a **hypothesis
generator**. It cannot produce a submission-ready chain until the graph edge
requirements above are satisfied.

## 7. Workstreams and Exit Conditions

### A. Controlled website proof loop

**Status:** controlled recon is complete; full analysis/verification remains.

1. Start pinned Juice Shop only on loopback.
2. Browse normal flows through ZAP and export HAR.
3. Import redacted, in-scope HAR evidence.
4. Run controlled recon.
5. Analyze candidate evidence.
6. Execute one known-vulnerable decisive check and one known-clean check.

**Exit:** Oracle confirms one intended local condition and closes one
lookalike/non-finding without destabilizing the target.

### B. Collaborative reasoning

**Status:** failover router exists; collaboration is not yet implemented.

1. Preserve separate scout, adversary, and local-review artifacts.
2. Use OpenRouter for primary candidate generation.
3. Ask NVIDIA to attack the exact candidate/evidence, not generate unrelated
   new ideas.
4. Use Local Qwen for private source/evidence review or cloud-offline work.
5. Record controller promotion/closure rationale.

**Exit:** high-value candidate artifacts show all roles and the deterministic
verdict; model attribution is queryable in the ledger.

### C. Program profile and account workflow

**Status:** alias/header/session scaffolding exists; profile contract is missing.

Each profile must record:

- program URL, scope source, prohibited actions, rate limits;
- mandatory researcher header and alias format;
- Account A / Account B purpose and owned test resources;
- permitted login/session workflow, MFA notes, and evidence requirements;
- exact asset-intake status and authorization source.

Passwords are terminal-prompted without echo and never written. Browser/CDP
sessions or session tokens remain in process memory only.

**Exit:** a user can initialize a policy-compliant two-account workspace and
Oracle refuses to test if required profile fields are absent.

### D. Platform intake and target truth

**Status:** main filters/ranker are fixed; per-adapter conformance remains.

1. Normalize each adapter’s fields: platform, name, URL, kind, payout,
   fast-triage status, report count, launch date, asset/source status.
2. Make API → authenticated session → public fallback status explicit.
3. Test each platform-shaped record with missing and malformed metadata.
4. Fix adapter claims that hardcode or infer fast triage without evidence.

**Exit:** a selected program’s priority inputs and scope source are traceable;
unknown data is shown as unknown.

### E. Proof-chain graph

**Status:** confirmed-only keyword hypothesis engine exists; evidence graph is pending.

1. Add typed candidate outputs and typed candidate preconditions.
2. Record an edge only when output binds to precondition.
3. Execute the entire sequence as a scoped reproduction.
4. Add a valid known chain and an invalid keyword-similar chain to benchmarks.

**Exit:** valid chains reproduce; false composition is rejected.

## 8. Required Evaluation

| Test | What it proves |
|---|---|
| Known vulnerable local case | Oracle can find and confirm a real condition. |
| Known clean/lookalike case | Oracle can close false positives. |
| Two-account local case | Account ownership checks are correctly tested. |
| Valid and invalid chains | Impact composition is evidence-based. |
| Scope/header/profile failure cases | Safety and program compliance fail closed. |
| Scout-only vs scout+adversary vs all roles | Collaboration improves quality, not just volume. |
| Fresh/stale/unknown platform fixtures | Novelty/triage selection remains authoritative. |

Track: candidate-to-confirmed rate, closed false-lead rate, duplicate rate,
target health failures, time to decisive check, and outcomes by mindset move,
MITRE mapping, Invisible Seam type, and model role.

## 9. First Authorized Campaign

Only after Workstreams A–D pass:

1. Pick one fresh-asset or new-program target from the ranker.
2. Build/verify its program profile before any request.
3. Create permitted aliases and Account A/B test accounts.
4. Capture authorized traffic; run controlled recon.
5. Use collaboration only on the highest-value evidence-backed candidates.
6. Verify minimal checks, search duplicates, and submit only confirmed impact.
7. Record the triage outcome and feed it back into the scoreboard.

## 10. Not Yet

Do not delay first proof for SaaS packaging, billing, multi-tenant isolation,
large-scale fine-tuning, broad scanner expansion, or customer dashboards.
Those follow evidence that Oracle reliably creates accepted findings.
