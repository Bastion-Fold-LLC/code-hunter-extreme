# Oracle Benchmark Evaluation Corpus

## Why Benchmarks Come Before Fine-Tuning

Oracle should first prove that it can detect, verify, close, and chain findings
against intentionally vulnerable targets with known ground truth.

Do not fine-tune a model on this corpus yet. Training on known solutions before
measurement can create benchmark memorization: a model appears capable because
it recognizes a challenge, not because it performed the Oracle reasoning and
verification loop.

The order is:

1. build a versioned evaluation corpus;
2. measure the unmodified system;
3. repair failing pipeline stages;
4. create separate training data from reviewed Oracle artifacts;
5. evaluate a tuned system only on a hidden holdout set.

`benchmarks/registry.json` is data, not hardcoded application logic. It names
approved local evaluation sources without cloning or running them automatically.
Every entry starts disabled and requires an explicit reviewed commit before use.
The Juice Shop entry is enabled at its recorded revision for the approved first
local website-only rehearsal; it must remain loopback-only.

## Initial Corpus

| Benchmark | Primary value to Oracle | Ground truth |
|---|---|---|
| [PyGoat](https://github.com/adeyosemanputra/pygoat) | Python/Django code seams and local runtime proof | Challenge definitions and solution material |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | Recon, business-logic reasoning, MITRE, and iPhone framing | Challenge system and scoreboard |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | Node authorization and middleware seams | Tutorial and documented exercise code |
| [DVWA](https://github.com/digininja/DVWA) | Runtime verification and false-positive resistance | Explicit challenge/difficulty states |
| [OWASP WebGoat](https://github.com/WebGoat/WebGoat) | Scoped web exercises and future Java support | Lesson definitions and solutions |
| [Damn Vulnerable DeFi](https://github.com/theredguild/damn-vulnerable-defi) | Solidity invariants, Foundry proofs, and exploit chains | Challenge prompts and Foundry tests |

These projects explicitly describe themselves as deliberately vulnerable training
or benchmarking applications. They must run only on a local, loopback-bound
environment. Never test public demos, mirrors, or unrelated deployments.

## Onboarding a Benchmark

For each repository:

1. Review its license, current README, setup instructions, and network behavior.
2. Clone it only after approval into a benchmark workspace outside production
   target storage.
3. Record the exact Git commit in `benchmarks/registry.json`.
4. Bind the service to `127.0.0.1`; do not expose intentionally vulnerable
   services to a LAN or the internet.
5. Record supported setup commands, port, reset procedure, and fixture accounts
   in a benchmark-specific adapter.
6. Import only challenge metadata into the visible evaluation labels.
7. Keep solutions and a portion of challenges as a hidden holdout set.

## What Every Benchmark Tests

Each benchmark run must create a ledger row for every expected outcome:

| Oracle layer | Required measurement |
|---|---|
| Scope gate | Oracle refuses non-loopback and out-of-benchmark assets. |
| Recon | Oracle discovers the expected local surface without unrelated noise. |
| Invisible Seam | Code claims and implementation behavior are extracted as candidate nodes. |
| Mindset | The selected philosophy, impossible-problem, or paradox move is relevant to the candidate. |
| MITRE | The mapped technique is useful, rather than a copied label. |
| iPhone framing | The result contains sourced Assertion A, observed Assertion B, one decisive check, and impact. |
| Verification | The expected test result promotes a true flaw and closes a non-flaw. |
| Chaining | Only individually confirmed nodes are joined. |

The score is not "did the model mention a vulnerability." The score is:

```text
expected status == Oracle status
and
the stored evidence independently explains the status
```

## Fine-Tuning Gate

Fine-tuning is allowed only after:

1. the baseline system has results on a pinned corpus;
2. every training artifact has a reviewed source, license, and label;
3. solution text and exploit code are excluded from the holdout evaluation set;
4. tuned models are compared against the unchanged baseline on the holdout;
5. promotion requires better confirmation quality, not merely more candidate
   volume.

Fine-tuning data should contain Oracle's own reviewed artifacts:

- scoped evidence packets;
- candidate-to-confirmed and candidate-to-closed examples;
- correct iPhone-format cards;
- adversarial reviews that identify missing preconditions;
- proof-only chain examples;
- triage outcomes when available.

Never train the system to equate a code smell with a vulnerability. Train it to
identify the invariant, demand the decisive check, and accept closure when the
evidence disproves the hypothesis.
