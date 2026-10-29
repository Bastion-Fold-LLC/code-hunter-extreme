# Oracle Owner-Intended Workflow

Recorded from the owner's design statement on 2026-10-28. This document
defines how the system is supposed to work. For pipeline workflow and
mindset composition it is the governing statement: where older docs,
boards, tests, or code disagree with it, they are drift to reconcile,
not competing designs. It is not a claim that the current implementation
already behaves this way at every stage.

## Purpose

The end of the pipeline is a real, submission-ready bug-bounty finding.
Anything that prevents that outcome is a pipeline issue. Passing component
tests, finding planted benchmark bugs, or producing intermediate reports
does not by itself prove that the pipeline works.

## Intended flow

```text
Scan4Me discovery/report
        -> Oracle verification
        -> multi-method download and context assembly
        -> Mindset 1 \
        -> Mindset 2  -> Mindset 3 adversarial invisible-seam synthesis
        -> deterministic / wire verification
        -> report and PoC bundle
        -> manual submission
```

## Stage 1 — Scan4Me discovery

Scan4Me searches the bounty-platform sites **without requiring a login**.
Its job is broad discovery of programs and the information published about
them, including listed targets/assets, scope, company and bounty details
available from those sources.

Scan4Me produces a discovery report/data handoff for Oracle. This output
is candidate material. It is not yet trusted product truth merely because
Scan4Me found it. Freshness still matters: an unavailable, stale, or
failed-refresh discovery feed cannot supply candidates. Public (no-login)
provenance by itself is not a failure and is not trust either.

## Stage 2 — Oracle verification

Oracle has an explicit verification stage for selected Scan4Me results.
Oracle independently checks the relevant site/program material using:

- the platform API, when one is available;
- Playwright/browser/CDP rendering, when browser verification is needed;
- other independent fetch/render methods where appropriate.

Verification must establish the program, company, bounty details, current
rules, and exact in-scope and out-of-scope assets before a program is
treated as verified. Unverified Scan4Me output must not silently become
hunt truth.

## Stage 3 — Download and context assembly

For a verified program, Oracle uses multiple methods to collect the target
material and avoid missing relevant information. Intended methods include,
as applicable:

- repositories and source code;
- authenticated or rendered browser views;
- Playwright/Crawl4AI rendering;
- Firecrawl and other independent fetch paths;
- plain HTTP(S) fetches;
- JavaScript, API specifications, documentation, robots/security files,
  screenshots, and other in-scope assets.

Different fetch paths corroborate one another. The workspace must record
what was obtained, which method supplied it, and what material is missing.
Silent gaps must not be presented as complete coverage.

## Stage 4 — Load the mindsets

Every product hunt loads Mindsets 1, 2, and 3. The following are shared
foundations for all three:

- bug-bounty information and rules;
- exact assets in scope and out of scope;
- company information;
- verified downloaded target material;
- invisible-seam reasoning and candidates;
- red-team pressure.

### Mindset 1

Mindset 1 additionally receives the MITRE ATT&CK material. It reasons from
real attacker techniques against the verified target surface while using
the shared invisible-seam and red-team foundations.

### Mindset 2

Mindset 2 additionally receives:

- philosophies;
- paradoxes;
- impossible problems;
- iPhone-level framing;
- the shared invisible-seam foundation;
- red-team pressure.

### Mindset 3

Mindset 3 receives the results of Mindsets 1 and 2 and the deterministic
invisible-seam candidates. It also retains the company information,
bug-bounty context, and exact scope. It adversarially red-teams and
synthesizes those inputs into the unified invisible-seam result. It must
not invent seams that neither Mindset 1, Mindset 2, nor the deterministic
invisible-seam feed produced.

## Invisible seam

Invisible seam does not depend on the bug matching a previously known
pattern. The target supplies claims through its documentation, code,
configuration, responses, and observed behavior. A seam exists when an
observed reality contradicts one of those claims:

- Assertion A: what the system claims, assumes, or appears to enforce.
- Assertion B: the contradictory reality.
- Check: the smallest decisive observation or request that proves which
  side is true.

Templates and technique catalogs may suggest where to look, but the seam
itself must be grounded in this target's own claims and behavior.

## Red teaming

Red teaming is part of every mindset, not only a final label:

- Mindset 1 applies MITRE-driven adversarial pressure to its candidates.
- Mindset 2 attacks assumptions, invariants, trust boundaries, and frames.
- Mindset 3 attacks the combined candidates, discards unsupported noise,
  and looks for valid compound chains.
- Final wire evidence decides whether a candidate is confirmed.

## Proof standard

Keep these states separate:

1. **Built** — code exists.
2. **Wired** — the stage is connected in the intended order.
3. **Exercised locally** — components or planted fixtures produced the
   expected component behavior.
4. **Exercised live** — the stage produced the intended artifact on a
   real selected target.
5. **Proven end to end** — a real target produced a submission-ready
   finding and PoC through the complete flow.

Planted benchmarks are component regression fixtures. Because their bugs
and expected checks are known in advance, passing them does not prove
that Scan4Me discovery, Oracle verification/download, the mindsets, or
the complete pipeline can discover unknown bugs on a real target.
