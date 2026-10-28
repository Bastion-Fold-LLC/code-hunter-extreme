> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Master Plan
_Consolidated 2026-10-03. Supersedes the scattered FINISH/MONEY/BOB_* docs for planning; those stay as detail._

## What Oracle is
A deterministic-at-the-core bug-bounty engine: pull program scope → recon → analyze through
two LLM lenses + a deterministic template engine → **prove every candidate on the wire with a
5-gate verifier** → synthesize a submission-ready PoC. ~17,740 lines of core Python (20.5K with
tests, 54 files). The distinguishing bet: the AI proposes, but nothing is "confirmed" unless a
code-only verifier sees a binary conflict proven on the wire.

## Current state (verified this session; HEAD ~4238a7f — run `git log --oneline` for exact)
**Working + committed:**
- 5-gate deterministic verifier — solid; refuses to confirm junk (proven: rejects benign /health).
- Two distinct lenses: paradox (philosophy corpus + invisible seam + scope wall) and mitre (full
  TTP + invisible seam + scope wall). Invisible seam feeds BOTH (5b0b45e).
- Template engine reaches the wire (Bug B fixed, df59405) and carries machine-checkable predicates.
- Precision: info-disclosure requires a real leak marker, not bare status 200 (0b03995); remaining
  templates given predicates + a severity floor so low/info confirmations never auto-draft a
  submission (4238a7f).
- Recon tools installed (ffuf/katana/nuclei/subfinder/httpx/gau). 12 platform sessions live
  (cookies persisted, written 0600 after the security fix 6ef9d3c). OpenRouter + local qwen models.
- Filters fixed (max_reports no longer silently blocks non-HackerOne platforms, adcdeeb).

**Verified precision (live app, both directions):** self-observing (/debug/config CONFIRMS,
/health REJECTS), artifact, open-redirect.

**NOT yet verified / unproven:**
- repulsive-gravity + deathless-hierarchy templates don't trigger on a basic fixture — UNTESTED.
- vacuum-identity's TRUE positive is untested (the test app's access-control bug needs an injected
  X-Original-Role header; the template sends a plain GET).
- No end-to-end run on a real external program. All confirmed findings to date are on the local app.

## The decision (owner: user)
Wire in the FULL philosophy set first — every philosophy/paradox/impossible-problem either a
verified template-move or an operating-stance block — THEN point at a real program once Bob's
work is verified. Breadth-first, by choice: the philosophy completeness is the system's identity.

## The hard constraint that shapes HOW
Template checks are plain GETs today. That caps findings at the "reachable thing leaks" class
(disclosure, misconfig, exposed debug/artifact, stale version, open redirect). The high-value
classes — IDOR, auth bypass, role escalation — and the auth/trust philosophies (Beautiful Liar,
Cliff and the Current) REQUIRE credentialed / multi-step checks: send a forged/invalid token or a
second account's session and see it accepted. The harness exists (oracle_auth_session.py:270); the
templates don't use it yet. Sanitizer allows `-H` and `-X GET/HEAD/OPTIONS`; POST is blocked.

## Work plan

### Phase A — Full philosophy coverage + clear verification debt (Bob, now)
1. Extract the technique-shaped philosophies into moves + templates:
   - The Beautiful Liar → trust/validation ("server never actually validated the token"). Check
     MUST carry a forged/invalid/second-account credential — not a plain GET.
   - The Cliff and the Current → alternate-path auth ("auth check doesn't run on THIS path").
   - The Invisible Architect → infrastructure/implementation seam → a concrete template.
2. Wire the STANCE docs into the system prompt as operating instructions (not templates):
   Pushing Physics, The Mind That Does Not Wait, Build the World. ("Used," just not as checks.)
3. Clear the debt: build a fixture (or second test app) that triggers repulsive + deathless and a
   no-auth-200 privileged endpoint so vacuum's true positive can be verified.
4. VERIFY every move BOTH directions on the live app (confirm a real finding, reject a benign/error
   page) via _run_check + verify_seam_card or the full `hunt 127.0.0.1:8765`. Never from a
   green pytest or a unit test passing status= directly (that masked Bug B). Commit each with evidence.
   DONE = every philosophy is a verified move or a stance block; all templates pass both-ways; debt cleared.

### Phase B — First real-program run (after Phase A verified)
Pick one HackerOne web2 program, ≥$500, real JS+API, not picked-over (don't set max_reports;
ignore patchstack's fake $15k). Scope intake (`oracle_scan.py --pick 1 --download-only`) →
`hunt <program> --auto`. Triage the CONFIRMED set: KEEP disclosure / access-control / IDOR /
secret-exposure / logic; DROP header-only. Goal: one real, in-scope finding end-to-end.

### Phase C — Credentialed multi-step (the ceiling raise)
Make templates produce credentialed checks via the dual-account harness for IDOR / auth-bypass /
role-escalation. This is what turns "reachable thing leaks" into four-figure findings. Do it after
Phase B proves the base loop earns something real.

### Phase D — Volume + submit
Fan out across many in-scope programs in parallel (the agent lever). Variant-sweep one confirmed
bug across remaining assets → N reports. HUMAN reviews every PoC before sending; never auto-submit.
Feed triage outcomes back into target selection + templates.

## Verification discipline (non-negotiable — the lesson of this session)
Verify by RUNNING the real path, both directions, on the live app. A green test suite is not
evidence (121 tests passed while the whole template path was silently blocked). "Looks done" has
been wrong every time this session until a real run confirmed it.

## Guardrails
- Submit only what the verifier CONFIRMED and a human eyeballed. The verifier's refusal to confirm
  junk is the moat — never bypass it to pad numbers.
- Session cookies expire (days); when a platform returns 0 programs, re-run save-cookies.
- Scope: 4 independent gates hold, but pick in-scope targets deliberately. Local-only testing until
  a real program is chosen; no scanning third-party infra without a named, in-scope target.

## Honest calibration
- Simple disclosure/misconfig findings on real targets: reasonably likely with volume — the engine's
  wheelhouse, now tuned to avoid false positives.
- High-value logic/auth-bypass: gated on Phase C (credentialed checks). Low until then.
- The engineering is nearly there; "money in hand" is Phase B proving it on reality + Phase D volume
  and some luck — throughput, not a deadline.
