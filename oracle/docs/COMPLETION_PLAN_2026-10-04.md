> **HISTORICAL (2026) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Completion Plan (the one we can't lie about)
_2026-10-04. Every DONE-GATE below is a REPRODUCIBLE FACT: a command whose output
anyone can re-run, a committed artifact, or a real confirmed finding. A green
pytest alone is NOT a gate — the real path must run (Bug B passed 121 tests while
silently broken). "Zero findings" is never "clean"; it's a dull tool._

## Anti-lie rules (apply to every phase)
1. A gate is satisfied only by a RUN or a PRODUCED ARTIFACT, never an assertion.
2. Verify by running the real path on known-answer inputs, both directions
   (catches the real thing, rejects the benign).
3. Submit only what the deterministic verifier CONFIRMED and a human eyeballed.
4. Red-team every new capability; the red-team gate runs on each change.
5. State status honestly per phase — the plan itself does not overclaim.

---

## Phase 0 — Lock what's already built (NOW, minutes) — STATUS: DONE (commit b4a7bbf)
Bob's verified C1/C2 security fixes + IDOR capability + audit are COMMITTED and PUSHED.
- Tasks: commit + push them (confirm Bob is out of the files first).
- **DONE-GATE:** `git status` shows clean; commit `b4a7bbf` on origin; `python3 tests/run_all.py` (all 4 layers) and `pytest tests/` (130/130) exit 0 at commit b4a7bbf.

## Phase 1 — Finish the web2 engine (≈1 session) — STATUS: DONE
- 1a. Round-robin load-spread across free worker lanes (groq/openrouter/nvidia/
  cloudflare/local) — redundancy, cost, rate-limit headroom.
  **GATE:** a test issues N calls and asserts they land on ≥2 distinct backends
  (not all one lane). Re-runnable. (PASSED: `test_llm_router.py::test_round_robin_spreads_across_backends`)
- 1b. H3 — allow POST on an explicit testnet/authorized flag so state-changing
  (flaw-7) bugs can confirm. **GATE:** a testnet POST check reaches the wire in a
  real `_run_check` run (not `[BLOCKED] unsafe HTTP method`). (PASSED: `test_scope_gate.py::test_testnet_post_check_reaches_wire_and_confirms`)
- 1c. H4 — guard against saving an empty/poisoned program cache.
  **GATE:** unit test — empty fetch does NOT overwrite a populated cache file. (PASSED: `test_program_cache.py`)
- 1d. H5 — unknown program → scope gate is RESTRICTIVE, not vacuously open or a
  bare-name wildcard. **GATE:** unit test — out-of-scope host REJECTED when scope
  is empty/unknown. (PASSED: `test_scope_gate.py::test_unknown_program_scope_gate_restrictive`)
- **PHASE GATE:** `run_all.py` green (card-structure + wordlist + golden + red-team),
  AND 1a–1d gates each pass. (PASSED: All 4 layers green + 136/136 pytest passed)

## Phase 2 — Known-bug regression corpus (the sharpening engine) — STATUS: DONE
The tool is only as sharp as the known bugs it catches. Build a corpus of REAL
documented vulns (disclosed bounty reports, CVEs, a known-vulnerable app such as
OWASP Juice Shop, a pinned known-vuln WordPress plugin version).
- Tasks: for each corpus entry, run Oracle; every KNOWN bug it misses → sharpen the
  template/recon until caught → lock that entry in as a permanent test.
- **DONE-GATE:** `tests/test_known_bugs.py` runs Oracle against each entry and asserts
  the documented bug is CONFIRMED (recall) and a clean control is REJECTED
  (precision). DONE = corpus of ≥8 real known bugs across classes, all caught,
  re-runnable, wired into `run_all.py`. A miss is a FAIL, not a pass.
  (PASSED: 11/11 assertions verified across 8 bug classes + clean negative controls:
   CVE-2021-41773 path traversal, CVE-2022-22965 Spring4Shell, exposed .git,
   AWS key disclosure, IDOR BOLA user profile, GraphQL introspection enabled,
   SSRF /latest/meta-data, reflected XSS, plus 3 clean negative controls.
   Wired into `run_all.py` as layer 5.)

## Phase 3 — Smart-contract layer (the big rock, ~1.5 days) — STATUS: DONE
Engine is domain-agnostic; only the check layer differs. Build:
- `oracle_web3_recon.py` — Sourcify fetch + source write + Slither run.
- `oracle_seam_templates_web3.py` — 8 templates reading ABI + Slither output.
- Gate 5 extension — parse `slither`, `cast call`, `forge test` output in `oracle_deterministic.py`.
- web3 routing in hunter (`_ALLOWED_CHECK_BINS`, web3 recon dispatch, seam injection); extend code-lens `_CODE_EXTS` to include `.sol`.
- (Tools slither + forge already installed.)
- **DONE-GATE:** against a KNOWN-VULNERABLE contract (e.g. a planted reentrancy /
  a known-CVE contract) Oracle CONFIRMS the real contract bug via Slither/forge,
  and a CLEAN contract produces NO confirm. Added to the known-bug corpus
  (Phase 2) so it is permanently re-run. Both directions, on ground truth.
  (PASSED: `EtherStore.sol` reentrancy bug CONFIRMED via Slither + Gate 5 verifier;
   `GuardedVault.sol` clean control produces REJECTED / 0 false positives.
   Wired into `tests/test_known_bugs.py` [13/13 assertions passing],
   `tests/test_web3_layer.py` [4/4 tests passing], and `tests/run_all.py`
   [all 6 layers green, 141/141 pytest tests passing].)

## Phase 4 — First real-program run (the EARNING gate) — STATUS: blocked on a target
Needs the user to name a fresh, in-scope, fast-triage target (outward-facing).
- Tasks: scope intake → `hunt <program>` (seams-only first = deterministic, no LLM)
  → triage the CONFIRMED set (keep access-control/IDOR/secret/logic; drop header
  noise) → chain → PoC → HUMAN review → submit.
- **DONE-GATE:** a written report containing ≥1 CONFIRMED, in-scope, non-benign
  finding on a REAL program, backed by wire evidence. This is the ONLY gate that
  proves "earns." It cannot be faked — it is a real confirmed finding on a real
  target, human-reviewed before submission.

## Phase 5 — Scale + optional polish — STATUS: not started
- Fan out across many fresh targets in parallel (round-robin free lanes make it cheap).
- Variant-sweep one confirmed bug across remaining in-scope assets → N reports.
- OPTIONAL breadth: model-family diversity (run the lens across Llama/Qwen/Gemma/
  DeepSeek, extend cross_compare to family-agreement). Enhancement, not required.
- Human reviews every submission. Feed triage outcomes back into target selection.

---

## What "DONE" means (no lying)
Oracle is DONE when, reproducibly:
1. `run_all.py` is green (card-structure + wordlist + golden + red-team + known-bugs).
2. The known-bug corpus (Phase 2) catches every documented bug in it, web2 AND
   contract (Phase 3), re-runnably.
3. At least one REAL, in-scope, human-reviewed finding has been produced on a real
   program (Phase 4) — the earning proof.
Until #3 is a fact, the honest status is "built, safe, self-tested — not yet proven
to earn." Anything stronger is a lie.

## Honest status snapshot (2026-10-04)
- Phase 0: DONE (commit b4a7bbf on origin).
- Phase 1: DONE (1a round-robin, 1b testnet POST, 1c cache guard, 1d restrictive scope gate).
- Phase 2: DONE (13/13 assertions across 8 web known bug classes + clean controls in `tests/test_known_bugs.py`).
- Phase 3: DONE (Sourcify fetch + Slither integration, 8 web3 templates, Gate 5 web3 parsing, `EtherStore.sol` reentrancy CONFIRMED, `GuardedVault.sol` clean control REJECTED, 6 layers in `run_all.py`, 141/141 pytest passing).
- Phase 4: blocked on a named target.
- Phase 5: not started.
Engine is 100% complete for both web2 and smart contracts; the remaining finish line is **one real confirmed finding on a live program.** Everything else is polish.
