> **HISTORICAL (2026) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Plan to First Paid Finding (2026-10-03)

Constraint model: agent-driven (you + Bob + me). Engineering is hours, not weeks.
The distance to money is a VOLUME × PRECISION game, not a schedule.

## Phase 0 — Ready NOW (verified this session)
- Engine: 5-gate verifier (solid), two lenses + invisible seam in both, PoC synthesis.
- Bugs fixed + committed: Bug A (expected), Bug B (checks reach wire), Bug C (mitre ctx),
  max_reports null-rejection, cookie-file 0600 security.
- Recon tools ALL installed (ffuf, katana, nuclei, subfinder, httpx, gau) — status ✓.
- Access: 12 platform sessions live via Chromium Profile 2, cookies persisted + auto-restored.
- LLM: OpenRouter + local qwen3-coder:30b / qwen2.5-coder:14b, Firecrawl.

## Phase 1 — Prove the engine PULLS (this session)
- Full local proof hunt on 127.0.0.1:8765 (bad_code_app): does a TEMPLATE
  seam reach CONFIRMED on real surface (/debug/config secrets, /api/v1/admin/metrics)?
  → If yes: the deterministic template→wire→verify path is proven. [RUNNING]
  → If no: the exact rejecting gate tells us the next fix.
- Optional: fix _t_t1552 properly (thread JS source URL into js_secrets so its check can
  re-fetch the file; NOT `curl|grep` — that's sanitizer-blocked). One finding class.

## Phase 2 — First REAL target (the money step — deliberate, you/Bob name the target)
1. Pick: HackerOne, web2, >=$500, real JS frontend AND API, not picked-over
   (use triage ranker; ignore patchstack's fake $15k; don't set max_reports).
2. Scope intake: `oracle_scan.py --pick 1 --download-only` → structured_scopes populated.
3. Run: `oracle_hunter.py hunt <program> --auto`.
4. Triage the CONFIRMED set:
   - DROP: missing-header / informational (won't pay on real programs).
   - KEEP: broken access control, IDOR, exposed secrets/debug endpoints, business logic,
     real info disclosure from APIs. These are the $500–$2,500+ band.

## Phase 3 — Volume (the agent lever that beats human-serial)
- Fan out across many in-scope programs in parallel.
- Variant sweep (triage.yaml: variant_sweep:true): one confirmed finding re-fired across
  remaining in-scope assets → N reports from one bug class.
- Precision is the moat: only the deterministic-CONFIRMED set gets a PoC. No guessing.

## Phase 4 — Submit + iterate
- PoC synthesis is built (_synthesize_poc) → submission_draft per confirmed seam.
- HUMAN reviews every PoC before sending. Do NOT auto-submit (legal + quality gate).
- Feed triage accept/reject outcomes back into target selection + seam templates.

## Guardrails (this session's hard-won lessons)
- Submit only what the verifier CONFIRMED and a human eyeballed. The verifier's refusal to
  confirm junk is the whole value — never bypass it to pad numbers.
- Verify by RUNNING the real path, never by a green test suite (that masked Bug B).
- Session cookies expire (days) — when a platform returns 0 programs, re-run save-cookies.
- Scope: 4 independent gates hold, but pick in-scope targets deliberately.

## Honest expectation
First findings are most likely info-disclosure / access-control / IDOR class. Each real,
in-scope, payable CONFIRMED finding is a shot on goal. More targets + good recon + the
verifier's precision = eventual paid finding. Throughput, not a deadline.

---

## Phase 1 PROOF RESULT (2026-10-03 ~06:19) — plumbing works, precision doesn't
Ran `hunt 127.0.0.1:8765 --auto --mindset seam`. First-ever end-to-end template-seam path:
generated → allow-listed `curl -i -s` check → real wire evidence → 5-gate verify → CONFIRMED
→ PoC synth. Bug B fix validated in a real run. **The path pulls.**

BUT the CONFIRMED finding is a FALSE POSITIVE:
- Seam: "Information Disclosure — /health reachable"; check returned HTTP 200
  `{"status":"ok","app":"vulnerable_testbed"}`; verdict CONFIRMED on `status 200` match.
- `/health` returning `{"status":"ok"}` is NOT a vuln. The template's `expected: status 200`
  confirms ANY reachable endpoint. Real vuln (/debug/config leaking AWS keys) was never
  found — ffuf wordlist surfaced only /health.

### New priority: PRECISION before real targets
1. Tighten template predicates — info-disclosure/self-observing must require a BODY predicate
   (version/env/secret/path markers), not bare `status 200`. Otherwise every live endpoint
   "confirms". This is now the #1 blocker to real targets (false positives = triage reject +
   reputation/ban risk).
2. Recon wordlist/depth — /debug/config existed and was missed. Tune ffuf wordlist so the
   templates fire on the paths that actually matter.
3. Only THEN point at a real program — a false-positive machine on a live program is worse
   than nothing.
