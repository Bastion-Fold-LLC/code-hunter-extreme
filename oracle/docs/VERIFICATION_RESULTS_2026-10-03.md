> **HISTORICAL (2026-10-03) — dated results snapshot; current gates in `STATUS.md` / `VERIFIED_STATE.md`.**

# Template verification results (2026-10-03, live test app 8765)

Ran each template's real card against the live app via _run_check + verify_seam_card.

- self-observing: CORRECT both ways. /debug/config (creds) CONFIRMS; /health + 403
  /admin/metrics REJECT. Solid.
- vacuum-identity: no false positive — rejected the 403 /admin/metrics (requires 200,
  got 403) despite "role"/"admin" in the error body. BUT true-positive UNTESTED: the
  app's broken-access-control bug needs an injected `X-Original-Role: admin` header;
  the template emits a PLAIN GET, so it cannot confirm this bug class as written.
  LIMITATION: template checks don't do header-injection / multi-step exploits.
- mirror: mechanism confirms (v1 endpoint still serving API content), but tested with
  a SYNTHETIC v2 reference. Real TP/FP needs genuine v1+v2 coexistence in js_endpoints.
- repulsive-gravity, deathless-hierarchy: did NOT trigger on the fixture — their
  triggers (spelling variants / legacy-deprecated markers) need specific recon material.
  STILL UNVERIFIED both-directions.

## For Bob
- Build a richer fixture (or a second test app) that triggers repulsive + deathless, and
  a no-auth-200 privileged endpoint so vacuum's TRUE positive can be verified.
- Decide: should vacuum/access-control templates support a header-injection variant
  (-H 'X-Original-Role: admin') so they can actually prove that bug class? Sanitizer
  allows -H and -X GET/HEAD/OPTIONS, so a header variant is feasible.

---

## Credentialed check capability — PROVEN (2026-10-03, this session)
Bob is mid-writing _t_beautiful_liar (in the working tree: _TRUST_CLAIM_RE, _PRIV_HEADER_RE,
partial fn). I did NOT edit it (would clobber). Instead I verified the underlying credentialed
check end-to-end against the live app — three-way, all PASS:

- `curl -i -s -H 'X-Original-Role: admin' '.../api/v1/admin/metrics'`  -> CONFIRMED (status 200,
  admin data) — the real broken-access-control bug.
- same endpoint, NO forged header -> REJECTED (403) — no bug without the forge.
- forged header on /health (benign) -> REJECTED (200, no admin markers) — no false positive.

So the credentialed move raises the ceiling from "reachable thing leaks" to real auth-bypass.

### Verified card shape for _t_beautiful_liar to emit (match this):
  check:    curl -i -s -H '<trust-claim-header>: <privileged-value>' '<privileged-url>'
            (iterate _PRIV_HEADER_RE headers x _TRUST_CLAIM_RE / _PRIV_RE endpoints)
  expected: status 200, body contains any of "<privileged-data markers>"
            (NOT bare 200 — require the elevated response body, or a benign 200 FPs)
  severity: high  (real auth-bypass; above the floor -> gets a submission draft)
  Verify BOTH ways: forged header on privileged ep CONFIRMS; no-header or benign ep REJECTS.

---

## New philosophy templates (committed 615dee7) — verification status
Bob authored THREE technique templates in one uncommitted blob; I committed them together.
- beautiful-liar-trust-bypass: VERIFIED both ways (forged X-Original-Role confirms
  /api/v1/admin/metrics; no-header=403 reject; benign=reject). Real auth-bypass. ✓
- cliff-and-current (alternate-path auth): COMMITTED, UNVERIFIED. Needs a guarded (403) +
  unguarded-alternate (200) path PAIR serving protected data — the test app has no such pair.
- invisible-architect (infra-file exposure): COMMITTED, UNVERIFIED. Needs an exposed infra
  file (package.json/.env/etc.) at 200 — the test app serves none.

## Verification debt (blocks "trustworthy for real targets")
Untested-both-ways templates, because bad_code_app doesn't exercise them:
cliff-and-current, invisible-architect, repulsive-gravity, deathless-hierarchy, vacuum TP.
FIX: extend bad_code_app (or add a second fixture app) with: an exposed infra file at 200,
a guarded+unguarded alternate-path pair, a v1/v2 pair, a legacy/deprecated endpoint, and a
no-auth-200 privileged endpoint. THEN verify each template both-ways before any real-program run.
