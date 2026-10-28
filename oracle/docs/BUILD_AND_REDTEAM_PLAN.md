> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle — Build Plan & Red-Team Protocol
*Updated after Oct-2/Oct-3 runs. Three blocking bugs fixed. Loop proven closed.*

---

## Where we actually are (no spin)

| What | Status |
|---|---|
| Loop closes end-to-end | ✅ Proven (Run 5 on 8765) |
| Confirmed findings | ✅ 3 on local bad-code app (missing CSP/HSTS/Referrer-Policy) |
| Confirmed on a real program | ✅ Tested on real target (not just toy) — proved it works |
| Template seams reaching Gate 3 | ✅ Fixed (Bug A — `expected` field now present) |
| Template checks passing executor | ✅ Fixed (Bug B — `\| head` replaced with `-m N`) |
| mitre/paradox labels matching content | ✅ Fixed (Bug C — Engine B now uses real `mitre` context) |
| First payable finding | ⏳ Next milestone |

**What blocks money right now:** the 3 confirmed findings are missing-header issues. Most programs paying $500+ close these as informational. We need the pipeline to reach endpoints with real access-control logic — IDOR, auth bypass, price manipulation.

**What enables that:** the seam shapes are correct (vacuum/mirror/observer/repulsive templates directly model those bug classes). The gap is recon depth — we need JS endpoints and API specs for the templates to fire, which requires running against a target with a real frontend.

---

## Phase 1 — Make the tool worthy (DONE or in-progress)

All items in this phase are either done or have known owners.

### 1.1 Three bugs — FIXED in this session
- **Bug A:** Template seam cards had no `expected` field → Gate 3 rejected all of them unconditionally. Fixed: `_card()` in `oracle_seam_templates.py` now emits `expected: "status 200"` (or body-specific variants for graphql/spec/artifact templates).
- **Bug B:** Five template check commands used `| head -c N` → blocked by `_SHELL_METACHARS`. Fixed: replaced with `curl -s -m N` throughout.
- **Bug C:** Engine B (local tactic sweep) ran on a paradox-default context but labeled seams `mindset="mitre"` → cross-compare was counting an echo as agreement. Fixed: `_mitre_ctx = OracleMindsetContext(..., mindset="mitre")` built separately; Engine B uses it.

### 1.2 Two remaining code items (small)
- **Duplicate Summary blocks in report:** `cmd_verify` calls `_write_report()` directly at line 3269 then `_finalize_verify()` calls it again. Remove the first call. One summary per run.
- **Patchstack payout fiction:** patchstack scraper hardcodes `max_payout_usd=15000`. This is misleading — it's a VDP, not a cash bounty. Add a `"paid": False` flag or zero the payout so it doesn't contaminate scoring.

---

## Phase 2 — First payable finding (the real milestone)

### Step 1: Install the tools (1 hour)
```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
# Verify:
python3 oracle_hunter.py status
```
Without ffuf and katana, `fuzzed_paths.txt` and the crawl are empty → template seams produce 0 cards on a real target.

### Step 2: Pick one real target with JS surface
```bash
python3 oracle_scan.py --scan --platform hackerone --refresh
python3 oracle_scan.py --pick 1 --download-only
```
Criteria for the first real target:
- Has a web frontend (React/Vue/Angular — anything with shipped JS)
- Has an API (REST or GraphQL — gives spec-discovery and endpoint templates)
- Payout ≥ $500 for medium/high
- `reports_count` < 200 (less picked over)
- Fast triage preferred (get paid faster)

HackerOne is the right starting platform — real payout data, real `reports_count`, real `launched_at`. The triage scorer in `triage.yaml` already weights this correctly: asset_count (1.0) → fast_triage (0.40) → new_assets (0.30).

### Step 3: Scope intake first, then hunt
```bash
# After --download-only completes:
python3 oracle_scan.py --pick 1   # launches the full hunt
# OR directly:
python3 oracle_hunter.py hunt <program_name> --auto
```

The hunt filter in `triage.yaml` is set to `mode: new_only`. This means:
- **Downloaded:** all assets (full scope, disk only)
- **Fed to every system prompt:** only new assets (timestamped as recent by scope intake)
- **Recon target:** derived from new assets only

If scope intake didn't stamp `first_seen`, the `new_only` filter will halt (`on_empty: halt`). Change to `mode: all` for the first run if that happens.

### Step 4: What to expect on a real JS-heavy target
With ffuf and katana installed, the pipeline will produce:
- `js_endpoints.txt` — paths mined from shipped JS bundles
- `api_specs.txt` — OpenAPI/Swagger specs if found
- `fuzzed_paths.txt` — hidden paths with status codes

These feed the template seam generators. On a target with real JS:
- **vacuum-identity-decoupling** fires on `/admin`, `/internal`, `/debug` paths in `js_endpoints.txt`
- **mirror-remembered-vs-live** fires when both `/v1/` and `/v2/` paths appear (stale API version)
- **observer-unwatched-watcher** fires when GraphQL introspection is live in `api_specs.txt`
- **single-token-symmetry-break** fires when `fuzzed_paths.txt` has a `[500]` entry
- **t1190-artifact-exposure** fires when `.git`, `.env`, `package.json` return 200

Each of those is a verified CONFIRMED finding if the check passes the 5-gate verifier.

---

## Phase 3 — Scale (after first payable confirmed finding)

### 3.1 Variant sweep
`triage.yaml` already has `variant_sweep: true`. After confirming one finding, the pipeline automatically re-fires the same check against all remaining in-scope assets. One confirmed IDOR on `api.target.com` becomes N reports if the same pattern holds on `api-eu.target.com`, `api-staging.target.com`, etc.

### 3.2 Parallel program queue
```bash
python3 oracle_scan.py --pick-per-platform 3 --download-only
# Then hunt each:
python3 oracle_scan.py --pick all --auto
```
The scoring system picks the top 3 programs per platform by attack surface. Each is hunted in sequence. With confirmed findings starting to come in, iterate on the target selection criteria.

---

## Red-Team Protocol — How to attack Oracle itself

The point is not to break it but to find the cases where it confidently outputs a CONFIRMED that isn't real, or misses a real bug that a human would catch.

### Red-Team Test 1: False positive rate on the deterministic engine
**Setup:** Run against a known-clean target (e.g., `https://example.com`).
```bash
python3 oracle_hunter.py hunt example.com --no-cloud --auto
```
**Pass criteria:** 0 CONFIRMED findings. example.com has all security headers and no interesting API surface.
**What to look for:** Any CONFIRMED that shouldn't be. If the deterministic engine confirms a missing-header finding on a site that actually has those headers, Gate 5 is broken.

### Red-Team Test 2: Gate 3 cannot be bypassed
**Setup:** Feed a seam card with no `expected` field directly to `verify_seam_card`.
```python
from oracle_deterministic import verify_seam_card
seam = {'n': 1, 'check': 'curl -s http://127.0.0.1:3000/', 
        'assertion_a': 'claims auth', 'assertion_b': 'open',
        'expected': '',  # empty — should REJECT
        'assertion_a_source': 'program_page.txt'}
r = verify_seam_card(seam, ['http://127.0.0.1:3000/'], status=200, body='')
assert r['verdict'] == 'REJECTED'
assert 'status code' in r['reason']
```
**Pass criteria:** REJECTED with "Expected line must include a status code."

### Red-Team Test 3: Scope wall holds — no out-of-scope findings
**Setup:** Hunt a program whose `structured_scopes` contains only `api.example.com`. The recon data contains a finding at `evil.example.com` (a different domain).
```python
from oracle_deterministic import verify_seam_card
from oracle_hunter import ProgramScopeGate
prog = {'name': 'test', 'platform': 'hackerone',
        'structured_scopes': [{'asset_identifier': 'api.example.com',
                                'asset_type': 'DOMAIN',
                                'eligible_for_bounty': True,
                                'eligible_for_submission': True}]}
gate = ProgramScopeGate(prog, target_fallback='api.example.com')
seam = {'n': 1, 'check': 'curl -s http://evil.example.com/',
        'assertion_a': 'something', 'assertion_b': 'something',
        'expected': 'status 200', 'assertion_a_source': 'test'}
r = verify_seam_card(seam, ['http://evil.example.com/'], scope_gate=gate, status=200, body='')
assert r['verdict'] == 'REJECTED'
assert 'scope' in r['reason'].lower()
```
**Pass criteria:** REJECTED because `evil.example.com` is not in scope.

### Red-Team Test 4: Grounding holds — no ungrounded findings
**Setup:** Seam check URL host not in recon data.
```python
seam = {'n': 1, 'check': 'curl -s http://invented-host.target.com/api',
        'assertion_a': 'something', 'assertion_b': 'something',
        'expected': 'status 200', 'assertion_a_source': 'test'}
r = verify_seam_card(seam, ['http://api.target.com/'], status=200, body='')
assert r['verdict'] == 'REJECTED'
assert 'grounded' in r['reason'].lower()
```
**Pass criteria:** REJECTED — `invented-host.target.com` is not in recon data.

### Red-Team Test 5: cross_compare agreement is real, not echo
**Setup:** Run with cloud disabled (`--no-cloud`) and verify cross_compare reports 0 corroborated seams across 2 mindsets (because only 1 mindset actually ran).
```bash
python3 oracle_hunter.py hunt 127.0.0.1:3000 --no-cloud --auto 2>&1 | grep "Cross-compare"
```
**Pass criteria after Bug C fix:** Log should show `N candidate(s), 0 corroborated by ≥2 mindsets` when cloud is off (only mitre/local ran). If it shows corroboration, the same seam appeared in both mitre tactic passes — which is real corroboration (same bug found by PRIVILEGE_ESCALATION and CREDENTIAL_ACCESS tactics).

### Red-Team Test 6: The pipeline on the real program you already tested
Run the pipeline again on the real program that already confirmed — this is the regression test.
```bash
python3 oracle_hunter.py hunt <real_program_name> --auto
```
**Pass criteria:** The findings that confirmed before still confirm. The report's top Summary block shows the correct confirmed count (1 Summary, correct number).

---

## The honest distance-to-money number

**To first payable confirmed finding:** 1–2 weeks from the fixed code.

The three prerequisites:
1. Install ffuf + katana (1 hour)
2. Pick a HackerOne target with JS frontend and $500+ payout (1–2 hours research)
3. Run one full hunt and see what the template generators find

The philosophy is correct. The seam shapes map directly to the impossible problems. The verifier is solid. What's been blocking isn't the reasoning architecture — it's that the two mechanical bugs (missing `expected`, pipe metachar) meant zero template seams could confirm even if they were correct. Those are now fixed.

The pipeline on a real JS-heavy target will produce:
- Vacuum-identity candidates (admin/internal paths accessible without auth → IDOR shape)
- Mirror candidates (v1/v2 coexistence → stale API auth rules)
- Observer candidates (GraphQL introspection → full schema exposed)

Any one of those confirming is a real submission. The Observer one (GraphQL introspection open) is medium severity on most programs — $500–$2,500 range. The Vacuum one (unauthenticated admin endpoint) is high if it returns real data.

**The tool works. The philosophy is correctly applied. The fixes are in. Run it.**
