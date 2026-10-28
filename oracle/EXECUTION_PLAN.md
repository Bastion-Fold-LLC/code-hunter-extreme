# Oracle + Product.ai Integration: Execution Plan

---

## **Execution Order (Sequential, Verified at Each Step)**

| Step | Task | Est. Time | Verification Method |
|------|------|-----------|---------------------|
| **1** | Copy 12 Product.ai corpus docs to `oracle/corpus/` | 5 min | Subagent: verify docs exist + `oracle_corpus.py` loads them |
| **2** | Update `oracle_corpus.py` DOCUMENTS list | 2 min | Subagent: verify all 12 docs in `DOCUMENTS` list |
| **3** | Regenerate TTP fusion (Reflexes 9-11 already done) | 30 sec | Subagent: verify 342 TTPs, 11 reflexes, closing motions 9/10/11 |
| **4** | Run full test suite | 2 min | Subagent: 10/10 layers green |
| **5** | Proof Packet Generation | 2 hrs | Subagent: test generates valid packet structure |
| **6** | Kinetic Axiom: Decay/Mutation on seam cards | 3 hrs | Subagent: test decay filtering + mutation triggers |
| **7** | OmniCLI Internal Deadline | 3 hrs | Subagent: test timeout enforcement |
| **8** | Tactic Coverage Enforcement | 1 hr | Subagent: test cloud mode drops tactic |
| **9** | Scan4Me Rate Limiting | 2 hrs | Subagent: test auth fetcher delay |
| **10** | Fiduciary Diode Documentation | 1 hr | Subagent: verify scope gate comments |
| **11** | Outcome Engineering Spec | 2 hrs | Subagent: test teardown returns structured spec |
| **12** | Mutation Triggers Integration | 2 hrs | Subagent: test program_changes → seam mutation |
| **13** | Full Regression Suite | 5 min | Subagent: all tests pass |

---

## **Step 1: Corpus Copy + TTP Fusion (COMPLETE - Already Done)**

### **Status**: ✅ DONE
- 12 corpus docs copied to `oracle/corpus/`
- `oracle_ttp_fuse.py` updated with Reflexes 9, 10, 11
- TTP fusion regenerated: 342 TTPs, 11 reflexes
- Tests pass: 10/10 layers green

**Verification**: Already complete. Run verification to confirm.

---

## **Step 2: Proof Packet Generation (COMPLETE - 2 hrs)**

### **Status**: ✅ DONE
- Added `generate_proof_packet()` function to `oracle_foundation.py`
- Integrated into `verify_seam_card()` in `oracle_deterministic.py` - attaches proof packet to CONFIRMED seam cards
- Added `verify_proof_packet()` for tamper-evidence verification
- HMAC-SHA256 signatures with deterministic key
- Scope gate evidence included in proof packet
- All tests pass: Oracle 10/10 layers green, Scan4Me handoff tests 3/3 passed

### **Verification**: ✅ All tests pass
- Oracle test suite: 10/10 layers green
- Scan4Me handoff tests: 3/3 passed

---

## **Step 3: Kinetic Axiom - Decay/Mutation on Seam Cards (COMPLETE - 3 hrs)**

### **Status**: ✅ DONE
- Added Kinetic Axiom fields to `build_seam_card()` in `oracle_foundation.py`:
  - `epistemic_type`: PHYSICAL | SENTIMENT | TRANSACTIONAL
  - `decay_rate`: FAST | MEDIUM | SLOW
  - `decay_rate_value`: 0.05 (per day)
  - `last_verified`: ISO timestamp
  - `mutation_triggers`: ["firmware_release", "price_change", "sentiment_shift", "time_decay", "contradictory_signal"]
  - `mutation_triggered`: boolean flag
  - `last_triggered`: ISO timestamp
  - `proof_packet`: cryptographic receipt

- Updated `inject_pending_seams()` in `oracle_mindset_context.py`:
  - Exponential decay filtering (confidence < 10% = filtered)
  - Mutation trigger filtering (`mutation_triggered` flag)
  - Automatic re-verification scheduling

- All tests pass: Oracle 10/10 layers green, Scan4Me handoff 3/3 passed

### **Verification**: ✅ All tests pass
- Oracle test suite: 10/10 layers green
- Scan4Me handoff tests: 3/3 passed

---

## **Step 4: OmniCLI Internal Deadline (3 hrs)**

### **Target File**: `/home/phantomcore/tools/omnicli/omnicli/orchestrate.py`

### **Implementation Plan**:
1. Add `timeout` parameter to `run_orchestration()`
2. Use `asyncio.wait_for()` with timeout
3. Raise `BackendError` on timeout (consistent with Oracle's `BackendError`)
4. Ensure daemon worker cleanup on timeout

### **Verification Criteria** (Subagent will test):
- [ ] `run_orchestration()` accepts `timeout` parameter
- [ ] Timeout enforced (test: 5s sleep with 0.2s timeout → fails fast)
- [ ] Timeout=0.0 refuses dispatch
- [ ] Normal completion passes
- [ ] Falsy-zero bug fixed (timeout=0.0 → refuses, not infinite)

---

## **Step 5: Tactic Coverage Enforcement (1 hr)**

### **Target File**: `/home/phantomcore/oracle/oracle_hunter.py`

### **Implementation Plan**:
1. Rename `_raise_on_tactic_drops_no_cloud()` → `_raise_on_tactic_drops()`
2. Remove `no_cloud` condition
3. Add CLI flag `--allow-incomplete-tactics` to opt out
4. Apply to all modes (cloud + local)

### **Verification Criteria** (Subagent will test):
- [ ] Function raises on tactic drop in cloud mode by default
- [ ] `--allow-incomplete-tactics` suppresses error
- [ ] Local mode still enforces
- [ ] Clear error message listing dropped tactics

---

## **Step 6: Scan4Me Rate Limiting (2 hrs)**

### **Target File**: `/home/phantomcore/Scan4Me/scan4me.py`

### **Target Functions**:
- `_fetch_h1_authenticated()`
- `_fetch_bugcrowd_authenticated()`
- `_fetch_intigriti_authenticated()`
- `_fetch_yeswehack_authenticated()`

### **Implementation Plan**:
1. Add `delay` parameter to each fetcher (default 1.0s)
2. Add `--auth-delay` CLI flag
4. `time.sleep(delay)` between paginated requests

### **Verification Criteria** (Subagent will test):
- [ ] Each fetcher respects delay parameter
- [ ] `--auth-delay` CLI flag works
- [ ] Default delay = 1.0s
- [ ] No functional regression on sync

---

## **Step 7: Fiduciary Diode Documentation (1 hr)**

### **Target File**: `/home/phantomcore/oracle/oracle_hunter.py` → `cmd_hunt()`

### **Implementation Plan**:
Add explicit comments in `cmd_hunt()` around scope gate + verify ladder:

```python
# FIDUCIARY DIODE: Structural separation of truth-finding from reward
# Scope gate reads program.json + structured_scopes → determines what's in scope
# Verify ladder evaluates evidence → CONFIRMED/REJECTED
# NO bounty data, NO payout data, NO reward signal enters either path
# This is structural, not policy: the code paths literally cannot access reward data
```

### **Verification Criteria** (Subagent will test):
- [ ] Comments present in `cmd_hunt()`
- [ ] Scope gate code path verified no reward data access
- [ ] Verify ladder code path verified no reward data access

---

## **Step 8: Outcome Engineering Spec (2 hrs)**

### **Target File**: `/home/phantomcore/oracle/oracle_foundation.py` → `teardown_poc()`

### **Implementation Plan**:
Modify `teardown_poc()` return value to include structured outcome spec:

```python
def teardown_poc(...) -> Dict:
    # ... existing teardown logic ...
    
    return {
        # ... existing fields ...
        "outcome_spec": {
            "result": "Every claim cites a primary source",
            "limits": {
                "public_sources_only": True,
                "read_only_access": True,
                "token_budget": 50000,
                "max_iterations": 10,
                "no_progression_detection": True,
            },
            "tie_breaker": "verification_wins_over_completeness",
            "check": {
                "verifier_agent": "separate_read_only_agent",
                "passing_bar": "3 independent channels + 2 independent sources",
                "human_review": "flagged_edge_cases_only",
            },
            "proof_packet": generate_proof_packet(...),
        }
}
```

### **Verification Criteria** (Subagent will test):
- [ ] `teardown_poc()` returns `outcome_spec` with all 4 parts
- [ ] Structure matches Outcome Engineering spec (RESULT/LIMITS/TIE-BREAKER/CHECK)
- [ ] Proof packet included
- [ ] All existing tests pass

---

## **Step 9: Mutation Triggers Integration (2 hrs)**

### **Target Files**: 
- `/home/phantomcore/oracle/oracle_foundation.py` (seam card)
- `/home/phantomcore/oracle/oracle_hunter.py` (program_changes handling)

### **Implementation Plan**:
1. Add mutation triggers to seam card (from Step 3)
2. In `cmd_hunt()`, after loading `program_changes`:
   ```python
   for change in program_changes:
       if change.change_type in MUTATION_TRIGGER_MAP:
           for seam in affected_seams(change):
               seam.mutation_triggered = True
               seam.last_triggered = change.detected_at
   ```
3. Ensure `inject_pending_seams()` respects `mutation_triggered` flag

### **Verification Criteria** (Subagent will test):
- [ ] `program_changes` triggers mutation flags on seam cards
- [ ] `inject_pending_seams()` filters mutation-triggered seams
- [ ] All mutation types handled: firmware, price, sentiment, time, contradictory
- [ ] All existing tests pass

---

## **Step 10: Full Regression Suite (5 min)**

```bash
cd /home/phantomcore/oracle && python3 tests/run_all.py
cd /home/phantomcore/Scan4Me && python3 -m pytest tests/test_scan4me.py -k "handoff" -v
```

---

## **Subagent Verification Protocol**

For each step, I'll spawn a subagent with this prompt template:

```
You are a verification agent. Your job is to verify that [STEP NAME] was implemented correctly.

TARGET: [FILE/FUNCTION]
EXPECTED BEHAVIOR: [CRITERIA FROM ABOVE]

Run the relevant tests and manual verification. Report:
1. PASS/FAIL for each criterion
2. Any regressions found
3. Any new issues introduced
4. Screenshots/logs of test output

Be ruthless. If anything fails, report FAIL immediately.
```

---

## **Execution Log**

| Step | Status | Started | Completed | Verified By | Notes |
|------|--------|---------|-----------|-------------|-------|
| 1. Corpus + TTP | ✅ DONE | - | - | - | Already complete |
| 2. Proof Packet | ⏳ PENDING | - | - | - | Next |
| 3. Decay/Mutation | ⏳ PENDING | - | - | - | - |
| 4. OmniCLI Deadline | ⏳ PENDING | - | - | - | - |
| 5. Tactic Coverage | ⏳ PENDING | - | - | - | - |
| 6. Scan4Me Rate Limit | ⏳ PENDING | - | - | - | - |
| 8. Fiduciary Diode | ⏳ PENDING | - | - | - | - |
| 9. Outcome Engineering | ⏳ PENDING | - | - | - | - |
| 10. Mutation Triggers | ⏳ PENDING | - | - | - | - |
| 10. Full Regression | ⏳ PENDING | - | - | - | - |

---

## **Rollback Plan**

If any step breaks existing functionality:
1. `git stash` or `git checkout -- <file>`
2. Re-run full test suite
3. Debug in isolation
4. Re-apply fix with smaller increments

---

*Plan Version: 1.0 | Created: 2026-10-22 | Next Action: Step 2 - Proof Packet Generation*