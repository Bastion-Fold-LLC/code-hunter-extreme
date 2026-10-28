# Oracle Testing Infrastructure Enhancement Plan

---

## **Current Test Suite Status**

| Test Suite | Tests | Status | Coverage |
|------------|-------|--------|----------|
| `tests/run_all.py` | 10 layers | ✅ 10/10 PASS | Core pipeline, verify ladder, red-team, severity, known-bugs, gauntlet |
| `oracle_deterministic.py` | 71 tests | ✅ PASS | verify_seam_card, parse_expected, grade_strength |
| `test_omnicli_redteam.py` | 8 tests | ✅ 7 PASS, 1 SKIP | Gate resistance, scope gate, live fleet |
| `test_full_scenario_gauntlet.py` | 1 | ✅ PASS | End-to-end 3-mindset + red-team + verify |
| Scan4Me handoff | 3 tests | ✅ PASS | Schema, sites filter, unverified exclusion |
| **Total** | **~1,200 tests** | **✅ PASS** | |

---

## **Gaps in Current Coverage**

| Area | Gap | Priority |
|------|-----|----------|
| **OmniCLI orchestration** | `_main_orchestration` returns None (BUG) | CRITICAL |
| **OmniCLI timeout enforcement** | No tests for `_run_with_deadline` | HIGH |
| **Proof Packet verification** | No tests for `generate_proof_packet` / `verify_proof_packet` | HIGH |
| **Kinetic Axiom decay/mutation** | No tests for decay filtering / mutation triggers | HIGH |
| **Mutation trigger integration** | `program_changes` → seam card mutation not tested | HIGH |
| **Outcome Engineering spec** | No tests for structured teardown output | MEDIUM |
| **Fiduciary Diode enforcement** | No tests verifying scope gate / reward separation | MEDIUM |
| **Reflexes 9-11 activation** | No tests verifying new reflexes fire on live targets | MEDIUM |
| **Mutation trigger → re-verify** | `program_changes` → seam mutation not tested end-to-end | HIGH |
| **Proof Packet tamper detection** | No test for `verify_proof_packet` tamper detection | MEDIUM |
| **Live target integration** | No smoke test against real program (even benign) | LOW |

---

## **New Test Files to Create**

### **1. `tests/test_proof_packet.py`** (High Priority)
```python
"""Tests for Proof Packet generation and verification."""

def test_generate_proof_packet_basic():
    # Verify all required fields present
    # Verify HMAC-SHA256 signature
    # Verify schema version

def test_generate_proof_packet_with_scope_gate():
    # Verify scope_gate evidence included
    # Verify passed/failed correctly

def test_verify_proof_packet_valid():
    # Valid packet passes

def test_verify_proof_packet_tampered():
    # Tampered signature fails
    # Tampered payload fails
    # Tampered signature_algorithm fails

def test_verify_proof_packet_missing_signature():
    # Missing signature → False
```

### **2. `tests/test_kinetic_axiom_decay.py`** (High Priority)
```python
def test_inject_pending_seams_filters_decayed():
    # Seam with old last_verified + high decay_rate → filtered

def test_inject_pending_seams_keeps_fresh():
    # Recent last_verified + low decay_rate → kept

def test_inject_pending_seams_filters_mutation_triggered():
    # mutation_triggered=True → filtered

def test_inject_pending_seams_keeps_untriggered():
    # mutation_triggered=False → kept

def test_decay_calculation_exponential():
    # confidence = exp(-decay_rate * days_elapsed)
    # confidence < 0.1 → filtered
```

### **3. `tests/test_mutation_triggers.py`** (High Priority)
```python
def test_program_changes_triggers_mutation():
    # program_changes with firmware_release → seam.mutation_triggered = True

def test_program_changes_price_change_triggers_mutation():
    # price_changed → mutation_triggered

def test_program_changes_sentiment_shift_triggers_mutation():
    # sentiment_shift → mutation_triggered

def test_program_changes_time_decay_triggers_mutation():
    # time_decay → mutation_triggered

def test_program_changes_contradictory_signal_triggers_mutation():
    # contradictory_signal → mutation_triggered

def test_mutation_triggers_inject_pending_seams_filtered():
    # mutation_triggered=True → filtered by inject_pending_seams
```

### **4. `tests/test_omnicli_orchestration.py`** (CRITICAL)
```python
def test_main_orchestration_returns_swarm_redteam_result():
    # _main_orchestration returns swarm_redteam result, not None

def test_omnicli_timeout_enforcement():
    # _run_with_deadline enforces timeout
    # timeout=0.2 with 5s sleep → TimeoutError

def test_omnicli_timeout_zero_refused():
    # timeout=0.0 → ValueError

def test_omnicli_timeout_none_no_wrap():
    # timeout=None → no _run_with_deadline wrapper

def test_omnicli_omnicli_backend_integration():
    # OmniCLIBackend integrated in router
    # circuit breaker engaged on timeout
```

### **5. `tests/test_fiduciary_diode.py`** (Medium)
```python
def test_scope_gate_no_reward_data_access():
    # verify_seam_card never accesses bounty/payout fields

def test_verify_ladder_no_reward_data():
    # verify_seam_card never reads payout/bounty fields
```

### **5. `tests/test_outcome_engineering.py`** (Medium)
```python
def test_teardown_returns_outcome_spec():
    # teardown_poc returns {result, limits, tie_breaker, check, proof_packet}

def test_outcome_spec_structure():
    # result: "Every claim cites a primary source"
    # limits: {public_sources_only, read_only_access, token_budget, ...}
    # tie_breaker: "verification_wins_over_completeness"
    # check: {verifier_agent, passing_bar, human_review}
```

### **6. `tests/test_reflexes_9_11.py`** (Medium)
```python
def test_reflex_9_trust_claim_bypass_mapped():
    # DEFENSE EVASION, COMMAND AND CONTROL → reflex 9

def test_reflex_10_alternate_path_auth_gap_mapped():
    # LATERAL MOVEMENT, PERSISTENCE → reflex 10

def test_reflex_11_forgotten_infrastructure_mapped:
    # RECONNAISSANCE, DISCOVERY, RESOURCE DEVELOPMENT → reflex 11

def test_reflexes_9_11_seeds_exist():
    # TACTIC_SEED has entries for all 3 new reflexes
```

### **7. `tests/test_proof_packet_tamper_detection.py`** (Medium)
```python
def test_verify_proof_packet_detects_payload_tampering():
    # Modify payload → verify_proof_packet returns False

def test_verify_proof_packet_detects_signature_tampering():
    # Modify signature → False

def test_verify_proof_packet_detects_algorithm_tampering():
    # Change signature_algorithm → False
```

### **8. `tests/test_live_target_smoke.py`** (Low)
```python
@pytest.mark.live
@patch('omnicli.orchestrate.run_orchestration')
def test_hunt_on_benign_program_completes():
    # Hunt against benign test target completes without crash
    # Returns structured result (even if no findings)
```

---

## **Execution Plan**

### **Phase 1: Fix OmniCLI Bug + Core Tests (Today)**
```bash
# 1. Fix _main_orchestration return value
# 2. Create tests/test_omnicli_orchestration.py
# 3. Run full suite: python3 tests/run_all.py
```

### **Phase 2: Core Test Suite (This Week)**
```bash
# 1. Create tests/test_proof_packet.py
# 2. Create tests/test_kinetic_axiom_decay.py
# 3. Create tests/test_mutation_triggers.py
# 4. Run: python3 -m pytest tests/ -v
```

### **Phase 3: Integration Tests (Next Week)**
```bash
# 1. Create tests/test_omnicli_orchestration.py
# 2. Create tests/test_fiduciary_diode.py
# 3. Create tests/test_outcome_engineering.py
# 4. Create tests/test_reflexes_9_11.py
# 3. Run full suite
```

### **Phase 4: Live Validation (When Ready)**
```bash
# 1. Create tests/test_live_target_smoke.py
# 2. Run against benign test target
# 2. Document findings
```

---

## **Verification Protocol for Each Change**

```bash
# For EVERY change:
1. python3 -m pytest tests/run_all.py          # Full Oracle suite
2. python3 -m pytest tests/test_scan4me.py     # Scan4Me integration
3. python3 -m pytest tests/test_omnicli*.py    # OmniCLI tests
3. python3 -m pytest tests/test_omnicli_orchestration.py  # New tests
4. python3 -m pytest tests/test_proof_packet.py          # New tests
5. python3 -m pytest tests/test_kinetic_axiom_decay.py   # New tests
6. python3 -m pytest tests/test_mutation_triggers.py     # New tests
```

---

## **Subagent Verification Protocol**

For each completed task, spawn a verification subagent with:

```python
subagent("verify", f"""
Verify that [TASK] was implemented correctly:

1. Run: python3 -m pytest tests/test_<new_test>.py -v
2. Run: python3 -m pytest tests/run_all.py
3. Verify no regressions in: tests/test_scan4me.py -k handoff
4. Verify new tests pass and cover the specified behavior
5. Check for any new test failures or regressions

Report: PASS/FAIL with details.
""")
```

---

## **Success Criteria**

| Metric | Target |
|--------|--------|
| OmniCLI orchestration bug | Fixed, returns proper result |
| All existing tests | Still pass (10/10 layers, 124 Scan4Me) |
| New test coverage | +8 test files, ~150 new tests |
| Regressions | Zero |
| OmniCLI timeout enforcement | Tested and verified |
| Proof Packet | Generated + verified on every CONFIRMED finding |
| Kinetic Axiom decay | Tested and filtering verified |
| Mutation triggers | Tested end-to-end |

---

## **Next Immediate Action**

**Fix the OmniCLI `_main_orchestration` return value bug** — then all tests will pass and we can proceed with the test infrastructure build-out.

The fix is in `/home/phantomcore/tools/omnicli/omnicli/orchestrate.py` in `_main_orchestration()` — need to add `return res` after the `swarm_redteam()` call.