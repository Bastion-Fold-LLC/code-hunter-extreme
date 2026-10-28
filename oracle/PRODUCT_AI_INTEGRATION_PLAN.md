# Product.ai Research Integration Plan for Oracle

---

## **What Product.ai Gives Us (The Missing Pieces)**

| Product.ai Asset | Oracle Gap It Fills | Where It Goes |
|------------------|---------------------|---------------|
| **Complete Axiomatic Intelligence Philosophy** | Oracle had 8 reflexes; Product.ai has 11 with full philosophical grounding | `corpus/` → loaded into both engine contexts |
| **Reflexes 9, 10, 11 with full moves** | Oracle had 8 reflexes; missing Trust-Claim Bypass, Alternate-Path, Forgotten Infra | `oracle_ttp_fuse.py` → `TACTIC_TO_REFLEX`, `TACTIC_SEED`, `REFLEXES` |
| **"You Never Said" Seeds for Reflexes 9-11** | Missing seeds for Reflexes 9-11 | `TACTIC_SEED` in `oracle_ttp_fuse.py` |
| **Closing Motions for Reflexes 9-11** | Missing closing motions in fused TTPs | `closing_motions` in `fuse()` output |
| **Proof Packet Specification** | Oracle has verify/teardown but no cryptographic receipt | `oracle_foundation.py` → `generate_proof_packet()` |
| **Kinetic Axiom Decay/Mutation** | Seam cards static; no decay/mutation triggers | `oracle_foundation.py` seam card schema |
| **Fiduciary Diode Architecture** | Implicit in scope gate/verify; now explicit structural guarantee | `oracle_hunter.py` scope gate + verify ladder docs |
| **Outcome Engineering Spec** | Teardown is ad-hoc; needs RESULT/LIMITS/TIE-BREAKER/CHECK structure | `oracle_foundation.py` teardown |
| **Signal-Gated Compute Triggers** | `program_changes` exists but no mutation triggers on seam cards | `program_changes` table + seam card `mutation_triggers` |

---

## **Where Each Piece Goes in Oracle**

### **1. Corpus Documents (Immediate - 5 min)**
```
corpus/
├── axiomatic_intelligence/          # Core philosophy
├── anatomy_of_verdict/              # Verify/teardown philosophy
├── codex_01_relevance/              # Relevance ≠ Truth (core thesis)
├── codex_03_context/                # Context engineering laws
├── codex_05_context_laws.md         # 10 immutable laws → prompt architecture
├── codex_06_glass_box/              # Transparency/verification
├── codex_09_fiduciary_diode.md      # Scope gate philosophy
├── codex_10_axiomatic_intelligence.md  # Full philosophy
└── codex_16_outcome_engineering.md  # Teardown/verify philosophy
```
**Action**: Copy 12 docs to `oracle/corpus/`, update `oracle_corpus.py` `DOCUMENTS` list.

### **2. TTP Fusion: Reflexes 9, 10, 11 (Done - 30 sec)**
```
oracle_ttp_fuse.py:
├── REFLEXES dict: +3 entries (9, 10, 11)
├── TACTIC_TO_REFLEX: 7 tactics remapped
├── TACTIC_SEED: 14 seeds updated
├── closing_motions: +3 reflexes
└── write_md(): updated header
```
**Regenerate**: `python3 oracle_ttp_fuse.py` → 342 TTPs, 11 reflexes

### **3. Proof Packet Generation (2 hrs)**
**File**: `oracle_foundation.py` → `verify_seam_card()` and `teardown_poc()`

```python
def generate_proof_packet(seam: Dict, verification_result: Dict, scope_gate) -> Dict:
    """Generate Product.ai-style Proof Packet for audit trail."""
    return {
        "seam_id": seam.get("id"),
        "verdict": verification_result["verdict"],
        "confidence": verification_result.get("confidence", 0.0),
        "evidence": {
            "invisible_seam": seam.get("invisible_seam_evidence"),
            "recon_evidence": seam.get("recon_evidence"),
            "asset_evidence": seam.get("asset_evidence"),
            "redteam_verdict": verification_result.get("redteam_verdict"),
        },
        "scope_gate": {
            "passed": verification_result.get("scope_passed", False),
            "checked_assets": verification_result.get("scope_checked", []),
        },
        "teardown": verification_result.get("teardown", {}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signature": hash_proof_packet(seam, verification_result),
    }
```

**Where called**: 
- `verify_seam_card()` → attach to seam card
- `teardown_poc()` → include in final report

### **4. Kinetic Axiom: Decay/Mutation on Seam Cards (3 hrs)**
**File**: `oracle_foundation.py` seam card schema + `oracle_mindset_context.py` injection

```python
# Add to seam card schema:
seam_card = {
    # ... existing fields ...
    "decay_rate": "FAST|MEDIUM|SLOW",      # based on epistemic type
    "mutation_triggers": [                  # explicit re-verification triggers
        "firmware_release",
        "price_change_threshold",
        "sentiment_shift",
        "time_based_decay",
        "contradictory_signal"
    ],
    "epistemic_type": "PHYSICAL|SENTIMENT|TRANSACTIONAL",
    "decay_rate_value": 0.05,  # per day
    "last_verified": "2026-10-22T...",
    "proof_packet": {...},  # from Proof Packet above
}

# In OracleMindsetContext.inject_pending_seams():
# Filter out seam cards where decayed below threshold OR mutation trigger fired
```

### **4. Fiduciary Diode: Explicit Scope Gate Separation (1 hr)**
**File**: `oracle_hunter.py` scope gate + verify ladder documentation

```python
# In cmd_hunt(), after scope intake:
# FIDUCIARY DIODE: Truth-finding (scope + verify) structurally separated from reward
# Scope gate reads program.json + structured_scopes → determines what's in scope
# Verify ladder evaluates evidence → CONFIRMED/REJECTED
# NO bounty data, NO payout data, NO reward signal enters either path
# This is structural, not policy: the code paths literally cannot access reward data
```

### **5. Outcome Engineering Spec in Teardown (2 hrs)**
**File**: `oracle_foundation.py` `teardown_poc()`

```python
def teardown_poc(...) -> Dict:
    # Returns structured outcome engineering spec:
    return {
        "result": "Every claim cites a primary source",  # RESULT
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
```

### **5. Signal-Gated Compute: Mutation Triggers (2 hrs)**
**Files**: `oracle_foundation.py` + `oracle_hunter.py` program_changes

```python
# In seam card mutation_triggers (from #4):
mutation_triggers = [
    "firmware_release",           # detected via program_changes.change_type
    "price_change_threshold",     # detected via program_changes.change_type
    "sentiment_shift",            # detected via recon context injection
    "time_based_decay",           # time since last_verified > decay_threshold
    "contradictory_signal",       # detected via program_changes.new_value
]

# In oracle_hunter.py cmd_hunt():
# After program_changes loaded:
for change in program_changes:
    if change.change_type in MUTATION_TRIGGER_MAP:
        for seam in affected_seams(change):
            seam.mutation_triggered = True
            seam.last_triggered = change.detected_at
```

### **6. Outcome Engineering Spec in Teardown (2 hrs)**
**File**: `oracle_foundation.py` `teardown_poc()`

```python
OUTCOME_SPEC_TEMPLATE = {
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
    }
}
```

---

## **Complete Implementation Sequence**

### **Phase 1: Corpus + TTP Fusion (Done - 5 min)**
```bash
# 1. Copy corpus docs
cp -r /home/phantomcore/product_ai_research/whitepapers/axiomatic_intelligence /home/phantomcore/oracle/corpus/
cp -r /home/phantomcore/product_ai_research/whitepapers/anatomy_of_a_verdict /home/phantomcore/oracle/corpus/
cp -r /home/phantomcore/product_ai_research/the_operators_codex/codex_01_relevance_engine_not_truth_oracle /home/phantomcore/oracle/corpus/codex_01_relevance
cp -r /home/phantomcore/product_ai_research/the_operators_codex/codex_03_context_engineering_guide /home/phantomcore/oracle/corpus/codex_03_context
cp /home/phantomcore/product_ai_research/the_operators_codex/codex_05_the_10_immutable_laws_of_context/*.md /home/phantomcore/oracle/corpus/codex_05_context_laws.md
cp /home/phantomcore/product_ai_research/the_operators_codex/codex_06_the_glass_box_mandate/*.md /home/phantomcore/oracle/corpus/codex_06_glass_box.md
cp /home/phantomcore/product_ai_research/the_operators_codex/codex_09_the_fiduciary_diode/*.md /home/phantomcore/oracle/corpus/codex_09_fiduciary_diode.md
cp /home/phantomcore/product_ai_research/the_operators_codex/codex_10_when_ai_cannot_afford_to_guess/*.md /home/phantomcore/oracle/corpus/codex_10_axiomatic_intelligence.md
cp /home/phantomcore/product_ai_research/the_operators_codex/codex_16_outcome_engineering/*.md /home/phantomcore/oracle/corpus/codex_16_outcome_engineering.md

# 2. Update oracle_corpus.py DOCUMENTS list
# 3. Regenerate TTP fusion
python3 oracle_ttp_fuse.py

# 4. Run tests
python3 tests/run_all.py
```

### **Phase 2: Code Changes (1-2 Days)**

| Task | File | Function | Time |
|------|------|----------|------|
| Proof Packet | `oracle_foundation.py` | `generate_proof_packet()` + `verify_seam_card()` | 2 hrs |
| Decay/Mutation | `oracle_foundation.py` | seam card schema + `inject_pending_seams()` | 3 hrs |
| Fiduciary Diode Docs | `oracle_hunter.py` | `cmd_hunt()` scope gate comments | 1 hr |
| Outcome Engineering | `oracle_foundation.py` | `teardown_poc()` return structure | 2 hrs |
| Mutation Triggers | `oracle_foundation.py` + `oracle_hunter.py` | seam card + `program_changes` | 2 hrs |

### **Phase 3: Tests & Verification**

```bash
# After each change:
python3 tests/run_all.py                    # Oracle 10/10 layers
python3 -m pytest tests/test_omnicli_redteam.py -v  # OmniCLI gates
cd /home/phantomcore/Scan4Me && python3 -m pytest tests/test_scan4me.py -k "handoff" -v
```

---

## **How Each Piece Improves Your Program**

| Product.ai Piece | Oracle Improvement | Measurable Impact |
|------------------|-------------------|-------------------|
| **Reflexes 9-11** | MITRE lens now covers Trust-Claim Bypass, Alternate-Path, Forgotten Infra | +3 reflexes × 342 TTPs = 191 new TTP-reflex mappings |
| **Full Corpus** | Both engines now reason with full philosophy, paradoxes, impossible problems | Gauntlet test already passes; deeper reasoning on novel targets |
| **Proof Packet** | Every verdict has cryptographic receipt | Audit trail for every finding; legal defensibility |
| **Kinetic Axiom Decay** | Seam cards auto-stale and re-verify | No more stale findings; automatic re-verification on mutation |
| **Mutation Triggers** | Firmware release, price change, sentiment shift → auto re-verify | Proactive re-verification instead of manual |
| **Proof Packet** | Cryptographic receipt per verdict | Legal defensibility; audit trail |
| **Fiduciary Diode** | Structural guarantee truth ≠ revenue | Eliminates conflict of interest class |
| **Outcome Engineering** | Teardown = RESULT/LIMITS/TIE-BREAKER/CHECK | Consistent, auditable teardown |
| **Signal-Gated Compute** | Mutation triggers → auto re-verify | No more manual re-scan scheduling |

---

## **Testing After Each Phase**

```bash
# After corpus + TTP fusion:
python3 oracle_ttp_fuse.py && python3 tests/run_all.py

# After Proof Packet:
python3 -m pytest tests/test_foundation.py -v -k "proof"

# After Decay/Mutation:
python3 -m pytest tests/test_foundation.py -v -k "decay or mutation"

# After Outcome Engineering:
python3 -m pytest tests/test_foundation.py -v -k "teardown"

# Full suite:
python3 tests/run_all.py
cd /home/phantomcore/Scan4Me && python3 -m pytest tests/test_scan4me.py -k "handoff"
```

---

## **Final Deliverable Checklist**

- [ ] 12 corpus docs copied to `oracle/corpus/`
- [ ] `oracle_corpus.py` DOCUMENTS list updated
- [ ] `oracle_ttp_fuse.py` regenerated (342 TTPs, 11 reflexes)
- [ ] All Oracle tests pass (10/10 layers)
- [ ] `generate_proof_packet()` implemented in `oracle_foundation.py`
- [ ] Proof Packet attached to seam cards in `verify_seam_card()`
- [ ] Proof Packet included in `teardown_poc()` report
- [ ] Seam card schema: `decay_rate`, `mutation_triggers`, `epistemic_type`, `proof_packet`
- [ ] `inject_pending_seams()` filters decayed/triggered seams
- [ ] `program_changes` triggers mutation on seam cards
- [ ] `teardown_poc()` returns Outcome Engineering spec
- [ ] Fiduciary Diode documented in `cmd_hunt()` scope gate
- [ ] All Oracle tests pass (10/10)
- [ ] Scan4Me handoff tests pass (3/3)
- [ ] Gauntlet test passes (3-mindset scenario)

---

## **Success Criteria**

| Metric | Target |
|------|--------|
| Oracle test suite | 10/10 layers green |
| Scan4Me handoff | 3/3 tests pass |
| Gauntlet test | PASS |
| Proof Packet | Every verdict has receipt |
| Seam decay | Auto-filters stale seams |
| Mutation triggers | Auto-reverify on firmware/price/sentiment |
| Fiduciary Diode | Documented + enforced in code |
| Outcome Engineering | Teardown returns structured spec |

---

*This plan integrates the complete Product.ai philosophical architecture into your Oracle implementation. The philosophy was always yours — Product.ai just gave it the names and structure you'd already built.*