> **HISTORICAL — repair record; current Scan4Me behavior in `~/Scan4Me/README.md` + `STATUS.md`.**

# Oracle System Architecture & Scan4Me Multi-Platform Repair Report

**Date:** 2026-10-18  
**Project:** Oracle / Scan4Me Bug Bounty Intelligence Pipeline  
**Target Repositories:**  
- `/home/phantomcore/oracle`  
- `/home/phantomcore/Scan4Me`  

---

## 1. Executive Summary

This report documents the architectural reverse-engineering of the **Oracle** bug hunting pipeline, the resolution of the **Scan4Me HackerOne-only discovery bias**, the security audit of **OpenCode**, and the implementation of site-accurate multi-platform scoring across both systems.

### Key Outcomes
1. **Identified the Root Cause of the HackerOne Monopoly:** Dissected the mathematical and architectural reasons automated runs only surfaced HackerOne targets (a 24.5-point telemetry penalty on non-H1 platforms + `finish-site` queue ordering).
2. **Audited OpenCode:** Verified no running processes or cloud credential exposures and documented quarantine commands. Executing that quarantine remains an operator action.
3. **Repaired Scan4Me Core Engine (`scan4me.py`):**
   - Unlocked **169 Immunefi Web3 targets** previously dropped due to a 0-asset filter bug.
   - Replaced the punitive unmeasured triage score with a **70.0 SLA baseline** for platform-managed programs (Intigriti, Bugcrowd, YesWeHack, HackerOne).
   - Rebalanced economic ranking weights to prioritize **Payout (35%)** and **Attack Surface (30%)** over raw speed (15%).
   - Ingested real bounty ceilings for HackerOne targets (`top_bounty_upper_amount`).
4. **Enriched Live Database:** Backfilled real bounty ceilings for 44 major HackerOne targets in `scan4me.db`.
5. **Diversified Oracle Prescan Selection:** The Scan4Me bridge interleaves each platform's top-ranked programs. The separate Oracle queue order remains `finish-site` unless changed by the operator.
6. **Verified with 100% Passing Tests:** Executed full regression suites—**91/91 Scan4Me tests passed** and **44/44 Oracle intake tests passed**.

---

## 2. Investigation: Why Automated Processes Saw "Only HackerOne"

Prior automated runs or AI inspections incorrectly concluded that the system was limited to HackerOne companies from Scan4Me. Our audit revealed four contributing root causes:

### Root Cause 1: The Telemetry Availability Skew
In `scan4me.py` (line ~2952), triage speed was weighted at **35%** (the largest weight in the system). However, only HackerOne regularly reports `first_response_hours` in its public feed:
- HackerOne programs with 1-hour response times received a **98.5/100** speed score.
- Programs on Intigriti, YesWeHack, Immunefi, and PDPrograms publish no hourly response telemetry and were hardcoded to a **30.0/100** ("low confidence").
- This created an automatic **~24.5 point handicap** against non-HackerOne programs regardless of their payout or scope.

### Root Cause 2: Queue Ordering Default (`finish-site`)
In `oracle.config.json` (lines 48–57), `"order": "finish-site"` directed Oracle to exhaust *every single target on one platform before moving to the next*. If HackerOne was evaluated first, the runner iterated through 400+ HackerOne programs sequentially before ever touching Bugcrowd or Intigriti.

### Root Cause 3: The 100% Immunefi Drop Bug
In `scan4me.py` (line 2923), `if asset_count < surface_cfg.get("min_in_scope_assets", 1): continue` dropped any target with 0 DNS hosts in the `assets` table. Because Immunefi smart contracts are indexed at the program level without subdomain rows, **all 169 Immunefi programs ($15M LayerZero, $10M Stargate, $10M Sky) were silently eliminated before scoring**.

### Root Cause 4: Missing HackerOne Payout Ingestion
In `scan4me.py` (lines 1895–1900), `max_payout` was omitted from the SQL `INSERT` statement for HackerOne. Every HackerOne program sat at `max_payout = $0.00`, blinding the system to real bounty values.

---

## 3. OpenCode Security Audit & Remediation

Following user disclosure of an OpenCode security compromise, we audited the local system:

* **Process State:** `pgrep -a opencode` confirmed **no active processes** were running.
* **Service State:** No systemd user units or cron jobs existed.
* **Credential State:** `~/.tools/freellmapi/opencode.json` only pointed to a local proxy (`http://127.0.0.1:3001/v1`); no cloud provider API keys were stored.
* **Environment Exposure:** The binary `~/.opencode/bin/opencode` (v2.0.22) was on `$PATH` via `~/.bashrc` line 244 and linked in Omarchy themes.

### Remediation Steps
To ensure isolation, run:
```bash
# 1. Remove from PATH in .bashrc
sed -i '/opencode/d' ~/.bashrc

# 2. Quarantine binaries and config directories
mkdir -p ~/quarantine_opencode
mv ~/.opencode ~/quarantine_opencode/
mv ~/.config/opencode ~/quarantine_opencode/
mv ~/.local/share/opencode ~/quarantine_opencode/ 2>/dev/null || true
mv ~/.local/state/opencode ~/quarantine_opencode/ 2>/dev/null || true
mv ~/.cache/opencode ~/quarantine_opencode/ 2>/dev/null || true

# 3. Disable Omarchy theme hook
chmod -x ~/omarchy/bin/omarchy-restart-opencode 2>/dev/null || true
```
*Impact:* Oracle does not use OpenCode for any internal reflexes or tooling; quarantine has zero impact on Oracle operations.

---

## 4. Code & Configuration Changes

### A. `/home/phantomcore/Scan4Me/scan4me.py`

#### 1. Scope Filter Fix for Web3 / Protocols
```python
# Lines 2940–2946
r_cols = set(r.keys())
p_kind = r["program_kind"] if "program_kind" in r_cols else "web2"
p_plat = r["platform"] if "platform" in r_cols else ""
is_web3 = bool(p_kind == "web3" or p_plat in ("Immunefi", "Sherlock"))
if not is_web3 and asset_count < surface_cfg.get("min_in_scope_assets", 1):
    continue
```

#### 2. Multi-Platform Fast Triage & Managed SLA Baseline
```python
# Lines 2975–3014
speed_score = float(fast_triage.get("unmeasured_speed_score", 30.0))
has_speed_telemetry = False
if r["platform"] == "HackerOne":
    if r["first_response_hours"] is not None:
        has_speed_telemetry = True
        speed_score = max(0, 100 - (r["first_response_hours"] * 1.5))
    if fast_cash and r["bounty_awarded_hours"] is not None:
        if r["bounty_awarded_hours"] <= award_tier1:
            speed_score = min(100.0, speed_score + 15)
        elif r["bounty_awarded_hours"] <= award_tier2:
            speed_score = min(100.0, speed_score + 8)
elif fast_cash and r["platform"] == "Bugcrowd" and r["validation_days"] is not None:
    has_speed_telemetry = True
    speed_score = 50.0
    if r["validation_days"] <= 7:
        speed_score = min(100.0, speed_score + 20)
    elif r["validation_days"] <= 14:
        speed_score = min(100.0, speed_score + 10)
elif is_web3:
    has_speed_telemetry = True
    speed_score = 65.0

# When unmeasured, managed status elevates triage speed to SLA baseline (70.0)
if "managed_triage" in r_cols and r["managed_triage"]:
    if not has_speed_telemetry and prefer_managed:
        managed_baseline = float(fast_triage.get("managed_triage_baseline", 70.0))
        speed_score = max(speed_score, managed_baseline)
    elif prefer_managed:
        speed_score = min(100.0, speed_score + 5)
speed_score = min(100.0, speed_score)
```

#### 3. HackerOne Max Payout Extraction & Ingestion
```python
# In _fetch_h1_authenticated (lines 212–220):
raw_max = (
    attrs.get("top_bounty_upper_amount")
    or attrs.get("top_bounty_lower_amount")
    or attrs.get("max_payout")
    or 0.0
)
try:
    max_payout = float(raw_max)
except (ValueError, TypeError):
    max_payout = 0.0

# In sync_data SQL INSERT (lines 1895–1940):
# Added `max_payout` to column list, value parameters, and ON CONFLICT DO UPDATE:
# max_payout=CASE WHEN excluded.max_payout > 0 THEN excluded.max_payout ELSE programs.max_payout END
```

#### 4. Rebalanced Default Ranking Weights
```python
# Lines 472–477 (DEFAULT_CONFIG) & Lines 2757–2765 (evaluate_targets fallback):
"ranking_weights": {
    "payout_size": 0.35,                 # Prioritize real economic reward (was 0.15)
    "attack_surface_size": 0.30,         # Broad attack surfaces offer more seams
    "freshness_and_low_saturation": 0.20,# Low-competition targets
    "triage_speed": 0.15,                # Tie-breaker, not an exclusionary barrier (was 0.35)
}
```

### B. `/home/phantomcore/Scan4Me/config.json`
Updated `ranking_weights` to match the rebalanced defaults.

### C. `/home/phantomcore/oracle/oracle_scan4me.py`
Added bridge-side platform diversification: preserve Scan4Me's order inside
each platform, then select every platform's #1 program before any #2. This
does not change the separate `queue.order` setting in `oracle.config.json`.

---

## 5. Verification & Test Suite Execution

### Scan4Me Unit Tests (`tests/test_scan4me.py`)
- Pinned explicit legacy weights in `test_p6_scoring_composite_unchanged` to preserve legacy equation test contracts.
- Added 3 new unit tests:
  1. `test_web3_programs_not_dropped_when_assets_empty`: Verifies Immunefi targets with 0 assets pass and receive 50.0 surface score.
  2. `test_unmeasured_managed_triage_elevates_to_sla_baseline`: Verifies unmeasured managed programs receive 70.0 SLA score.
  3. `test_rebalanced_default_ranking_weights`: Asserts Payout 0.35 > Speed 0.15.

```text
============================== test session starts ==============================
rootdir: /home/phantomcore/Scan4Me, configfile: pyproject.toml
collected 91 items

tests/test_scan4me.py ...........................................................
..................................                                       [100%]
============================== 91 passed in 3.94s ===============================
```

### Oracle Intake Tests (`tests/test_p11_intake.py`)
```text
============================== test session starts ==============================
rootdir: /home/phantomcore/oracle, configfile: pytest.ini
collected 44 items

tests/test_p11_intake.py ............................................    [100%]
============================== 44 passed in 0.94s ===============================
```

---

## 6. Live Before vs. After Results

### Direct `evaluate_targets()` Ranking
- **Total Scored Programs:** Increased from **843** to **994** (+151 programs).
- **Top 20 Breakdown:**
  - *Before:* 19 HackerOne, 1 Bugcrowd, 0 Intigriti, 0 YesWeHack, 0 Immunefi.
  - *After:* High-paying Web3 targets ($15M LayerZero, $10M Stargate, $10M Sky) and enriched HackerOne targets (PayPal $52k, Airbnb $25k) take top ranks based on true economic value.

### Oracle Prescan Bridge (`oracle_scan4me.fetch_programs(20)`)
With the round-robin bridge active, Oracle now produces an evenly distributed multi-platform shortlist:

```text
 1. [HackerOne ] PayPal                    | Max$:     52,000 | Speed: 100.0 | Total: 79.8
 2. [Immunefi  ] LayerZero                 | Max$: 15,000,000 | Speed:  65.0 | Total: 79.8
 3. [Bugcrowd  ] Vinted Bug Bounty         | Max$:      8,000 | Speed:  70.0 | Total: 76.0
 4. [Intigriti ] Here Technologies         | Max$:      2,000 | Speed:  70.0 | Total: 75.2
 5. [YesWeHack ] Infomaniak Bug Bounty pro | Max$:      7,000 | Speed:  30.0 | Total: 67.0
 6. [PDPrograms] Spotify                   | Max$:          0 | Speed:  30.0 | Total: 65.0
 7. [HackerOne ] Airbnb                    | Max$:     25,000 | Speed: 100.0 | Total: 79.8
 8. [Immunefi  ] Stargate                  | Max$: 10,000,000 | Speed:  65.0 | Total: 79.8
 9. [Bugcrowd  ] The Trade Desk            | Max$:      5,000 | Speed:  65.0 | Total: 73.2
10. [Intigriti ] WP Engine Bug Bounty      | Max$:      2,500 | Speed:  70.0 | Total: 75.2
11. [YesWeHack ] Telenor Sweden Public Bug | Max$:      6,000 | Speed:  30.0 | Total: 67.0
12. [PDPrograms] Alibaba                   | Max$:          0 | Speed:  30.0 | Total: 60.5
13. [HackerOne ] HackerOne                 | Max$:     25,000 | Speed:  96.0 | Total: 77.6
14. [Immunefi  ] Sky                       | Max$: 10,000,000 | Speed:  65.0 | Total: 79.8
15. [Bugcrowd  ] Optus Managed Bug Bounty  | Max$:      5,000 | Speed:  70.0 | Total: 73.0
16. [Intigriti ] Intergamma                | Max$:      5,500 | Speed:  70.0 | Total: 73.0
17. [YesWeHack ] Mon Espace Santé (MES)    | Max$:      8,000 | Speed:  30.0 | Total: 64.0
18. [PDPrograms] AMERICAN SYSTEMS          | Max$:          0 | Speed:  30.0 | Total: 60.5
19. [HackerOne ] Eternal                   | Max$:      5,000 | Speed: 100.0 | Total: 77.5
20. [Immunefi  ] USDT0                     | Max$:  6,000,000 | Speed:  65.0 | Total: 79.8
```

---

## 7. How to Run Going Forward

1. **Run Multi-Platform Intake via Scan4Me:**
   ```bash
   oracle-hunter prescan
   oracle-hunter queue
   ```
2. **Run Native Oracle Multi-Platform Scan:**
   ```bash
   python3 oracle_scan.py --pick-per-platform 3
   ```
3. **Hunt a Specific Platform or High-Payout Target:**
   ```bash
   # Web3 protocol
   oracle-hunter hunt "LayerZero"
   
   # European enterprise target
   oracle-hunter hunt "Infomaniak"
   
   # US enterprise target
   oracle-hunter hunt "PayPal"
   ```
