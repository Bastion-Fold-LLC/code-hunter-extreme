# Scan4Me Improvement Plan
**Goal**: Harden Scan4Me, add machine-readable handoff output for Oracle, preserve all filter/triage decisions as first-class fields.

---

## 1. Quick Fixes (30 min — Audit Follow-ups)

| # | Fix | File | Effort |
|---|-----|------|--------|
| Q1 | Replace bare `float()` with `_safe_non_negative_float` in authenticated fetchers (Bugcrowd, Intigriti, YesWeHack) + `_normalize_weights` | `scan4me.py` | 5 min |
| Q2 | Clean stale Federacy row (`okteto`) from DB | One-time SQL | 1 min |
| Q3 | Fix queue resume fingerprint — use stable `platform+handle` not position/wave | `oracle_queue.py` | 10 min |
| Q4 | Fix verify fast-path needle — sanitize names consistently at write + read | `oracle_hunter.py` | 15 min |

**Acceptance**: All 121 tests still pass; audit follow-ups resolved.

---

## 2. Machine-Readable Handoff Output (Oracle Pipe Format)

### 2.1 New CLI Command: `scan4me handoff`

```bash
# Produces a single JSON file Oracle can consume directly
python3 scan4me.py handoff \
  --prescan-file reports/prescan_<stamp>.json \
  --scan-file reports/scan_<stamp>.json \
  --output oracle_handoff.json \
  --format oracle.p12.handoff/v1
```

### 2.2 Handoff Schema (`oracle.p12.handoff/v1`)

```json
{
  "_schema": "oracle.p12.handoff/v1",
  "created_utc": "2026-10-22T00:00:00+00:00",
  "source": {
    "scan4me_version": "git-short-sha",
    "db_path": "scan4me.db",
    "sync_metadata": {
      "upstream_sha": "abc1234",
      "last_refresh_ok": true,
      "last_sync_ts": 1708435200,
      "platform_status": {
        "hackerone": {"status": "ok", "count": 449, "source": "authenticated"},
        "bugcrowd": {"status": "ok", "count": 298, "source": "public-file"},
        ...
      }
    }
  },
  "prescan_report": "reports/prescan_20261022_000000.json",
  "scan_report": "reports/scan_20261022_000000.json",
  "no_cloud": false,
  "selector": {"top_n": 5, "sites": null},
  "triage_config": {
    "source": "triage.yaml",
    "payout_floor_usd": 500,
    "fast_triage_enabled": true,
    "max_first_response_hours": 24,
    "min_response_efficiency_pct": 90,
    "min_in_scope_assets": 1,
    "wildcard_multiplier": 2.5,
    "prefer_new_assets": true,
    "new_asset_days": 30,
    "prefer_new_companies": true,
    "new_company_days": 90,
    "max_rewarded_vulnerabilities": 150,
    "ranking_weights": {
      "payout_size": 0.35,
      "attack_surface_size": 0.30,
      "freshness_and_low_saturation": 0.20,
      "triage_speed": 0.15
    }
  },
  "ranked_verified": [
    {
      "rank": 1,
      "name": "Shopify",
      "handle": "shopify",
      "platform": "HackerOne",
      "url": "https://hackerone.com/shopify",
      "score": 87.5,
      "max_payout_usd": 25000,
      "currency": "USD",
      "verdict": "verified",
      "checks": {
        "scope_live": {
          "passed": true,
          "live_hosts": 18,
          "total_scope_hosts": 23,
          "details": ["api.shopify.com [200]", "app.shopify.com [200]", "..."]
        },
        "payouts_match": {
          "passed": true,
          "platform_max_payout": 25000,
          "db_max_payout": 25000,
          "delta": 0
        },
        "rules_unchanged": {
          "passed": true,
          "prescan_rules_sha256": "abc...",
          "scan_rules_sha256": "abc..."
        }
      },
      "deep_dive": {
        "assets": [
          {"identifier": "api.shopify.com", "type": "url", "is_wildcard": false, "eligible_for_bounty": true, "eligible_for_submission": true, "instruction": "", "max_severity": "critical", "first_seen_ts": 1708000000},
          {"identifier": "*.shopify.com", "type": "wildcard", "is_wildcard": true, "eligible_for_bounty": true, "eligible_for_submission": true, "instruction": "", "max_severity": "", "first_seen_ts": 1708000000}
        ],
        "company": {
          "handle": "shopify",
          "name": "Shopify",
          "website": "https://shopify.com",
          "offers_bounties": true,
          "managed_program": true,
          "avg_first_response_hours": 12.5,
          "avg_bounty_awarded_hours": 72.0,
          "avg_report_resolved_hours": 168.0,
          "response_efficiency_pct": 95.0,
          "rewarded_vulnerabilities": 42,
          "validation_days": 7.0,
          "average_payout_usd": 1200.0,
          "program_kind": "web2",
          "official_start_ts": 1609459200,
          "official_scope_updated_ts": 1708000000
        },
        "resources": {
          "program_page_corroboration": "targets/HackerOne/shopify/program_page_corroboration.txt",
          "download_report": "targets/HackerOne/shopify/download_report.json",
          "scope_intake_status": "ok",
          "scope_intake_new": 3,
          "scope_intake_missing": 0
        },
        "sources": ["scan4me:programs+assets", "oracle:download+corroboration"]
      }
    }
  ],
  "excluded_named": [],
  "note": "unverified programs never appear here; see the scan report"
}
```

### 2.3 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Single file output** | Atomic, pipeable, versioned schema |
| **Full triage config embedded** | Oracle never guesses what filters ran; replayable |
| **Per-program `checks` object** | Each verification leg (scope_live, payouts_match, rules_unchanged) has pass/fail + evidence |
| **`deep_dive.assets` includes eligibility + first_seen** | Oracle inherits exact scope with provenance |
| **`deep_dive.company` = full program record** | All triage metrics (response time, payout history, rewarded vulns) available for Mindset 3 |
| **`resources` paths relative to Oracle root** | Oracle can locate corroboration files directly |
| **`excluded_named` array** | Explicit `--sites` overrides tracked |

---

## 3. Filter/Triage Fields Oracle Must Receive

Every field below **must** be present in the handoff so Oracle's `oracle_intake.py` can enforce doctrine without re-computing.

### 3.1 Hard Gates (Fail-Closed)

| Field | Source | Oracle Use |
|-------|--------|------------|
| `paid_bounties_only` | `triage.yaml` / config | Prescan filters non-bounty programs |
| `min_max_payout_usd` | `triage.yaml` / config | Prescan + scan payout gate |
| `min_in_scope_assets` | `triage.yaml` / config | Prescan + scan attack surface gate |
| `offers_bounties` (per program) | DB | Scan verification: program must offer bounties |

### 3.2 Scoring Weights (For Transparency)

| Field | Source | Oracle Use |
|-------|--------|------------|
| `ranking_weights` | `triage.yaml` / config (normalized) | Mindset 3 synthesis context |
| `wildcard_multiplier` | `triage.yaml` / config | Attack surface scoring context |

### 3.3 Triage Bonuses (Soft Signals)

| Field | Source | Oracle Use |
|-------|--------|------------|
| `fast_triage.enabled` | `triage.yaml` | Mindset 1: prioritize fast-response programs |
| `max_first_response_hours` | `triage.yaml` | Triage speed scoring |
| `min_response_efficiency_pct` | `triage.yaml` | Triage speed scoring |
| `prefer_new_assets` / `new_asset_days` | `triage.yaml` | Freshness scoring |
| `prefer_new_companies` / `new_company_days` | `triage.yaml` | Freshness scoring |
| `max_rewarded_vulnerabilities` | `triage.yaml` | Saturation penalty |
| `prefer_large_attack_surface` | `triage.yaml` | Attack surface scoring |
| `prioritize_wildcards` | `triage.yaml` | Attack surface scoring |
| `prioritize_fast_cash` | `triage.yaml` | Payout velocity scoring |

### 3.4 Per-Program Verification Evidence (From Scan)

| Field | Source | Oracle Use |
|-------|--------|------------|
| `checks.scope_live.passed` | Scan verify | Gate: only verified programs proceed |
| `checks.scope_live.live_hosts` | Scan verify | Recon seed count |
| `checks.payouts_match.passed` | Scan verify | Gate |
| `checks.payouts_match.platform_max_payout` | Scan verify | Cross-check |
| `checks.rules_unchanged.passed` | Scan verify | Gate |
| `checks.rules_unchanged.prescan_rules_sha256` | Scan verify | Change detection |

### 3.5 Per-Asset Fields (From DB → Deep Dive)

| Field | Source | Oracle Use |
|-------|--------|------------|
| `identifier` | DB `assets.asset_identifier` | Recon target |
| `type` | DB `assets.asset_type` (canonical) | Scope matching |
| `is_wildcard` | DB `assets.is_wildcard` | Wildcard handling |
| `eligible_for_bounty` | DB `assets.eligible_for_bounty` | Submission eligibility |
| `eligible_for_submission` | DB `assets.eligible_for_submission` | Submission eligibility |
| `instruction` | DB `assets.instruction` | Special handling notes |
| `max_severity` | DB `assets.max_severity` | Severity ceiling |
| `first_seen_ts` | DB `assets.first_seen_timestamp` | Freshness signal |

---

## 4. Enhanced Sync (Medium Effort)

### 4.1 Program Change Detection

**New table**: `program_changes`

```sql
CREATE TABLE program_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER,
    change_type TEXT,  -- 'scope_added', 'scope_removed', 'payout_changed', 'rules_changed', 'new_asset', 'tombstone_resurrected'
    old_value TEXT,
    new_value TEXT,
    detected_at INTEGER,
    FOREIGN KEY (program_id) REFERENCES programs(id)
);
```

**Sync emits**: `program_changes.json` alongside handoff — Oracle can trigger re-verify on changed programs only.

### 4.2 Live FX Rates (Daily Cached)

```python
# New module: scan4me/fx_rates.py
# Fetches from exchangerate.host (free, no key) or ECB daily
# Falls back to static _FX_TO_USD if network fails
# Cache TTL: 24h in data_cache/fx_rates.json
```

### 4.3 Authenticated Scope for Listing-Only Platforms

| Platform | Current | Target |
|----------|---------|--------|
| Bugbase | 0 assets (listing-only) | CDP session → real scope |
| HackenProof | 0 assets | API key / CDP |
| Cantina | 0 assets | CDP session |
| Patchstack | 0 assets | CDP session |
| Huntr | 0 assets | CDP session |
| CodeHawks | 0 assets | CDP session |

**Implementation**: Extend `download_program_assets` logic to sync-time for these platforms when credentials exist.

---

## 5. Active Reconnaissance Enrichment (Optional, Future)

| Feature | Table | Trigger |
|---------|-------|---------|
| `httpx` live probe on all assets | `site_scans` | `sync --enrich` |
| `nuclei` template scan | `site_scans` | `sync --enrich` |
| TLS cert transparency | `site_scans` | `sync --enrich` |
| Subdomain enumeration (passive) | `assets` (new) | `sync --enrich` |

**Doctrine**: Enrichment never blocks sync. Results stored separately, referenced in handoff `resources.enrichment`.

---

## 6. Implementation Order

### Phase 1: Quick Fixes + Handoff Command (Week 1)
- [ ] Q1–Q4 quick fixes
- [ ] Add `handoff` subcommand to `scan4me.py`
- [ ] Implement `oracle.p12.handoff/v1` schema
- [ ] Embed full triage config + per-program checks + deep_dive assets
- [ ] Test: `scan4me handoff` → `oracle-hunter queue --handoff` works end-to-end

### Phase 2: Filter Completeness (Week 1–2)
- [ ] Audit `oracle_intake.py` for every triage field it reads
- [ ] Ensure every field in §3 appears in handoff
- [ ] Add `triage_config` object to handoff (source file + all effective values)
- [ ] Test: Oracle prescan/scan produces identical results with handoff vs direct DB

### Phase 3: Change Detection + Live FX (Week 2)
- [ ] Add `program_changes` table + migration
- [ ] Emit `program_changes.json` with handoff
- [ ] Implement `fx_rates.py` with 24h cache
- [ ] Update `_to_usd()` to use cached rates

### Phase 4: Listing-Only Authenticated Scope (Week 2–3)
- [ ] Add CDP/API auth paths for Bugbase, HackenProof, Cantina, Patchstack, Huntr, CodeHawks
- [ ] Sync real scope assets (not just listings)
- [ ] Update `LISTING_ONLY_PLATFORMS` → `LISTING_ONLY_PLATFORMS_WITHOUT_AUTH`

### Phase 5: Active Enrichment (Future)
- [ ] `--enrich` flag
- [ ] Store in `site_scans`
- [ ] Reference in handoff

---

## 7. Test Plan

### New Tests Required

```python
# tests/test_handoff.py
def test_handoff_schema_matches_oracle_p12_v1():
    # Validate emitted JSON against schema

def test_handoff_embeds_full_triage_config():
    # Every field in §3 present

def test_handoff_per_program_checks_complete():
    # scope_live, payouts_match, rules_unchanged all have passed + evidence

def test_handoff_deep_dive_assets_include_eligibility():
    # eligible_for_bounty, eligible_for_submission, first_seen_ts

def test_handoff_roundtrip_oracle_intake():
    # oracle_intake.select_deep_dive consumes handoff → identical ranked_verified

# tests/test_program_changes.py
def test_program_changes_detected_on_scope_add():
def test_program_changes_detected_on_payout_change():
def test_program_changes_detected_on_rules_change():

# tests/test_fx_rates.py
def test_fx_rates_cache_ttl():
def test_fx_rates_fallback_to_static():
```

### Regression Tests (Must Stay Green)
- All 121 existing `test_scan4me.py` tests
- Oracle `tests/run_all.py` 10/10 layers
- Live gate: `sync → prescan → scan → download → queue --execute → hunt`

---

## 8. File Outputs (Artifacts Preserved)

| File | Purpose | Retention |
|------|---------|-----------|
| `reports/prescan_<stamp>.json` | Raw prescan (untrusted) | Gitignored, kept locally |
| `reports/scan_<stamp>.json` | Verified scan report | Gitignored, kept locally |
| `reports/oracle_handoff_<stamp>.json` | **Primary Oracle input** | Gitignored, kept locally |
| `reports/program_changes_<stamp>.json` | Change detection (Phase 3) | Gitignored, kept locally |
| `targets/<Platform>/<program>/download_report.json` | Per-program download evidence | Gitignored, kept locally |
| `targets/<Platform>/<program>/program_page_corroboration.txt` | Independent render | Gitignored, kept locally |

**All files are written to `reports/` and `targets/` — never lost, always traceable.**

---

## 9. Oracle Consumption (No Code Changes Needed in Oracle)

`oracle_intake.py` already expects `HANDOFF_SCHEMA = "oracle.p12.handoff/v1"` and consumes:
- `ranked_verified` → `select_deep_dive` → `write_handoff`
- `triage_config` → already reads from `triage.yaml` (now also in handoff for replay)
- `deep_dive.assets` → `download_selected_workspaces` uses for scope refresh
- `deep_dive.company` → loaded as bounty context for all 3 mindsets
- `resources` paths → `oracle_bulk_download.py` correlates

**Only change**: Oracle's `cmd_scan` / `cmd_queue` can now accept `--handoff-file` directly from Scan4Me output.

---

## 10. Success Criteria

| Metric | Target |
|--------|--------|
| Scan4Me tests | 121 → 121+ (new handoff/change/fx tests) |
| Oracle layers | 10/10 PASS |
| Live gate | `sync → handoff → queue --execute → hunt` completes end-to-end |
| Handoff replay | Oracle produces identical `ranked_verified` from handoff vs direct DB |
| Filter completeness | Every triage field in §3 present in handoff `triage_config` |
| File artifacts | All 6 file types written and locatable |

---

## 11. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Handoff schema drift | Version in `_schema` field; Oracle rejects unknown versions |
| Large handoff file (2000+ programs) | `--top-n` / `--sites` limits deep_dive; prescan/scan reports stay full |
| FX rate cache stale | 24h TTL; fallback to static rates; log warning |
| Listing-only auth fails | Soft-fail: log warning, keep listing-only record, don't block sync |
| Change detection noise | Only emit on semantic changes (scope/payout/rules), not timestamp updates |

---

**Next Step**: Approve Phase 1 scope → I'll implement quick fixes + `handoff` command + schema.