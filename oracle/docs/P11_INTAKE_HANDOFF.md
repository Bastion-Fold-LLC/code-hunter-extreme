# P11 → P12 handoff: ranked-verified list

P11 (`oracle_intake.py`, `oracle-hunter prescan` / `oracle-hunter scan`) ends
by writing the **ranked-verified list**. P12 (scheduling) consumes it. Queue
*semantics* (order, concurrency) stay P12's domain, with one exception:
`cmd_scan` reads ONE value from queue config — `queue.default_count` — as
the fallback selection count when neither `-N` nor `--sites` is given
(`oracle_hunter.cmd_scan`).

## Files

All paths are logged to stdout when written.

| Step | File | Schema |
|---|---|---|
| prescan (raw, untrusted) | `reports/prescan_<stamp>.json` | `oracle.intake.prescan/v1` |
| scan (verify pass) | `reports/scan_<stamp>.json` | `oracle.intake.scan/v1` |
| P12 handoff | `reports/intake_ranked_verified_<stamp>.json` | `oracle.p12.handoff/v1` |

## Handoff payload (`oracle.p12.handoff/v1`)

```json
{
  "_schema": "oracle.p12.handoff/v1",
  "created_utc": "2026-10-12T00:00:00+00:00",
  "prescan_report": "reports/prescan_<stamp>.json",
  "scan_report": "reports/scan_<stamp>.json",
  "no_cloud": false,
  "selector": {"top_n": 5, "sites": null},
  "ranked_verified": [
    {
      "rank": 1,
      "name": "...", "handle": "...", "platform": "...", "url": "...",
      "score": 87.5, "max_payout_usd": 25000, "currency": "USD",
      "verdict": "verified",
      "checks": {"scope_live": {}, "payouts_match": {}, "rules_unchanged": {}},
      "workspace": {"path": "...", "status": "present|downloaded|empty|error", "detail": "..."},
      "oracle_rescan": {
        "source": "hackerone-api-authenticated",
        "independent": true,
        "found": true
      },
      "deep_dive": {
        "assets": [],
        "company": {},
        "resources": {},
        "sources": ["scan4me:programs+assets", "scan-rescan:hackerone-api-authenticated"],
        "checks": {}
      }
    }
  ],
  "excluded_named": [{"site": "...", "program": "...", "reason": "..."}],
  "oracle_rescan": {
    "mode": "independent|mixed|scan4me-db|no-oracle-adapter|none",
    "independent": true,
    "programs": 1,
    "independent_programs": 1,
    "sources": ["hackerone-api-authenticated"]
  },
  "feed_provenance": {},
  "feed_trust": {"ok": false, "raw_candidate_ok": true, "issues": ["unauthenticated feed rows: ..."], "enforced": true},
  "note": "unverified programs never appear here; see the scan report"
}
```

## Contract guarantees

- Scan4Me discovery is no-login (`prescan --sync` uses `use_auth=False`).
  Prescan/scan reject unavailable, stale (including age over 48h), or
  failed-refresh feeds. Fresh `public-file`/public-listing rows pass only
  as raw candidates (`feed_trust.raw_candidate_ok=true` while the separate
  authenticated verdict `feed_trust.ok` stays false). `prescan` preserves
  a rejected report; there is no operator bypass.
- Trust is created on the verify pass, per program. HackerOne scope is
  re-fetched from HackerOne's authenticated Hacker API with Oracle's own
  `HACKERONE_USERNAME` + `HACKERONE_API_TOKEN`/`HACKERONE_API_KEY`.
  Auth/transport failure fails the scan; a 404 is a vanished program,
  never stale scope. Other platforms have no Oracle adapter yet, stamp
  `source=no-oracle-adapter, independent=false`, and cannot verify. A
  Scan4Me DB copy never corroborates itself, and a non-independent fresh
  listing contributes no `_fresh` scope downstream.
- Deep-dive consumes each verdict's embedded `_fresh` listing; it never
  re-resolves through the Scan4Me DB and never falls back to prescan
  snapshot scope. The handoff copies the scan report's
  `feed_provenance` verbatim and re-derives `feed_trust` from it (a
  stored trust block is never copied) — a later live sync cannot
  relabel what the scan consumed.
- `build_schedule(require_trusted_handoff=True)` (historical flag name),
  `queue --execute`, downloads, and chain hunts all apply the shared
  strict entry check (`oracle_intake.is_independently_verified_entry`):
  `verdict=verified`, no `failed_checks`, and re-scan metadata with
  `independent=true`, `found=true`, a non-bridge source, and — whenever
  the adapter stamps one (HackerOne always does) — a handle bound to
  the entry. Schedule items carry `verdict`/`failed_checks`
  forward so execution re-checks the whole record, and re-joined
  handoff entries are validated before any download or hunt. Public
  discovery provenance alone is neither sufficient nor a blocker after
  Oracle verification.
- `pick_hunt_target` returns the entry's verdict, failed checks, and
  deep-dive assets/out-of-scope. A chain hunt pins those scan-verified
  assets (`_chain_scope_prog`) — DB re-resolution never supplies its
  scope — then stamps chain-vs-final scope hashes plus hunt-time intake
  status (`hunt_scope`) into the hunt snapshot and runlog.
- Product readiness applies the strict re-scan metadata check
  (`independent=true`, `found=true`, non-bridge source) with a handle
  stamp that must be present and bound to the workspace `program.json`,
  for every platform. `feed_trust` is discovery provenance only.
  Direct/non-queue workspaces are therefore never submission-ready.
- `ranked_verified` contains ONLY independently verified programs
  (`verdict == "verified"` and `oracle_rescan.independent is True`),
  ranked by Scan4Me score descending. Unverified or bridge-only programs
  NEVER appear here — not even when named via `--sites` (those land in
  `excluded_named` with a reason).
- Named `--sites` override `-N/--top-n` entirely. With neither flag,
  `cmd_scan` falls back to `queue.default_count`; `write_handoff` itself
  applies no count.
- Empty verified set still writes a file (`ranked_verified: []`) — a
  fail-closed empty, never a missing file.
- `excluded_named` covers named sites that are unverified or match nothing.
- Every program's verify evidence (`checks`) travels with it, so P12 never
  re-verifies from scratch.
- Apex exclusion (P7) held throughout: wildcard scope was never expanded to
  cover an apex during the scope-live check (see the scan report's per-host
  `skipped` reasons).

## Download leg (P11 --download)

`download_selected_workspaces(selection, ...)` downloads one workspace
per entry in `selection["ranked_verified"]` and returns the **mutated
`selection`**. It re-checks every entry itself: only `verified` entries
with `oracle_rescan.independent=true` are touched; anything else is
recorded as `workspace.status=skipped`, even if a caller hand-placed it
in the ranked list.
Each entry gains `workspace: {path, status, detail}` where status is
`present` (manifest already on disk), the downloader's own status
(`downloaded`/`empty`), or `error`. A failure on one program never aborts
the rest. Entry points: `scan --download` and `queue` (the schedule's own
handoff only). `queue --execute` calls this function; the internal
`pick_hunt_target` only resolves one schedule item for execution.
