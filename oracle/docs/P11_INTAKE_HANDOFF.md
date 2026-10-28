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
        "source": "hackerone-api-authenticated|scan4me-db",
        "independent": true,
        "found": true
      },
      "deep_dive": {
        "assets": [],
        "company": {},
        "resources": {},
        "sources": ["scan4me:programs+assets"],
        "checks": {}
      }
    }
  ],
  "excluded_named": [{"site": "...", "program": "...", "reason": "..."}],
  "oracle_rescan": {
    "mode": "independent|mixed|scan4me-db|none",
    "independent": true,
    "programs": 1,
    "independent_programs": 1,
    "sources": ["hackerone-api-authenticated"]
  },
  "feed_provenance": {},
  "feed_trust": {"ok": true, "issues": [], "enforced": true},
  "note": "unverified programs never appear here; see the scan report"
}
```

## Contract guarantees

- Prescan/scan reject stale, failed-refresh, `public-file`, or
  no-authenticated-row Scan4Me feeds. `prescan` preserves the rejected
  report; `scan` refuses to launder it. There is no operator bypass.
- On the verify pass, HackerOne scope is re-fetched from HackerOne's
  authenticated Hacker API with Oracle's own `HACKERONE_USERNAME` +
  `HACKERONE_API_TOKEN`/`HACKERONE_API_KEY`. Auth/transport failure fails
  the scan; a 404 is a vanished program, never stale scope. Other platforms
  fall back to the Scan4Me bridge and stamp `independent=false`.
- The handoff carries `feed_trust`; `build_schedule(require_trusted_handoff=True)`
  and `queue --execute` reject untrusted handoffs/schedules before dispatch.
- Product readiness re-checks both stamps inside the workspace snapshot:
  `feed_trust.ok=true` and Oracle re-scan provenance are required. A
  HackerOne product additionally requires `oracle_rescan.independent=true`.
  Direct/non-queue workspaces are therefore never submission-ready.
- `ranked_verified` contains ONLY `verdict == "verified"` programs, ranked by
  Scan4Me score descending. Unverified programs NEVER appear here — not even
  when named via `--sites` (those land in `excluded_named` with a reason).
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
per entry in `selection["ranked_verified"]` (unverified programs are never
in that list by construction) and returns the **mutated `selection`**.
Each entry gains `workspace: {path, status, detail}` where status is
`present` (manifest already on disk), the downloader's own status
(`downloaded`/`empty`), or `error`. A failure on one program never aborts
the rest. Entry points: `scan --download` and `queue` (the schedule's own
handoff only). `queue --execute` calls this function; the internal
`pick_hunt_target` only resolves one schedule item for execution.
