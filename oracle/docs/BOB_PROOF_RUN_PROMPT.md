Next task: the first real end-to-end proof run. The engine is code-complete and sessions are live — this is the run that proves (or breaks) the productive half. Read-only on analysis; you may install tools and run the hunt.

Context you already established:
- Bug A/B/C are committed (ancestors of HEAD 783324f) — do NOT re-commit them; GAP_1 in whats-left.json is stale, verify with `git log --oneline` and move on.
- max_reports null-rejection is fixed (adcdeeb).
- 12 platform sessions are live (Profile 2, cookies snapshotted).

## Step 1 — install the recon tools (the real blocker)
```
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
python3 oracle_hunter.py status
```
Gate: `status` shows ffuf + katana FOUND. Without them, 5 of the template seam types produce 0 candidates.

## Step 2 — pick ONE real target (print your reasoning)
Criteria: HackerOne, web2, ≥$500 payout, has a real JS frontend AND an API (so js_endpoints/api_specs/fuzzed_paths actually populate). Do NOT set max_reports for this run.
```
python3 oracle_programs.py list --platform hackerone --refresh
python3 oracle_scan.py --pick 1 --download-only
```
Gate: program.json has non-empty structured_scopes before hunting.

## Step 3 — run it end to end
```
python3 oracle_hunter.py hunt <program> --auto
```

## Step 4 — report the ONE number that matters, with evidence
Does a **template** seam (id like vacuum-/mirror-/observer-/single-token-/spec-) reach **CONFIRMED** — not just the header/LLM cards? Show:
- recon: are js_endpoints.txt / api_specs.txt / fuzzed_paths.txt non-empty? (if empty, recon is the gap, not the engine)
- verify-results JSON: how many CONFIRMED, and what origin/mindset each is
- if 0 template CONFIRMED: the exact gate that rejected them (grounding? expected? wire mismatch?) — don't hand-wave

Do NOT declare success from a green test suite or a unit test that passes `status=` directly — only from a real hunt's verify-results. If it confirms a real, in-scope, non-header finding, synthesize the PoC and stop there for review.

## Secondary (only if the run is blocked and you're waiting)
_t_t1552 (oracle_seam_templates.py:335) is dead — its check is a `# comment`, no URL. A real fix is NOT `curl HOST | grep` (no URL in js_secrets, and `|grep` is sanitizer-blocked). It needs the JS source URL threaded into js_secrets so the check can re-fetch that file. Scope it; don't ship a check that the sanitizer will block.
