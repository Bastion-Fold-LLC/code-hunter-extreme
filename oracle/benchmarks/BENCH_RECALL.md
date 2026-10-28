# Per-bench recall mapping (doctrine §5 denominators)

> Dated 2026-10-11 as a testbed map. Detection recall here is **testbed**
> recall; as of 2026-10-20 there is no live-hunt recall number to report
> beside it (no completed live hunt yet). Never read one as the other.

Machine source: [bench_recall.json](bench_recall.json) (12 bar + 23 named).
Enforcer: `tests/test_p14_bench_recall.py`. Pins must match
[registry.json](registry.json) (test fails on drift).

## Two tables, two meanings

- **Detection recall** (suite-enforced): template→check→verify against the
  LIVE bench with seeded recon + operator session. Bar 1.0, currently
  12/12. Answers: "can the engine confirm this plant on the wire?"
- **E2E hunt recall** (reported per hunt, not suited to the suite):
  full recon→verify→report with no seeding. Answers: "does the hunt
  FIND it?" Discovery gaps (auth walls, crawling) show up here, not in
  detection. P14 trio + re-hunts carry the E2E numbers in the P14 report.

## In-class misses (named, red in E2E, with walls)

These are REAL plants the envelope cannot take — reported, never silent.
Fixing a wall moves its items to bar; nothing moves off bar without a
doctrine change (P2-lock).

| Miss | Wall | Fix direction |
|---|---|---|
| juice XSS x9 | browser rendering (DOM) | rendered-DOM differential (crawl4ai/playwright fetch + reflection check) |
| juice IDOR (viewBasket et al) | 2 accounts + JWT | dual-account harness auto-provisioning (register 2 users, cross-read) |
| juice Login Jim/Bender, UNION, NoSQL | targeted inference | email discovery + UNION/NoSQL grammars |
| juice blueprint / .bak | undiscoverable path / 403 | none without seeding (documented as such) |
| dvwa authbypass module | 2nd (non-admin) account | same dual-account direction as juice IDOR |
| dvwa bac IDOR | forged user_id cookie | cookie-minting reframes (param/cookie cross-product) |
| dvwa stored XSS | form-POST + re-GET two-step | form-aware persist probes (parse form, POST, re-GET) |
| dvwa blind SQLi | boolean/time inference | timing differential + inference loop |
| pygoat SQLi labs | Django CSRF + form POST | CSRF-aware form replay (fetch form, echo token) |
| pygoat ba/bau/OTP labs | credential/cookie flows | flow-aware auth probing |

## Bare + uncovered (not misses)

- pygoat IDOR: no per-user object endpoint exists (URL inventory in the
  mapping). IDOR recall stays enforced on fixtures (P2 GOLDEN_CLASS).
- Out-of-class (weak_id sessions, SSTI/XXE/cmd/deser, exec/upload/fi,
  open redirect, JS-client logic): named per bench in the mapping.

## Running

`python3 -m pytest tests/test_p14_bench_recall.py` — needs the three
bench containers (juice :3000, DVWA :8080, pygoat :8000); tests SKIP
when a bench is unreachable. Auth is self-provisioned per run
(DVWA admin login, fresh pygoat registration).
