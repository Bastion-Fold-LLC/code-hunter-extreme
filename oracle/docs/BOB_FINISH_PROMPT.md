Finish task: generalize the precision fix across the remaining seam templates, tune recon, and fix T1552. Build on current HEAD. Read-only on analysis; you may edit templates/recon and run the local test app.

## Orient first (do NOT repeat stale claims)
`git log --oneline -6`. HEAD is 0b03995. Bug A/B/C, invisible-seam-both-lenses, max_reports,
cookie-security (0600), AND the first precision fix are ALL committed. The "commit Bug A/C"
gap in older whats-left reports is STALE — stop surfacing it.

The precision pattern is already proven on ONE template (self-observing / info-disclosure):
bare `status 200` confirmed any reachable endpoint (/health "confirmed" as disclosure). Fix
was: require the body to actually contain a leak marker. Verified on the live test app —
/health REJECTS, /debug/config (AWS+broker creds) CONFIRMS. Use the same pattern below.

Syntax available in parse_expected (oracle_deterministic.py):
- `status 200, body contains "X"`            (AND — all must be present)
- `status 200, body contains any of "a","b"` (OR — at least one; I added this)
- `status 401, body not contains "token"`    (exclusion — good for ruling out HTML error pages)

## Task 1 — give every reachability-only template a real predicate (the main work)
A template that confirms on bare `status 200` is a false-positive machine: a benign page or
an HTML error page also returns 200. For EACH template below, ask: "could a benign/error
response also satisfy this?" If yes, add a predicate only a real finding satisfies.
- Explicit bare-status: the artifact-exposure template at oracle_seam_templates.py:408
  (.env/.git/package.json at 200). A 200 HTML error page would FP. Require e.g.
  `status 200, body not contains "<html"` AND a body marker matching the artifact
  (`body contains any of "=","PRIVATE KEY","aws","ref:","dependencies"`).
- Implicit bare-status (builder omits `expected` → _card default at ~line 668): vacuum-
  identity (privileged path no-auth), mirror-remembered (stale v1/v2), repulsive-gravity,
  deathless-hierarchy, open-redirect. For each, set an `expected` with a predicate:
  * vacuum: body returns privileged data markers (not just reachable). If it's only
    reachability, tag it `"severity": "low"` so the floor keeps it out of submission drafts.
  * mirror: evidence the OLD contract still serves (version string / old field).
  * open-redirect: `header location contains "example.com"` (the redirect actually fires).
- Set a sensible `"severity"` per template (`_card` reads it; low/info skips the PoC draft).

## Task 2 — recon wordlist (so templates fire on paths that matter)
fuzz_hidden_paths (oracle_deeprecon.py:~290, wordlists in oracle/wordlists) found only
/health on the test app — missed /debug/config. Point ffuf at a wordlist that includes the
sensitive paths that produce findings: /debug, /debug/config, /admin, /.env, /.git/HEAD,
/actuator, /api/v1/*, /swagger.json, /openapi.json, /metrics, /.git/config.

## Task 3 — fix the dead T1552 (oracle_seam_templates.py:335)
Its check is a `# comment` (no URL). js_secrets.txt is bare `key=value` with no source URL,
and `curl|grep` is sanitizer-blocked. Real fix: thread the JS file URL into js_secrets
(change mine_js in oracle_deeprecon.py to write the source URL alongside each secret), then
emit check `curl -i -s '<js-url>'` with `expected: status 200, body contains "<key>"`.

## Verification discipline (NON-NEGOTIABLE — this is how Bug B slipped through before)
For EVERY precision change, verify against the LIVE test app BOTH directions:
- a benign endpoint must REJECT,
- a real-finding endpoint must CONFIRM.
Use `_run_check` + `verify_seam_card` directly, or run the full `hunt 127.0.0.1:8765`.
Do NOT declare a template fixed from a green pytest or a unit test that passes `status=`
directly — that is exactly what masked Bug B. Commit each fix with the evidence in the message.

## Done = this gate
`hunt 127.0.0.1:8765 --auto` (after seeding recon with /debug/config,
/admin, etc.) confirms the REAL findings and rejects /health and benign pages. Then the
engine is trustworthy enough to point at a real program.
