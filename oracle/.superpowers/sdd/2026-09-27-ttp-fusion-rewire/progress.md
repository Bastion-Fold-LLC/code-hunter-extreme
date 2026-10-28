# SDD ledger — plan: bounded change (in-chat design), branch feat/ttp-fusion-rewire off master f56298d

Design (bounded): re-wire orphaned oracle_ttps_fused.json into the reflex pass as GROUNDING not parrot-bait.
- _load_fused_ttps(): load fused json -> {code: record}, cached, fail-soft ({} if missing).
- _format_ttp_line(t, fused): if fused record for t.code exists, emit paradox + reflex_move + you_never_said framed "reason FROM this, do not copy"; else fall back to heatmap description.
- _map_ttps_to_recon uses _format_ttp_line; heatmap still SELECTS techniques, fused ENRICHES them.
Anti-parrot: grounding framing + existing grounded-check gate in _parse_seams + strong backend via router.
Ruling: bounded path (no spec doc) — enrichment of one function's data+framing, user pre-approved "do it".
Task complete (commit faa0088): fused TTP re-wire. tests: pytest tests/ -> green; real integration verified (8/8 techniques paradox-fused on 127.0.0.1_3000 recon).
