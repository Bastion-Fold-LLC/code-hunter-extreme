#!/usr/bin/env bash
# Oracle's one gate — "is the whole thing legit, right now".
#
# Stands up the vulnerable benches, confirms the local model, runs BOTH test
# layers against them, and tears the benches down no matter how it exits:
#   1. local model preflight  (ollama has the configured qwen model)
#   2. benches up + verified   (benches/bringup.sh up)
#   3. pytest suite            (plumbing + live recall: test_p14 no longer skips)
#   4. run_all.py              (e2e: golden hunt, known-bug corpus, 3-mindset ...)
# Exit 0 only if every layer passes. No layer may silently skip.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODEL="qwen3-coder:30b-16k"
OLLAMA="http://localhost:11434"

log()  { printf '\033[36m[verify]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[verify] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. local model preflight ────────────────────────────────────────────────
log "preflight: local model $MODEL on $OLLAMA"
tags="$(curl -fsS --max-time 5 "$OLLAMA/api/tags" 2>/dev/null)" \
  || die "ollama not answering at $OLLAMA — start it (the LLM-lens layers need it)"
printf '%s' "$tags" | grep -q "$MODEL" \
  || die "ollama is up but model '$MODEL' is not pulled — run: ollama pull $MODEL"
log "model present"

# ── 2. benches up (teardown always) ─────────────────────────────────────────
teardown() { log "tearing down benches"; bash benches/bringup.sh down || true; }
trap teardown EXIT
bash benches/bringup.sh up || die "bench bring-up failed"

rc=0

# ── 3. pytest suite (now exercises live bench recall, no skips) ──────────────
log "running pytest suite"
python3 -m pytest -q -p no:cacheprovider || rc=1

# ── 4. end-to-end layers ─────────────────────────────────────────────────────
log "running run_all.py (end-to-end layers)"
python3 tests/run_all.py || rc=1

if [ "$rc" -eq 0 ]; then
  log "GATE PASS — model + benches + pytest + e2e all green"
else
  printf '\033[31m[verify] GATE FAIL — see failing layer(s) above\033[0m\n' >&2
fi
exit "$rc"
