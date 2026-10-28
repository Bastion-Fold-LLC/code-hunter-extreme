#!/usr/bin/env bash
#
# Local AI PR review using omnicli as the model backend (full provider force).
#
# How it fits together:
#   pr-agent (runs here, on your computer)
#     --> http://localhost:8000/v1   (omnicli's local proxy, also on your computer)
#       --> whichever real provider omnicli routes to (nvidia / openrouter / ...)
#
# The "API key for omnicli" is its proxy token (OMNICLI_PROXY_TOKEN). It never
# leaves your machine. Nothing is exposed to the internet; the GitHub cloud is
# not involved in running the model — only in reading/posting the PR.
#
# Prerequisites (one-time):
#   1. Start omnicli's proxy locally with a token, e.g.:
#        export OMNICLI_PROXY_TOKEN="$(openssl rand -hex 24)"   # your omnicli key
#        omni proxy                      # (or: python -c 'from omnicli.proxy import start_proxy; start_proxy()')
#      Keep that same OMNICLI_PROXY_TOKEN exported in this shell too.
#   2. Be logged in with gh (gh auth login) so pr-agent can read/post the PR.
#
# Usage:
#   export OMNICLI_PROXY_TOKEN=...            # same token the proxy expects
#   export PR_REVIEW_MODEL="openai/nvidia/meta/llama-3.3-70b-instruct"   # any model omnicli routes
#   scripts/pr-review.sh <github-pr-url> [review|describe|improve|ask "..."]
#
set -euo pipefail

PR_URL="${1:?usage: pr-review.sh <github-pr-url> [review|describe|improve|ask]}"
CMD="${2:-review}"

# --- omnicli endpoint + key (the token you host on this computer) -------------
: "${OMNICLI_PROXY_TOKEN:?set OMNICLI_PROXY_TOKEN to the token your omnicli proxy expects}"
export OPENAI__API_BASE="${OMNICLI_BASE:-http://localhost:8000/v1}"
export OPENAI__KEY="$OMNICLI_PROXY_TOKEN"

# --- which omnicli-routed model does the reviewing (full provider force) ------
# The "openai/" prefix tells LiteLLM to use the OpenAI-compatible path; omnicli
# then resolves the rest ("nvidia/...") to the real provider.
MODEL="${PR_REVIEW_MODEL:-openai/nvidia/meta/llama-3.3-70b-instruct}"
export CONFIG__MODEL="$MODEL"
export CONFIG__FALLBACK_MODELS="[\"$MODEL\"]"
export CONFIG__CUSTOM_MODEL_MAX_TOKENS="${PR_REVIEW_MAX_TOKENS:-128000}"

# --- GitHub auth so pr-agent can read the diff and post the review ------------
export GITHUB__DEPLOYMENT_TYPE="user"
export GITHUB__USER_TOKEN="${GITHUB_TOKEN:-$(gh auth token)}"

# --- isolated venv with pr-agent (self-installs on first run) -----------------
VENV="${PR_AGENT_VENV:-$HOME/.cache/pr-agent-venv}"
if [ ! -f "$VENV/bin/python" ]; then
  echo "[pr-review] creating venv + installing pr-agent at $VENV ..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip pr-agent
fi

echo "[pr-review] $CMD on $PR_URL via omnicli ($MODEL)"
exec "$VENV/bin/python" -m pr_agent.cli --pr_url="$PR_URL" "$CMD"
