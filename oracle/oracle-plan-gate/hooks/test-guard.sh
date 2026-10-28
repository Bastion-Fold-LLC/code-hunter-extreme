#!/bin/sh
# test-guard: PreToolUse hook. Blocks bash pytest invocations that narrow
# the gate with `-k not` or `--deselect`. Full-file/full-package runs and
# non-pytest commands (including searches mentioning pytest) are allowed.
#
# Exit 0 = allow. Exit 2 + stderr = block (same contract as commit-gate).
# Unknown/unparseable hook input FAILS OPEN (allow) so a format mismatch
# can never brick the session; this limit is disclosed in the finish plan.
set -u

INPUT="$(cat)"
if [ -z "$INPUT" ]; then
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

PARSED="$(printf '%s' "$INPUT" | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("UNPARSEABLE")
    sys.exit(0)
if not isinstance(d, dict):
    print("UNPARSEABLE")
    sys.exit(0)
tool = d.get("tool_name") or d.get("toolName") or d.get("tool") or ""
params = d.get("tool_input") or d.get("toolInput") or d.get("params") or d
cmd = ""
if isinstance(params, dict):
    cmd = params.get("command") or ""
print(tool)
print(cmd if cmd else (json.dumps(params) if not isinstance(params, str) else params))
' 2>/dev/null)"
if [ "$PARSED" = "UNPARSEABLE" ]; then
  exit 0
fi
TOOL="$(printf '%s' "$PARSED" | head -n 1)"
TEXT="$(printf '%s' "$PARSED" | tail -n +2)"

HOOK_TOOL="$TOOL" HOOK_TEXT="$TEXT" python3 -c '
import os,re,sys
tool = os.environ.get("HOOK_TOOL", "")
text = os.environ.get("HOOK_TEXT", "")
low = tool.lower()
if low and "bash" not in low:
    sys.exit(0)
invoke = re.compile(r"^(?:\S*/)?(?:pytest|py\.test)\b|^(?:\S*/)?python3?\s+-m\s+pytest\b")
narrow = re.compile(r"--deselect\b|-k\s+[\"\x27]?not\b")
for seg in re.split(r"[;&|]+", text):
    s = seg.strip().lstrip("\"{\x27 ").strip()
    if invoke.search(s) and narrow.search(s):
        print("test-guard BLOCKED: narrowed pytest run (-k not / --deselect). Run the full focused gate unmodified.", file=sys.stderr)
        sys.exit(2)
sys.exit(0)
'
