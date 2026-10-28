#!/bin/sh
# spec-guard: PreToolUse hook. Blocks mutations of the frozen owner spec
# (docs/OWNER_MINDSET_SPEC.md) and the saved finish plan
# (docs/OWNER_MINDSET_FINISH_PLAN.md) once each file exists. Creation of a
# not-yet-existing file is allowed; reads are always allowed.
#
# Exit 0 = allow. Exit 2 + stderr = block (same contract as commit-gate).
# Unknown/unparseable hook input FAILS OPEN (allow) so a format mismatch
# can never brick the session; this limit is disclosed in the finish plan.
set -u

REPO="${ORACLE_PLAN_REPO:-/home/phantomcore/oracle}"

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
path = ""
if isinstance(params, dict):
    path = params.get("path") or params.get("file_path") or params.get("filePath") or ""
print(tool)
print(path)
print(json.dumps(params) if not isinstance(params, str) else params)
' 2>/dev/null)"
if [ "$PARSED" = "UNPARSEABLE" ]; then
  exit 0
fi
TOOL="$(printf '%s' "$PARSED" | head -n 1)"
HPATH="$(printf '%s' "$PARSED" | head -n 2 | tail -n 1)"
TEXT="$(printf '%s' "$PARSED" | tail -n +3)"

HOOK_TOOL="$TOOL" HOOK_PATH="$HPATH" HOOK_TEXT="$TEXT" REPO="$REPO" python3 -c '
import os,sys
tool = os.environ.get("HOOK_TOOL", "")
hpath = os.environ.get("HOOK_PATH", "")
text = os.environ.get("HOOK_TEXT", "")
repo = os.environ.get("REPO", "/home/phantomcore/oracle")
frozen = ["OWNER_MINDSET_SPEC.md", "OWNER_MINDSET_FINISH_PLAN.md"]
if hpath:
    hits = [f for f in frozen if os.path.basename(hpath) == f]
else:
    hits = [f for f in frozen if f in text]
if not hits:
    sys.exit(0)
low = tool.lower()
is_write = ("write" in low) or ("edit" in low)
is_bash = ("bash" in low) or low == ""
mutators = [">", "sed -i", "tee ", "rm ", "mv ", "truncate", "dd "]
for name in hits:
    if not os.path.isfile(os.path.join(repo, "docs", name)):
        continue
    if is_write or (is_bash and any(m in text for m in mutators)):
        print(f"spec-guard BLOCKED: {name} is frozen. Amend via a new plan revision, not an in-place edit.", file=sys.stderr)
        sys.exit(2)
sys.exit(0)
'
