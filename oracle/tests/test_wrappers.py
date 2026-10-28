"""Wrapper entrypoints must launch THIS workspace's code.

Regression (connection trace DEAD #1): oracle-hunter/oracle-bounty/
oracle-email exec'd a stale extracted copy under
oracle-main-extracted/, so every workspace fix was unreachable through
the installed entrypoints. oracle-programs already resolves relative
to its own location — all wrappers must do the same.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WRAPPERS = {
    "oracle-hunter": "oracle_hunter.py",
    "oracle-bounty": "oracle_bounty.py",
    "oracle-email": "oracle_email.py",
    "oracle-programs": "oracle_programs.py",
}


def test_wrappers_resolve_workspace():
    for wrapper, target in WRAPPERS.items():
        text = (ROOT / wrapper).read_text(encoding="utf-8")
        assert "oracle-main-extracted" not in text, wrapper
        assert 'readlink -f "$0"' in text, wrapper
        assert f"/{target}" in text, wrapper
        assert (ROOT / target).is_file(), target
