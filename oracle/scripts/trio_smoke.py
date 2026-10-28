#!/usr/bin/env python3
# LAYER: seal
# DEST: codecrusher
# ENDPOINTS: main
# TOPICS: none
"""Trio integration smoke (Phase F) — Oracle + Scan4Me + OmniCLI at HEADs.

Run: python3 scripts/trio_smoke.py [--scan4me PATH] [--omnicli PATH]

Read-only against the real Scan4Me DB. Exits nonzero on any FAIL.
Not a pytest: it proves the three independently-versioned repos on
this machine agree on scope and can find each other via env/sibling
resolution — no hardcoded user paths.
"""

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

FAILURES = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def git_head(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        return out.stdout.strip() or "?"
    except Exception:
        return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan4me", default=None, help="Scan4Me repo (default: resolve)")
    ap.add_argument("--omnicli", default=None, help="OmniCLI repo (default: resolve)")
    args = ap.parse_args()
    if args.scan4me:
        import os

        os.environ["SCAN4ME_HOME"] = args.scan4me
    if args.omnicli:
        import os

        os.environ["OMNICLI_HOME"] = args.omnicli

    import oracle_scan4me as bridge
    import oracle_llm
    from oracle_hunter import ProgramScopeGate

    s4m_home = bridge.scan4me_home()
    omni_home = oracle_llm.omnicli_home()
    check("oracle HEAD", True, git_head(HERE))
    check("scan4me resolved", s4m_home is not None and Path(s4m_home).exists(),
          f"{s4m_home} @{git_head(Path(s4m_home)) if s4m_home else '?'}")
    check("omnicli resolved", omni_home is not None and Path(omni_home).exists(),
          f"{omni_home} @{git_head(Path(omni_home)) if omni_home else '?'}")
    if FAILURES:
        return 1

    # Scan4Me module loaded from its own home (no baked paths).
    spec = importlib.util.spec_from_file_location(
        "scan4me_smoke", Path(s4m_home) / "scan4me.py"
    )
    scan4me = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(s4m_home))
    spec.loader.exec_module(scan4me)

    check("scan4me DB exists", bridge.scan4me_db_path().exists(),
          str(bridge.scan4me_db_path()))

    progs = bridge.fetch_programs(limit=3)
    check("bridge fetch_programs(3)", len(progs) > 0, f"{len(progs)} programs")

    conn = bridge._db()
    try:
        conn.execute("INSERT INTO programs(platform, name) VALUES('smoke','smoke')")
        check("bridge DB read-only", False, "INSERT succeeded")
    except Exception as e:
        check("bridge DB read-only", True, type(e).__name__)
    finally:
        conn.close()

    # Real-data scope agreement: first concrete host from live scope data.
    agreed = None
    for p in progs:
        for s in p.get("structured_scopes") or []:
            ident = (s.get("asset_identifier") or "").strip()
            if ident and "*" not in ident and "/" not in ident and "." in ident \
                    and " " not in ident:
                host = ident.split("://")[-1].lower()
                b = bridge.verify_in_scope(host, p)[0]
                g = ProgramScopeGate(dict(p), "").is_host_in_scope(host)[0]
                s_ok = scan4me.scope_match(host, ident, s.get("is_wildcard", 0))
                agreed = (b == g) and (g is True) and bool(s_ok)
                check("real-host trio agreement", agreed,
                      f"{host} bridge={b} gate={g} scan4me={s_ok}")
                break
        if agreed is not None:
            break
    if agreed is None:
        check("real-host trio agreement", False, "no concrete host in fetched scopes")

    # Fixed parity vectors across the three matchers.
    glued = {"name": "smoke", "structured_scopes": [
        {"asset_identifier": "*-vpn.example.com", "is_wildcard": 1}]}
    vec_ok = True
    for host, expected in (("x-vpn.example.com", True), ("a.b-vpn.example.com", False),
                           ("example.com", False)):
        g = ProgramScopeGate(dict(glued), "").is_host_in_scope(host)[0]
        b = bridge.verify_in_scope(host, glued)[0]
        s_ok = scan4me.scope_match(host, "*-vpn.example.com", True)
        if not (g == b == bool(s_ok) == expected):
            vec_ok = False
            print(f"  vector {host}: gate={g} bridge={b} scan4me={s_ok} want={expected}")
    check("glued parity vectors", vec_ok)

    # OmniCLI CLI starts standalone from its own home.
    r = subprocess.run([sys.executable, "-m", "omnicli", "--help"],
                       cwd=str(omni_home), capture_output=True, text=True, timeout=60)
    check("omnicli --help", r.returncode == 0 and "OmniCLI" in r.stdout)

    print("\nTRIO SMOKE:", "FAIL" if FAILURES else "PASS", FAILURES or "")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
