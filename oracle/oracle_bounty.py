#!/usr/bin/env python3
# LAYER: seal
# DEST: vortex
# ENDPOINTS: recon, run_reflexes, cmd_hunt, cmd_analyze, cmd_report, main
# TOPICS: none
"""
Oracle Bounty Daemon
─────────────────────
Local bug-bounty recon + Oracle 8-reflex analysis engine.
Runs entirely on your 64GB HP (Ollama) — no API keys needed.
Cloud-bridge optional: pipe seams to Claude/Gemini for PoC depth.

Usage:
    python3 oracle_bounty.py hunt <target>            # full pipeline
    python3 oracle_bounty.py recon <target>           # recon only (no analysis)
    python3 oracle_bounty.py analyze <recon_dir>      # analyze existing recon
    python3 oracle_bounty.py reflexes <recon_dir>     # run 8 reflexes, print seams
    python3 oracle_bounty.py report <recon_dir>       # generate final report
    python3 oracle_bounty.py interactive              # step-by-step REPL
    python3 oracle_bounty.py check-tools             # check what's installed

Examples:
    python3 oracle_bounty.py hunt example.com
    python3 oracle_bounty.py hunt https://bugcrowd.com/programs/target
    python3 oracle_bounty.py analyze ./recon/example.com
"""

import sys
import json
import argparse
import subprocess
import shutil
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
RECON_DIR = _HERE / "recon"
REPORTS_DIR = _HERE / "reports"
ORACLE_PROMPT = _HERE / "ORACLE_SYSTEM_PROMPT.md"

RECON_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


# ── Oracle system prompt ──────────────────────────────────────────────────────
def _oracle_prompt() -> str:
    if ORACLE_PROMPT.exists():
        return ORACLE_PROMPT.read_text(encoding="utf-8")
    return (
        "You are THE ORACLE security co-pilot. "
        "Core reflex: 'You never said.' "
        "Find the gap between what the spec CLAIMS and what is actually ENFORCED. "
        "Output: Assertion A (claim), Assertion B (wire behavior), one curl PoC. "
        "Rank by real user harm. No essays — seams only."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tool availability
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = {
    "nmap": "Network port scanner",
    "subfinder": "Passive subdomain enumeration",
    "amass": "Active subdomain enumeration",
    "httpx": "HTTP probe / response fingerprinting",
    "ffuf": "Directory / parameter fuzzer",
    "gau": "Get All URLs (Wayback + OTX + Common Crawl)",
    "waybackurls": "Wayback Machine URL enumeration",
    "getjs": "Extract JS files from URLs",
    "secretfinder": "Secret/key finder in JS files",
    "trufflehog": "Secret scanning in files/repos",
    "sqlmap": "SQL injection automation",
    "dalfox": "XSS scanner",
    "wfuzz": "Web fuzzer",
    "curl": "HTTP requests (always available)",
    "python3": "Python 3 interpreter",
    "ollama": "Local LLM inference",
}


def check_tools() -> Dict[str, bool]:
    return {tool: shutil.which(tool) is not None for tool in TOOLS}


def cmd_check_tools():
    available = check_tools()
    if RICH:
        tbl = Table(title="🔧 Tool Status", show_lines=True)
        tbl.add_column("Tool")
        tbl.add_column("Status")
        tbl.add_column("Purpose")
        for t, ok in available.items():
            status = "[green]✓ installed[/green]" if ok else "[red]✗ missing[/red]"
            tbl.add_row(t, status, TOOLS[t])
        console.print(tbl)
    else:
        print(f"\n{'Tool':<16} {'Status':<14} Purpose")
        print("-" * 70)
        for t, ok in available.items():
            status = "✓ installed" if ok else "✗ missing"
            print(f"{t:<16} {status:<14} {TOOLS[t]}")

    missing = [
        t
        for t, ok in available.items()
        if not ok and t not in ("curl", "python3", "ollama")
    ]
    if missing:
        print("\n📦 Quick install:")
        print(
            "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )
        print("  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("  go install -v github.com/ffuf/ffuf/v2@latest")
        print("  go install -v github.com/lc/gau/v2/cmd/gau@latest")
        print("  go install -v github.com/hakluke/hakrawler@latest")


# ─────────────────────────────────────────────────────────────────────────────
# Recon pipeline
# ─────────────────────────────────────────────────────────────────────────────


def _run(
    cmd: List[str], timeout: int = 120, cwd: Optional[Path] = None
) -> Tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return -1, "", f"[tool not found: {cmd[0]}]"


def _spin(label: str):
    """Context manager: spinner if rich, plain print otherwise."""

    class _Ctx:
        def __enter__(self):
            if RICH:
                self._p = Progress(
                    SpinnerColumn(),
                    TextColumn("{task.description}"),
                    transient=True,
                    console=console,
                )
                self._t = self._p.add_task(label)
                self._p.start()
            else:
                print(f"  → {label}")

        def __exit__(self, *_):
            if RICH:
                self._p.stop()

    return _Ctx()


def sanitize_target(target: str) -> str:
    """Strip protocol, path — return bare domain."""
    target = target.strip().rstrip("/")
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0]
    return target


def recon(target: str, output_dir: Optional[Path] = None) -> Path:
    """Run full recon against a target. Returns the recon directory."""
    domain = sanitize_target(target)
    out_dir = output_dir or (
        RECON_DIR / domain / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    tools = check_tools()
    results: Dict[str, Any] = {
        "target": domain,
        "started": datetime.now().isoformat(),
        "steps": {},
    }

    _info(f"\n🎯 Target: {domain}")
    _info(f"📁 Recon output: {out_dir}\n")

    # ── 1. Port scan ──────────────────────────────────────────────────────────
    if tools["nmap"]:
        with _spin("nmap: top-1000 port scan"):
            rc, out, err = _run(
                [
                    "nmap",
                    "-sV",
                    "--top-ports",
                    "1000",
                    "-T4",
                    "--open",
                    "-oN",
                    str(out_dir / "nmap.txt"),
                    domain,
                ],
                timeout=300,
            )
        results["steps"]["nmap"] = {"rc": rc, "lines": out.count("\n")}
        _info(f"  nmap: {out.count(chr(10))} lines")

    # ── 2. Subdomain enumeration ──────────────────────────────────────────────
    subs_file = out_dir / "subdomains.txt"
    if tools["subfinder"]:
        with _spin("subfinder: passive subdomain enum"):
            rc, out, err = _run(
                ["subfinder", "-d", domain, "-silent", "-o", str(subs_file)],
                timeout=180,
            )
        results["steps"]["subfinder"] = {"rc": rc}
        _info(f"  subfinder: {_line_count(subs_file)} subdomains")

    if tools["amass"] and not subs_file.exists():
        with _spin("amass: subdomain enum (passive)"):
            rc, out, err = _run(
                ["amass", "enum", "-passive", "-d", domain, "-o", str(subs_file)],
                timeout=240,
            )
        _info(f"  amass: {_line_count(subs_file)} subdomains")

    # ── 3. HTTP probe ─────────────────────────────────────────────────────────
    live_file = out_dir / "live_hosts.txt"
    if tools["httpx"] and subs_file.exists():
        with _spin("httpx: probing live hosts"):
            rc, out, err = _run(
                [
                    "httpx",
                    "-l",
                    str(subs_file),
                    "-silent",
                    "-title",
                    "-status-code",
                    "-tech-detect",
                    "-o",
                    str(live_file),
                ],
                timeout=180,
            )
        results["steps"]["httpx"] = {"rc": rc}
        _info(f"  httpx: {_line_count(live_file)} live hosts")
    elif not subs_file.exists():
        # Just probe the main target
        with _spin("httpx: probing main target"):
            rc, out, err = _run(
                (
                    [
                        "httpx" if tools["httpx"] else "curl",
                        "-silent",
                        f"https://{domain}",
                        "-title",
                        "-status-code",
                    ]
                    if tools["httpx"]
                    else ["curl", "-sIL", f"https://{domain}"]
                ),
                timeout=30,
            )
            (out_dir / "live_hosts.txt").write_text(f"https://{domain}\n{out}")

    # ── 4. URL discovery ──────────────────────────────────────────────────────
    urls_file = out_dir / "all_urls.txt"
    if tools["gau"]:
        with _spin("gau: historical URL discovery"):
            rc, out, err = _run(
                ["gau", "--threads", "5", "--o", str(urls_file), domain],
                timeout=180,
            )
        _info(f"  gau: {_line_count(urls_file)} URLs")
    elif tools["waybackurls"]:
        with _spin("waybackurls: Wayback Machine URLs"):
            rc, out, err = _run(["waybackurls", domain], timeout=120)
            urls_file.write_text(out)
        _info(f"  waybackurls: {_line_count(urls_file)} URLs")

    # ── 5. JS endpoint / secret discovery ────────────────────────────────────
    js_secrets_file = out_dir / "js_secrets.txt"
    if tools["trufflehog"] and urls_file.exists():
        with _spin("trufflehog: scanning JS files for secrets"):
            rc, out, err = _run(
                ["trufflehog", "filesystem", str(out_dir), "--json"],
                timeout=120,
            )
            js_secrets_file.write_text(out)
        _info(f"  trufflehog: {out.count(chr(10))} findings")

    # ── 6. Header / security-policy audit ────────────────────────────────────
    headers_file = out_dir / "headers.txt"
    with _spin("curl: security header audit"):
        rc, out, err = _run(
            [
                "curl",
                "-sIL",
                "--max-time",
                "15",
                "-A",
                "Mozilla/5.0 (compatible; Oracle-Bounty/1.0)",
                f"https://{domain}",
            ],
            timeout=30,
        )
        headers_file.write_text(out)
    _info(f"  headers: {_line_count(headers_file)} lines")

    # ── 7. robots.txt ────────────────────────────────────────────────────────
    robots_file = out_dir / "robots.txt"
    rc, out, err = _run(
        ["curl", "-s", "--max-time", "10", f"https://{domain}/robots.txt"],
        timeout=15,
    )
    robots_file.write_text(out)

    # ── 9. Directory fuzz (light — 200 words) ─────────────────────────────────
    fuzz_file = out_dir / "fuzz.txt"
    if tools["ffuf"]:
        wordlist = _find_wordlist()
        if wordlist:
            with _spin("ffuf: light directory fuzz"):
                rc, out, err = _run(
                    [
                        "ffuf",
                        "-u",
                        f"https://{domain}/FUZZ",
                        "-w",
                        wordlist,
                        "-mc",
                        "200,204,301,302,307,401,403",
                        "-t",
                        "50",
                        "-of",
                        "json",
                        "-o",
                        str(fuzz_file),
                    ],
                    timeout=120,
                )
            _info(f"  ffuf: results in {fuzz_file.name}")

    # ── Save manifest ─────────────────────────────────────────────────────────
    results["finished"] = datetime.now().isoformat()
    (out_dir / "MANIFEST.json").write_text(json.dumps(results, indent=2))
    _info(f"\n✅ Recon complete → {out_dir}")
    return out_dir


# ─────────────────────────────────────────────────────────────────────────────
# Oracle 8-reflex analysis
# ─────────────────────────────────────────────────────────────────────────────


def _collect_recon_text(recon_dir: Path, max_chars: int = 18000) -> str:
    """Assemble recon files into a single string for the Oracle."""
    priority = [
        "robots.txt",
        "headers.txt",
        "js_secrets.txt",
        "live_hosts.txt",
        "subdomains.txt",
        "fuzz.txt",
        "nmap.txt",
        "all_urls.txt",
    ]
    chunks = []
    total = 0
    for name in priority:
        f = recon_dir / name
        if not f.exists():
            continue
        txt = f.read_text(errors="ignore")
        if not txt.strip():
            continue
        budget = min(len(txt), max_chars - total, 4000)
        chunks.append(f"### {name}\n{txt[:budget]}")
        total += budget
        if total >= max_chars:
            break
    return "\n\n".join(chunks)


def run_reflexes(
    recon_dir: Path, model: str = "qwen2.5:14b-instruct-q4_K_M", use_local: bool = True
) -> str:
    """Run the 8 Oracle reflexes against collected recon. Returns analysis text."""
    recon_text = _collect_recon_text(Path(recon_dir))
    if not recon_text.strip():
        return "[no recon data found in directory]"

    system = _oracle_prompt()
    task = (
        "Run all 8 Oracle reflexes against this in-scope bug-bounty target's recon data.\n\n"
        "For each candidate seam you find, output EXACTLY:\n"
        "  SEAM: <short title>\n"
        "  REFLEX: <which of the 8 reflexes applies>\n"
        "  ASSERTION A: <what the docs/policy/UI claims>\n"
        "  ASSERTION B: <what the wire protocol actually does or likely does>\n"
        "  CHECK: <one curl/wget command that proves it>\n"
        "  IMPACT: <one sentence — real harm to a real user>\n"
        "  SEVERITY: <critical|high|medium|low>\n\n"
        "Rank by SEVERITY then IMPACT. Strip noise. No essays.\n\n"
        f"--- RECON DATA ---\n{recon_text}"
    )

    if use_local:
        _info(f"\n🧠 Running Oracle reflexes via {model}…")
        try:
            result = subprocess.run(
                ["ollama", "run", model, "--system", system, task],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return f"[ollama error] {result.stderr.strip()}"
        except FileNotFoundError:
            _info(
                "[!] ollama not found — outputting paste-ready prompt for Claude/Gemini"
            )
        except subprocess.TimeoutExpired:
            return "[timeout — try a smaller model: --model qwen2.5:7b-instruct-q4_K_M]"

    # Cloud paste mode
    return f"=== PASTE THIS INTO CLAUDE / GEMINI ===\n\n{system}\n\n---\n\n{task}"


def cmd_analyze(recon_dir: str, model: str, local: bool):
    """Analyze an existing recon directory."""
    d = Path(recon_dir)
    if not d.exists():
        _die(f"Directory not found: {recon_dir}")
    analysis = run_reflexes(d, model=model, use_local=local)
    _show_analysis(analysis, d)


def cmd_reflexes(recon_dir: str, model: str, local: bool):
    """Print raw seams from the Oracle."""
    d = Path(recon_dir)
    if not d.exists():
        _die(f"Directory not found: {recon_dir}")
    analysis = run_reflexes(d, model=model, use_local=local)
    print(analysis)


def cmd_report(recon_dir: str, model: str, local: bool):
    """Generate a formatted bounty report from recon + analysis."""
    d = Path(recon_dir)
    if not d.exists():
        _die(f"Directory not found: {recon_dir}")

    manifest = {}
    mf = d / "MANIFEST.json"
    if mf.exists():
        manifest = json.loads(mf.read_text())

    analysis = run_reflexes(d, model=model, use_local=local)
    seams = _parse_seams(analysis)

    target = manifest.get("target", d.name)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    report = _format_report(target, ts, seams, analysis)

    report_file = (
        REPORTS_DIR / f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    report_file.write_text(report)
    _info(f"\n📄 Report saved: {report_file}")
    print(report)


def cmd_hunt(target: str, model: str, local: bool):
    """Full pipeline: recon → Oracle analysis → report."""
    recon_dir = recon(target)
    analysis = run_reflexes(recon_dir, model=model, use_local=local)
    _show_analysis(analysis, recon_dir)

    seams = _parse_seams(analysis)
    domain = sanitize_target(target)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    report = _format_report(domain, ts, seams, analysis)
    rf = REPORTS_DIR / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    rf.write_text(report)
    _info(f"\n📄 Report saved: {rf}")


# ─────────────────────────────────────────────────────────────────────────────
# Interactive REPL
# ─────────────────────────────────────────────────────────────────────────────


def cmd_interactive(model: str, local: bool):
    if RICH:
        console.print(
            Panel(
                "[bold cyan]Oracle Bounty Daemon[/bold cyan]\n"
                "Commands: hunt <target> · recon <target> · analyze <dir> · reflexes <dir> · "
                "report <dir> · check-tools · seam · quit",
                style="cyan",
            )
        )
    else:
        print("\n=== Oracle Bounty Daemon ===")
        print(
            "Commands: hunt · recon · analyze · reflexes · report · check-tools · seam · quit\n"
        )

    oracle = _InlineOracle()

    while True:
        try:
            raw = input("\noracle-bounty> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break
        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            print("Signing off.")
            break
        elif cmd == "hunt" and arg:
            cmd_hunt(arg, model, local)
        elif cmd == "recon" and arg:
            recon(arg)
        elif cmd == "analyze" and arg:
            cmd_analyze(arg, model, local)
        elif cmd == "reflexes" and arg:
            cmd_reflexes(arg, model, local)
        elif cmd == "report" and arg:
            cmd_report(arg, model, local)
        elif cmd in ("check-tools", "tools"):
            cmd_check_tools()
        elif cmd == "seam":
            oracle.seam_wizard()
        elif cmd == "help":
            print(
                "hunt <target> | recon <target> | analyze <dir> | reflexes <dir> | "
                "report <dir> | check-tools | seam | quit"
            )
        else:
            print(f"Unknown: {raw}  (type 'help')")


class _InlineOracle:
    """Quick binary-conflict / spec-audit wizard without needing a recon dir."""

    def seam_wizard(self):
        print("\n=== Binary Conflict Wizard ===")
        a = input("Assertion A (what docs/policy CLAIM): ").strip()
        b = input("Assertion B (what wire protocol DOES): ").strip()
        if not a or not b:
            print("Need both assertions.")
            return
        prompt = (
            f"{_oracle_prompt()}\n\n"
            "Run REFLEX 8 — Binary Conflict Isolation:\n\n"
            f"ASSERTION A: {a}\n"
            f"ASSERTION B: {b}\n\n"
            "Output:\n"
            "  - Which assertion is false and why\n"
            "  - ONE curl command that decides it\n"
            "  - Impact (one sentence)\n"
            "  - CVSS severity estimate"
        )
        print("\n⚙️  Asking Oracle…")
        try:
            r = subprocess.run(
                ["ollama", "run", "qwen2.5:14b-instruct-q4_K_M", prompt],
                capture_output=True,
                text=True,
                timeout=120,
            )
            print(r.stdout.strip() if r.returncode == 0 else r.stderr)
        except FileNotFoundError:
            print("[ollama not installed]")


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────


def _parse_seams(text: str) -> List[Dict]:
    """Extract SEAM blocks from Oracle output."""
    seams = []
    blocks = re.split(r"\n(?=SEAM:)", text)
    for block in blocks:
        if not block.strip().startswith("SEAM:"):
            continue
        s = {}
        for field in [
            "SEAM",
            "REFLEX",
            "ASSERTION A",
            "ASSERTION B",
            "CHECK",
            "IMPACT",
            "SEVERITY",
        ]:
            m = re.search(rf"{field}:\s*(.+?)(?=\n[A-Z ]+:|$)", block, re.DOTALL)
            s[field.lower().replace(" ", "_")] = m.group(1).strip() if m else ""
        seams.append(s)
    return seams


def _format_report(target: str, ts: str, seams: List[Dict], raw: str) -> str:
    lines = [
        f"# Oracle Bounty Report — {target}",
        f"*Generated: {ts}*\n",
        "---\n",
        f"## Target\n`{target}`\n",
    ]
    if seams:
        lines.append("## Findings\n")
        for i, s in enumerate(seams, 1):
            lines += [
                f"### Finding {i}: {s.get('seam', '?')}",
                f"**Severity:** {s.get('severity', '?')}  ",
                f"**Reflex:** {s.get('reflex', '?')}\n",
                f"**Assertion A (claim):** {s.get('assertion_a', '?')}  ",
                f"**Assertion B (behavior):** {s.get('assertion_b', '?')}\n",
                "**Reproducible Check:**",
                f"```bash\n{s.get('check', '')}\n```",
                f"**Impact:** {s.get('impact', '?')}\n",
            ]
    else:
        lines += ["\n## Raw Oracle Analysis\n", raw]

    return "\n".join(lines)


def _show_analysis(analysis: str, recon_dir: Path):
    seams = _parse_seams(analysis)
    if RICH and seams:
        console.print(
            Panel(f"[bold]Oracle found {len(seams)} seam(s)[/bold]", style="red")
        )
        for s in seams:
            sev_color = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "green",
            }.get(s.get("severity", "").lower(), "white")
            console.print(
                Panel(
                    f"[bold]{s.get('seam', '?')}[/bold]\n"
                    f"Reflex: {s.get('reflex', '?')}\n\n"
                    f"A: {s.get('assertion_a', '?')}\n"
                    f"B: {s.get('assertion_b', '?')}\n\n"
                    f"Check:\n  {s.get('check', '?')}\n\n"
                    f"Impact: {s.get('impact', '?')}",
                    title=f"[{sev_color}]{s.get('severity', '?').upper()}[/{sev_color}]",
                    style=sev_color,
                )
            )
    else:
        print(analysis)


def _find_wordlist() -> Optional[str]:
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def _line_count(f: Path) -> int:
    if not f.exists():
        return 0
    try:
        return f.read_text(errors="ignore").count("\n")
    except Exception:
        return 0


def _info(msg: str):
    if RICH:
        console.print(msg)
    else:
        print(msg)


def _die(msg: str):
    if RICH:
        console.print(f"[red]{msg}[/red]")
    else:
        print(msg)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Oracle Bounty Daemon — local recon + 8-reflex analysis engine"
    )
    parser.add_argument(
        "--model",
        default="qwen2.5:14b-instruct-q4_K_M",
        help="Ollama model tag (default: qwen2.5:14b-instruct-q4_K_M)",
    )
    parser.add_argument(
        "--no-local",
        action="store_true",
        help="Skip Ollama — output paste-ready prompt for Claude/Gemini",
    )

    sub = parser.add_subparsers(dest="command")
    p_hunt = sub.add_parser("hunt", help="Full pipeline: recon + reflexes + report")
    p_hunt.add_argument("target")

    p_recon = sub.add_parser("recon", help="Recon only (no analysis)")
    p_recon.add_argument("target")

    p_analyze = sub.add_parser(
        "analyze", help="Run Oracle analysis on existing recon dir"
    )
    p_analyze.add_argument("recon_dir")

    p_ref = sub.add_parser("reflexes", help="Run 8 reflexes, print raw seams")
    p_ref.add_argument("recon_dir")

    p_rep = sub.add_parser("report", help="Generate formatted report from recon dir")
    p_rep.add_argument("recon_dir")

    sub.add_parser("check-tools", help="Check which recon tools are installed")
    sub.add_parser("interactive", help="Interactive REPL mode")

    args = parser.parse_args()
    local = not args.no_local

    if args.command == "hunt":
        cmd_hunt(args.target, args.model, local)
    elif args.command == "recon":
        recon(args.target)
    elif args.command == "analyze":
        cmd_analyze(args.recon_dir, args.model, local)
    elif args.command == "reflexes":
        cmd_reflexes(args.recon_dir, args.model, local)
    elif args.command == "report":
        cmd_report(args.recon_dir, args.model, local)
    elif args.command == "check-tools":
        cmd_check_tools()
    else:
        cmd_interactive(args.model, local)


if __name__ == "__main__":
    main()
