# Oracle Daemon Setup Guide

Two daemons, both live in this folder.

---

## Daemon 1 — `oracle-email` (Gmail + approval gate)

**No OAuth. No GCP project. No credentials file.** (An earlier edition of this
guide walked through Gmail-OAuth setup; that path has been deliberately removed
from the product. Do not follow it.)

- **Read:** Gmail scraped via WebPipe/CDP against your signed-in **Firefox**
  session (`BrowserSession`, CDP port **9222** by default; `--webpipe-cdp`).
- **Send:** real CDP mouse/keyboard clicks inside that session (human-input
  path), behind the approval queue — nothing sends without approval.
- **Config:** `~/.config/trio/daemon.json`.

### Setup
1. Start Firefox with remote debugging on 9222 and sign in to Gmail yourself.
2. Run `oracle-email` — it attaches to the existing session. There are no
   tokens to mint and nothing to paste.

```bash
oracle-email                    # interactive TUI
oracle-email inbox              # list inbox (20 most recent)
oracle-email read <message_id>  # read full message
oracle-email compose            # write → approval gate → queue
oracle-email reply <message_id> # Oracle drafts reply → approval gate
oracle-email queue              # see what's waiting to send
oracle-email approve <draft_id> # review final time → send
```

### How the approval gate works

Every outbound email goes into a **queue** (`email_queue.json`).
Nothing sends until YOU run `oracle-email approve <id>`.
The `reply` command calls your local Ollama model (Oracle email persona)
to draft the reply as you — profanity-off, direct, honest.
You see the draft, choose: send now / queue / edit / discard.

---

## Daemon 2 — Oracle hunter (bug bounty engine)

> Historical note: this section once documented the `oracle-bounty` wrapper
> CLI (`oracle_bounty.py`: hunt/recon/analyze/reflexes/report/interactive).
> That legacy local engine still exists and runs, but it is not the
> production path. The production entry point is `oracle_hunter.py`;
> `oracle.py` remains the prompt feeder (`--feed/--local`).

### Models (local floor — API lanes are primary)

```bash
# Shipped model names (oracle_backends.json / oracle_llm defaults):
#   qwen3-coder:30b-16k    heavy local floor
#   qwen2.5-coder:14b-16k  light local model
# If `ollama pull <name>` fails, the tag is a local Modelfile build — create it locally.
```

### Recon tools

```bash
command -v subfinder httpx katana nuclei dnsx   # expected in ~/go/bin
```

### Usage

```bash
# One target, full pipeline (recon → Oracle analysis → wire verify → drafts):
python3 oracle_hunter.py hunt <program-or-target>

# The production chain (Scan4Me DB must be synced first):
python3 oracle_hunter.py prescan --limit 24
python3 oracle_hunter.py scan --prescan-file <prescan.json> -N 3 --download --cdp-port 9227
python3 oracle_hunter.py queue --handoff <intake.json> --execute --max-items 1 --controlled --cdp-port 9227

# Resume analysis on an existing workspace/recon:
python3 oracle_hunter.py analyze targets/<platform>/<slug>

# Verify installation health:
python3 oracle_hunter.py status
python3 tests/run_all.py   # full verification gate (set NO_PROXY=127.0.0.1,localhost)
```

### What a hunt does

1. **Recon** — subfinder/httpx/katana/dnsx + CDP JS surfacing + inline-handler mining
2. **Downloads** — scope refreshed from source; CDP-authoritative program page +
   independent corroboration renders (see `ORACLE_DOCTRINE.md` §3/§7)
3. **Mindset passes** — MITRE + Paradox lenses over the API lanes, template seams
4. **Wire verify** — gate ladder; nothing confirms without live proof
5. **Chain + draft** — one-step severity compounding; manual review before any submit

### Philosophy

This is not a script-kiddie scanner. The Oracle doesn't dump 50,000 lines.
It runs the 8 reflexes and for each seam outputs:
- **Assertion A** — what the target *claims*
- **Assertion B** — what the wire *does*
- **One curl** — the proof
- **Impact** — one sentence, real user harm

That's your bug report. Clean. No log dumps.

---

## Recon output structure

```
recon/
  example.com/
    20250101_120000/
      nmap.txt
      subdomains.txt
      live_hosts.txt
      all_urls.txt
      headers.txt
      robots.txt
      nuclei.txt
      js_secrets.txt
      fuzz.txt
      MANIFEST.json

reports/
  example.com_20250101_120000.md
```
