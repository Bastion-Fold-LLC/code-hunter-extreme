> **HISTORICAL — email-session snapshot, superseded by `STATUS.md` (kept as a session record; do not treat as current system status).** Port corrections: email Firefox CDP is **9222**; hunt Chromium CDP is **9227**. Voice-model claims below (`qwen2.5:3b`) predate the shipped harness (`qwen3-coder:30b-16k` heavy / `qwen2.5-coder:14b-16k` light).

# Oracle / Vortex Session Status
*Last updated: email system rewrite — WebPipe CDP, no OAuth*

---

## What We Are Building

### 1. Oracle Email Daemon (`oracle_email.py`) — ✅ COMPLETE
- **No OAuth, no GCP, no credentials file needed**
- Gmail read via WebPipe CDP (your real Chrome session on port 9225)
- Gmail send via real CDP mouse/keyboard clicks (HumanInput, isTrusted=true)
- LinkedIn Connection Map spider — **toggle on/off with `--spider`** (off by default)
  - Never sends anything — only ranks who to connect with, surfaces next-to-add.md
  - Uses Connection Map's own budget caps (25-30 page loads max)
- Background daemon mode — polls inbox every 2 min, notify-send + SMS on new mail
- SMS via T-Mobile gateway (`{number}@tmomail.net`) — same click-send path as email
- WebPipe recon subcommand — bug bounty targets only, politeness cooldown enforced
- Approval queue — draft → review → approve → send
- Oracle-voice reply drafting via local `qwen2.5:3b`

**Usage:**
```bash
oracle-email                    # interactive TUI
oracle-email inbox              # list inbox
oracle-email compose            # compose + real click send
oracle-email daemon --phone 5551234567  # background polling + SMS
oracle-email --spider spider    # run Connection Map cycle
oracle-email recon <url>        # bug bounty target recon
oracle-email sms "message" --phone 5551234567
```

**Requires:** Chrome running with `--remote-debugging-port=9225`

### 2. Oracle Programs (`oracle_programs.py`) — BUILT
- Scrapes HackerOne, Bugcrowd, Intigriti, HackenProof, Immunefi, Bugbase, YesWeHack, HatsFinance
- Filters by min payout, platform, fast-triage, web2/web3
- Caches results 6 hours
- Ranks by payout desc
- `oracle-programs` launcher — CREATED (`./oracle-programs`)

### 3. Oracle Hunter (`oracle_hunter.py`) — BUILT (2150 lines)
- Reads scope/assets for a target program (ProgramScopeGate)
- Runs recon + Oracle 8-reflex pipeline → seam cards → verify → PoC → report
- All LLM calls now flow through the **backend router** (`oracle_llm.py`),
  configured via `oracle_backends.json` (see `oracle_backends.example.json`):
  CLI agents (claude/copilot/gemini/bob) / OpenRouter (live model discovery) /
  local ollama, cascading with a fail-closed exhaustion error. Model IDs are
  no longer hardcoded. `oracle-hunter status` shows live backends per task;
  `oracle-hunter backends test [--task]` compares them side by side.
- Deep tasks default to OpenRouter first, local `devstral:24b` next (local is
  optional / skipped when ollama or the drive is down).

### 4. Oracle Bounty Daemon (`oracle_bounty.py`) — BUILT (original)
- Web2 recon + Oracle 8-reflex analysis
- `oracle-bounty` launcher fixed — DONE

---

## The Full Stack Architecture

```
VORTEX SYSTEM (super-repo — pins the blessed trio)
    │
    ├── BASILISK          — FIND half, deterministic, NO LLM
    │     fang/* (static EVM detectors)
    │     coil/* (fuzz)
    │     hiss/* (taint/dataflow)
    │     gaze/* (recon/classify — steers others)
    │     venom/* (symbolic/range)
    │     scale/hunt/* (multi-chain)
    │     Engine: FindOrganism (IntelBlob round loop, convergence)
    │     Output: Finding → CodeCrusher detector port
    │
    ├── CODECRUSHER       — PROVE/JUDGE/SEAL, LLM lives here
    │     ingest → scan → court (LLM dialectic) → exploit synth
    │     → fork-replay (anvil) → one real CONFIRMED → receipt spine
    │     Argus/Splunk: ArgusDetector reads SPL candidates → fork-prove
    │     SplunkHEC: sends all events to omni_guard_security index
    │
    └── VORTEX ANCHOR     — thin conductor
          eyes (scope scraper, payout-rank assets)
          FIND (Basilisk organism) → PROVE (CodeCrusher)
          → JUDGE → SEAL (receipt + on-chain anchor)
          VZMQ bus, IDZMQ artifact correlation
```

**Rule:** Basilisk = engine (deterministic). CodeCrusher = LLM layer. Vortex = conductor.

---

## GH Repo Status

- **Auth:** Switched to `Alexander-Sorrell-IT` (was `matrixbuilderops`) ✅
- Both accounts saved in keyring — switch with `gh auth switch --user Alexander-Sorrell-IT`

| Repo | Local HEAD | GH HEAD | Status |
|---|---|---|---|
| vortex-anchor | `1c8e8bc` Jun 26 | `1c8e8bc` Jun 26 | ✅ In sync (minor uncommitted: vzmq.py +28 lines + 1 test) |
| basilisk | `c643627` (Step 2 batch 3) | `6389456` Jun 30 | ⚠️ Local AHEAD — needs push |
| codecrusher | `41852e4` local | `1e7c162` Jun 16 | ⚠️ Local AHEAD — needs push |
| vortex-system | submodule super-repo | exists on GH | needs submodule pointer bump after pushes |

**Action needed (you run these):**
```bash
# Basilisk
cd /media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/vortex-system/basilisk
git push origin master

# CodeCrusher  
cd /media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/vortex-system/codecrusher
git push origin master

# Vortex anchor — commit the two local changes first
cd /media/phantomcore/AI_DRIVE/VORTEX_SYSTEM/vortex
git add plugins/vzmq.py tests/test_idzmq_persist.py
git commit -m "IDZMQ persist + vzmq hardening"
git push origin master
```

---

## Splunk

- **Installed locally:** `/opt/splunk/bin/splunk`
- **Ports:** HEC on 8088, mgmt on 8089, web on 8000
- **Already wired in CodeCrusher:**
  - `codecrusher/validate/splunk_hec.py` — sends events via HEC
  - `codecrusher/plugins/argus_detector.py` — reads SPL candidates
  - Index: `omni_guard_security`
- **Needs:** `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN` in `.env`
- **Password saved at:** `~/.splunk_admin_pass`

---

## Models on This Machine (Ollama)

| Model | Size | Use |
|---|---|---|
| `qwen2.5:3b` | 1.9GB | Email drafting, SMS notifications, lightweight summaries |
| `qwen2.5:14b` | 9.0GB | Mid-tier analysis |
| `devstral:24b` | 14GB | Deep security analysis, Oracle 8-reflex |
| `qwen3-coder:30b` | 18GB | Exploit synthesis, CodeCrusher court |
| `mixtral:8x7b` | 38GB | Heavy lifting when needed |

---

## SMS / Phone Notifications

- **Carrier:** T-Mobile
- **Gateway:** `{number}@tmomail.net`
- **Method:** Oracle email daemon sends email to gateway address via Gmail
- **Zero cost, zero extra account** — Gmail already wired
- **Status:** NOT YET WIRED — needs ~30 lines added to oracle_email.py

---

## Next Steps (in order)

1. **Wire SMS** into oracle_email.py — T-Mobile gateway, triggered on: new email, CONFIRMED finding, high-priority alert
2. **Add background daemon mode** to oracle_email.py — polling loop + notify-send
3. **Build oracle_hunter.py** — Program 2, reads scope, runs recon + Vortex pipeline
4. **Push local-ahead repos** to GH (basilisk, codecrusher, vortex-anchor)
5. **Wire Splunk** — add HEC URL + token to .env, pipe Oracle findings → omni_guard_security index
6. **M2: wire Basilisk finders into Vortex conductor** — the critical path to first CONFIRMED

---

## Bug Bounty Platforms Covered

HackerOne (API), Bugcrowd, Intigriti, HackenProof (API), Immunefi, Bugbase, YesWeHack, HatsFinance
— Plus suggestions: Cantina, Code4rena, Codehawks, Hats Finance, Remedy, YesWeHack

---

## Oracle Voice / Mindset

- `ORACLE_SYSTEM_PROMPT.md` — 8 paradox→reflex worked examples
- `ORACLE_VOICE.md` + `ORACLE_EMAIL.md` — persona files for email drafting
- Core reflex: "You never said." — find the gap between what the spec CLAIMS and what is ENFORCED
- Output format: Assertion A (claim) vs Assertion B (wire behavior) + one curl PoC + impact

---

## Files in oracle-main-extracted/oracle-main/

- `oracle_email.py` — Gmail daemon (needs daemon mode + SMS)
- `oracle_bounty.py` — Web2 recon + Oracle analysis
- `oracle_programs.py` — NEW: multi-platform program discovery
- `oracle.py` — Oracle prompt generator / local model driver
- `oracle-email` — launcher (fixed, hardcoded path)
- `oracle-bounty` — launcher (fixed, hardcoded path)
- `ORACLE_SYSTEM_PROMPT.md` — the 8 reflexes
- `ORACLE_VOICE.md` — persona
- `SETUP.md` — setup guide
- `WIRING.md` — how to wire Oracle into models
