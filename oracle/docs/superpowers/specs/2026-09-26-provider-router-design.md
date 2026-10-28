> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle Backend Provider Router — Design Spec

*Date: 2026-09-26*
*Status: DRAFT — awaiting user review*
*Scope: `oracle_hunter.py` (and a new `oracle_llm.py`)*

---

## 1. Problem

Oracle's model backend is hardcoded and brittle:

- `oracle_hunter.py:927–937` pins a static list of 9 OpenRouter "free" model IDs.
  Verified 2026-09-26: **2 of 9 are dead** (`nex-agi/nex-n2.5-pro:free`,
  `z-ai/glm-5.2:free`) and several of the rest are intermittently HTTP 429
  rate-limited. The list rots and no one edits it.
- Local model constants (`LOCAL_MODEL = "qwen2.5:3b"`, `FALLBACK_MODEL =
  "qwen2.5-coder:7b"` at lines 61–62) contradict the code's own docstring/comments
  and `FINISH_PLAN.md`, which expect `devstral:24b`.
- Backend selection logic is copy-pasted across five call sites
  (`_query_local`, `_query_openrouter`, `run_reflexes`, `_cloud_escalate`,
  `_assess_response`, `_correlate_seams`), each with its own ad-hoc
  cloud-vs-local branching.
- `cmd_audit` (`:1969`) references an undefined global `OPENROUTER_API_KEY`
  → `NameError` on `oracle-hunter audit <dir>` without an explicit `--cloud`/`--no-cloud` flag.

The machine actually has **five** usable backends (detected 2026-09-26):
`claude`, `copilot`, `gemini`, `bob` (interactive agent CLIs), `ollama`
(local HTTP, models currently on unmounted `AI_DRIVE`), plus OpenRouter (HTTP,
key present and working — 17 free models visible).

## 2. Goal

One settings-driven backend router. No model IDs in source. Every LLM call in
Oracle goes through a single entry point that picks a backend from user config,
discovers OpenRouter models live, and cascades to a backup when one is
down/rate-limited — so a job **always finds something that answers**, at the
lowest configured cost.

## 3. Roles (agreed with user)

| Tier | Backend(s) | Role |
|---|---|---|
| **Driver** | one of `claude`/`copilot`/`gemini`/`bob` | The interactive agent the user runs; orchestrates Oracle. Also callable **headless** for deep PoC synthesis (a strong agent writing an exploit beats a free model). |
| **Workhorse** | OpenRouter | Oracle's internal LLM calls (reflex pass, triage, correlation). Model list discovered live. |
| **Floor** | `ollama` (local) | **Optional.** Cheap/offline tasks + last-resort fallback. Skipped silently when unavailable; the system runs fully on CLI + OpenRouter with no local model. |

## 3.1 Empirical test findings (2026-09-26 — real reflex prompt on `recon/127.0.0.1_3000`)

Ran Oracle's actual reflex prompt through each live backend. Results **overturn**
the pre-test assumption that local `devstral` should lead deep work:

- **OpenRouter** produced 3 well-formed cards (real OWASP Juice Shop seams). It is
  the only backend that both works *and* accepts the task. Its 181s latency was
  caused entirely by the hardcoded dead/429 model list — §6 live discovery fixes it.
- **`claude` CLI refuses the real task.** Trivial prompts pass, but the security
  reflex prompt returned rc=1: *"safeguards flagged this session … Details: `[cyber]`."*
  → `claude`/agent CLIs on strong-safeguard models are **not** reliable reflex
  backends; keep them for benign/driver use only. Router must treat a refusal as a
  `BackendError` and cascade.
- **local `devstral:24b` — speed inconclusive.** In the combined run it didn't
  return within its leftover budget, but that run was unfair to it: the 14 GB model
  was **cold-loaded off the just-mounted external drive** and only got the time left
  after OpenRouter (181s) and claude ran first. The operator reports devstral is
  acceptable on this hardware. A fair standalone (warm, full budget) benchmark is
  pending; until it lands, devstral stays a first-class deep-route option, not
  demoted to batch-only.
- **A separate, confirmed parser bug** (`oracle_hunter.py:1541`): `_parse_seams`
  only matches `**SEAM**`/`# SEAM`; a bare `SEAM 1` header yields **0 parsed cards**
  even when the body is perfect. Verified: bare→0, bolded→1. This silently discarded
  all 3 OpenRouter cards. **Fix precedes/accompanies the router** — a perfect backend
  is worthless if the parser eats its output. Relax the header regex to also accept
  a line-start `SEAM\s*\d+` with no bold/heading marker; add a regression test.

**Corrected default routes:** deep (`reflex`,`poc`,`correlate`) → OpenRouter first,
then local `devstral`, then `copilot` (cost-flagged, opt-in). `claude` CLI stays out
of the deep routes (refuses). Light (`assess`,`draft`) → small local model first
(fast, free), OpenRouter fallback. Ordering of OpenRouter vs local `devstral` for
deep work is provisional pending the standalone devstral benchmark.

## 4. Non-goals (YAGNI)

- No parallel ensemble / voting **at runtime** (the user chose fallback-cascade,
  not fan-out). Cross-backend comparison exists only as an explicit test command
  (§9), never on the hot path.
- No new provider SDKs. CLI backends are driven as subprocesses; HTTP backends
  use the existing `urllib`/`requests` calls.
- No config UI. Settings are a JSON file + `.env` for secrets.
- No changes to recon, scope-gate, or seam-parsing logic.

## 5. Architecture

### 5.1 New module: `oracle_llm.py`

Isolates the router so `oracle_hunter.py` shrinks and the router is unit-testable
alone. Contains: the adapters, the router, the config loader, and the single
`complete()` entry point.

### 5.2 Two adapter shapes

Common contract:

```python
class Backend:
    name: str
    def available(self) -> bool: ...            # cheap liveness probe
    def complete(self, system: str, prompt: str,
                 timeout: Optional[int]) -> str: ...   # raises BackendError on failure
```

- **`HttpBackend`** — for OpenRouter and ollama.
  - `OpenRouterBackend`: reads key from `.env`. Model chosen via **live discovery**
    (§6). On HTTP 429 / provider error for a model, raises `BackendError` so the
    model-cascade (inside the adapter) tries the next discovered model; when all
    discovered models fail, the adapter itself raises and the **router** moves to
    the next backend.
  - `OllamaBackend`: POSTs to `http://localhost:11434/api/generate`. `available()`
    returns False (no raise) when ollama is down or its model store is unmounted —
    this is how "local optional" is honored.
- **`CliBackend`** — for `claude`/`copilot`/`gemini`/`bob`.
  - One-shot subprocess, system+prompt fed in, stdout captured, timeout enforced.
  - Non-interactive invocation is `<cli> -p "<prompt>"` for all four (verified via
    `--help` 2026-09-26). A CLI whose headless call can't be established or fails
    its liveness probe is marked unavailable, never invoked blindly.
  - **Verified viability (spike, 2026-09-26 — one trivial one-shot call each):**
    | CLI | Result | Note |
    |---|---|---|
    | `claude -p` | ✅ works | 7s, clean output — the default CLI backend |
    | `copilot -p` | ⚠️ works, costly | 20s; **0.38 AI credits / 15.3k tokens** for a trivial prompt → deep/occasional use only, never bulk reflex volume |
    | `gemini -p` | ❌ 90s timeout | no return; needs auth/first-run debugging before it counts |
    | `bob -p` | ❌ blocked | requires `BOB_API_KEY` (not set) |
  - Implication for default `routes` (§7): bulk work (`reflex`, `assess`,
    `correlate`) → OpenRouter free first; `poc` → `claude` CLI first. `copilot` is
    an opt-in deep backend (cost-flagged). `gemini`/`bob` ship configured-but-
    -unavailable until fixed, so `available()` returning False keeps them out of
    rotation automatically.

### 5.3 The router

```python
def complete(prompt: str, system: str, task_type: str,
             timeout: Optional[int] = None) -> str
```

- Loads config (§7), gets the ordered backend list for `task_type`.
- Walks the list: for each backend, `if not b.available(): log+skip`; else
  `try b.complete(...) → return`; on `BackendError`, log the reason and continue.
- **All backends exhausted → raise `RuntimeError`** with the per-backend failure
  reasons. Never returns fabricated or placeholder text. (Honors the user's
  "no silent fallback — scream loudly" rule: the *inter-backend* cascade is the
  requested feature; exhaustion is loud, not swallowed.)

### 5.4 Call-site migration

Every existing model call routes through `complete()` with a `task_type`:

| Call site | task_type |
|---|---|
| `run_reflexes` | `reflex` (deep) |
| `_assess_response` | `assess` (light) |
| `_synthesize_poc` / `_cloud_escalate` | `poc` (deep) |
| `_correlate_seams` | `correlate` (mid) |
| email/SMS drafting (`oracle_email.py`, later) | `draft` (light) |

`_query_local` and `_query_openrouter` become thin shims over `complete()` (or are
deleted once no caller remains). `cmd_audit:1969` `NameError` is fixed as part of
this migration — it will ask the router whether any backend is available instead
of reading an undefined global.

## 6. OpenRouter live model discovery

- `GET https://openrouter.ai/api/v1/models` with the key → filter to `:free`
  (unless config sets `allow_paid: true`, then include a configured allow-list).
- Cache the resolved list to `recon/.openrouter_models.json` with a **1-hour TTL**
  to avoid a network round-trip per call.
- A per-task `preferred_models` list in config is honored first; unknown/dead IDs
  are dropped against the discovered set; 429s advance to the next model.
- Result: dead IDs like `z-ai/glm-5.2:free` can never again wedge the pipeline.

## 7. Settings

Secrets stay in `.env` (unchanged). Routing policy moves to a new
`oracle_backends.json` (settings only, no secrets):

```json
{
  "driver_cli": "claude",
  "allow_paid_openrouter": false,
  "local_enabled": true,
  "local_model": "devstral:24b",
  "routes": {
    "reflex":    ["openrouter", "local"],
    "poc":       ["openrouter", "copilot", "local"],
    "assess":    ["local", "openrouter"],
    "correlate": ["openrouter", "local"],
    "draft":     ["local", "openrouter"]
  },
  "_note": "claude CLI omitted from deep routes: refuses [cyber] tasks (verified 2026-09-26). local=devstral; deep openrouter-vs-local order provisional pending benchmark. copilot cost-flagged.",
  "openrouter": {
    "reflex_preferred":  ["nvidia/nemotron-3-super-120b-a12b:free", "google/gemma-4-31b-it:free"],
    "assess_preferred":  ["liquid/lfm-2.5-2.6b:free", "cohere/north-mini-code:free"]
  }
}
```

- `local_enabled: false` (or ollama simply being down) removes `local` from every
  route at load time — the CLI + OpenRouter-only mode the user asked for.
- Missing required keys raise `KeyError` (no masking defaults), except the
  `.env`-style optional keys.
- A shipped `oracle_backends.example.json` documents every field.

## 8. `oracle-hunter status` (Phase D gate)

Extended to print, for each backend: configured? available? (live probe), and for
OpenRouter the count of free models currently reachable. This is the
`FINISH_PLAN` Phase D gate — "status lists which providers are live."

## 9. Test-and-compare mode (user request + Phase A gate)

New subcommand:

```
oracle-hunter backends test [--task reflex] [--recon-dir <dir>]
```

Runs one fixed sample (or a real recon dir's reflex prompt) across **every
configured & available backend**, prints each backend's output, latency, and
success/failure side by side. This is how we prove which backend gives real cards
(`FINISH_PLAN` Phase A) and compare CLI vs OpenRouter vs local — without making
comparison a runtime cost.

## 10. Error handling

- Specific exceptions only (`BackendError` subclasses); no bare `except:`.
- Every skipped/failed backend logs *why* (`_warn`).
- Router exhaustion raises; callers that today expect a string get a real error
  instead of `[ollama error] ...` sentinel strings leaking into reports.
- CLI subprocesses: hard timeout, captured stderr surfaced in the `BackendError`.

## 11. Testing (Phase E alignment)

- `test_llm_router.py`:
  - route selection returns configured order per task_type;
  - cascade skips unavailable, advances past `BackendError`, returns first success;
  - all-exhausted raises `RuntimeError` (not a sentinel string);
  - `local_enabled:false` and ollama-down both drop `local` from routes.
- OpenRouter discovery: parse a mocked `/models` payload, drop dead IDs, honor TTL cache.
- `CliBackend`: driven against a fake echo binary to prove the subprocess contract.
- All with mocked adapters/HTTP — no live network in CI.

## 12. Rollout

1. Add `oracle_llm.py` + `oracle_backends.example.json` + tests (green).
2. Migrate call sites one at a time, verifying each still runs.
3. Delete the hardcoded `free_models` list and the dead-ID cruft.
4. Fix `cmd_audit:1969`.
5. Update `status`, add `backends test`.
6. Update `SESSION_STATUS.md` (currently stale).

Note: this directory is **not a git repo**, so the spec is written but not
committed. Say the word if you want it under version control.
