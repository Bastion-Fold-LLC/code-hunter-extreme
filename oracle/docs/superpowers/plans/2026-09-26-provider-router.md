> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Oracle Backend Provider Router — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Oracle's hardcoded model list with one settings-driven router (`complete(prompt, system, task_type)`) that every LLM call flows through, cascading across CLI / OpenRouter / local backends.

**Architecture:** New isolated module `oracle_llm.py` holds a config loader, two adapter shapes (HTTP for OpenRouter+ollama, subprocess for CLI agents), live OpenRouter model discovery, and a cascade router. `oracle_hunter.py` call sites are migrated to call `complete()`. Routing policy lives in `oracle_backends.json`; secrets stay in `.env`.

**Tech Stack:** Python 3.12, `requests`/`urllib`, `subprocess`, `pytest`. No new third-party deps.

**Spec:** `docs/superpowers/specs/2026-09-26-provider-router-design.md`

## Global Constraints

- No model IDs hardcoded in source — OpenRouter models come from live discovery (`/api/v1/models`), cached 1h in `recon/.openrouter_models.json`.
- Secrets only in `.env` (loaded via existing `oracle_hunter._load_env`); routing policy only in `oracle_backends.json`. Missing *required* config keys raise `KeyError` (no masking defaults).
- The inter-backend cascade is the requested feature; **exhaustion of all backends raises `RuntimeError`** — never return a sentinel/placeholder string.
- No bare `except:`. Every skipped/failed backend logs why via `oracle_hunter._warn`.
- `claude` CLI is excluded from deep routes (verified 2026-09-26: refuses `[cyber]` tasks). `copilot` is cost-flagged/opt-in. Local `devstral` order vs OpenRouter is data in config, not code.
- Do not touch recon, scope-gate, or seam-parsing logic. Do not fix the pre-existing `console`/`Panel` Pyright warnings.

## Review Focus

- **Empty/missing `oracle_backends.json`** → loader must fall back to a documented built-in default route map, not crash. (Task 1 test.)
- **OpenRouter key absent** → `OpenRouterBackend.available()` returns False (skip), never raises. (Task 3 test.)
- **All backends in a route unavailable/failing** → router raises `RuntimeError` naming each reason, not a silent "" or sentinel. (Task 5 test.)
- **CLI returns non-zero / refusal text** (e.g. claude `[cyber]`) → treated as `BackendError` so the router cascades past it. (Task 4 test.)
- **ollama down / model store unmounted** → `OllamaBackend.available()` returns False; `local_enabled:false` removes `local` from every route at load. (Task 1 + Task 3 tests.)

---

### Task 1: Backend config loader + example config

**Files:**
- Create: `oracle_backends.example.json`
- Create: `oracle_llm.py` (start it here — config section only)
- Test: `tests/test_llm_config.py`

**Interfaces:**
- Produces: `load_backend_config(path: Optional[Path] = None) -> dict`. Returns a dict with keys `driver_cli:str`, `allow_paid_openrouter:bool`, `local_enabled:bool`, `local_model:str`, `light_local_model:str`, `routes:Dict[str,List[str]]`, `openrouter:dict`, `cli:Dict[str,str]`. When the JSON file is absent, returns `DEFAULT_CONFIG`. When present, the file is shallow-merged over `DEFAULT_CONFIG`. If `local_enabled` is False, every list in `routes` has `"local"` removed.
- Produces: `DEFAULT_CONFIG: dict` (module constant).

- [ ] **Step 1: Write `oracle_backends.example.json`**

```json
{
  "driver_cli": "claude",
  "allow_paid_openrouter": false,
  "local_enabled": true,
  "local_model": "devstral:24b",
  "light_local_model": "qwen2.5:3b",
  "routes": {
    "reflex":    ["openrouter", "local"],
    "poc":       ["openrouter", "copilot", "local"],
    "assess":    ["local", "openrouter"],
    "correlate": ["openrouter", "local"],
    "draft":     ["local", "openrouter"]
  },
  "openrouter": {
    "reflex_preferred": ["nvidia/nemotron-3-super-120b-a12b:free", "google/gemma-4-31b-it:free"],
    "assess_preferred": ["liquid/lfm-2.5-2.6b:free", "cohere/north-mini-code:free"]
  },
  "cli": {
    "claude": "claude -p",
    "copilot": "copilot -p",
    "gemini": "gemini -p",
    "bob": "bob -p"
  }
}
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_llm_config.py
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L

def test_absent_file_returns_default():
    cfg = L.load_backend_config(Path("/nonexistent/oracle_backends.json"))
    assert cfg["routes"]["reflex"] == ["openrouter", "local"]

def test_local_disabled_strips_local_from_routes(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"local_enabled": False}))
    cfg = L.load_backend_config(p)
    assert all("local" not in r for r in cfg["routes"].values())

def test_file_overrides_merge(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"driver_cli": "gemini"}))
    cfg = L.load_backend_config(p)
    assert cfg["driver_cli"] == "gemini"
    assert "reflex" in cfg["routes"]  # default preserved
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_config.py -v`
Expected: FAIL (`ModuleNotFoundError: oracle_llm`).

- [ ] **Step 4: Write `oracle_llm.py` config section**

```python
#!/usr/bin/env python3
"""Oracle backend provider router — settings-driven multi-backend LLM access."""
import json, copy
from pathlib import Path
from typing import Optional, List, Dict

_HERE = Path(__file__).resolve().parent
_CONFIG_PATH = _HERE / "oracle_backends.json"

DEFAULT_CONFIG: dict = {
    "driver_cli": "claude",
    "allow_paid_openrouter": False,
    "local_enabled": True,
    "local_model": "devstral:24b",
    "light_local_model": "qwen2.5:3b",
    "routes": {
        "reflex":    ["openrouter", "local"],
        "poc":       ["openrouter", "copilot", "local"],
        "assess":    ["local", "openrouter"],
        "correlate": ["openrouter", "local"],
        "draft":     ["local", "openrouter"],
    },
    "openrouter": {},
    "cli": {"claude": "claude -p", "copilot": "copilot -p",
            "gemini": "gemini -p", "bob": "bob -p"},
}

def load_backend_config(path: Optional[Path] = None) -> dict:
    path = path or _CONFIG_PATH
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path.exists():
        try:
            user = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid {path}: {e}") from e
        cfg.update({k: v for k, v in user.items() if k != "routes"})
        if "routes" in user:
            cfg["routes"].update(user["routes"])
    if not cfg.get("local_enabled", True):
        cfg["routes"] = {k: [b for b in v if b != "local"]
                         for k, v in cfg["routes"].items()}
    return cfg
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_config.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add oracle_llm.py oracle_backends.example.json tests/test_llm_config.py
git commit -m "feat(llm): settings-driven backend config loader"
```

---

### Task 2: OpenRouter live model discovery + TTL cache

**Files:**
- Modify: `oracle_llm.py` (add discovery)
- Test: `tests/test_llm_discovery.py`

**Interfaces:**
- Consumes: `load_backend_config` (Task 1).
- Produces: `discover_openrouter_models(api_key: str, allow_paid: bool = False, cache_path: Optional[Path] = None, ttl: int = 3600, _now: Optional[float] = None, _fetch=None) -> List[str]`. Returns model IDs; when `allow_paid` False, only IDs ending `:free`. Writes/reads a JSON cache `{ "ts": float, "models": [...] }`; a cache younger than `ttl` short-circuits the network. `_fetch` (a callable returning the parsed `/models` JSON dict) is injected in tests.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_discovery.py
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L

_PAYLOAD = {"data": [
    {"id": "vendor/big:free"}, {"id": "vendor/small:free"}, {"id": "vendor/paid"},
]}

def test_filters_free_only(tmp_path):
    got = L.discover_openrouter_models("k", allow_paid=False,
                                       cache_path=tmp_path / "c.json",
                                       _fetch=lambda key: _PAYLOAD)
    assert got == ["vendor/big:free", "vendor/small:free"]

def test_allow_paid_includes_all(tmp_path):
    got = L.discover_openrouter_models("k", allow_paid=True,
                                       cache_path=tmp_path / "c.json",
                                       _fetch=lambda key: _PAYLOAD)
    assert "vendor/paid" in got

def test_cache_hit_skips_fetch(tmp_path):
    cache = tmp_path / "c.json"
    cache.write_text(json.dumps({"ts": 1000.0, "models": ["cached:free"]}))
    calls = []
    got = L.discover_openrouter_models("k", cache_path=cache, ttl=3600,
                                       _now=lambda: 1100.0,
                                       _fetch=lambda key: calls.append(1) or _PAYLOAD)
    assert got == ["cached:free"] and not calls
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_discovery.py -v`
Expected: FAIL (`AttributeError: discover_openrouter_models`).

- [ ] **Step 3: Implement discovery in `oracle_llm.py`**

```python
import time, urllib.request

def _http_fetch_models(api_key: str) -> dict:
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/models",
        headers={"Authorization": f"Bearer {api_key}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())

def discover_openrouter_models(api_key, allow_paid=False, cache_path=None,
                               ttl=3600, _now=None, _fetch=None):
    now = (_now or time.time)()
    cache_path = cache_path or (_HERE / "recon" / ".openrouter_models.json")
    if cache_path.exists():
        try:
            c = json.loads(cache_path.read_text())
            if now - c.get("ts", 0) < ttl and c.get("models"):
                return c["models"]
        except (json.JSONDecodeError, OSError):
            pass
    fetch = _fetch or _http_fetch_models
    data = fetch(api_key)
    ids = [m["id"] for m in data.get("data", [])]
    if not allow_paid:
        ids = [i for i in ids if i.endswith(":free")]
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"ts": now, "models": ids}))
    except OSError:
        pass
    return ids
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_discovery.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_llm.py tests/test_llm_discovery.py
git commit -m "feat(llm): live OpenRouter model discovery with TTL cache"
```

---

### Task 3: Backend base + HTTP adapters (OpenRouter, ollama)

**Files:**
- Modify: `oracle_llm.py`
- Test: `tests/test_llm_http_backends.py`

**Interfaces:**
- Produces: `class BackendError(Exception)`.
- Produces: `class Backend` with `name: str`, `available() -> bool`, `complete(system: str, prompt: str, timeout: Optional[int]) -> str`.
- Produces: `class OpenRouterBackend(Backend)` — `__init__(self, task_type, cfg, env)`; `available()` True iff `env.get("OPENROUTER_API_KEY")`; `complete()` discovers models (task-specific `<task>_preferred` first, then discovered list), POSTs chat/completions, raises `BackendError` if every model 429s/fails.
- Produces: `class OllamaBackend(Backend)` — `__init__(self, model, url="http://localhost:11434")`; `available()` True iff `GET {url}/api/tags` returns 200; `complete()` POSTs `/api/generate`, raises `BackendError` on non-200 or exception.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_http_backends.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import pytest

def test_openrouter_unavailable_without_key():
    b = L.OpenRouterBackend("reflex", L.DEFAULT_CONFIG, env={})
    assert b.available() is False

def test_openrouter_raises_when_all_models_fail(monkeypatch):
    b = L.OpenRouterBackend("reflex", L.DEFAULT_CONFIG, env={"OPENROUTER_API_KEY": "k"})
    monkeypatch.setattr(b, "_models", lambda: ["m1:free", "m2:free"])
    def boom(model, system, prompt, timeout):
        raise L.BackendError("429")
    monkeypatch.setattr(b, "_one_call", boom)
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt", timeout=5)

def test_ollama_unavailable_when_down(monkeypatch):
    b = L.OllamaBackend("devstral:24b")
    monkeypatch.setattr(b, "_ping", lambda: False)
    assert b.available() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_http_backends.py -v`
Expected: FAIL (`AttributeError: BackendError`).

- [ ] **Step 3: Implement adapters in `oracle_llm.py`**

```python
import requests

class BackendError(Exception):
    pass

class Backend:
    name = "base"
    def available(self) -> bool:
        raise NotImplementedError
    def complete(self, system: str, prompt: str, timeout=None) -> str:
        raise NotImplementedError

class OpenRouterBackend(Backend):
    name = "openrouter"
    def __init__(self, task_type, cfg, env):
        self.task_type = task_type
        self.cfg = cfg
        self.env = env
    def available(self) -> bool:
        return bool(self.env.get("OPENROUTER_API_KEY"))
    def _models(self):
        key = self.env["OPENROUTER_API_KEY"]
        pref = self.cfg.get("openrouter", {}).get(f"{self.task_type}_preferred", [])
        discovered = discover_openrouter_models(
            key, allow_paid=self.cfg.get("allow_paid_openrouter", False))
        seen, ordered = set(), []
        for m in list(pref) + discovered:
            if m in discovered and m not in seen:
                seen.add(m); ordered.append(m)
        return ordered
    def _one_call(self, model, system, prompt, timeout):
        key = self.env["OPENROUTER_API_KEY"]
        r = requests.post("https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}]}, timeout=timeout or 90)
        data = r.json()
        if "choices" not in data:
            raise BackendError(f"{model}: {str(data.get('error'))[:120]}")
        return (data["choices"][0]["message"]["content"] or "").strip()
    def complete(self, system, prompt, timeout=None):
        errs = []
        for m in self._models():
            try:
                out = self._one_call(m, system, prompt, timeout)
                if out:
                    return out
            except (BackendError, requests.RequestException, KeyError, ValueError) as e:
                errs.append(f"{m}:{e}")
        raise BackendError(f"openrouter exhausted: {'; '.join(errs[:5])}")

class OllamaBackend(Backend):
    name = "local"
    def __init__(self, model, url="http://localhost:11434"):
        self.model = model
        self.url = url
    def _ping(self) -> bool:
        try:
            return requests.get(f"{self.url}/api/tags", timeout=4).ok
        except requests.RequestException:
            return False
    def available(self) -> bool:
        return self._ping()
    def complete(self, system, prompt, timeout=None):
        try:
            r = requests.post(f"{self.url}/api/generate",
                json={"model": self.model, "system": system,
                      "prompt": prompt, "stream": False}, timeout=timeout)
        except requests.RequestException as e:
            raise BackendError(f"ollama {self.model}: {e}") from e
        if not r.ok:
            raise BackendError(f"ollama {self.model}: HTTP {r.status_code}")
        out = (r.json().get("response") or "").strip()
        if not out:
            raise BackendError(f"ollama {self.model}: empty response")
        return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_http_backends.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_llm.py tests/test_llm_http_backends.py
git commit -m "feat(llm): HTTP backend adapters (OpenRouter + ollama)"
```

---

### Task 4: CLI subprocess adapter

**Files:**
- Modify: `oracle_llm.py`
- Test: `tests/test_llm_cli_backend.py`

**Interfaces:**
- Produces: `class CliBackend(Backend)` — `__init__(self, name, invoke: str)` where `invoke` is e.g. `"claude -p"`. `available()` True iff the binary (`invoke.split()[0]`) is on PATH. `complete()` runs `shlex.split(invoke) + ["--append-system-prompt", system, prompt]` for claude, else `shlex.split(invoke) + [prompt]` with system prepended; captures stdout; raises `BackendError` on non-zero exit, timeout, or empty stdout.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_cli_backend.py
import os, stat, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import pytest

def _fake_bin(tmp_path, name, body):
    p = tmp_path / name
    p.write_text("#!/usr/bin/env bash\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p

def test_cli_success(tmp_path, monkeypatch):
    _fake_bin(tmp_path, "fakecli", 'echo "SEAM 1 ok"\n')
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    b = L.CliBackend("fakecli", "fakecli -p")
    assert b.available() is True
    assert "SEAM 1 ok" in b.complete("sys", "prompt", timeout=10)

def test_cli_nonzero_raises(tmp_path, monkeypatch):
    _fake_bin(tmp_path, "failcli", 'echo "refused [cyber]" >&2\nexit 1\n')
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    b = L.CliBackend("failcli", "failcli -p")
    with pytest.raises(L.BackendError):
        b.complete("sys", "prompt", timeout=10)

def test_cli_unavailable_when_missing():
    b = L.CliBackend("nope-xyz", "nope-xyz -p")
    assert b.available() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_cli_backend.py -v`
Expected: FAIL (`AttributeError: CliBackend`).

- [ ] **Step 3: Implement `CliBackend` in `oracle_llm.py`**

```python
import shlex, shutil, subprocess

class CliBackend(Backend):
    def __init__(self, name, invoke):
        self.name = name
        self.invoke = invoke
    def available(self) -> bool:
        return shutil.which(shlex.split(self.invoke)[0]) is not None
    def complete(self, system, prompt, timeout=None):
        parts = shlex.split(self.invoke)
        if self.name == "claude":
            argv = parts + ["--append-system-prompt", system, prompt]
        else:
            argv = parts + [f"{system}\n\n{prompt}"]
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout or 180, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"{self.name}: timeout") from e
        except OSError as e:
            raise BackendError(f"{self.name}: {e}") from e
        if r.returncode != 0:
            raise BackendError(f"{self.name}: rc={r.returncode} {r.stderr.strip()[:160]}")
        out = (r.stdout or "").strip()
        if not out:
            raise BackendError(f"{self.name}: empty stdout")
        return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_cli_backend.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_llm.py tests/test_llm_cli_backend.py
git commit -m "feat(llm): CLI subprocess backend adapter"
```

---

### Task 5: Router core — build_backends_for + complete()

**Files:**
- Modify: `oracle_llm.py`
- Test: `tests/test_llm_router.py`

**Interfaces:**
- Consumes: all adapters + `load_backend_config` + `_load_env` from `oracle_hunter`.
- Produces: `build_backends_for(task_type, cfg, env) -> List[Backend]` — maps each name in `cfg["routes"][task_type]` to an adapter instance (`openrouter`→`OpenRouterBackend`; `local`→`OllamaBackend(cfg["local_model"])`, or `light_local_model` for task in {assess,draft}; `claude`/`copilot`/`gemini`/`bob`→`CliBackend`). Unknown task_type raises `KeyError`.
- Produces: `complete(prompt, system, task_type, timeout=None, cfg=None, env=None) -> str` — walks the backend list, skips `not available()`, returns first successful `complete()`, cascades past `BackendError`, raises `RuntimeError` when all fail.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm_router.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L
import pytest

class Fake(L.Backend):
    def __init__(self, name, ok, out="OUT", avail=True):
        self.name, self.ok, self.out, self._avail = name, ok, out, avail
    def available(self): return self._avail
    def complete(self, system, prompt, timeout=None):
        if not self.ok: raise L.BackendError(f"{self.name} boom")
        return self.out

def test_returns_first_success(monkeypatch):
    order = [Fake("a", ok=False), Fake("b", ok=True, out="B")]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    assert L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={}) == "B"

def test_skips_unavailable(monkeypatch):
    order = [Fake("a", ok=True, out="A", avail=False), Fake("b", ok=True, out="B")]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    assert L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={}) == "B"

def test_all_fail_raises(monkeypatch):
    order = [Fake("a", ok=False), Fake("b", ok=False)]
    monkeypatch.setattr(L, "build_backends_for", lambda t, c, e: order)
    with pytest.raises(RuntimeError):
        L.complete("p", "s", "reflex", cfg=L.DEFAULT_CONFIG, env={})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_llm_router.py -v`
Expected: FAIL (`AttributeError: build_backends_for`).

- [ ] **Step 3: Implement router in `oracle_llm.py`**

```python
_LIGHT_TASKS = {"assess", "draft"}

def _warn(msg):
    try:
        import oracle_hunter
        oracle_hunter._warn(msg)
    except Exception:
        import sys
        print(f"WARN: {msg}", file=sys.stderr)

def build_backends_for(task_type, cfg, env) -> List[Backend]:
    names = cfg["routes"][task_type]
    out: List[Backend] = []
    for n in names:
        if n == "openrouter":
            out.append(OpenRouterBackend(task_type, cfg, env))
        elif n == "local":
            model = cfg["light_local_model"] if task_type in _LIGHT_TASKS else cfg["local_model"]
            out.append(OllamaBackend(model))
        elif n in cfg.get("cli", {}):
            out.append(CliBackend(n, cfg["cli"][n]))
        else:
            _warn(f"router: unknown backend '{n}' in route '{task_type}' — skipped")
    return out

def complete(prompt, system, task_type, timeout=None, cfg=None, env=None) -> str:
    if cfg is None:
        cfg = load_backend_config()
    if env is None:
        import oracle_hunter
        env = oracle_hunter._load_env()
    backends = build_backends_for(task_type, cfg, env)
    reasons = []
    for b in backends:
        if not b.available():
            reasons.append(f"{b.name}:unavailable"); _warn(f"router[{task_type}]: {b.name} unavailable — skip")
            continue
        try:
            return b.complete(system, prompt, timeout=timeout)
        except BackendError as e:
            reasons.append(f"{b.name}:{e}"); _warn(f"router[{task_type}]: {b.name} failed — {e}")
    raise RuntimeError(f"All backends failed for task '{task_type}': {'; '.join(reasons)}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_llm_router.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_llm.py tests/test_llm_router.py
git commit -m "feat(llm): cascade router complete() + backend builder"
```

---

### Task 6: Migrate oracle_hunter call sites + delete hardcoded list + fix cmd_audit

**Files:**
- Modify: `oracle_hunter.py` (`run_reflexes`, `_assess_response`, `_cloud_escalate`, `_correlate_seams`, delete `_query_openrouter` hardcoded `free_models`, fix `cmd_audit:1969`)
- Test: `tests/test_hunter_uses_router.py`

**Interfaces:**
- Consumes: `oracle_llm.complete` (Task 5).
- Produces: no new public API; each call site now calls `oracle_llm.complete(prompt, system, task_type=...)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hunter_uses_router.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh

def test_correlate_routes_through_complete(monkeypatch):
    seen = {}
    def fake_complete(prompt, system, task_type, **kw):
        seen["task"] = task_type
        return "## Compound Threat Analysis\n- Composite Severity: High"
    import oracle_llm
    monkeypatch.setattr(oracle_llm, "complete", fake_complete)
    out = oh._correlate_seams(
        [{"seam": {"n": 1, "reflex": "r", "assertion_a": "a", "assertion_b": "b", "impact": "i"}},
         {"seam": {"n": 2, "reflex": "r", "assertion_a": "a", "assertion_b": "b", "impact": "i"}}],
        "target")
    assert seen["task"] == "correlate"
    assert out and "Compound" in out["summary"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_hunter_uses_router.py -v`
Expected: FAIL (`_correlate_seams` still calls `_query_openrouter`/`_query_local`).

- [ ] **Step 3: Migrate `_correlate_seams`**

Replace its two-line backend block (`analysis = _query_openrouter(...); if not analysis: analysis = _query_local(...)`) with:

```python
    import oracle_llm
    try:
        analysis = oracle_llm.complete(prompt, system, task_type="correlate")
    except RuntimeError as e:
        _warn(f"correlation: all backends failed — {e}")
        return None
```

- [ ] **Step 4: Migrate `run_reflexes`**

Replace the cloud/local branch (`if use_cloud: ... _query_openrouter ... return _query_local(...)`) with:

```python
    import oracle_llm
    _info("Running Oracle 8 reflexes via backend router…")
    try:
        return oracle_llm.complete(task, system, task_type="reflex", timeout=None)
    except RuntimeError as e:
        return f"[no backend produced output] {e}"
```

- [ ] **Step 5: Migrate `_assess_response` and `_cloud_escalate`**

In `_assess_response`, replace the `cloud_verdict = _query_openrouter(...); ... return _query_local(...)` tail with:

```python
    import oracle_llm
    try:
        return oracle_llm.complete(prompt, system, task_type="assess", timeout=None)
    except RuntimeError:
        return "INCONCLUSIVE — no backend available to assess this response."
```

In `_cloud_escalate`, replace the provider if/elif chain that ends in `_query_local(task, system)` with:

```python
    import oracle_llm
    try:
        return oracle_llm.complete(task, system, task_type="poc")
    except RuntimeError as e:
        return f"[no backend produced a PoC] {e}"
```

- [ ] **Step 6: Delete the hardcoded model list and fix cmd_audit**

Delete the `free_models = [...]` list body in `_query_openrouter` (lines ~927–937) — either remove `_query_openrouter` entirely if no caller remains (grep first), or have it delegate: `return oracle_llm.complete(prompt, system, task_type="assess")`. Then fix `cmd_audit`:

```python
    # was: cloud = bool(OPENROUTER_API_KEY)   # NameError
    import oracle_llm
    cloud = getattr(args, "cloud", None)
    if cloud is None:
        cfg = oracle_llm.load_backend_config()
        env = _load_env()
        cloud = bool(env.get("OPENROUTER_API_KEY")) or cfg.get("local_enabled", True)
```

- [ ] **Step 7: Run tests + regression**

Run: `python3 -m pytest tests/ -q && python3 -m py_compile oracle_hunter.py oracle_llm.py`
Expected: all green, compile clean. Grep to confirm no `OPENROUTER_API_KEY` bare-global reference and no hardcoded `:free` list remain: `grep -n '":free"\|free_models\|bool(OPENROUTER_API_KEY)' oracle_hunter.py` → no results.

- [ ] **Step 8: Commit**

```bash
git add oracle_hunter.py tests/test_hunter_uses_router.py
git commit -m "refactor(hunter): route all model calls through oracle_llm; drop hardcoded list; fix cmd_audit NameError"
```

---

### Task 7: status backends view + `backends test` command + doc refresh

**Files:**
- Modify: `oracle_hunter.py` (`cmd_status`, add `cmd_backends_test`, argparse subparser)
- Modify: `SESSION_STATUS.md`
- Test: `tests/test_backends_cmd.py`

**Interfaces:**
- Consumes: `oracle_llm` (config, adapters, `complete`).
- Produces: `cmd_backends_test(args)` — for a `--task` (default `reflex`), builds that task's backends, runs a fixed sample prompt through each *available* one, prints name / latency / ok-or-error / first 400 chars. `oracle-hunter backends test` subcommand wired in `main()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_backends_cmd.py
import sys, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh

def test_backends_test_runs_available(monkeypatch, capsys):
    import oracle_llm
    class Fake(oracle_llm.Backend):
        name = "openrouter"
        def available(self): return True
        def complete(self, system, prompt, timeout=None): return "SEAM 1 sample"
    monkeypatch.setattr(oracle_llm, "build_backends_for", lambda t, c, e: [Fake()])
    args = types.SimpleNamespace(task="reflex")
    oh.cmd_backends_test(args)
    out = capsys.readouterr().out
    assert "openrouter" in out and "SEAM 1 sample" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_backends_cmd.py -v`
Expected: FAIL (`AttributeError: cmd_backends_test`).

- [ ] **Step 3: Implement `cmd_backends_test` + status in `oracle_hunter.py`**

```python
def cmd_backends_test(args):
    import time as _t, oracle_llm
    cfg = oracle_llm.load_backend_config()
    env = _load_env()
    task = getattr(args, "task", "reflex")
    sample_sys = "You are a terse security analyst."
    sample = "Reply with one line beginning 'SEAM 1' describing a test finding."
    _banner(f"backends test — task '{task}'")
    for b in oracle_llm.build_backends_for(task, cfg, env):
        if not b.available():
            print(f"  {b.name}: unavailable (skipped)"); continue
        t0 = _t.time()
        try:
            out = b.complete(sample_sys, sample, timeout=120)
            print(f"  {b.name}: OK {(_t.time()-t0):.1f}s :: {out[:400]}")
        except oracle_llm.BackendError as e:
            print(f"  {b.name}: FAIL {(_t.time()-t0):.1f}s :: {e}")
```

Extend `cmd_status()` to append, after the ollama/keys block:

```python
    import oracle_llm
    cfg = oracle_llm.load_backend_config()
    env = _load_env()
    print("\n  backends by task:")
    for task in cfg["routes"]:
        avail = [b.name for b in oracle_llm.build_backends_for(task, cfg, env) if b.available()]
        print(f"    {task}: {', '.join(avail) or '(none available)'}")
```

- [ ] **Step 4: Wire the subcommand in `main()`**

```python
    p_bk = sub.add_parser("backends", help="Backend router utilities")
    bk_sub = p_bk.add_subparsers(dest="bk_cmd")
    p_bk_test = bk_sub.add_parser("test", help="Run one sample across each backend for a task")
    p_bk_test.add_argument("--task", default="reflex")
```

and in the dispatch block:

```python
    elif args.cmd == "backends":
        if getattr(args, "bk_cmd", None) == "test":
            cmd_backends_test(args)
        else:
            parser.print_help()
```

- [ ] **Step 5: Run test + full regression**

Run: `python3 -m pytest tests/ -q`
Expected: all green.

- [ ] **Step 6: Refresh `SESSION_STATUS.md`**

Correct the stale lines: mark `oracle_hunter.py` and the `oracle-programs` launcher as **built**, and add a line under the model section noting the backend router (`oracle_llm.py`) is now the single entry point for all LLM calls, configured via `oracle_backends.json`.

- [ ] **Step 7: Commit**

```bash
git add oracle_hunter.py SESSION_STATUS.md tests/test_backends_cmd.py
git commit -m "feat(hunter): status backend view + 'backends test' compare command; refresh status doc"
```

---

## Notes for the executor

- This repo is **not currently a git repo**. Either `git init` first (so the per-task commits work) or drop the commit steps and rely on the test gates. Confirm with the operator.
- The `devstral` vs OpenRouter order in `routes.reflex` is provisional; the standalone devstral benchmark (running 2026-09-26) sets the final default. Changing it is a one-line config edit, no code change.
- Adding `gemini`/`bob` later = fix their auth/headless issue, then they already work via `CliBackend` — no plan changes needed.
