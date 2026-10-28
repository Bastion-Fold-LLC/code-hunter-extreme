#!/usr/bin/env python3
# LAYER: think
# DEST: codecrusher
# ENDPOINTS: complete, collaborate, build_backends_for, build_second_vote_packet, cloud_lane_available, estimate_tokens, emit_logic_trace, Backend, BackendError
# TOPICS: none
"""Oracle backend provider router — settings-driven multi-backend LLM access.

Every LLM call in Oracle flows through ``complete(prompt, system, task_type)``,
which walks a configured, per-task list of backends (CLI agents / OpenRouter /
local ollama) and returns the first that answers, cascading past failures. No
model IDs are hardcoded: OpenRouter models are discovered live.

Config lives in ``oracle_backends.json`` (routing policy only); secrets stay in
``.env`` (loaded via ``oracle_hunter._load_env``).
"""
import collections
import copy
import json
import os
import re
import sys
import shlex
import shutil
import subprocess
import threading
import time
import requests
import urllib3.util.connection as _urllib3_cn

_urllib3_cn.HAS_IPV6 = False  # Avoid 20s TCP timeout on hosts with blackholed IPv6
from pathlib import Path
from typing import (
    Any,
    Optional,
    List,
    Dict,
    Tuple,
)  # noqa: F401 (used across later sections)

_HERE = Path(__file__).resolve().parent
_CONFIG_PATH = _HERE / "oracle_backends.json"

DEFAULT_CONFIG: dict = {
    "controller": "external-interface",
    "allow_paid_openrouter": False,
    "local_enabled": True,
    "round_robin": True,
    "preflight": {"min_alive_lanes": 2},
    "local_model": "qwen3-coder:30b-16k",
    "light_local_model": "qwen2.5-coder:14b-16k",
    "local_context_tokens": 16000,
    "routes": {
        "reflex": ["openrouter", "nvidia", "local"],
        "poc": ["openrouter", "nvidia", "local"],
        "assess": ["openrouter", "nvidia", "local"],
        "correlate": ["openrouter", "nvidia", "local"],
        "draft": ["openrouter", "nvidia", "local"],
    },
    "nvidia": {},
    "openrouter": {},
    "cli": {
        "claude": "claude -p",
        "copilot": "copilot -p",
        "gemini": "gemini -p",
        "bob": "bob -p",
    },
}


def load_backend_config(path: Optional[Path] = None) -> dict:
    """Load routing config, shallow-merged over DEFAULT_CONFIG.

    Absent file → DEFAULT_CONFIG. ``local_enabled: false`` removes ``local``
    from every route. Invalid JSON raises ValueError (no silent masking).
    """
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
        cfg["routes"] = {
            k: [b for b in v if b != "local"] for k, v in cfg["routes"].items()
        }
    return cfg


# ── OpenRouter live model discovery ─────────────────────────────────────────


def _http_fetch_models(api_key: str) -> dict:
    """Fetch OpenRouter's model catalog. Injectable for tests via _fetch."""
    r = requests.get(
        "https://openrouter.ai/api/v1/models",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=20,
    )
    return r.json()


def discover_openrouter_models(
    api_key, allow_paid=False, cache_path=None, ttl=3600, _now=None, _fetch=None
) -> List[str]:
    """Return current OpenRouter model IDs (``:free`` only unless allow_paid).

    Reads/writes a JSON cache ``{ts, models}``; a cache younger than ``ttl``
    short-circuits the network. ``_now``/``_fetch`` are injected in tests.
    """
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


# ── Backend adapters ─────────────────────────────────────────────────────────


class BackendError(Exception):
    """A single backend failed (unavailable, rate-limited, refused, empty)."""


def _one_call_with_retry(one_call, model, system, prompt, timeout, attempts=3, deadline=None):
    """Retry transient network failures with backoff.

    IncompleteRead / ChunkedEncodingError / timeouts are transient — the
    Wolt run died on IncompleteRead(135194 bytes read) with no retry.
    BackendError (model-level refusal) is NOT retried: it fails fast to the
    next model. Raises the last exception when attempts are exhausted.
    When deadline (monotonic) is set, each attempt's timeout shrinks to
    the time left, and retries stop at the deadline — transient
    recovery still works, but cannot overrun the lane budget.
    """
    last: Exception | None = None
    for i in range(attempts):
        attempt_timeout = timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if last is not None:
                    raise last
                raise BackendError("lane-deadline")
            attempt_timeout = remaining if timeout is None else min(float(timeout), remaining)
        try:
            return one_call(model, system, prompt, attempt_timeout)
        except BackendError:
            raise
        except (requests.RequestException, TimeoutError, ConnectionError) as e:
            last = e
            if i < attempts - 1:
                time.sleep(1.5 * (i + 1))
    assert last is not None
    raise last


def _lane_call_timeout(deadline, per_call_cap):
    """Per-model call timeout under a lane-total deadline.

    deadline None -> None (legacy per-call defaults inside _one_call).
    Otherwise min(remaining, per_call_cap); <=0 means the lane budget
    is spent and the caller must stop trying more models.
    """
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0.0
    return min(remaining, float(per_call_cap))


def _run_with_deadline(
    label: str, timeout_s: Optional[float], fn: Any, *args: Any, **kwargs: Any
) -> Any:
    """Bound one lane call in a daemon worker thread.

    The runtime debts fail loud: ``timeout=None`` keeps legacy unbounded
    behavior (per-call defaults live inside backends), but a concrete
    timeout MUST bound the call — E0-2, spawned because the OmniCLI lane
    ignored its own deadline and wedged the router on a slow orchestration.
    On overrun the worker is abandoned (daemon thread; a late result is
    discarded) and ``BackendError`` reports the timeout so the lane
    health/breaker machinery engages instead of a stall. Exceptions from
    the worker propagate verbatim, preserving prior semantics for
    synchronous failures.
    """
    if timeout_s is None:
        return fn(*args, **kwargs)
    if float(timeout_s) <= 0.0:
        raise BackendError(
            f"{label}: lane-deadline already spent "
            f"({float(timeout_s):.1f}s); not dispatched"
        )
    result_box: List[Any] = []
    error_box: List[BaseException] = []

    def _worker() -> None:
        try:
            result_box.append(fn(*args, **kwargs))
        except BaseException as exc:  # forwarded verbatim to the caller
            error_box.append(exc)

    worker = threading.Thread(
        target=_worker, daemon=True, name=f"oracle-lane-{label}"
    )  # noqa: E501
    worker.start()
    worker.join(float(timeout_s))
    if worker.is_alive():
        raise BackendError(
            f"{label}: lane-deadline timed out after {float(timeout_s):.1f}s — "
            "run_orchestration worker abandoned (daemon)"
        )
    if error_box:
        raise error_box[0]
    return result_box[0]


def _timeout_or(default: float, timeout: Optional[float]) -> float:
    """Backend timeout law — no falsy ``or`` anywhere (2026-10-21 hardening).

    ``None`` = the backend's caller default (legacy free-running choice).
    ``0``/``0.0``/negatives PASS THROUGH: the http/proc layer refuses or
    times out loudly, so a spent deadline can never silently become the
    (large) default again — the falsy-zero bug class that wedged the
    OmniCLI lane before E0-2. The four remaining ``timeout or N`` sites
    were converted to this helper in the same change.
    """
    return default if timeout is None else float(timeout)


def estimate_tokens(system: str, prompt: str) -> int:
    """Conservative chars/4 token estimate for context guarding.

    Deliberately simple and stated: it exists to keep a prompt that
    provably cannot fit off a lane, not to price calls precisely.
    """
    return (len(system or "") + len(prompt or "") + 3) // 4


# ── Logic tracing (MLflow-ready) ────────────────────────────────────
# Opt-in via ORACLE_TRACE=1 (router env dict first, then process env).
# Spans are one JSON object per line in a flat MLflow-shaped schema
# (trace_id, span, ts, status, attributes as top-level fields) so the
# file can be loaded into Databricks MLflow / a Delta table without
# transformation when the MLflow SDK is present. Attributes carry
# SIZES, lane/model, latency, and status only — prompt and system
# TEXT is never traced. Emitting must never break routing: write
# failures are swallowed by documented design (a lost trace is an
# observability gap, never a hunt failure).


def _logic_trace_path(env) -> Optional[Path]:
    # Router env dict wins, process env fills gaps: hunters pass a
    # file-loaded env dict, operators enable tracing from the shell.
    def _get(key: str) -> str:
        if env is not None and (env or {}).get(key):
            return str(env[key])
        return str(os.environ.get(key, "") or "")

    if _get("ORACLE_TRACE").strip().lower() not in ("1", "true", "yes"):
        return None
    raw = _get("ORACLE_TRACE_FILE").strip()
    return Path(raw) if raw else _HERE / "traces" / "oracle_traces.jsonl"


def emit_logic_trace(env, record: Dict) -> None:
    path = _logic_trace_path(env)
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # observability never breaks the hunt (see header above)


def _new_trace_id() -> str:
    import uuid

    return uuid.uuid4().hex


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class Backend:
    name = "base"
    # Model ID that produced the last successful complete() call.
    # Set by each backend on success; read by complete(return_model=True).
    last_model: Optional[str] = None
    # Known context window in tokens; None = not recorded in config.
    # complete() never sends a prompt estimated larger than a KNOWN
    # window to that lane, and a lane with an UNKNOWN window is skipped
    # entirely (fail-closed, per tests/test_llm_context_guard.py): blind
    # dispatch risks provider-side truncation. A misconfigured lane that
    # omits context_tokens therefore stays unused until configured.
    context_tokens: Optional[int] = 128_000
    # Optional per-request token cap (provider TPM/request-size limits
    # can reject requests far below the context window, e.g. Groq
    # on-demand). None = no cap beyond the context window.
    max_request_tokens: Optional[int] = None

    def effective_limit(self) -> Optional[int]:
        ctx = getattr(self, "context_tokens", None)
        if ctx is None:
            return None
        try:
            limit = int(ctx)
        except (TypeError, ValueError):
            return None
        cap = getattr(self, "max_request_tokens", None)
        if cap is None:
            return limit
        try:
            cap_i = int(cap)
        except (TypeError, ValueError):
            return 0  # unparseable cap: fail closed, never raise
        if cap_i <= 0:
            return 0  # configured shut: never fits (fail-closed)
        return min(limit, cap_i)

    def fits(self, need_tokens: int) -> bool:
        limit = self.effective_limit()
        if limit is None:
            return False
        return need_tokens <= limit

    def available(self) -> bool:
        raise NotImplementedError

    def complete(self, system: str, prompt: str, timeout=None) -> str:
        raise NotImplementedError


class OpenRouterBackend(Backend):
    """HTTP workhorse. Model chosen by live discovery (task-preferred first)."""

    name = "openrouter"

    def __init__(self, task_type, cfg, env):
        self.task_type = task_type
        self.cfg = cfg
        self.env = env
        self.context_tokens = (cfg.get("openrouter", {}) or {}).get("context_tokens")
        self.max_request_tokens = (cfg.get("openrouter", {}) or {}).get(
            "max_request_tokens"
        )

    def available(self) -> bool:
        return bool(self.env.get("OPENROUTER_API_KEY"))

    def _models(self) -> List[str]:
        key = self.env["OPENROUTER_API_KEY"]
        pref = self.cfg.get("openrouter", {}).get(f"{self.task_type}_preferred", [])
        discovered = discover_openrouter_models(
            key, allow_paid=self.cfg.get("allow_paid_openrouter", False)
        )
        seen, ordered = set(), []
        for m in list(pref) + discovered:
            if m in discovered and m not in seen:
                seen.add(m)
                ordered.append(m)
        return ordered

    def _one_call(self, model, system, prompt, timeout) -> str:
        key = self.env["OPENROUTER_API_KEY"]
        r = requests.post(  # nosec B113
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=_timeout_or(90, timeout),
        )
        data = r.json()
        if "choices" not in data:
            raise BackendError(f"{model}: {str(data.get('error'))[:120]}")
        return (data["choices"][0]["message"]["content"] or "").strip()

    def complete(self, system, prompt, timeout=None) -> str:
        try:
            models = self._models()
        except Exception as e:
            raise BackendError(f"openrouter discovery failed: {e}") from e
        # timeout is the TOTAL lane budget across models, not per call.
        deadline = None if timeout is None else time.monotonic() + float(timeout)
        errs = []
        for m in models:
            call_to = _lane_call_timeout(deadline, 90)
            if call_to == 0.0:
                errs.append("lane-deadline")
                break
            try:
                out = _one_call_with_retry(
                    self._one_call, m, system, prompt, call_to, deadline=deadline
                )
                if out:
                    self.last_model = m
                    return out
            except (BackendError, requests.RequestException, KeyError, ValueError, TypeError, AttributeError) as e:
                errs.append(f"{m}:{e}")
        raise BackendError(f"openrouter exhausted: {'; '.join(errs[:5])}")


class NvidiaNimBackend(Backend):
    """NVIDIA NIM free-endpoint workhorse. Model IDs verified live Oct 1 2026.
    Config ``nvidia`` -> ``{task}_preferred`` first, then built-in defaults."""

    name = "nvidia"
    BASE_URL = "https://integrate.api.nvidia.com/v1"
    DEFAULT_MODELS = [
        "poolside/laguna-xs-2.1",
        "google/gemma-4-31b-it",
        "nvidia/nemotron-3.5-lightning-30b-a3b",
    ]

    def __init__(self, task_type, cfg, env):
        self.task_type = task_type
        self.cfg = cfg
        self.env = env
        self.context_tokens = (cfg.get("nvidia", {}) or {}).get("context_tokens")
        self.max_request_tokens = (cfg.get("nvidia", {}) or {}).get(
            "max_request_tokens"
        )

    def available(self) -> bool:
        return bool(self.env.get("NVIDIA_API_KEY"))

    def _models(self) -> List[str]:
        pref = self.cfg.get("nvidia", {}).get(f"{self.task_type}_preferred", [])
        seen, ordered = set(), []
        for m in list(pref) + self.DEFAULT_MODELS:
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        return ordered

    def _one_call(self, model, system, prompt, timeout) -> str:
        key = self.env["NVIDIA_API_KEY"]
        r = requests.post(  # nosec B113
            f"{self.BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "temperature": self.cfg.get("nvidia", {}).get("temperature", 0.2),
                "max_tokens": 4096,
            },
            timeout=_timeout_or(120, timeout),
        )
        data = r.json()
        if "choices" not in data:
            raise BackendError(f"{model}: {str(data.get('error'))[:120]}")
        return (data["choices"][0]["message"].get("content") or "").strip()

    def complete(self, system, prompt, timeout=None) -> str:
        # timeout is the TOTAL lane budget across models, not per call.
        deadline = None if timeout is None else time.monotonic() + float(timeout)
        errs = []
        for m in self._models():
            call_to = _lane_call_timeout(deadline, 120)
            if call_to == 0.0:
                errs.append("lane-deadline")
                break
            try:
                out = _one_call_with_retry(
                    self._one_call, m, system, prompt, call_to, deadline=deadline
                )
                if out:
                    self.last_model = m
                    return out
            except (BackendError, requests.RequestException, KeyError, ValueError, TypeError, AttributeError) as e:
                errs.append(f"{m}:{e}")
        raise BackendError(f"nvidia exhausted: {'; '.join(errs[:5])}")


class OllamaBackend(Backend):
    """Local ollama. available() is False (not an error) when down/unmounted."""

    name = "local"

    def __init__(self, model, url="http://localhost:11434", context_tokens=16000):
        self.model = model
        self.url = url
        self.context_tokens = context_tokens

    def _ping(self) -> bool:
        try:
            return requests.get(f"{self.url}/api/tags", timeout=4).ok
        except requests.RequestException:
            return False

    def available(self) -> bool:
        return self._ping()

    # Idle silence that proves a dead/lost request, not slow generation.
    # A generating model emits bytes continuously; 600s without a byte
    # (hunt-1/hunt-2 hangs: idle server, waiting client, zero CPU both
    # sides) always meant a dead peer. Slow CPU generation is unaffected:
    # with timeout=None there is no total cap, only this idle watchdog.
    _IDLE_LIMIT_S = 600

    def complete(self, system, prompt, timeout=None) -> str:
        deadline = None if timeout is None else time.monotonic() + timeout
        idle = (
            self._IDLE_LIMIT_S if timeout is None else min(timeout, self._IDLE_LIMIT_S)
        )
        try:
            with requests.post(
                f"{self.url}/api/generate",
                json={
                    "model": self.model,
                    "system": system,
                    "prompt": prompt,
                    "stream": True,
                    # Explicit window: without num_ctx the server default
                    # silently truncates oversized system prompts.
                    "options": (
                        {"num_ctx": int(self.context_tokens)}
                        if self.context_tokens
                        else {}
                    ),
                },
                timeout=(10, idle),
                stream=True,
            ) as r:
                if not r.ok:
                    raise BackendError(f"ollama {self.model}: HTTP {r.status_code}")
                parts = []
                for line in r.iter_lines():
                    if deadline is not None and time.monotonic() > deadline:
                        raise BackendError(
                            f"ollama {self.model}: lane-deadline exceeded timeout={timeout}s"
                        )
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except ValueError:
                        continue
                    parts.append(data.get("response", ""))
                    if data.get("done"):
                        break
        except requests.RequestException as e:
            raise BackendError(f"ollama {self.model}: {e}") from e
        out = "".join(parts).strip()
        if not out:
            raise BackendError(f"ollama {self.model}: empty response")
        self.last_model = self.model
        return out


# CLI agents that cannot be spawned as subprocesses of themselves.
# When BOB_SESSION=1 (running inside bob shell), bob/claude/gemini cannot be
# subprocess-called — they ARE the current interface. Skip them; route to API backends.
_AGENT_SESSION_ENV_FLAGS = (
    "BOB_SESSION",
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS",
    "ANTHROPIC_SESSION",
    "CLAUDE_SESSION",
)
_CLI_BLOCKED_IN_SESSION = {"bob", "claude", "gemini"}


def _in_agent_session() -> bool:
    """Returns True when running inside an interactive agent shell (bob, claude, gemini)."""
    import os as _os

    return any(_os.environ.get(flag) for flag in _AGENT_SESSION_ENV_FLAGS)


class CliBackend(Backend):
    """Interactive agent CLI driven headless (``<cli> -p``).

    When running inside an agent session (BOB_SESSION=1 etc.), bob/claude/gemini
    cannot spawn child sessions of themselves — available() returns False so the
    router skips them and falls through to OpenRouter or local Ollama.
    copilot is safe to subprocess in any context.
    """

    def __init__(self, name, invoke):
        self.name = name
        self.invoke = invoke

    def available(self) -> bool:
        # Block self-spawning: if we're inside an agent session, skip that agent's CLI
        if self.name in _CLI_BLOCKED_IN_SESSION and _in_agent_session():
            return False
        return shutil.which(shlex.split(self.invoke)[0]) is not None

    def complete(self, system, prompt, timeout=None) -> str:
        parts = shlex.split(self.invoke)
        if self.name == "claude":
            argv = parts + ["--append-system-prompt", system, prompt]
        else:
            argv = parts + [f"{system}\n\n{prompt}"]
        try:
            r = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=_timeout_or(180, timeout),
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"{self.name}: lane-deadline timeout") from e
        except OSError as e:
            raise BackendError(f"{self.name}: {e}") from e
        if r.returncode != 0:
            raise BackendError(
                f"{self.name}: rc={r.returncode} {r.stderr.strip()[:160]}"
            )
        out = (r.stdout or "").strip()
        if not out:
            raise BackendError(f"{self.name}: empty stdout")
        self.last_model = self.name
        return out


# ── Router ───────────────────────────────────────────────────────────────────

_LIGHT_TASKS = {"assess", "draft"}

# Process-wide --no-cloud enforcement. When set (via set_no_cloud() or the
# no_cloud parameter on complete()/build_backends_for()), the router admits
# ONLY the local Ollama backend — OpenRouter and the CLI agent backends
# (claude/gemini/copilot/bob, all of which call cloud APIs) are excluded, so
# zero external network calls for model services can happen. Fail-closed:
# when no local backend is available the call raises RuntimeError.
_NO_CLOUD = False
_PREFERRED_LOCAL_MODEL: Optional[str] = None


def set_no_cloud(flag: bool = True) -> None:
    """Force local-only routing for every subsequent complete() call."""
    global _NO_CLOUD
    _NO_CLOUD = bool(flag)


def set_preferred_local_model(model: Optional[str]) -> None:
    """Pin the local model for every subsequent complete() call.

    The hunt's --model wins over cfg local/light models (hunt-3/4b:
    router asked qwen3-coder:30b 15-17x on 7b hunts). None clears.
    """
    global _PREFERRED_LOCAL_MODEL
    _PREFERRED_LOCAL_MODEL = model


def no_cloud_enabled() -> bool:
    """True when process-wide --no-cloud enforcement is active."""
    return _NO_CLOUD


def _warn(msg: str) -> None:
    """Log via oracle_hunter._warn when importable, else stderr. Lazy import
    avoids a circular dependency once oracle_hunter imports this module."""
    try:
        import oracle_hunter

        oracle_hunter._warn(msg)
    except Exception:
        import sys

        print(f"WARN: {msg}", file=sys.stderr)


class OpenAICompatBackend(Backend):
    """Generic OpenAI-compatible chat backend (Groq, Gemini, Mistral, Cloudflare
    Workers AI, …). Config under cfg['backends'][name]:
        base_url, api_key_env, [account_env], {task}_preferred: [models], models.
    base_url may contain {account_id}, filled from env[account_env] (Cloudflare).
    No secrets in config — only the NAME of the env var holding the key."""

    def __init__(self, name, task_type, cfg, env):
        self.name = name
        self.task_type = task_type
        self.cfg = cfg
        self.env = env
        self._bc = (cfg.get("backends", {}) or {}).get(name, {})
        self.context_tokens = self._bc.get("context_tokens")
        self.max_request_tokens = self._bc.get("max_request_tokens")

    def _key(self) -> str:
        return self.env.get(self._bc.get("api_key_env", ""), "")

    def _base_url(self) -> str:
        url = self._bc.get("base_url", "")
        acct_env = self._bc.get("account_env")
        if acct_env:
            url = url.replace("{account_id}", self.env.get(acct_env, ""))
        return url.rstrip("/")

    def available(self) -> bool:
        if not self._key() or not self._bc.get("base_url"):
            return False
        acct_env = self._bc.get("account_env")
        return bool(self.env.get(acct_env)) if acct_env else True

    def _models(self) -> List[str]:
        return list(
            self._bc.get(f"{self.task_type}_preferred", [])
            or self._bc.get("models", [])
        )

    def _one_call(self, model, system, prompt, timeout) -> str:
        headers = {
            "Authorization": f"Bearer {self._key()}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",  # noqa: E501
        }
        if self.name == "monkeycode":
            secret = self.env.get("MONKEYCODE_SIGNING_SECRET", "")
            if secret:
                import hmac
                import hashlib

                sys_prompt = system or "You are a helpful assistant."
                sig = (
                    "v1="
                    + hmac.new(
                        secret.encode("utf-8"),
                        sys_prompt.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                )
                headers["X-OhMyAgent-Signature"] = sig

        r = requests.post(  # nosec B113
            self._base_url() + "/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "temperature": self._bc.get("temperature", 0.2),
            },
            timeout=_timeout_or(90, timeout),
        )
        data = r.json()
        if isinstance(data, list):  # some providers wrap errors/results in a list
            data = data[0] if data else {}
        if "choices" not in data:
            raise BackendError(
                f"{self.name}/{model} HTTP {r.status_code}: "
                f"{str(data.get('error'))[:140]}"
            )
        content = data["choices"][0]["message"].get("content")
        if isinstance(content, list):
            # Reasoning models (e.g. databricks gpt-oss) return content as a list
            # of blocks [{"type":"reasoning",...},{"type":"text","text":...}];
            # join the text blocks and drop reasoning. .strip() on a list crashes.
            content = "".join(
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        return (content or "").strip()

    def complete(self, system, prompt, timeout=None) -> str:
        # timeout is the TOTAL lane budget across models, not per call.
        deadline = None if timeout is None else time.monotonic() + float(timeout)
        errs = []
        for m in self._models():
            call_to = _lane_call_timeout(deadline, 90)
            if call_to == 0.0:
                errs.append("lane-deadline")
                break
            try:
                out = _one_call_with_retry(
                    self._one_call, m, system, prompt, call_to, deadline=deadline
                )
                if out:
                    self.last_model = f"{self.name}:{m}"
                    return out
            except (BackendError, requests.RequestException, KeyError, ValueError, TypeError, AttributeError) as e:
                errs.append(f"{m}:{e}")
        raise BackendError(f"{self.name} exhausted: {'; '.join(errs[:4])}")


# ─────────────────────────────────────────────────────────────────────────────
# OmniCLI Swarm Backend — multi-model adversarial orchestration with streaming
# Drops into the normal router route list as the name "omnicli".
# When present it fans out to every configured provider family in parallel,
# synthesises a consensus answer, and streams tokens back as they arrive.
# Falls back gracefully if OmniCLI is not installed.
# ─────────────────────────────────────────────────────────────────────────────
def omnicli_home() -> Optional[Path]:
    """Locate the OmniCLI checkout. No hardcoded usernames.

    OMNICLI_HOME is authoritative when set (invalid → None, never a
    silent fallthrough to layout guesses); else ~/tools/omnicli,
    ~/omnicli, then sibling-of-oracle candidates (sandbox $HOME).
    A candidate counts only when it contains omnicli/__init__.py.
    """
    env_home = os.environ.get("OMNICLI_HOME", "").strip()
    if env_home:
        cand = Path(env_home).expanduser()
        try:
            return cand if (cand / "omnicli" / "__init__.py").is_file() else None
        except OSError:
            return None
    _oracle_dir = Path(__file__).resolve().parent
    cands = [
        Path.home() / "tools" / "omnicli",
        Path.home() / "omnicli",
        _oracle_dir.parent / "tools" / "omnicli",
        _oracle_dir.parent / "omnicli",
    ]
    for cand in cands:
        try:
            if (cand / "omnicli" / "__init__.py").is_file():
                return cand
        except OSError:
            continue
    return None


def ensure_omnicli_importable() -> bool:
    """Make `import omnicli` work. True when importable, else False."""
    try:
        import omnicli  # noqa: F401

        return True
    except ImportError:
        pass
    home = omnicli_home()
    if home is not None and str(home) not in sys.path:
        sys.path.insert(0, str(home))
    try:
        import omnicli  # noqa: F401

        return True
    except ImportError:
        return False


class OmniCLIBackend(Backend):
    """OmniCLI multi-model swarm orchestration backend.

    Runs ``run_orchestration("collaborate", ...)`` from OmniCLI, which fans the
    prompt out to every configured model family in parallel and returns a
    deterministically merged answer.  Streaming is emulated by printing tokens
    as each swarm member responds; the merged final answer is returned as a
    single str for downstream Oracle consumers (same contract as every other
    backend).

    Available only when an OmniCLI checkout is importable (see omnicli_home()).
    """

    def __init__(self, task_type: str, env: Dict):
        self.name = "omnicli"
        self.task_type = task_type
        self.env = env
        self._available: Optional[bool] = None
        self.last_model = "omnicli:swarm"

    def _load(self):
        if not ensure_omnicli_importable():
            raise ImportError("no OmniCLI checkout found (see omnicli_home())")
        from omnicli.config import ConfigManager
        from omnicli.client import OmniClient
        from omnicli.orchestrate import run_orchestration

        return ConfigManager, OmniClient, run_orchestration

    def available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            self._load()
            self._available = True
        except Exception:
            self._available = False
        return self._available

    def complete(self, system: str, prompt: str, timeout=None) -> str:
        ConfigManager, OmniClient, run_orchestration = self._load()
        # Merge env into process environment so OmniCLI ConfigManager picks up keys
        import os

        saved = {}
        for k, v in self.env.items():
            saved[k] = os.environ.get(k)
            os.environ[k] = v
        try:
            cfg = ConfigManager()
            client = OmniClient(cfg)
            # Role separation is preserved: the system prompt travels as a
            # real system message to every swarm member (never flattened
            # into the user prompt). No file enrichment runs on this path.
            # E0-2: the timeout arg is now ENFORCED — a concrete deadline
            # bounds run_orchestration in a daemon worker; overruns raise
            # BackendError so the breaker engages (was: silently unbounded).
            result = _run_with_deadline(
                "omnicli",
                timeout,
                run_orchestration,
                "collaborate",
                cfg,
                client,
                prompt,
                max_tokens=1024,
                synth=True,
                system=system or None,
            )
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        final = result.get("final") or ""
        members = result.get("members") or result.get("responses") or []
        if not final:
            # Fallback: concatenate member responses if synthesis is empty.
            # run_orchestration returns members as a LIST of per-member records;
            # a legacy dict shape (name -> response text) is accepted too.
            if isinstance(members, dict):
                final = "\n\n---\n\n".join(
                    f"[{name}]\n{resp}" for name, resp in members.items() if resp
                )
            elif isinstance(members, list):
                parts = []
                for record in members:
                    if isinstance(record, dict):
                        answer = record.get("answer") or ""
                        if answer:
                            parts.append(
                                f"[{record.get('provider', '?')}:{record.get('model', '?')}]\n{answer}"
                            )
                    elif isinstance(record, str) and record:
                        parts.append(record)
                final = "\n\n---\n\n".join(parts)
        if not final:
            raise BackendError("omnicli swarm: empty synthesis")
        # Stream indication (visible in terminal but not in returned string)
        count = len(members) if isinstance(members, (list, dict)) else 0
        _warn(f"OmniCLI swarm complete — {count} models contributed")
        self.last_model = "omnicli:swarm"
        return final.strip()


def build_backends_for(task_type, cfg, env, no_cloud: bool = False) -> List[Backend]:
    """Map the configured route for ``task_type`` to adapter instances.
    Unknown task_type raises KeyError (no silent empty route).
    no_cloud=True (or the process-wide set_no_cloud flag) restricts the route
    to the local backend only — fail-closed RuntimeError when the route then
    has no local backend."""
    names = cfg["routes"][task_type]
    if no_cloud or _NO_CLOUD:
        names = [n for n in names if n == "local"]
        if not names:
            raise RuntimeError(
                f"--no-cloud is set but route for task '{task_type}' has no "
                f"local backend — refusing to call cloud services"
            )
    out: List[Backend] = []
    for n in names:
        if n == "openrouter":
            out.append(OpenRouterBackend(task_type, cfg, env))
        elif n == "nvidia":
            out.append(NvidiaNimBackend(task_type, cfg, env))
        elif n == "omnicli":
            out.append(OmniCLIBackend(task_type, env))
        elif n == "local":
            model = _PREFERRED_LOCAL_MODEL or (
                cfg["light_local_model"]
                if task_type in _LIGHT_TASKS
                else cfg["local_model"]
            )
            out.append(
                OllamaBackend(
                    model,
                    context_tokens=int(cfg.get("local_context_tokens", 16000)),
                )
            )
        elif n in cfg.get("backends", {}):
            out.append(OpenAICompatBackend(n, task_type, cfg, env))
        elif n in cfg.get("cli", {}):
            out.append(CliBackend(n, cfg["cli"][n]))
        else:
            _warn(f"router: unknown backend '{n}' in route '{task_type}' — skipped")
    return out


def cloud_lane_available(cfg, env, task_type: str = "reflex") -> bool:
    """True when any configured non-local lane for the task is available.

    The honest cloud gate: derived from the same route/config complete()
    walks (every lane's own credential/config check), never from a
    hardcoded pair of API-key names.
    """
    for backend in build_backends_for(task_type, cfg, env):
        if backend.name == "local":
            continue
        try:
            if backend.available():
                return True
        except Exception:
            continue
    return False


_RR_COUNTERS: Dict[str, int] = collections.defaultdict(int)

# Per-run lane circuit breaker. A lane whose complete() raised (it
# already exhausted all of its models to get there) is skipped fast on
# later calls until its cooldown expires, instead of being re-walked
# from the top on every pass/round. Success clears the lane at once.
# Cooldown covers a full Engine-A collect (420s) plus the ladder round
# (180s) so lanes that failed the main round stay skipped in L1/L2.
# Keyed by lane identity including the local model, so light/heavy
# local lanes never poison each other through the shared name "local".
import threading as _threading

_LANE_DOWN_UNTIL: Dict[str, float] = {}
_LANE_HEALTH_LOCK = _threading.Lock()
_LANE_COOLDOWN_S = 600.0
# A lane allotted less than this was budget-starved, not proven dead:
# its failure never trips the breaker.
_LANE_FAIR_SHOT_S = 30.0
# With alternative lanes waiting, no lane may hold the router for more
# than this in one attempt. A sole remaining lane keeps the full budget.
_LANE_MAX_SLICE_S = 120.0


def _lane_key(backend) -> str:
    model = getattr(backend, "model", None)
    return f"{backend.name}:{model}" if model else str(backend.name)


def reset_lane_health() -> None:
    with _LANE_HEALTH_LOCK:
        _LANE_DOWN_UNTIL.clear()


def _lane_is_down(key: str) -> bool:
    with _LANE_HEALTH_LOCK:
        until = _LANE_DOWN_UNTIL.get(key, 0.0)
        if until and time.monotonic() >= until:
            _LANE_DOWN_UNTIL.pop(key, None)
            return False
        return bool(until)


def _mark_lane_down(key: str) -> None:
    with _LANE_HEALTH_LOCK:
        _LANE_DOWN_UNTIL[key] = time.monotonic() + _LANE_COOLDOWN_S


def _mark_lane_up(key: str) -> None:
    with _LANE_HEALTH_LOCK:
        _LANE_DOWN_UNTIL.pop(key, None)


_OWN_DEADLINE_RE = re.compile(
    r"lane[- ]deadline|exceeded timeout=|timed out after.*run_orchestration"
)


def _is_own_deadline_error(exc: BaseException) -> bool:
    """Recognize deadlines this router imposed, including legacy spellings."""
    return bool(_OWN_DEADLINE_RE.search(str(exc).strip().lower()))


def _failure_trips_breaker(exc: BaseException, allotted_s, sole_lane: bool) -> bool:
    """Decide whether a lane failure proves the lane dead.

    Never trips for: the sole lane (marking it down is a total outage
    with no alternative), a budget-starved slice, our own lane
    deadline cutting the attempt, or a size rejection (the lane may
    serve smaller prompts fine — fits()/caps own that decision).
    """
    if sole_lane:
        return False
    if allotted_s is not None and float(allotted_s) < _LANE_FAIR_SHOT_S:
        return False
    msg = str(exc).lower()
    if _is_own_deadline_error(exc):
        return False
    if any(s in msg for s in ("too large", "413", "context length", "context_length")):
        return False
    return True


def reset_round_robin():
    """Reset round-robin rotation counters (testing and fresh sessions)."""
    _RR_COUNTERS.clear()
    reset_lane_health()


def _lane_timeout_slice(
    remaining_s,
    lanes_remaining,
    fair_shot_s: float = _LANE_FAIR_SHOT_S,
    max_slice_s: float = _LANE_MAX_SLICE_S,
) -> float:
    """Allot one lane's share of the remaining total router budget.

    Reserve a fair shot for every later eligible lane. When the total
    cannot fund a fair shot for all, divide what remains equally so
    later lanes are still attempted. Unused time naturally rolls into
    the next dynamic calculation. A sole remaining lane gets all of it.
    """
    try:
        remaining = float(remaining_s)
        lanes = int(lanes_remaining)
        fair_shot = max(0.0, float(fair_shot_s))
        max_slice = max(0.0, float(max_slice_s))
    except (TypeError, ValueError):
        return 0.0
    if remaining <= 0 or lanes <= 0:
        return 0.0
    if lanes == 1:
        return remaining
    reserve = fair_shot * (lanes - 1)
    if remaining > reserve + fair_shot:
        allotted = remaining - reserve
    else:
        allotted = remaining / lanes
    return min(allotted, max_slice) if max_slice > 0 else allotted


def viable_lane_limits(backends, minimum_tokens: int = 0) -> List[Tuple[str, int]]:
    """Known effective limits for lanes usable for at least ``minimum_tokens``.

    A lane is viable only when it is available, not in circuit-breaker
    cooldown, and has a known positive effective limit. Unknown windows
    stay excluded, matching complete()'s fail-closed dispatch law.
    """
    try:
        minimum = int(minimum_tokens)
    except (TypeError, ValueError):
        minimum = 0
    out: List[Tuple[str, int]] = []
    for backend in backends or []:
        try:
            limit = (
                backend.effective_limit()
                if hasattr(backend, "effective_limit")
                else getattr(backend, "context_tokens", None)
            )
            if limit is None or int(limit) <= 0 or int(limit) < minimum:
                continue
            if _lane_is_down(_lane_key(backend)):
                continue
            if not backend.available():
                continue
        except Exception:
            continue
        out.append((str(getattr(backend, "name", "unknown")), int(limit)))
    return sorted(out, key=lambda item: (item[1], item[0]))


def smallest_viable_lane_limit(
    task_type: str = "reflex",
    cfg: Optional[dict] = None,
    env: Optional[dict] = None,
    no_cloud: bool = False,
    minimum_tokens: int = 0,
) -> Optional[int]:
    """Smallest known effective limit among currently viable route lanes."""
    if cfg is None:
        cfg = load_backend_config()
    if env is None:
        import oracle_hunter

        env = oracle_hunter._load_env()
    effective_no_cloud = bool(no_cloud or _NO_CLOUD)
    try:
        if effective_no_cloud:
            backends = build_backends_for(task_type, cfg, env, no_cloud=True)
        else:
            backends = build_backends_for(task_type, cfg, env)
    except Exception:
        return None
    limits = viable_lane_limits(backends, minimum_tokens=minimum_tokens)
    return limits[0][1] if limits else None


def lane_preflight(
    task_type: str = "reflex",
    cfg: Optional[dict] = None,
    env: Optional[dict] = None,
    min_alive: Optional[int] = None,
) -> Tuple[List[str], List[str], int]:
    """Living-reflex-lane census BEFORE a hunt spends anything (E0-3).

    'Living' = configured for the route and NOT stamped down by this
    run's circuit breaker ledger. Deliberately NO network probes, so a
    preflight cannot itself hang a hunt: per-call availability failures
    still flow through complete() where a real death cascades into the
    breaker. What this defends against is the already-known-dead class —
    follow-on hunts (queue --execute re-uses the router process) starting
    on a ledger where earlier hunts burned every lane (the 2026-10-19
    lane-starvation death was exactly a hunt entering dead lanes).

    Floor lives in cfg['preflight']['min_alive_lanes'] (DEFAULT ships 2)
    with a per-call override. A SOLE-LANE route is exempt — a pinned
    single lane is a declared regime, never a dying fleet (mirror of the
    breaker's sole-lane law: one lane cannot trip its own breaker).
    Returns (living_keys, dead_keys, floor).
    """
    cfg = cfg if cfg is not None else load_backend_config(None)
    if min_alive is None:
        floor = int((cfg.get("preflight") or {}).get("min_alive_lanes", 2))
    else:
        floor = int(min_alive)
    backends = build_backends_for(task_type, cfg, env or {})
    living: List[str] = []
    dead: List[str] = []
    for backend in backends:
        key = _lane_key(backend)
        if _lane_is_down(key):
            dead.append(key)
        else:
            living.append(key)
    if len(backends) == 1 and floor > 1:
        floor = 1
    return living, dead, floor


def enforce_lane_preflight(
    task_type: str = "reflex",
    cfg: Optional[dict] = None,
    env: Optional[dict] = None,
    min_alive: Optional[int] = None,
    no_cloud: bool = False,
) -> Tuple[List[str], List[str], int]:
    """Fail loud when living lanes are below the floor.

    no_cloud hunts declare a local-only regime up-front and bypass the
    gate (their lanes are local; a burning cloud ledger is irrelevant).
    RuntimeError carries the dead-lane names and the operator escapes:
    wait out the breaker cooldown, fix the lanes, or --no-cloud.
    """
    if no_cloud or _NO_CLOUD:
        return [], [], 0
    living, dead, floor = lane_preflight(task_type, cfg, env, min_alive)
    if len(living) < floor:
        raise RuntimeError(
            "LANE PREFLIGHT: living=floor breach — "
            f"{len(living)}/{floor} required lane(s) alive, "
            f"{len(dead)} dead. hunts that starve mid-analysis burn their "
            "budget (2026-10-19 death mode); refusing to start. "
            f"living: {living or '(none)'}; dead: {dead or '(none)'}. "
            "Escape: wait the breaker cooldown, fix the lanes, or run "
            "--no-cloud to declare a local-only regime."
        )
    return living, dead, floor


def complete(
    prompt,
    system,
    task_type,
    timeout=None,
    cfg=None,
    env=None,
    no_cloud: bool = False,
    return_model: bool = False,
):
    """Single entry point for every Oracle LLM call. Walks the task's backend
    list, skips unavailable ones, returns the first success, cascades past a
    BackendError. Fail-closed: raises RuntimeError when all backends fail —
    never returns a sentinel/placeholder string.
    no_cloud=True forces local-only routing (see set_no_cloud).
    return_model=True returns (text, "backend:model_id") so callers can
    attribute which model actually answered; default False keeps the plain
    str return for all existing callers."""
    if cfg is None:
        cfg = load_backend_config()
    if env is None:
        import oracle_hunter

        env = oracle_hunter._load_env()
    effective_no_cloud = bool(no_cloud or _NO_CLOUD)
    reasons = []
    # NB: no_cloud is only passed as a keyword when truthy, so existing
    # 3-arg monkeypatched builders (tests) keep working untouched.
    if effective_no_cloud:
        backends = build_backends_for(task_type, cfg, env, no_cloud=True)
    else:
        backends = build_backends_for(task_type, cfg, env)

    if len(backends) > 1 and cfg.get("round_robin", True):
        # Round-robin load-spread across worker lanes (preserving local as floor)
        pool = [b for b in backends if b.name != "local"]
        floor = [b for b in backends if b.name == "local"]
        if len(pool) > 1:
            idx = _RR_COUNTERS[task_type] % len(pool)
            _RR_COUNTERS[task_type] += 1
            backends = pool[idx:] + pool[:idx] + floor
        elif not pool and len(backends) > 1:
            idx = _RR_COUNTERS[task_type] % len(backends)
            _RR_COUNTERS[task_type] += 1
            backends = backends[idx:] + backends[:idx]

    need_tokens = estimate_tokens(system, prompt)
    _trace_id = _new_trace_id()
    _sizes = {
        "need_tokens": need_tokens,
        "system_chars": len(system or ""),
        "prompt_chars": len(prompt or ""),
    }

    def _span(backend_name: str, status: str, **extra) -> None:
        emit_logic_trace(
            env,
            {
                "trace_id": _trace_id,
                "span": "backend_attempt",
                "ts": _utc_now_iso(),
                "task_type": task_type,
                "backend": backend_name,
                "status": status,
                **_sizes,
                **extra,
            },
        )

    # timeout, when given, is the TOTAL router budget across lanes.
    # Pre-classify eligibility so only lanes that can actually take this
    # prompt participate in timeout shares; skipped lanes must not make
    # the first viable lane's slice artificially tiny.
    _router_deadline = None if timeout is None else time.monotonic() + float(timeout)
    _lane_plan = []
    for b in backends:
        _lkey = _lane_key(b)
        if _lane_is_down(_lkey):
            _lane_plan.append((b, _lkey, "lane_down", None))
        elif not b.available():
            _lane_plan.append((b, _lkey, "unavailable", None))
        elif not b.fits(need_tokens):
            _limit = (
                b.effective_limit() if hasattr(b, "effective_limit") else b.context_tokens
            )
            _lane_plan.append((b, _lkey, "overflow", _limit))
        else:
            _lane_plan.append((b, _lkey, "eligible", None))
    _eligible_total = sum(1 for _item in _lane_plan if _item[2] == "eligible")
    _eligible_remaining = _eligible_total

    for b, _lkey, _lane_status, _limit in _lane_plan:
        if _router_deadline is not None and time.monotonic() >= _router_deadline:
            reasons.append("router:timeout-budget-exhausted")
            _warn(f"router[{task_type}]: timeout budget exhausted — stop")
            break
        if _lane_status == "lane_down":
            reasons.append(f"{b.name}:lane-down-cooldown")
            _warn(f"router[{task_type}]: {b.name} down (cooldown) — skip")
            _span(b.name, "skipped_lane_down")
            continue
        if _lane_status == "unavailable":
            reasons.append(f"{b.name}:unavailable")
            _warn(f"router[{task_type}]: {b.name} unavailable — skip")
            _span(b.name, "unavailable")
            continue
        if _lane_status == "overflow":
            reasons.append(
                f"{b.name}:context-overflow need~{need_tokens}tok "
                f"> limit {_limit}tok"
            )
            _warn(
                f"router[{task_type}]: {b.name} context-overflow "
                f"(need~{need_tokens}tok > limit {_limit}tok) — skip"
            )
            _span(b.name, "skipped_overflow", context_tokens=b.context_tokens)
            continue
        _lanes_left = _eligible_remaining
        _eligible_remaining = max(0, _eligible_remaining - 1)
        if _lane_is_down(_lkey):
            reasons.append(f"{b.name}:lane-down-cooldown")
            _warn(f"router[{task_type}]: {b.name} down (cooldown) — skip")
            _span(b.name, "skipped_lane_down")
            continue
        _lane_timeout = timeout
        if _router_deadline is not None:
            _remaining_router_s = max(0.0, _router_deadline - time.monotonic())
            _lane_timeout = _lane_timeout_slice(
                _remaining_router_s, _lanes_left
            )
        _t0 = time.monotonic()
        try:
            out = b.complete(system, prompt, timeout=_lane_timeout)
            _mark_lane_up(_lkey)
            _span(
                b.name,
                "ok",
                model=getattr(b, "last_model", None),
                latency_ms=int((time.monotonic() - _t0) * 1000),
                out_chars=len(out or ""),
                lane_timeout_s=(
                    None if _lane_timeout is None else round(float(_lane_timeout), 3)
                ),
                eligible_lanes_remaining=_lanes_left,
            )
            if return_model:
                return out, f"{b.name}:{getattr(b, 'last_model', None) or 'unknown'}"
            return out
        except Exception as e:
            _span(
                b.name,
                "failed",
                latency_ms=int((time.monotonic() - _t0) * 1000),
                error_type=type(e).__name__,
                lane_timeout_s=(
                    None if _lane_timeout is None else round(float(_lane_timeout), 3)
                ),
                eligible_lanes_remaining=_lanes_left,
            )
            # Any backend failure (not just BackendError) cascades to the next.
            # Exhaustion below still raises RuntimeError — the router is fail-closed
            # and never leaks a backend's internal exception to callers.
            if _failure_trips_breaker(e, _lane_timeout, _eligible_total <= 1):
                _mark_lane_down(_lkey)
            reasons.append(f"{b.name}:{type(e).__name__}:{e}")
            _warn(f"router[{task_type}]: {b.name} failed — {e}")
    suffix = (
        " (--no-cloud was set: local-only, no local backend answered)"
        if effective_no_cloud
        else ""
    )
    raise RuntimeError(
        f"All backends failed for task '{task_type}'{suffix}: {'; '.join(reasons)}"
    )


def build_second_vote_packet(seams, system, budget_tokens):
    """Render top-ranked seam cards into one reviewer packet that fits.

    Cards are taken in the caller's (synthesis-ranked) order and appended
    verbatim by field while the estimated system+packet size stays
    within ``budget_tokens``; the first card that would overflow stops
    the packet (top-ranked first, never a silent mid-card cut). Returns
    (packet, included_indexes). Pure — no network, no models.
    """
    header = (
        "SECOND-VOTE REVIEW PACKET — synthesized candidate seams, "
        "ranked. Judge only what these cards state.\n"
    )
    packet = header
    included: List[int] = []
    for idx, seam in enumerate(seams or []):
        seam = seam or {}
        card = (
            f"\nSEAM {seam.get('n', idx + 1)} "
            f"[mindset={seam.get('mindset', '?')} "
            f"severity={seam.get('severity', '?')} "
            f"redteam={seam.get('redteam_verdict', 'unreviewed')}]\n"
            f"Assertion A: {seam.get('assertion_a', '')}\n"
            f"Assertion B: {seam.get('assertion_b', '')}\n"
            f"Check: {seam.get('check', '')}\n"
            f"Expected: {seam.get('expected', '')}\n"
        )
        if estimate_tokens(system, packet + card) > int(budget_tokens):
            break
        packet += card
        included.append(idx)
    if not included:
        return "", []
    return packet, included


def collaborate(
    prompt,
    system,
    task_type="reflex",
    timeout=None,
    cfg=None,
    env=None,
    no_cloud: bool = False,
) -> Dict[str, Dict[str, str]]:
    """Run bounded scout/adversary/private-review roles for one evidence packet.

    Roles are deliberately different model families so the adversary is
    independent of the generator: scout on the Databricks generation
    lane, adversary on the OmniCLI multi-model swarm, private review
    on the local lane. A role whose lane is absent/unavailable is
    recorded unavailable, never silently reassigned to the generator's
    own family.

    This is deliberately separate from ``complete``: normal low-value work
    keeps cheap failover semantics, while a high-value candidate must preserve
    independent model outputs for the interface controller to judge.
    """
    # Bound every role call so a slow local reviewer can't hang the hunt — a
    # role that exceeds this is recorded failed and collaborate proceeds with
    # whatever other roles returned.
    timeout = timeout if timeout is not None else 120
    if cfg is None:
        cfg = load_backend_config()
    if env is None:
        import oracle_hunter

        env = oracle_hunter._load_env()
    by_name = {
        backend.name: backend
        for backend in build_backends_for(task_type, cfg, env, no_cloud=no_cloud)
    }
    results: Dict[str, Dict[str, str]] = {}
    _trace_id = _new_trace_id()

    def run(role: str, backend_name: str, role_prompt: str) -> str:
        backend = by_name.get(backend_name)
        if backend is not None and _lane_is_down(_lane_key(backend)):
            results[role] = {
                "status": "unavailable",
                "backend": backend_name,
                "error": "lane-down-cooldown",
            }
            return ""
        if backend is None or not backend.available():
            results[role] = {"status": "unavailable", "backend": backend_name}
            emit_logic_trace(
                env,
                {
                    "trace_id": _trace_id,
                    "span": "collaborate_role",
                    "ts": _utc_now_iso(),
                    "task_type": task_type,
                    "role": role,
                    "backend": backend_name,
                    "status": "unavailable",
                },
            )
            return ""
        need = estimate_tokens(system, role_prompt)
        if not backend.fits(need):
            results[role] = {
                "status": "failed",
                "backend": backend_name,
                "error": f"context-overflow need~{need}tok > ctx {backend.context_tokens}tok",
            }
            emit_logic_trace(
                env,
                {
                    "trace_id": _trace_id,
                    "span": "collaborate_role",
                    "ts": _utc_now_iso(),
                    "task_type": task_type,
                    "role": role,
                    "backend": backend_name,
                    "status": "skipped_overflow",
                    "need_tokens": need,
                    "context_tokens": backend.context_tokens,
                },
            )
            return ""
        _t0 = time.monotonic()
        try:
            output = backend.complete(system, role_prompt, timeout=timeout)
            _mark_lane_up(_lane_key(backend))
            results[role] = {
                "status": "ok",
                "backend": backend_name,
                "model": str(backend.last_model or "unknown"),
                "output": output,
            }
            emit_logic_trace(
                env,
                {
                    "trace_id": _trace_id,
                    "span": "collaborate_role",
                    "ts": _utc_now_iso(),
                    "task_type": task_type,
                    "role": role,
                    "backend": backend_name,
                    "status": "ok",
                    "model": str(backend.last_model or "unknown"),
                    "need_tokens": need,
                    "latency_ms": int((time.monotonic() - _t0) * 1000),
                    "out_chars": len(output or ""),
                },
            )
            return output
        except Exception as exc:
            if _failure_trips_breaker(exc, timeout, len(by_name) <= 1):
                _mark_lane_down(_lane_key(backend))
            results[role] = {
                "status": "failed",
                "backend": backend_name,
                "error": f"{type(exc).__name__}: {exc}",
            }
            emit_logic_trace(
                env,
                {
                    "trace_id": _trace_id,
                    "span": "collaborate_role",
                    "ts": _utc_now_iso(),
                    "task_type": task_type,
                    "role": role,
                    "backend": backend_name,
                    "status": "failed",
                    "need_tokens": need,
                    "latency_ms": int((time.monotonic() - _t0) * 1000),
                    "error_type": type(exc).__name__,
                },
            )
            return ""

    scout = run("scout", "databricks", prompt)
    adversary_prompt = (
        "You are the adversarial reviewer. Do not invent new targets or claims. "
        "Attack the scout candidate below using only the supplied evidence. Identify "
        "missing preconditions, scope issues, false-positive explanations, and the "
        "single observation that would confirm or close it.\n\n"
        f"--- EVIDENCE PACKET ---\n{prompt}\n\n--- SCOUT OUTPUT ---\n{scout or '[unavailable]'}"
    )
    run("adversary", "omnicli", adversary_prompt)
    private_prompt = (
        "You are the private local reviewer. Independently assess the evidence and "
        "the scout/adversary outputs. Return only a concise promote/close/inconclusive "
        "recommendation and the missing decisive evidence.\n\n"
        f"--- EVIDENCE PACKET ---\n{prompt}\n\n--- SCOUT ---\n{scout or '[unavailable]'}"
        f"\n\n--- ADVERSARY ---\n{results.get('adversary', {}).get('output', '[unavailable]')}"
    )
    run("private_reviewer", "local", private_prompt)
    return results
