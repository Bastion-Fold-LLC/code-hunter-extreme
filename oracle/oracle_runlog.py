# LAYER: seal
# DEST: vortex
# ENDPOINTS: RunLog, redact
# TOPICS: run logs, observability, artifact hashes, secret redaction
"""Structured, append-only logs for every Oracle CLI run.

The console is for humans. This module is the machine record:

    reports/runs/<run_id>/events.jsonl   one JSON object per event
    reports/runs/<run_id>/summary.json   status, counts, artifacts, errors
    reports/runs/latest.json             pointer to the newest run

Logging is best-effort: a broken log directory must never take down a hunt.
Secrets are redacted at the logging boundary, not at the call site.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_SCHEMA = "oracle.runlog/v1"
# Credential-shaped names, matched by meaning not by exact enumeration:
# accounts, sessions, credentials, JWTs, signing/access keys, and long or
# short spellings of the same concepts are all protected. Over-redaction
# (e.g. "author") is the safe direction for a log file.
_SECRET_KEY_RE = re.compile(
    r"(?i)(auth|token|secret|password|passwd|cookie|authorization"
    r"|api[_-]?key|bearer|basic|account|credential|session|jwt|private"
    r"|access[_-]?key|signing|(?:^|[_-])key(?:$|[_-]))"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_BASIC_RE = re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=._-]+")
_AUTHORIZATION_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)[^\s,;\"'}]+(?:\s+[^\s,;\"'}]+)?"
)
_COOKIE_RE = re.compile(r"(?i)(cookie\s*[:=]\s*)[^\r\n\"'}']+")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_KV_SECRET_RE = re.compile(
    r"(?i)((?:auth|token|secret|password|passwd|cookie|api[_-]?key"
    r"|session|credential|jwt|account|signing[_-]?key|access[_-]?key)"
    r"\s*[=:]\s*)[^\s,;]+"
)
_SECRET_FLAGS = {
    "--account-a",
    "--account-b",
    "--api-key",
    "--auth",
    "--bearer",
    "--cookie",
    "--password",
    "--secret",
    "--token",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_secret_flag(arg: str) -> bool:
    """A flag bears credentials when listed or named like one."""
    if arg in _SECRET_FLAGS:
        return True
    if arg.startswith("--"):
        return bool(_SECRET_KEY_RE.search(arg[2:].split("=", 1)[0]))
    return False


def redact_argv(argv: Iterable[str]) -> List[str]:
    """Redact values that follow credential-bearing CLI flags."""
    out: List[str] = []
    redact_next = False
    for raw in argv:
        arg = str(raw)
        if redact_next:
            out.append("[REDACTED]")
            redact_next = False
            continue
        if "=" in arg and _is_secret_flag(arg):
            out.append(arg.split("=", 1)[0] + "=[REDACTED]")
            continue
        if _is_secret_flag(arg):
            out.append(arg)
            redact_next = True
            continue
        out.append(redact(arg))
    return out


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact credential-shaped keys and values."""
    if key and _SECRET_KEY_RE.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        value = _JWT_RE.sub("[REDACTED]", value)
        value = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", value)
        value = _COOKIE_RE.sub(r"\1[REDACTED]", value)
        value = _BEARER_RE.sub(r"\1[REDACTED]", value)
        value = _BASIC_RE.sub(r"\1[REDACTED]", value)
        value = _KV_SECRET_RE.sub(r"\1[REDACTED]", value)
        return value
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class RunLog:
    """One run's event stream and summary."""

    def __init__(
        self,
        command: str,
        argv: Optional[Iterable[str]] = None,
        root: Optional[Path] = None,
        meta: Optional[Dict[str, Any]] = None,
    ):
        self.command = str(command or "unknown")
        self.argv = redact_argv(argv or [])
        self.root = Path(root) if root is not None else Path.cwd() / "reports" / "runs"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_id = f"{stamp}-{uuid.uuid4().hex[:8]}"
        self.run_dir = self.root / self.run_id
        self.events_path = self.run_dir / "events.jsonl"
        self.summary_path = self.run_dir / "summary.json"
        self.started_at = _utc_now()
        self.finished_at: Optional[str] = None
        self.status = "running"
        self.error: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.meta: Dict[str, Any] = dict(meta or {})
        self.artifacts: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self._counts: Dict[str, int] = {}
        self._enabled = True
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._enabled = False
        self.event(
            "run.start",
            command=self.command,
            argv=self.argv,
            cwd=os.getcwd(),
            pid=os.getpid(),
            python=sys.version.split()[0],
            schema=_SCHEMA,
        )

    # ── event stream ────────────────────────────────────────────────────────
    def event(self, event: str, **data: Any) -> None:
        if not self._enabled:
            return
        self._counts[event] = self._counts.get(event, 0) + 1
        if event == "warning":
            msg = str(data.get("message", ""))
            if msg:
                self.warnings.append(msg)
        elif event == "error":
            msg = str(data.get("message", ""))
            if msg:
                self.errors.append(msg)
        line = {
            "ts": _utc_now(),
            "run_id": self.run_id,
            "event": event,
            **redact(data),
        }
        try:
            with self.events_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")
        except OSError:
            self._enabled = False
            return
        # Keep summary.json current on meaningful events without rewriting it
        # for every console line (a noisy hunt can emit hundreds).
        if event in {
            "run.start",
            "run.end",
            "run.exception",
            "stage",
            "artifact",
            "warning",
            "error",
        }:
            self._write_summary()

    def stage(
        self,
        name: str,
        status: str,
        *,
        duration_s: Optional[float] = None,
        error: Optional[str] = None,
        **data: Any,
    ) -> None:
        payload = {"name": name, "status": status, **data}
        if duration_s is not None:
            payload["duration_s"] = round(float(duration_s), 3)
        if error:
            payload["error"] = error
        self.event("stage", **payload)

    def artifact(self, path: Any, kind: str = "file", **meta: Any) -> None:
        p = Path(path)
        record: Dict[str, Any] = {
            "path": str(p),
            "kind": kind,
            "exists": p.exists(),
            **meta,
        }
        try:
            if p.is_file():
                record["bytes"] = p.stat().st_size
                record["sha256"] = _sha256_file(p)
        except OSError as exc:
            record["hash_error"] = f"{type(exc).__name__}: {exc}"
        self.artifacts.append(record)
        self.event("artifact", **record)

    def set_status(self, status: str, error: Optional[str] = None) -> None:
        self.status = str(status)
        if error:
            self.error = str(error)

    def finish(
        self,
        status: str = "ok",
        error: Optional[str] = None,
        exit_code: Optional[int] = None,
    ) -> None:
        if self.finished_at is not None:
            return
        self.status = str(status)
        if error:
            self.error = str(error)
        if exit_code is not None:
            self.exit_code = int(exit_code)
        elif self.status == "ok":
            self.exit_code = 0
        elif self.status == "failed":
            self.exit_code = 1
        self.finished_at = _utc_now()
        self.event(
            "run.end",
            status=self.status,
            error=self.error,
            exit_code=self.exit_code,
            duration_s=self.duration_s(),
        )
        self._write_summary()

    def duration_s(self) -> Optional[float]:
        try:
            start = datetime.fromisoformat(self.started_at)
            end = (
                datetime.fromisoformat(self.finished_at)
                if self.finished_at
                else datetime.now(timezone.utc)
            )
            return round((end - start).total_seconds(), 3)
        except ValueError:
            return None

    def summary(self) -> Dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "run_id": self.run_id,
            "command": self.command,
            "argv": self.argv,
            "status": self.status,
            "exit_code": self.exit_code,
            "error": redact(self.error) if self.error else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration_s(),
            "meta": redact(self.meta),
            "event_counts": dict(sorted(self._counts.items())),
            "artifacts": redact(self.artifacts),
            "errors": [redact(e) for e in self.errors],
            "warnings": [redact(w) for w in self.warnings],
            "events_path": str(self.events_path),
        }

    def _write_summary(self) -> None:
        if not self._enabled:
            return
        try:
            payload = json.dumps(
                self.summary(), indent=2, ensure_ascii=False, default=str
            )
            tmp = self.summary_path.with_suffix(".json.tmp")
            tmp.write_text(payload + "\n", encoding="utf-8")
            tmp.replace(self.summary_path)
            latest = {
                "schema": _SCHEMA,
                "run_id": self.run_id,
                "status": self.status,
                "summary": str(self.summary_path),
                "events": str(self.events_path),
            }
            latest_tmp = self.root / "latest.json.tmp"
            latest_tmp.write_text(
                json.dumps(latest, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            latest_tmp.replace(self.root / "latest.json")
        except OSError:
            self._enabled = False
