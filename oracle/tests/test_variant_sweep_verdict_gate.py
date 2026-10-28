"""Variant-sweep verdict gate: anchored classification for CONFIRMED.

Fail-first receipts (E0 2026-10-20): before parse_verdict landed, the sweep
matched the verdict by substring — 'UNCONFIRMED'/'POSSIBLY CONFIRMED IF...'
contained 'CONFIRMED' and matched no negation guard, so a sweep probe could
persist a fake CONFIRMED from prose that denies it. These tests capture the
anchored contract: only a verdict that truly starts CONFIRMED confirms;
denials and hedged prose are not findings.
"""

from pathlib import Path

import oracle_hunter as oh


class _Gate:
    def validate_check(self, check: str, is_testnet: bool = False):
        return True, check, "ok"


def _fire(monkeypatch, verdict: str):
    """Drive _run_variant_sweep with deterministic contradicting stubs."""
    monkeypatch.setattr(oh, "_run_check", lambda *a, **k: (0, "wire", ""))
    monkeypatch.setattr(oh, "_assess_response", lambda *a, **k: verdict)
    monkeypatch.setattr(oh, "_lens_prompt_for", lambda *a, **k: "SYS")
    plan = [
        {
            "check": "curl http://127.0.0.1:3001/api/item",
            "claim": "SQLi",
            "asset_ident": "127.0.0.1:3001",
            "parent_seam": 1,
            "parent_mindset": "mitre",
        }
    ]
    return oh._run_variant_sweep(
        plan=plan,
        scope_gate=_Gate(),
        target="t",
        recon_dir=Path("."),
        is_testnet=True,
        auto=True,
    )


def test_sweep_unconfirmed_verdict_never_confirms(monkeypatch):
    hits = _fire(monkeypatch, "UNCONFIRMED — probe did not reproduce it.")
    assert hits == {}


def test_sweep_possibly_confirmed_if_never_confirms(monkeypatch):
    hits = _fire(
        monkeypatch,
        "POSSIBLY CONFIRMED IF the endpoint lacks authz.",
    )
    assert hits == {}


def test_sweep_contract_confirmed_still_confirms(monkeypatch):
    """Recall preservation: the honest contract tail keeps confirming."""
    hits = _fire(
        monkeypatch,
        "CONFIRMED (deterministic) — Sensitive config exposed.",
    )
    entries = list(hits.values())
    assert entries and entries[0]["confirmed"] is True


def test_sweep_false_positive_still_miss(monkeypatch):
    hits = _fire(
        monkeypatch,
        "FALSE_POSITIVE — Target returned access denial.",
    )
    assert hits == {}


def test_sweep_not_confirmed_still_miss(monkeypatch):
    hits = _fire(monkeypatch, "NOT CONFIRMED — expected 403, seen 403.")
    assert hits == {}


def test_sweep_inconclusive_preserved(monkeypatch):
    """INCONCLUSIVE is not a finding class either: no sweep hit."""
    hits = _fire(
        monkeypatch,
        "INCONCLUSIVE — no backend available for assessment.",
    )
    assert hits == {}
