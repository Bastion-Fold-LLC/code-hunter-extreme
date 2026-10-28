#!/usr/bin/env python3
"""Harvest hygiene legs (E0 closeout, 2026-10-21).

Fail-first receipts (RED pre-patch, both captured):

  * fuzz_object_ids's cache write used default perms (0644) —
    probe hit lists persisted next to recon world-readable, while the
    login cache already used the house 0600 fd+chmod pattern (:576).
  * confirm_form_replay's standalone GET leg never consulted the scope
    gate: an out-of-scope check string sent recon traffic anywhere the
    POST leg would have refused. Now gated the same way — enforce when
    a gate is provided (including a raising gate → fail closed),
    fail-closed on gate error; gate=None stays the operator-declared
    ungated regime (legacy contract, test_form_replay_mutation_disabled).
"""

import json
import stat

from oracle_harvest import confirm_form_replay, fuzz_object_ids


class _Deny:
    def is_in_scope(self, url):
        return (False, "refused in test")


class _Raising:
    def is_in_scope(self, url):
        raise RuntimeError("gate exploded")


def test_fuzz_cache_written_0600(tmp_path):
    fuzz_object_ids({}, "http://127.0.0.1:9/x5/x", "5", tmp_path)
    cache = tmp_path / "id_fuzz.json"
    assert cache.exists(), "cache write skipped — test is vacuous"
    assert json.loads(cache.read_text())["hits"] == []
    mode = stat.S_IMODE(cache.stat().st_mode)
    assert mode == 0o600, f"fuzz cache perms {mode:o} (login cache ships 0600)"


def test_csrf_get_leg_refused_when_gate_denies():
    rc, _out, err = confirm_form_replay(
        "curl -i -s 'http://127.0.0.1:9/form'", scope_gate=_Deny()
    )
    assert rc == 1
    assert "scope" in err.lower()
    assert "form fetch failed" not in err.lower()


def test_csrf_get_leg_fail_closed_on_gate_error():
    rc, _out, err = confirm_form_replay(
        "curl -i -s 'http://127.0.0.1:9/form'", scope_gate=_Raising()
    )
    assert rc == 1
    assert "scope" in err.lower()
