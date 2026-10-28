"""Lane preflight — refuse hunts that cannot be carried (E0-3, 2026-10-21).

Fail-first receipts: before lane_preflight existed, follow-on hunts under
``queue --execute`` started with zero living reflex lanes — the per-run
breaker ledger stayed stamped down from an earlier hunt's lane failures,
and the hunt burned its budget into a doomed engine analysis instead of
refusing loudly (the 2026-10-19 lane-starvation death mode; STATUS).

Contract under test:

  * lane_preflight counts lanes configured for the reflex route that are
    NOT stamped down by the in-run breaker ledger. No network probes —
    preflight cannot hang a hunt; per-call availability still flows
    through complete() where a real failure cascades via the breaker.
  * living >= floor passes; living < floor refuses with honest names.
  * floor comes from cfg['preflight']['min_alive_lanes'] (ships 2) with
    a per-call override for operators.
  * --no-cloud hunts bypass the gate entirely (local-only is a declared
    regime, not an emergency).
"""

import pytest

from oracle_llm import (
    DEFAULT_CONFIG,
    _lane_key,
    _mark_lane_down,
    build_backends_for,
    enforce_lane_preflight,
    lane_preflight,
    load_backend_config,
    reset_lane_health,
)


def _reflex():
    cfg = load_backend_config(None)
    backends = build_backends_for("reflex", cfg, {})
    return cfg, backends


def _fresh_lanes():
    reset_lane_health()
    return _reflex()


def test_fresh_run_every_lane_alive():
    cfg, backends = _fresh_lanes()
    living, dead, floor = lane_preflight("reflex", cfg=cfg, env={})
    assert len(living) == len(backends)
    assert dead == []
    assert floor == DEFAULT_CONFIG["preflight"]["min_alive_lanes"]


def test_all_dead_refuses_with_names():
    cfg, backends = _fresh_lanes()
    for b in backends:
        _mark_lane_down(_lane_key(b))
    living, dead, floor = lane_preflight("reflex", cfg=cfg, env={})
    assert living == []
    assert len(dead) == len(backends)
    with pytest.raises(RuntimeError):
        enforce_lane_preflight("reflex", cfg=cfg, env={})


def test_exactly_floor_passes():
    cfg, backends = _fresh_lanes()
    for b in backends[2:]:
        _mark_lane_down(_lane_key(b))
    living, dead, floor = lane_preflight("reflex", cfg=cfg, env={})
    assert len(living) >= floor == 2
    assert len(dead) == len(backends) - 2
    enforce_lane_preflight("reflex", cfg=cfg, env={})  # no raise


def test_floor_override_honored():
    cfg, backends = _fresh_lanes()
    for b in backends[1:]:
        _mark_lane_down(_lane_key(b))
    enforce_lane_preflight("reflex", cfg=cfg, env={}, min_alive=1)  # no raise
    with pytest.raises(RuntimeError):
        enforce_lane_preflight("reflex", cfg=cfg, env={}, min_alive=2)


def test_sole_lane_route_exempted_from_multi_floor():
    """Verifier follow-up (E0-3): a user-pinned 1-lane route must not be
    refused by a fleet floor — mirror the breaker's sole-lane law (one
    lane is a declared regime, the breaker never stamps sole-lane down).

    Fail-first pre-patch: reflex route pinned to ['local'] at floor 2
    refused RuntimeError though the hunt is perfectly carable.
    """
    import copy

    from oracle_llm import DEFAULT_CONFIG

    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["routes"] = {**cfg["routes"], "reflex": ["local"]}
    reset_lane_health()
    backends = build_backends_for("reflex", cfg, {})
    assert len(backends) == 1
    living, dead, floor = lane_preflight("reflex", cfg=cfg, env={})
    assert living == [_lane_key(backends[0])] and dead == []
    assert floor == 1
    enforce_lane_preflight("reflex", cfg=cfg, env={})  # no raise


def test_no_cloud_bypasses_the_gate():
    cfg, backends = _fresh_lanes()
    for b in backends:
        _mark_lane_down(_lane_key(b))
    # no raise: --no-cloud declares a local-only regime, floor is bypassed
    enforce_lane_preflight("reflex", cfg=cfg, env={}, no_cloud=True)
