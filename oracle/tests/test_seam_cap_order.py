#!/usr/bin/env python3
"""Cap-cannot-bury law for [:25] template caps (E0, 2026-10-21).

Fail-first receipts (all RED before the patch, captured):

  * _t_legacy ranked purely alphabetically under the [:25] cap, so a
    crawled (observed-live) legacy endpoint could be cut while a
    fuzzed-404 entry that only PROVES the path was attempted filled
    the cap alphabetically — the hunt-4b bury class (live /metrics
    ranked 25th alphabetically and was cut; reports/live_gate_20261019).
  * _t_beautiful_liar dedupe seeded the seen-set with the stale fuzzed
    loop variable (seen.add(url) instead of abs_url) —
    cross-source duplicates and a NameError crash on empty fuzzed.
"""

from oracle_seam_templates import _t_beautiful_liar, _t_deathless

_BASE = {"live_hosts": ["https://t.example"]}


def test_legacy_cap_keeps_observed_live_not_fuzzed_404():
    js = [f"/a{n:02d}-legacy-app" for n in range(1, 25)] + ["/z-zone-legacy-app"]
    mat = {**_BASE, "js_endpoints": js, "fuzzed": ["/m1-legacy-app [404]"]}
    out = _t_deathless(mat)
    # The 25-slot cap must keep the crawled /z-zone-legacy-app (observed
    # live) and NOT spend the slot on the fuzzed-404 (path attempted,
    # never answered alive).
    first = out[0]["check"]
    cuts = "".join(c["check"] for c in out)
    # Among uniform live candidates alpha still governs; the law's proof
    # is that the fuzzed-only (404, never answered alive) candidate is
    # cut and the crawled one is kept inside the cap.
    assert "/z-zone-legacy-app" in cuts
    assert "/m1-legacy-app" not in cuts
    assert len(out) == 25


def test_beautiful_liar_cross_source_dedupe():
    mat = {
        **_BASE,
        "js_endpoints": ["/admin-dash"],
        "fuzzed": ["/admin-dash [200]"],
    }
    out = _t_beautiful_liar(mat)
    urls = [c["check"] for c in out]
    assert len(urls) == 1, urls  # pre-patch: 2 (stale-var dedupe miss)


def test_beautiful_liar_empty_fuzzed_no_crash():
    mat = {**_BASE, "js_endpoints": ["/admin-only"], "fuzzed": []}
    out = _t_beautiful_liar(mat)  # pre-patch: NameError (url unbound)
    assert len(out) == 1
    assert "admin-only" in out[0]["check"]
