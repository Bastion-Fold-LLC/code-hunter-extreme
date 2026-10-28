#!/usr/bin/env python3
"""Template coverage regression: all 7 planted flaws must produce at least one
seam from scan_template_seams() given realistic recon data.

These are DETERMINISTIC — no cloud, no live server required.
They lock the template engine so a regression can never silently drop a flaw class.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
import oracle_seam_templates as st  # noqa: E402

PORT = 55556
BASE = f"http://127.0.0.1:{PORT}"


def _make_recon(tmp_path: Path) -> Path:
    paths = [
        f"{BASE}/debug/config [200]",
        f"{BASE}/api/v1/admin/metrics [403]",
        f"{BASE}/api/internal/private [200]",
        f"{BASE}/api/v1/private/secure [403]",
        f"{BASE}/api/v1/users [200]",
        f"{BASE}/api/internal/dashboard [200]",
        f"{BASE}/static/package.json [200]",
        f"{BASE}/static/.env.bak [200]",
        f"{BASE}/health [200]",
        f"{BASE}/api/v1/orders/ord_101/apply_discount [200]",
    ]
    (tmp_path / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
    (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
    (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
    (tmp_path / "known_urls.txt").write_text(
        "\n".join(p.split(" ")[0] for p in paths) + "\n"
    )
    (tmp_path / "js_endpoints.txt").write_text(
        f"{BASE}/api/v1/users\n{BASE}/api/v2/users\n"
    )
    for f in ("js_secrets.txt", "api_specs.txt"):
        (tmp_path / f).write_text("")
    return tmp_path


@pytest.fixture(scope="module")
def all_seams(tmp_path_factory):
    recon = _make_recon(tmp_path_factory.mktemp("cov_recon"))
    seams = st.scan_template_seams(
        recon_dir=recon,
        repo_path=None,
        program=None,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
    )
    return [s["check"] for s in seams]


def test_grep_cards_carry_confirmable_static_evidence(tmp_path):
    """Connection-trace DEAD #3: grep-based code templates produced cards
    the wire scope gate always killed (no URL) with no static-evidence
    confirm path. They must carry CERTAIN verdict + localized evidence
    so the hunt code_only confirm path can confirm them like
    invisible-seam cards."""
    from oracle_foundation import validate_card_shape

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.json").write_text('{"MAX_RETRIES": 3}\n')
    (repo / "app.py").write_text("MAX_RETRIES = 9\n")
    (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
    (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
    for f in ("known_urls.txt", "fuzzed_paths.txt", "js_endpoints.txt",
              "js_secrets.txt", "api_specs.txt"):
        (tmp_path / f).write_text("")
    seams = st.scan_template_seams(
        recon_dir=tmp_path,
        repo_path=repo,
        program=None,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
    )
    grep_cards = [s for s in seams if s["check"].startswith("grep ")]
    assert grep_cards, [s["check"] for s in seams]
    for s in grep_cards:
        assert validate_card_shape(s) is None
        assert s["verdict"] == "CERTAIN"
        assert s["check_output"].strip()


def test_state_action_derived_from_discovered_resource(tmp_path):
    """Hunt regression (testbed 127.0.0.1:8765): ffuf discovered the order
    resource GET but not its POST action sub-path, so the coupon flaw was
    never mined. The state-invariant template must derive canonical
    action candidates from a discovered resource instance."""
    (tmp_path / "fuzzed_paths.txt").write_text(
        f"{BASE}/api/v1/orders/ord_101 [200]\n"
    )
    (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
    (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
    (tmp_path / "known_urls.txt").write_text(f"{BASE}/api/v1/orders/ord_101\n")
    (tmp_path / "js_endpoints.txt").write_text("")
    for f in ("js_secrets.txt", "api_specs.txt"):
        (tmp_path / f).write_text("")
    seams = st.scan_template_seams(
        recon_dir=tmp_path,
        repo_path=None,
        program=None,
        scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
    )
    checks = [s["check"] for s in seams]
    assert any("/api/v1/orders/ord_101/apply_discount" in c for c in checks)


class TestFlawCoverageByTemplate:
    """Each test asserts that at least one seam addresses the named flaw."""

    def test_flaw1_trust_bypass_template_fires(self, all_seams):
        assert any(
            "/api/v1/admin/metrics" in c and "X-Original-Role" in c
            for c in all_seams
        ), "No trust-bypass seam for /api/v1/admin/metrics with X-Original-Role header"

    def test_flaw2_cliff_and_current_template_fires(self, all_seams):
        assert any(
            "internal/private" in c
            for c in all_seams
        ), "No cliff-and-current seam pointing at /api/internal/private"

    def test_flaw3_debug_config_template_fires(self, all_seams):
        assert any(
            "/debug/config" in c
            for c in all_seams
        ), "No self-observing seam for /debug/config"

    def test_flaw4_mirror_v1_template_fires(self, all_seams):
        assert any(
            "/api/v1/users" in c
            for c in all_seams
        ), "No mirror seam for /api/v1/users"

    def test_flaw5_legacy_dashboard_template_fires(self, all_seams):
        assert any(
            "internal/dashboard" in c
            for c in all_seams
        ), "No deathless seam for /api/internal/dashboard"

    def test_flaw6_artifact_exposure_template_fires(self, all_seams):
        assert any(
            ("/static/.env.bak" in c or "/static/package.json" in c)
            for c in all_seams
        ), "No artifact-exposure seam for .env.bak or package.json"

    def test_flaw7_state_invariant_template_fires(self, all_seams):
        assert any(
            "apply_discount" in c
            for c in all_seams
        ), "No state-invariant seam for apply_discount endpoint"


class TestCliffAndCurrentSemanticFallback:
    """The semantic fallback (Pass 2) must fire when suffix exact-match fails."""

    def test_semantic_fallback_fires_for_mismatched_suffixes(self, tmp_path):
        """Guarded: /api/v1/admin/metrics [403], Unguarded: /api/internal/private [200].
        Suffixes don't match (/admin/metrics vs /private) so Pass 1 fails.
        Pass 2 must fire because both paths match _ALT_PATH_RE."""
        paths = [
            f"{BASE}/api/v1/admin/metrics [403]",
            f"{BASE}/api/internal/private [200]",
        ]
        (tmp_path / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
        (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "known_urls.txt").write_text(
            "\n".join(p.split(" ")[0] for p in paths) + "\n"
        )
        for f in ("js_endpoints.txt", "js_secrets.txt", "api_specs.txt"):
            (tmp_path / f).write_text("")
        seams = st.scan_template_seams(
            recon_dir=tmp_path,
            repo_path=None,
            program=None,
            scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
        )
        checks = [s["check"] for s in seams]
        assert any("internal/private" in c for c in checks), (
            "Semantic fallback did not fire: no cliff-and-current seam for "
            "mismatched suffix pair /admin/metrics [403] + /internal/private [200]"
        )


class TestStateInvariantTemplate:
    """State-invariant template must fire for action verbs on resource paths."""

    def test_apply_discount_fires(self, tmp_path):
        paths = [f"{BASE}/api/v1/orders/ord_101/apply_discount [200]"]
        (tmp_path / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
        (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "known_urls.txt").write_text(paths[0].split(" ")[0] + "\n")
        for f in ("js_endpoints.txt", "js_secrets.txt", "api_specs.txt"):
            (tmp_path / f).write_text("")
        seams = st.scan_template_seams(
            recon_dir=tmp_path,
            repo_path=None,
            program=None,
            scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
        )
        checks = [s["check"] for s in seams]
        assert any("apply_discount" in c for c in checks), (
            "state-invariant template did not fire for apply_discount"
        )

    def test_post_method_used(self, tmp_path):
        """State-invariant check must use POST (not GET)."""
        paths = [f"{BASE}/api/v1/payments/pay_001/refund [200]"]
        (tmp_path / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
        (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "known_urls.txt").write_text(paths[0].split(" ")[0] + "\n")
        for f in ("js_endpoints.txt", "js_secrets.txt", "api_specs.txt"):
            (tmp_path / f).write_text("")
        seams = st.scan_template_seams(
            recon_dir=tmp_path,
            repo_path=None,
            program=None,
            scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
        )
        state_checks = [
            s["check"] for s in seams
            if s.get("claim_type") == "state-invariant-violation"
        ]
        assert state_checks, "state-invariant template did not fire for /refund"
        assert all("-X POST" in c for c in state_checks), (
            "state-invariant check must use -X POST"
        )

    def test_no_fire_without_resource_keyword(self, tmp_path):
        """A path with an action verb but no resource type must NOT fire."""
        paths = [f"{BASE}/api/v1/users/apply_discount [200]"]
        (tmp_path / "fuzzed_paths.txt").write_text("\n".join(paths) + "\n")
        (tmp_path / "live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "clean_live_hosts.txt").write_text(BASE + "\n")
        (tmp_path / "known_urls.txt").write_text(paths[0].split(" ")[0] + "\n")
        for f in ("js_endpoints.txt", "js_secrets.txt", "api_specs.txt"):
            (tmp_path / f).write_text("")
        seams = st.scan_template_seams(
            recon_dir=tmp_path,
            repo_path=None,
            program=None,
            scope_gate=oh.ProgramScopeGate({}, target_fallback=BASE),
        )
        # "users" does NOT match _STATE_RESOURCE_RE (order/payment/invoice/etc.)
        # so the template must not fire
        checks = [s["check"] for s in seams if s.get("claim_type") == "state-invariant-violation"]
        assert not checks, (
            "state-invariant fired on /users path — resource keyword guard is broken"
        )
