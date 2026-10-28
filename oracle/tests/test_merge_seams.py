import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def _s(a, b, chk, **extra):
    return {"assertion_a": a, "assertion_b": b, "check": chk,
            "impact": "", "reflex": "r", "mitre": "N/A", "raw": "", **extra}


def test_concat_and_renumber():
    recon = [_s("a1", "b1", "curl x")]
    code = [_s("a2", "b2", "test y", origin="invisible-seam")]
    out = oh._merge_seams(recon, code)
    assert [s["n"] for s in out] == [1, 2]
    assert out[0]["origin"] == "recon-reflex"
    assert out[1]["origin"] == "invisible-seam"


def test_cross_lens_dedupe():
    recon = [_s("Same Claim", "Same Wire", "curl z")]
    code = [_s("same claim ", " same wire", "CURL z", origin="invisible-seam")]
    out = oh._merge_seams(recon, code)
    assert len(out) == 1  # deduped; first (recon) wins


def test_empty_code_lens():
    recon = [_s("a", "b", "c")]
    assert len(oh._merge_seams(recon, [])) == 1


def test_same_check_url_deduped():
    """Phase 2.3: seams with identical check URL but different A/B text collapse to one.
    (DVWA seams 1+6 pattern: both probe /.git/config, first wins.)"""
    url = "https://target.com/.git/config"
    seam1 = _s("Git repo is private", "git config exposed", f"curl -i -s '{url}'")
    seam6 = _s("No config in webroot", "/.git/config returns 200", f"curl -i -s '{url}'")
    out = oh._merge_seams([seam1, seam6], [])
    assert len(out) == 1, f"expected 1 after URL-dedup, got {len(out)}"
    assert out[0]["assertion_a"] == "Git repo is private"  # first wins


def test_same_url_different_probes_preserved():
    """Distinct probes at one URL are distinct findings: a plain-GET
    exposure card must not swallow the header-injection card for the
    same endpoint (testbed hunt: /api/v1/admin/metrics lost its
    X-Original-Role probe to URL-only dedup)."""
    url = "https://target.com/api/v1/admin/metrics"
    plain = _s("internals not exposed", "endpoint reachable", f"curl -i -s '{url}'")
    forged = _s(
        "role enforced server-side",
        "server trusts X-Original-Role header",
        f"curl -i -s -H 'X-Original-Role: admin' '{url}'",
    )
    out = oh._merge_seams([plain, forged], [])
    assert len(out) == 2


def test_different_check_urls_preserved():
    """Different URLs on the same target must NOT collapse."""
    s1 = _s("A", "B", "curl -i -s 'https://target.com/.git/config'")
    s2 = _s("C", "D", "curl -i -s 'https://target.com/phpinfo.php'")
    out = oh._merge_seams([s1, s2], [])
    assert len(out) == 2


def test_no_url_checks_unaffected():
    """Forge/cast checks with no http URL must not cross-dedup each other."""
    s1 = _s("Claim X", "Wire X", "forge test VaultTest")
    s2 = _s("Claim Y", "Wire Y", "cast call 0xabc 'fn()'")
    out = oh._merge_seams([s1, s2], [])
    assert len(out) == 2


def test_extract_check_url():
    from oracle_hunter import _extract_check_url
    assert _extract_check_url("curl -i -s 'https://host.com/path'") == "https://host.com/path"
    assert _extract_check_url("forge test X") == ""
    assert _extract_check_url("") == ""
