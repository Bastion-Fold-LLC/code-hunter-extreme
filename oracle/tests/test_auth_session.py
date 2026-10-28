import json
import pytest
from pathlib import Path
from oracle_auth_session import (
    ACCOUNT_B_AUTH_PLACEHOLDER,
    DualAccountHarness,
    evaluate_cross_account_idor,
    substitute_probe_placeholders,
)


def _harness(**kw):
    kw.setdefault("target_domain", "target.com")
    kw.setdefault("platform", "hackerone")
    kw.setdefault("researcher_username", "phantomcore")
    return DualAccountHarness(**kw)


def test_idor_ignores_llm_prose_urls():
    """C1: a hallucinated evil.com URL in assertion prose must not become a probe."""
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK"
    seams = [{
        "check": "curl -s 'https://target.com/api/orders/ord_12345'",
        "assertion_a": "a",
        "assertion_b": "see https://evil.com/api/orders/ord_99999 for details",
    }]
    probes = [p for p in h.build_idor_probes(seams) if p.get("check")]
    assert all("evil.com" not in p["check"] for p in probes)
    assert any("target.com/api/orders/ord_12345" in p["check"] for p in probes)


def test_idor_scope_gate_drops_out_of_scope():
    """C1: scope gate rejection must drop the candidate, never probe it."""
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK"

    class Gate:
        def is_in_scope(self, url):
            return ("victim.com" in url, "test gate")

    seams = [
        {"check": "curl -s 'https://victim.com/api/orders/ord_11111'", "assertion_a": "a", "assertion_b": "b"},
        {"check": "curl -s 'https://evil.com/api/orders/ord_22222'", "assertion_a": "a", "assertion_b": "b"},
    ]
    probes = [p for p in h.build_idor_probes(seams, scope_gate=Gate()) if p.get("check")]
    assert len(probes) == 1
    assert "victim.com" in probes[0]["check"]
    assert all("evil.com" not in p["check"] for p in probes)


def test_idor_recon_gate_drops_unverified_hosts():
    """C1: hosts not seen in recon must not become live probes."""
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK"
    seams = [{"check": "curl -s 'https://ghost.com/api/orders/ord_33333'", "assertion_a": "a", "assertion_b": "b"}]
    probes = [p for p in h.build_idor_probes(
        seams, recon_hosts=["https://target.com/"]) if p.get("check")]
    assert probes == []


def test_idor_stored_check_has_no_live_token():
    """C2: stored probe checks carry placeholders; secrets resolve at exec time."""
    h = _harness()
    h.account_b.token = "Bearer LIVE_ATK_123"
    seams = [{"check": "curl -s 'https://target.com/api/orders/ord_44444'", "assertion_a": "a", "assertion_b": "b"}]
    probes = [p for p in h.build_idor_probes(seams) if p.get("check")]
    assert probes
    for p in probes:
        assert "LIVE_ATK_123" not in p["check"]
        assert ACCOUNT_B_AUTH_PLACEHOLDER in p["check"]
    resolved, secrets = substitute_probe_placeholders(probes[0]["check"], h, as_account="b")
    assert "LIVE_ATK_123" in resolved
    assert secrets


def test_idor_placeholder_without_secret_fails_closed():
    """C2: placeholder with no secret available must not resolve (fail closed)."""
    h = _harness()  # no tokens set
    check = f'curl -s -H "Authorization: {ACCOUNT_B_AUTH_PLACEHOLDER}" "https://target.com/x/ord_55555"'
    resolved, secrets = substitute_probe_placeholders(check, h, as_account="b")
    assert secrets == []
    assert ACCOUNT_B_AUTH_PLACEHOLDER in resolved


def test_dual_account_alias_generation():
    # HackerOne — handle@wearehackerone.com (primary), handle+2@ (second account)
    h1 = DualAccountHarness("tinder.com", platform="hackerone", researcher_username="phantomcore")
    assert h1.alias_a == "phantomcore@wearehackerone.com"
    assert h1.alias_b == "phantomcore+2@wearehackerone.com"
    assert h1.compliance_headers["X-Bug-Bounty"] == "phantomcore"
    assert h1.compliance_headers["X-HackerOne-Research"] == "phantomcore"

    # Bugcrowd — [username]@bugcrowdninja.com confirmed from Rapyd/Chime/Okta program briefs
    bc = DualAccountHarness("tesla.com", platform="bugcrowd", researcher_username="phantomcore")
    assert bc.alias_a == "phantomcore@bugcrowdninja.com"
    assert bc.alias_b == "phantomcore+2@bugcrowdninja.com"
    assert "Bugcrowdninja-phantomcore" in bc.compliance_headers["User-Agent"]

    # Intigriti — uses code_hunter_extreme override (PLATFORM_HANDLE_OVERRIDES)
    inti = DualAccountHarness("uber.com", platform="intigriti", researcher_username="phantomcore")
    assert inti.alias_a == "code_hunter_extreme@intigriti.me"
    assert inti.alias_b == "code_hunter_extreme+2@intigriti.me"
    assert inti.compliance_headers["X-Intigriti-Researcher"] == "code_hunter_extreme"


def test_build_curl_probe_compliance_and_auth(tmp_path):
    from oracle_auth_session import (
        ACCOUNT_B_AUTH_PLACEHOLDER,
        substitute_probe_placeholders,
    )
    harness = DualAccountHarness("api.target.com", platform="hackerone", researcher_username="phantomcore")
    harness.account_a.token = "Bearer victim_token_123"
    harness.account_b.token = "Bearer attacker_token_456"

    # Build probe as Account B (attacker) — C2: stored check carries a
    # placeholder, never the live token.
    probe_b = harness.build_curl_probe("https://api.target.com/v1/profile/999", as_account="b")
    assert "-H \"X-Bug-Bounty: phantomcore\"" in probe_b
    assert f"Authorization: {ACCOUNT_B_AUTH_PLACEHOLDER}" in probe_b
    assert "attacker_token_456" not in probe_b
    assert "\"https://api.target.com/v1/profile/999\"" in probe_b

    # Execution-time substitution resolves the placeholder and tracks secrets.
    resolved, secrets = substitute_probe_placeholders(probe_b, harness, as_account="b")
    assert "attacker_token_456" in resolved
    assert secrets and any("attacker_token_456" in s for s in secrets)

    # Save and reload session
    sess_file = harness.save_session(tmp_path)
    assert sess_file.is_file()

    # Reload session from file
    new_harness = DualAccountHarness.from_session_file(sess_file)
    assert new_harness.account_a.token == "Bearer victim_token_123"
    assert new_harness.account_b.token == "Bearer attacker_token_456"


def test_dual_account_raises_rule_2_without_handle(monkeypatch):
    monkeypatch.delenv("RESEARCHER_HANDLE", raising=False)
    monkeypatch.delenv("BOUNTY_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.setattr("oracle_auth_session._extract_handle_from_browser_profile", lambda: None)
    monkeypatch.setattr("oracle_auth_session.Path.is_file", lambda self: False if ".env" in str(self) else True)
    with pytest.raises(ValueError, match="Rule 2 Violation"):
        DualAccountHarness("api.target.com", platform="hackerone", researcher_username=None)


def test_cross_account_idor_check():
    harness = DualAccountHarness("target.com", platform="hackerone", researcher_username="phantomcore")
    harness.account_a.token = "Bearer token_victim"
    harness.account_b.token = "Bearer token_attacker"

    card = evaluate_cross_account_idor(harness, "https://target.com/api/orders/{id}", "88412")
    assert "REFLEX 2" in card["reflex"]
    assert "CWE-639" in card["mitre"]
    assert "phantomcore@wearehackerone.com" in card["assertion_a"]
    assert "phantomcore+2@wearehackerone.com" in card["assertion_b"]
    # C2: live token never stored — placeholder in card, resolved at exec time.
    from oracle_auth_session import ACCOUNT_B_AUTH_PLACEHOLDER, substitute_probe_placeholders
    assert f"Authorization: {ACCOUNT_B_AUTH_PLACEHOLDER}" in card["check"]
    assert "token_attacker" not in card["check"]
    resolved, _secrets = substitute_probe_placeholders(card["check"], harness, as_account="b")
    assert "Authorization: Bearer token_attacker" in resolved
    assert "https://target.com/api/orders/88412" in card["check"]


def test_platforms_registry_ingested():
    reg_file = Path(__file__).resolve().parent.parent / "platforms_registry.json"
    assert reg_file.is_file()
    data = json.loads(reg_file.read_text())
    assert len(data) >= 50
    categories = {p["category"] for p in data}
    assert "government" in categories
    assert "web3" in categories
    assert "ai" in categories
    assert "crowdsourced" in categories


def test_substitution_strips_header_breakout_chars():
    """Findings 2+3 (unit half): quotes/CR/LF/$/backticks in stored session secrets
    must be stripped at substitution time — values land inside double-
    quoted -H strings and curl -K config files, where a quote breaks out
    (unvalidated extra-URL fetch), a newline injects config directives
    (arbitrary file write), and $ or backticks could trigger shell expansion."""
    from oracle_auth_session import ACCOUNT_B_COOKIES_PLACEHOLDER

    h = _harness()
    h.account_b.token = 'tok"en\noutput = /tmp/x$(whoami)`id`'
    h.account_b.cookies = {"s": 'x" http://evil.example/SMUGGLED "y$VAR`whoami`'}
    auth_check = f'curl -s -H "Authorization: {ACCOUNT_B_AUTH_PLACEHOLDER}"'
    cookie_check = f'curl -s -H "Cookie: {ACCOUNT_B_COOKIES_PLACEHOLDER}"'
    resolved_auth, secrets_auth = substitute_probe_placeholders(
        auth_check, h, as_account="b"
    )
    resolved_cookie, secrets_cookie = substitute_probe_placeholders(
        cookie_check, h, as_account="b"
    )
    for resolved in (resolved_auth, resolved_cookie):
        assert "\n" not in resolved and "\r" not in resolved
        assert "$" not in resolved and "`" not in resolved
        assert resolved.count('"') == 2, resolved
    assert "Bearer tokenoutput = /tmp/x(whoami)id" in resolved_auth
    assert "SMUGGLED" in resolved_cookie  # value kept, quoting neutralized
    assert all("\n" not in s and '"' not in s and "$" not in s and "`" not in s for s in secrets_auth + secrets_cookie)


def test_chromium_candidates_env_first(tmp_path, monkeypatch):
    import oracle_auth_session as sess

    prof = tmp_path / "My Profile"
    prof.mkdir()
    (prof / "Login Data").write_bytes(b"x")
    monkeypatch.setenv("ORACLE_CHROMIUM_PROFILE_DIR", str(prof))
    cands = list(sess._chromium_login_db_candidates())
    assert cands == [prof / "Login Data"]
