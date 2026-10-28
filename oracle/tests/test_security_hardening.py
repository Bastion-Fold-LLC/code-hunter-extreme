import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

import oracle_deeprecon
import oracle_deterministic


class _AllowOnlyExample:
    def is_in_scope(self, url):
        return url.startswith("https://example.test/"), "test scope"


def test_check_response_secrets_detects_aws_key_in_api_body():
    findings = oracle_deterministic.check_response_secrets(
        "https://example.test/debug/config",
        '{"aws_secret_key_mock": "AKIAIOSFODNN7EXAMPLE"}')
    assert any(f["check"] == "response_secret_exposed" for f in findings)
    assert findings[0]["severity"] == "high"


def test_run_deterministic_flags_secret_in_response_body():
    def fetch(url):
        return 200, {"Content-Type": "application/json"}, '{"k": "AKIAIOSFODNN7EXAMPLE"}', []
    findings = oracle_deterministic.run_deterministic(
        ["https://example.test/debug/config"], scope_gate=None, fetcher=fetch)
    assert any(f["check"] == "response_secret_exposed" for f in findings)


def test_js_secret_artifact_contains_only_fingerprint(monkeypatch, tmp_path):
    html = b'<script src="/app.js"></script>'
    javascript = b'const api_key = "super-secret-value";'

    def fake_fetch(url, scope_gate, **_kwargs):
        if url.endswith("/"):
            return html, 200, url
        return javascript, 200, url

    monkeypatch.setattr(oracle_deeprecon, "_fetch", fake_fetch)
    oracle_deeprecon.mine_js(
        ["https://example.test/"], _AllowOnlyExample(), tmp_path, max_js_per_host=1)

    artifact = (tmp_path / "js_secrets.txt").read_text()
    assert "super-secret-value" not in artifact
    assert "sha256:" in artifact


def test_deterministic_fetch_revalidates_redirect_destination(monkeypatch):
    class FakeResponse:
        status = 302
        headers = {"Location": "http://127.0.0.1:9222/"}

        def close(self):
            pass

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(oracle_deterministic.urllib.request, "build_opener",
                        lambda *_args: FakeOpener())
    status, _headers, _body, _scripts = oracle_deterministic._default_fetcher(
        "https://example.test/", _AllowOnlyExample())
    assert status == 0


def test_header_expectations_and_assertion_source_are_required():
    seam = {
        "n": 1,
        "check": "curl -i -s https://example.test/api",
        "expected": "status 200, header content-security-policy absent",
        "assertion_a_source": "security policy",
    }
    headers_present = (
        "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\nbody")
    rejected = oracle_deterministic.verify_seam_card(
        seam, ["https://example.test/"], _AllowOnlyExample(), 200, headers_present)
    assert rejected["verdict"] == "REJECTED"

    seam.pop("assertion_a_source")
    missing_source = oracle_deterministic.verify_seam_card(
        seam, ["https://example.test/"], _AllowOnlyExample(), 200, "HTTP/1.1 200 OK\r\n\r\n")
    assert missing_source["verdict"] == "REJECTED"
