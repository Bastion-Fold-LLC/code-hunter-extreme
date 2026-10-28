"""Regression coverage for the security-audit remediation set."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
import subprocess

import oracle_hunter as oh
import oracle_mindset_context as mindset
import oracle_programs as op
import oracle_rendered as rendered


def test_rendered_credentials_are_never_cross_origin():
    assert rendered._same_origin(
        "https://app.example.com/a", "https://app.example.com/b"
    )
    assert not rendered._same_origin(
        "https://app.example.com/a", "https://evil.example.com/b"
    )
    assert not rendered._same_origin(
        "https://app.example.com/a", "http://app.example.com/b"
    )


def test_scoped_fetch_skips_unsafe_rendering_backends(monkeypatch):
    calls = {}

    def fake_get(url, headers=None, timeout=30, redirect_validator=None):
        calls["url"] = url
        calls["validator"] = redirect_validator
        return "safe response"

    monkeypatch.setattr(op, "_get", fake_get)
    result = op._fetch(
        "https://app.example.com/start",
        redirect_validator=lambda candidate: candidate == "https://app.example.com/start",
    )
    assert result == "safe response"
    assert calls["url"] == "https://app.example.com/start"
    assert calls["validator"] is not None


def test_redirect_validator_prevents_out_of_scope_request():
    received = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    target = HTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    class Source(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{target.server_port}/private"
            )
            self.end_headers()

        def log_message(self, *args):
            pass

    source = HTTPServer(("127.0.0.1", 0), Source)
    threading.Thread(target=source.serve_forever, daemon=True).start()
    try:
        source_url = f"http://127.0.0.1:{source.server_port}/start"
        assert op._get(source_url, redirect_validator=lambda url: url == source_url) is None
        assert received == []
    finally:
        source.shutdown()
        target.shutdown()


def test_asset_redirect_policy_rejects_private_resolution(monkeypatch, tmp_path):
    workspace = mindset.ProgramWorkspace(
        {"scope": "app.example.com", "url": "https://app.example.com"},
        base=tmp_path,
    )
    monkeypatch.setattr(
        mindset.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("169.254.169.254", 0))],
    )
    assert not workspace._asset_url_allowed("https://app.example.com/redirect")


def test_variant_sweep_redacts_injected_credentials_before_assessment(monkeypatch):
    captured = {}

    class Gate:
        def validate_check(self, check, is_testnet=False):
            return True, check, "ok"

    monkeypatch.setattr(
        oh,
        "_run_check",
        lambda *args, **kwargs: (0, "response has Bearer topsecret and sid=abc123", ""),
    )

    import oracle_llm

    def complete(prompt, *args, **kwargs):
        captured["prompt"] = prompt
        return "FALSE_POSITIVE — safe test"

    monkeypatch.setattr(oracle_llm, "complete", complete)
    monkeypatch.setattr(oh, "_lens_prompt_for", lambda *args, **kwargs: "")
    oh._run_variant_sweep(
        plan=[
            {
                "check": "curl https://app.example.com/api",
                "claim": "test",
                "asset_ident": "app.example.com",
                "parent_seam": 1,
            }
        ],
        scope_gate=Gate(),
        target="app.example.com",
        recon_dir=Path("."),
        auth="Bearer topsecret",
        cookie="sid=abc123",
        auto=True,
    )
    assert "topsecret" not in captured["prompt"]
    assert "sid=abc123" not in captured["prompt"]


def test_ci_pins_and_verifies_gitleaks(tmp_path):
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "validate.yml"
    ).read_text()
    assert 'TAG="8.24.3"' in workflow
    assert "sha256sum --check" in workflow
    assert "releases/latest" not in workflow
    # Checksum must BLOCK: strict shell, no error-swallowing around verify.
    assert "set -euo pipefail" in workflow
    assert "set +e" not in workflow
    assert "persist-credentials: false" in workflow
    assert "permissions:\n      contents: read" in workflow
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "actions/setup-python@8d9ed9ac5c53483de85588cdf95a591a75ab9f55" in workflow
    assert "astral-sh/setup-uv@22695119d769bdb6f7032ad67b9bca0ef8c4a174" in workflow
    assert "uv sync --frozen --extra dev" in workflow
    checksum = re.search(r'SHA256="([0-9a-f]{64})"', workflow).group(1)
    tampered = tmp_path / "gitleaks.tar.gz"
    tampered.write_bytes(b"tampered archive")
    result = subprocess.run(
        ["sha256sum", "--check"],
        input=f"{checksum}  {tampered}\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0


def test_redact_known_secrets_covers_cookie_values_and_url_encoding():
    # S6 residual: servers reflect credentials transformed — bare cookie
    # pair values and URL-encoded forms must scrub too, not just exact.
    out = oh._redact_known_secrets(
        "leak1 tok-abc-123 leak2 tok%20xyz end",
        ["sid=tok-abc-123; theme=dark", "tok xyz"],
    )
    assert "tok-abc-123" not in out
    assert "tok%20xyz" not in out
    assert "leak1" in out and "end" in out  # surrounding text survives


def test_redact_known_secrets_url_encodes_cookie_pair_values():
    import urllib.parse

    val = "t o k/en"
    secret = f"sid={val}; theme=dark"
    reflected = urllib.parse.quote(val, safe="")
    out = oh._redact_known_secrets(f"echo {reflected} end", [secret])
    assert reflected not in out
    assert "[REDACTED]" in out
