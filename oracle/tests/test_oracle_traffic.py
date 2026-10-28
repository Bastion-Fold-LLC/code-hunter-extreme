import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle_traffic import import_har


class ScopeGate:
    def is_in_scope(self, url):
        return (url.startswith("http://127.0.0.1:3000/"), "local benchmark")


def test_import_har_redacts_secrets_and_rejects_out_of_scope_entries(tmp_path):
    har_path = tmp_path / "capture.har"
    har_path.write_text(json.dumps({
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://127.0.0.1:3000/api/orders?user=alice&token=secret",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer secret"},
                            {"name": "Cookie", "value": "session=secret"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {
                            "params": [
                                {"name": "quantity", "value": "1"},
                                {"name": "card", "value": "4111111111111111"},
                            ],
                        },
                    },
                    "response": {
                        "status": 201,
                        "content": {"mimeType": "application/json", "text": '{"secret":"no"}'},
                    },
                },
                {
                    "request": {"method": "GET", "url": "https://analytics.example/pixel"},
                    "response": {"status": 200, "content": {"mimeType": "image/gif"}},
                },
            ],
        },
    }))

    result = import_har(har_path, tmp_path / "recon", ScopeGate())

    assert result == {"accepted": 1, "rejected_out_of_scope": 1, "malformed": 0}
    evidence = (tmp_path / "recon" / "traffic_evidence.jsonl").read_text()
    assert "127.0.0.1" in evidence
    assert "user=%3Credacted%3E" in evidence
    assert "token=%3Credacted%3E" in evidence
    assert "authorization" not in evidence
    assert "session=secret" not in evidence
    assert "4111111111111111" not in evidence
    assert '"quantity"' in evidence
    assert "analytics.example" not in evidence


def test_import_har_requires_scope_gate(tmp_path):
    har_path = tmp_path / "capture.har"
    har_path.write_text('{"log":{"entries":[]}}')

    try:
        import_har(har_path, tmp_path / "recon")
    except ValueError as exc:
        assert "scope gate" in str(exc)
    else:
        raise AssertionError("HAR import accepted traffic without a scope gate")
