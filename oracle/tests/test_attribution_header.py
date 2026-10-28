#!/usr/bin/env python3
"""x-hackerone attribution header (E1 gate-in, tinder, 2026-10-21).

Tinder Bug Bounty Program Terms (fetched live from HackerOne 2026-10-21,
retained at targets/hackerone/tinder/assets/program_policy_20261021.md):

  * ``Include the HTTP header ``x-hackerone: <your_hackerone_username>``
    on all testing traffic`` — MANDATORY attribution on every request.
  * Only DESTRUCTIVE automated testing is banned; automated testing
    itself is allowed (the pipeline's GET-only+declared-mutation gates
    stay stricter than the program floor).

Fail-first receipts (RED pre-patch):

  * confirm_form_replay's built opener request carried only the fixed
    ``User-Agent`` pair — the mandatory attribution header was absent
    from pipeline traffic (mocked-opener capture below).
  * shutil-attributed curl checks (the sweep's main traffic) ran
    without the header; the pure transform that inserts it did not
    exist (import red).
"""

import unittest
from unittest.mock import MagicMock, patch

from oracle_harvest import confirm_form_replay


class TestAttributionHeader(unittest.TestCase):
    def test_curl_transform_inserts_header_once(self):
        from oracle_hunter import _attribution_curl_argv

        argv = ["curl", "-i", "-s", "http://a.local/form"]
        with patch.dict("os.environ", {"HACKERONE_USERNAME": "tester"}):
            out = _attribution_curl_argv(argv)
        self.assertIn("-H", out)
        self.assertIn("x-hackerone: tester", out)
        self.assertEqual(out.count("x-hackerone: tester"), 1)
        # existing flags + URL preserved in order
        self.assertIsNotNone(
            [i for i, t in enumerate(out) if t == "-i"], "-i flag lost"
        )

    def test_transform_no_env_is_noop(self):
        from oracle_hunter import _attribution_curl_argv

        argv = ["curl", "-i", "-s", "http://a.local/form"]
        with patch.dict("os.environ", {}, clear=True):
            out = _attribution_curl_argv(argv)
        self.assertEqual(out, argv)

    def test_transform_respects_existing_header(self):
        from oracle_hunter import _attribution_curl_argv

        argv = [
            "curl",
            "-H",
            "x-hackerone: existing",
            "http://a.local/form",
        ]
        with patch.dict("os.environ", {"HACKERONE_USERNAME": "tester"}):
            out = _attribution_curl_argv(argv)
        self.assertEqual(" ".join(out).count("x-hackerone"), 1)

    def test_replay_request_carries_attribution(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            b"<html><body><form action='/login' method='POST'>"
            b"<input name='csrf_token' value='abc'><input name='username'>"
            b"</form></body></html>"
        )
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_resp

        with patch("urllib.request.build_opener", return_value=mock_opener):
            with patch.dict("os.environ", {"HACKERONE_USERNAME": "tester"}):
                confirm_form_replay(
                    "curl -s https://a.local/login", allow_mutation=False
                )

        request = mock_opener.open.call_args.args[0]
        headers = {k.lower(): v for k, v in (request.header_items() or {})}
        self.assertIn("x-hackerone", headers, "header: ")


if __name__ == "__main__":
    unittest.main()
