#!/usr/bin/env python3
"""OmniCLIBackend timeout contract — the lane deadline must bound the call.

Fail-first receipts (E0-2, 2026-10-21): complete(timeout=...) was accepted
and then IGNORED — run_orchestration ran unbounded, so a hung swarm lane
wedged the whole router and dead lanes never tripped the circuit breaker
(the pre-existing degraded-lane ledger in STATUS). Contract under test:

  * timeout=N bounds the call: an N-second overrun raises BackendError
    quickly (fail-fast, no multi-second stall) so the router's lane
    health/breaker machinery sees a failure instead of a stall.
  * timeout=0.0 (deadline already spent) refuses to dispatch at all.
  * A call finishing inside its deadline passes the result through.
"""

import time
import unittest
from unittest.mock import MagicMock

from oracle_llm import BackendError, CliBackend, OmniCLIBackend, _timeout_or


class TestOmniCLITimeout(unittest.TestCase):
    def _backend_with(self, fake_run):
        backend = OmniCLIBackend("reflex", env={})
        backend._load = lambda: (MagicMock(), MagicMock(), fake_run)
        return backend

    def test_slow_swarm_raises_before_sleeper_ends(self):
        def fake_run(*args, **kwargs):
            time.sleep(5.0)
            return {"members": [], "final": "LATE"}

        backend = self._backend_with(fake_run)
        started = time.monotonic()
        with self.assertRaises(BackendError) as ctx:
            backend.complete("SYS", "task", timeout=0.2)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3.0, "fail fast on the lane deadline")
        self.assertIn("timed out", str(ctx.exception).lower())

    def test_timeout_zero_refuses_dispatch(self):
        def fake_run(*args, **kwargs):
            time.sleep(5.0)
            return {"members": [], "final": "SHOULD-NOT-RUN"}

        backend = self._backend_with(fake_run)
        started = time.monotonic()
        with self.assertRaises(BackendError) as ctx:
            backend.complete("SYS", "task", timeout=0.0)
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertIn("not dispatch", str(ctx.exception).lower())

    def test_result_completed_in_time_passes(self):
        def fake_run(*args, **kwargs):
            return {"members": [], "final": "SYNTH"}

        backend = self._backend_with(fake_run)
        self.assertEqual(backend.complete("SYS", "task", timeout=5.0), "SYNTH")


class TestFalsyZeroPassesThrough(unittest.TestCase):
    """Verifier follow-up (E0-2, 2026-10-21): the OTHER four backends carry
    the same ``timeout or N`` falsy-zero bug class OmniCLI had — timeout=0
    silently maps to the (large) default instead of being honored.

    Fail-first receipts: pre-patch, CliBackend with a child that prints and
    sleeps 5s SUCCEEDS at timeout=0.0 (the `or` mapped it to 180s — the call
    burned its full sleep) — RED below; post-patch, 0.0 is honored and the
    subprocess dies instantly with BackendError.
    """

    def test_timeout_or_law(self):
        # None = caller default; 0/0.0/negative pass through (loud refusal
        # at the http/proc layer); positives as given. No falsy `or`.
        self.assertEqual(_timeout_or(180, None), 180)
        self.assertEqual(_timeout_or(180, 0), 0)
        self.assertEqual(_timeout_or(90, 0.0), 0.0)
        self.assertEqual(_timeout_or(120, 2.5), 2.5)

    def test_cli_backend_timeout_zero_dies_fast(self):
        backend = CliBackend("probe", "python3 -c")
        started = time.monotonic()
        with self.assertRaises(BackendError) as ctx:
            backend.complete(
                "",
                "import time; print('ok'); time.sleep(5)",
                timeout=0.0,  # deadline spent → must NOT become 180s
            )
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            3.0,
            f"timeout=0 was not honored (took {elapsed:.1f}s — falsy `or` "
            "mapped it to the default again)",
        )
        self.assertIn("timeout", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
