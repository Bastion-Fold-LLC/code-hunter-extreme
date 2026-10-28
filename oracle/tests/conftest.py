#!/usr/bin/env python3
"""Suite-wide test isolation for Oracle process globals.

cmd_hunt pins the router's local model per process; without a reset,
one test's hunt leaks its model into later router tests (order-dependent
failure). The hunt CLI runs one command per process, so production needs
no reset — this fixture exists only for in-process suite isolation.
"""

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolate_runlogs(tmp_path_factory):
    """Keep test/subprocess run logs out of the operator's reports/runs."""
    previous = os.environ.get("ORACLE_RUNLOG_DIR")
    os.environ["ORACLE_RUNLOG_DIR"] = str(tmp_path_factory.mktemp("oracle-runlogs"))
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("ORACLE_RUNLOG_DIR", None)
        else:
            os.environ["ORACLE_RUNLOG_DIR"] = previous


@pytest.fixture(autouse=True)
def _reset_oracle_llm_model_override():
    import oracle_llm

    def _reset():
        oracle_llm.set_preferred_local_model(None)
        # Lane-health (circuit breaker) is per-run production state;
        # without a reset one test's dead fake lane poisons later
        # router tests.
        oracle_llm.reset_lane_health()
        # cmd_hunt/cmd_analyze flip process-global no-cloud flags via
        # _apply_no_cloud; a leaked True makes later router tests call
        # build_backends_for(no_cloud=True) and breaks 3-arg fakes.
        oracle_llm.set_no_cloud(False)
        try:
            import oracle_programs

            oracle_programs.NO_CLOUD = False
        except Exception:
            pass

    _reset()
    yield
    _reset()
