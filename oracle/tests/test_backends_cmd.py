import sys, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_hunter as oh


def test_backends_test_runs_available(monkeypatch, capsys):
    import oracle_llm

    class Fake(oracle_llm.Backend):
        name = "openrouter"

        def available(self):
            return True

        def complete(self, system, prompt, timeout=None):
            return "SEAM 1 sample"

    monkeypatch.setattr(oracle_llm, "build_backends_for", lambda t, c, e: [Fake()])
    args = types.SimpleNamespace(task="reflex")
    oh.cmd_backends_test(args)
    out = capsys.readouterr().out
    assert "openrouter" in out and "SEAM 1 sample" in out


def test_backends_test_marks_unavailable(monkeypatch, capsys):
    import oracle_llm

    class Down(oracle_llm.Backend):
        name = "local"

        def available(self):
            return False

        def complete(self, system, prompt, timeout=None):
            raise AssertionError("should not be called when unavailable")

    monkeypatch.setattr(oracle_llm, "build_backends_for", lambda t, c, e: [Down()])
    args = types.SimpleNamespace(task="reflex")
    oh.cmd_backends_test(args)
    out = capsys.readouterr().out
    assert "local" in out and "unavailable" in out
