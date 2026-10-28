from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location(
    "import_corpus", Path(__file__).resolve().parents[1] / "scripts" / "import_corpus.py")
import_corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(import_corpus)


def test_is_junk_flags_appledouble_and_dsstore():
    assert import_corpus.is_junk(Path("._The_iPhone_Problem.md"))
    assert import_corpus.is_junk(Path(".DS_Store"))
    assert not import_corpus.is_junk(Path("The_iPhone_Problem.md"))


def test_dedup_keeps_one_per_stem_first_wins():
    paths = [Path("a/The_iPhone_Problem.md"), Path("b/The_iPhone_Problem.md"),
             Path("a/Pushing_Physics.md")]
    kept = import_corpus.dedup_documents(paths)
    assert kept == [Path("a/The_iPhone_Problem.md"), Path("a/Pushing_Physics.md")]


def test_rtf_to_text_strips_control_words():
    raw = r"{\rtf1\ansi\deff0 {\fonttbl} Hello \b world\b0 .}"
    out = import_corpus.rtf_to_text(raw)
    assert "Hello" in out and "world" in out
    assert "\\rtf1" not in out and "fonttbl" not in out
