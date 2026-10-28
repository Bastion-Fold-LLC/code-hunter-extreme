import hashlib
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_corpus


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_registry_covers_every_unique_corpus_text():
    registered_hashes = {_hash(document.path) for document in oracle_corpus.DOCUMENTS}
    on_disk_hashes = {
        _hash(path)
        for path in oracle_corpus.CORPUS_DIR.rglob("*")
        if path.is_file() and path.name != "_TEMPLATE.md"
    }

    assert all(document.path.is_file() for document in oracle_corpus.DOCUMENTS)
    assert on_disk_hashes == registered_hashes


def test_template_is_not_registered():
    assert all(
        document.path.name != "_TEMPLATE.md"
        for document in oracle_corpus.DOCUMENTS
    )


def test_source_context_contains_every_document_verbatim():
    context = oracle_corpus.source_context(
        "authentication authorization identity ownership decouple",
        max_chars=400_000,
    )

    for document in oracle_corpus.DOCUMENTS:
        assert f"[{document.identifier}]" in context
        assert oracle_corpus.read_document(document.identifier) in context
    assert "/home/phantomcore/Documents" not in context


def test_source_context_fails_loud_when_cap_cannot_hold_all():
    with pytest.raises(ValueError, match="cannot fit all corpus documents") as excinfo:
        oracle_corpus.source_context(
            "authentication authorization identity ownership decouple",
            max_chars=18_000,
        )

    assert "paradox-impossible-crossover" in str(excinfo.value)


def test_standalone_prompt_contains_every_corpus_document():
    import oracle

    prompt = oracle.load_oracle_system_prompt("security")

    for document in oracle_corpus.DOCUMENTS:
        assert f"[{document.identifier}]" in prompt


def test_hunter_prompt_contains_every_corpus_document():
    import oracle_hunter

    prompt = oracle_hunter._load_oracle_prompt(voice=False, query="security")

    for document in oracle_corpus.DOCUMENTS:
        assert f"[{document.identifier}]" in prompt


def test_corpus_inventory_lists_every_packaged_document():
    inventory = oracle_corpus.corpus_inventory()

    for document in oracle_corpus.DOCUMENTS:
        assert f"`{document.identifier}`" in inventory


def test_source_context_chunks_cover_every_document():
    chunks = oracle_corpus.source_context_chunks(
        "authentication authorization identity ownership decouple",
        max_chars=60_000,
    )

    assert len(chunks) > 1, "175k corpus cannot fit one 60k chunk"
    assert all(len(c) <= 60_000 for c in chunks)
    foundations = set(oracle_corpus._FOUNDATION_IDS)
    for document in oracle_corpus.DOCUMENTS:
        text = oracle_corpus.read_document(document.identifier)
        hits = sum(1 for c in chunks if text in c)
        if document.identifier in foundations:
            assert hits == len(chunks), document.identifier
        else:
            assert hits == 1, document.identifier


def test_source_context_chunks_fail_loud_below_largest_document():
    with pytest.raises(ValueError, match="cannot fit corpus document"):
        oracle_corpus.source_context_chunks(
            "authentication",
            max_chars=10_000,
        )
