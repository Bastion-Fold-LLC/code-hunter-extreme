# LAYER: find
# DEST: basilisk
# ENDPOINTS: CorpusDocument, corpus_inventory, read_document, source_context, validate_registry
# TOPICS: none
"""Canonical Oracle corpus packaged with the application.

The documents in ``corpus/`` are the original source texts.  Every unique
text is returned verbatim for each request or the call fails loud; this
module deliberately does not summarize, select, or rewrite them.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Iterable


_HERE = Path(__file__).resolve().parent
CORPUS_DIR = _HERE / "corpus"


@dataclass(frozen=True)
class CorpusDocument:
    """One canonical, vendored Oracle source document."""

    identifier: str
    title: str
    relative_path: str
    keywords: tuple[str, ...]

    @property
    def path(self) -> Path:
        return CORPUS_DIR / self.relative_path


DOCUMENTS = (
    CorpusDocument(
        "pushing-physics",
        "Pushing Physics",
        "philosophies/Pushing_Physics.md",
        ("impossible", "limit", "constraint", "rule", "physics", "build"),
    ),
    CorpusDocument(
        "wave-makers-axiom",
        "The Wave-Maker's Axiom",
        "philosophies/The Wave-Maker’s Axiom.txt",
        ("impact", "harm", "risk", "action", "change", "consequence"),
    ),
    CorpusDocument(
        "beautiful-liar",
        "The Beautiful Liar",
        "philosophies/The_Beautiful_Liar.md",
        ("authority", "assumption", "claim", "trust", "build"),
    ),
    CorpusDocument(
        "cliff-and-current",
        "The Cliff and the Current",
        "philosophies/the_cliff_and_the_current.md",
        ("convention", "assumption", "boundary", "reframe", "risk"),
    ),
    CorpusDocument(
        "invisible-architect",
        "The Invisible Architect",
        "philosophies/The_Invisible_Architect.md",
        ("infrastructure", "architecture", "system", "implementation"),
    ),
    CorpusDocument(
        "mind-that-does-not-wait",
        "The Mind That Does Not Wait",
        "philosophies/The_Mind_That_Does_Not_Wait.md.txt",
        ("paradox", "reframe", "rule", "constraint", "solution", "recursive"),
    ),
    CorpusDocument(
        "build-the-world",
        "Build the World",
        "philosophies/build_the_world_speech.md",
        ("build", "action", "change", "possibility"),
    ),
    CorpusDocument(
        "geometry-of-absence",
        "The Geometry of Absence",
        "philosophies/The_Geometry_of_Absence.md",
        ("absence", "deleted", "destroyed", "erasure", "missing", "closure", "proof"),
    ),
    CorpusDocument(
        "single-token-language",
        "Single-Token Language",
        "impossible_problems/Single_Token_Language.md",
        ("token", "ambiguous", "definition", "language", "meaning", "input"),
    ),
    CorpusDocument(
        "repulsive-gravity",
        "Repulsive Gravity Universe",
        "impossible_problems/Repulsive_Gravity_Universe.md",
        ("impossible", "blocked", "waf", "rate", "limit", "rewrite", "axiom"),
    ),
    CorpusDocument(
        "universe-without-death",
        "Universe Without Death",
        "impossible_problems/Universe_Without_Death.md",
        ("pattern", "recall", "known", "class", "history"),
    ),
    CorpusDocument(
        "vacuum-consciousness",
        "Vacuum Consciousness",
        "impossible_problems/Vacuum_Consciousness.md",
        ("identity", "ownership", "authentication", "authorization", "decouple"),
    ),
    CorpusDocument(
        "forgetting-ledger",
        "The Forgetting Ledger",
        "impossible_problems/The_Forgetting_Ledger.md",
        ("ledger", "erasure", "absence", "destroyed", "proof", "verify", "trajectory"),
    ),
    CorpusDocument(
        "self-observing-equation",
        "Self-Observing Equation",
        "paradoxes/Self_Observing_Equation.md",
        ("validate", "verify", "proof", "test", "recursive", "evidence"),
    ),
    CorpusDocument(
        "observer-consumes-observation",
        "Observer That Consumes Observation",
        "paradoxes/Observer_That_Consumes_Observation.md",
        ("clean", "unsolved", "loop", "recursive", "contradiction"),
    ),
    CorpusDocument(
        "mirror-remembers-differently",
        "Mirror That Remembers Differently",
        "paradoxes/Mirror_That_Remembers_Differently.md",
        ("spec", "claim", "enforce", "undefined", "ambiguity", "observer"),
    ),
    CorpusDocument(
        "iphone-problem",
        "The iPhone Problem",
        "analysis/The_iPhone_Problem.md",
        ("binary", "conflict", "assertion", "evidence", "logs", "noise", "security"),
    ),
    CorpusDocument(
        "four-modes",
        "Cognitive Analysis: The Four Modes",
        "analysis/Cognitive_Analysis_Problem_Solving_Modes.md",
        ("mode", "stuck", "reframe", "breakthrough", "recall", "solution"),
    ),
    CorpusDocument(
        "phililo-speech",
        "Phililo: Build the World (full speech)",
        "philosophies/Phililo me 1.md",
        ("build", "remember", "will", "path", "world", "action", "curious"),
    ),
    CorpusDocument(
        "paradox-impossible-crossover",
        "Impossible Problems and Paradoxes (crossover index)",
        "philosophies/paradoxe and impssoble complee1.md",
        ("impossible", "paradox", "crossover", "index", "mode", "type", "rulebook"),
    ),
    CorpusDocument(
        "impossible-paradox-record",
        "Impossible Problems and Paradoxes (record)",
        "philosophies/README.md",
        ("impossible", "paradox", "record", "type", "mode", "crossover"),
    ),
    CorpusDocument(
        "codex-01-relevance-engine",
        "Codex 01: Relevance Engine, Not Truth Oracle",
        "philosophies/codex_01_relevance_engine.md",
        ("relevance", "oracle", "truth", "probabilistic", "validation", "moat"),
    ),
    CorpusDocument(
        "codex-05-context-laws",
        "Codex 05: The 10 Immutable Laws of Context",
        "philosophies/codex_05_context_laws.md",
        ("context", "laws", "prompt", "architecture", "engineering", "substrate"),
    ),
    CorpusDocument(
        "codex-06-glass-box",
        "Codex 06: The Glass Box Mandate",
        "philosophies/codex_06_glass_box.md",
        ("glass-box", "audit", "black-box", "transparency", "minimalism", "verification"),
    ),
    CorpusDocument(
        "codex-09-fiduciary-diode",
        "Codex 09: The Fiduciary Diode",
        "philosophies/codex_09_fiduciary_diode.md",
        ("fiduciary", "diode", "neutrality", "axiomatic", "signal", "noise"),
    ),
)

_FOUNDATION_IDS = ("mind-that-does-not-wait", "iphone-problem", "four-modes")
_WORD_RE = re.compile(r"[a-z0-9_/-]{3,}", re.IGNORECASE)


def _by_id(identifier: str) -> CorpusDocument:
    for document in DOCUMENTS:
        if document.identifier == identifier:
            return document
    raise KeyError(f"Unknown Oracle corpus document: {identifier}")


_EXCLUDED_FILENAMES = frozenset({"_TEMPLATE.md"})


def _content_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_registry() -> None:
    """Fail loud unless every unique packaged text is registered exactly once.

    Duplicate copies of the same text under different folders count once.
    Files named in ``_EXCLUDED_FILENAMES`` are authoring templates, not
    source texts, and must never be registered.
    """
    registered_hashes: dict[str, str] = {}
    for document in DOCUMENTS:
        if not document.path.is_file():
            raise RuntimeError(
                f"Packaged Oracle corpus document is missing: {document.path}"
            )
        digest = _content_hash(document.path)
        if digest in registered_hashes:
            raise RuntimeError(
                "Oracle corpus registry registers the same text twice: "
                f"{registered_hashes[digest]} and {document.identifier}"
            )
        registered_hashes[digest] = document.identifier

    unregistered = sorted(
        str(path.relative_to(CORPUS_DIR))
        for path in CORPUS_DIR.rglob("*")
        if path.is_file()
        and path.name not in _EXCLUDED_FILENAMES
        and _content_hash(path) not in registered_hashes
    )
    if unregistered:
        raise RuntimeError(
            "Unregistered Oracle corpus texts on disk: " + ", ".join(unregistered)
        )


def corpus_inventory() -> str:
    """Return the packaged corpus inventory without replacing source text."""
    entries = "\n".join(
        f"- `{document.identifier}` — {document.title}" for document in DOCUMENTS
    )
    return (
        "## PACKAGED ORACLE SOURCE CORPUS\n"
        "The original Oracle documents are bundled with this application. "
        "Selected documents below are quoted verbatim; do not treat a "
        "document title as a substitute for its source text.\n"
        f"{entries}"
    )


def read_document(identifier: str) -> str:
    """Read one canonical source document or fail clearly if the package is broken."""
    document = _by_id(identifier)
    try:
        return document.path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise RuntimeError(
            f"Packaged Oracle corpus document is missing: {document.path}"
        ) from error


def _rank_documents(
    query: str, documents: Iterable[CorpusDocument]
) -> list[CorpusDocument]:
    terms = set(_WORD_RE.findall(query.lower()))
    ranked = []
    for position, document in enumerate(documents):
        score = sum(term in terms for term in document.keywords)
        ranked.append((-score, position, document))
    return [document for _, _, document in sorted(ranked)]


def source_context(query: str, max_chars: int = 18_000) -> str:
    """Return every original corpus document verbatim, or fail loud.

    Foundation texts come first and keyword relevance only orders the rest;
    it never selects a subset.  If ``max_chars`` cannot hold every document,
    raise naming each document that would not fit instead of silently
    dropping it.  Nothing is truncated or rewritten.
    """
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    validate_registry()

    candidates = [_by_id(identifier) for identifier in _FOUNDATION_IDS]
    candidates.extend(
        document
        for document in _rank_documents(query, DOCUMENTS)
        if document.identifier not in _FOUNDATION_IDS
    )
    header = [
        "## ORIGINAL ORACLE SOURCE TEXTS",
        "These are canonical source documents bundled with Oracle. "
        "Apply their moves to the target; do not paraphrase them into a new doctrine.",
    ]
    blocks = list(header)
    for document in candidates:
        text = read_document(document.identifier)
        blocks.append(f"### SOURCE: {document.title} [{document.identifier}]\n{text}")

    joined = "\n\n".join(blocks)
    if len(joined) > max_chars:
        used = sum(len(block) + 2 for block in header)
        dropped: list[str] = []
        for document, block in zip(candidates, blocks[len(header) :]):
            if used + len(block) + 2 > max_chars:
                dropped.append(document.identifier)
            else:
                used += len(block) + 2
        raise ValueError(
            f"max_chars={max_chars} cannot fit all corpus documents "
            f"(need {len(joined)} chars); dropped: {', '.join(dropped)}"
        )

    return joined


def source_context_chunks(
    query: str,
    max_chars: int,
    *,
    repeat_foundations: bool = True,
    split_oversized: bool = False,
) -> list[str]:
    """Return every corpus document verbatim, grouped into fitting chunks.

    Default (cloud) law: foundation texts lead every chunk (core framing
    on each pass); every other document appears in exactly one chunk,
    relevance-ordered. Nothing is selected away, split, or truncated: a
    single document that cannot fit one chunk (with header +
    foundations) fails loud naming the document, mirroring
    source_context's law.

    Local-window options (opt-in, used only for small local contexts):
    ``repeat_foundations=False`` delivers foundation documents exactly
    once like every other document, and ``split_oversized=True`` splits
    a document that cannot fit whole into sequential ``(part i/n)``
    blocks. Every character is still delivered exactly once across the
    chunk set; nothing is truncated or dropped.
    """
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    validate_registry()

    header = [
        "## ORIGINAL ORACLE SOURCE TEXTS",
        "These are canonical source documents bundled with Oracle. "
        "Apply their moves to the target; do not paraphrase them into a new doctrine.",
    ]
    foundations = [_by_id(identifier) for identifier in _FOUNDATION_IDS]
    rest = [
        document
        for document in _rank_documents(query, DOCUMENTS)
        if document.identifier not in _FOUNDATION_IDS
    ]

    def _block(document: CorpusDocument) -> str:
        return (
            f"### SOURCE: {document.title} [{document.identifier}]\n"
            f"{read_document(document.identifier)}"
        )

    if repeat_foundations:
        base_blocks = list(header) + [_block(d) for d in foundations]
        ordered = rest
    else:
        base_blocks = list(header)
        ordered = foundations + rest
    base_len = len("\n\n".join(base_blocks))
    if base_len > max_chars:
        raise ValueError(
            f"max_chars={max_chars} cannot fit chunk header/foundations "
            f"alone ({base_len} chars)"
        )

    blocks: list[str] = []
    for document in ordered:
        block = _block(document)
        if base_len + 2 + len(block) <= max_chars:
            blocks.append(block)
            continue
        if not split_oversized:
            raise ValueError(
                f"max_chars={max_chars} cannot fit corpus document "
                f"{document.identifier} ({len(block)} chars + "
                f"{base_len} header/foundations)"
            )
        text = read_document(document.identifier)
        prefix = f"### SOURCE: {document.title} [{document.identifier}]"
        avail = max_chars - base_len - 2 - len(prefix) - 24
        if avail <= 0:
            raise ValueError(
                f"max_chars={max_chars} cannot fit any part of corpus "
                f"document {document.identifier} ({base_len} base chars)"
            )
        parts: list[str] = []
        rest_text = text
        while rest_text:
            piece = rest_text[:avail]
            if len(rest_text) > avail:
                cut = piece.rfind("\n", avail // 2)
                if cut > 0:
                    piece = piece[:cut]
            parts.append(piece)
            rest_text = rest_text[len(piece):]
        total = len(parts)
        for i, piece in enumerate(parts, start=1):
            blocks.append(f"{prefix} (part {i}/{total})\n{piece}")

    chunks: list[str] = []
    current = list(base_blocks)
    current_len = base_len
    for block in blocks:
        if current_len + 2 + len(block) > max_chars:
            chunks.append("\n\n".join(current))
            current = list(base_blocks)
            current_len = base_len
        current.append(block)
        current_len += 2 + len(block)
    chunks.append("\n\n".join(current))
    return chunks
