#!/usr/bin/env python3
# LAYER: find
# DEST: vortex
# ENDPOINTS: import_tree, dedup_documents
# TOPICS: none
"""One-time build step: import the un-flattened philosophy/paradox/impossible/
iPhone sources into the bundled corpus/, deduping overlap and converting RTF.
Runtime never reads the source dirs — only the bundled corpus/."""
from __future__ import annotations
import re
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_CORPUS = _HERE.parent / "corpus"

# source folder -> corpus category subfolder
_CATEGORY = {
    "Impossible Problems": "impossible_problems",
    "Impossible Problems and Paradoxes": "impossible_problems",
    "Paradoxes": "paradoxes",
    "Philosophies": "philosophies",
}


def is_junk(path: Path) -> bool:
    name = path.name
    return name.startswith("._") or name == ".DS_Store"


def dedup_documents(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    kept: list[Path] = []
    for p in paths:
        stem = p.stem.lower()
        if stem in seen:
            continue
        seen.add(stem)
        kept.append(p)
    return kept


def rtf_to_text(raw: str) -> str:
    # Drop groups like {\fonttbl ...}, control words (\word), and braces.
    no_groups = re.sub(r"\{\\\*?[a-z]+[^{}]*\}", " ", raw)
    no_ctrl = re.sub(r"\\[a-z]+-?\d* ?", " ", no_groups)
    return re.sub(r"[{}]", "", no_ctrl).strip()


def import_tree(src_root: Path) -> int:
    """Copy real source docs into corpus/<category>/, converting rtf. Returns count."""
    count = 0
    for src_name, category in _CATEGORY.items():
        src_dir = src_root / src_name
        if not src_dir.is_dir():
            continue
        dest_dir = _CORPUS / category
        dest_dir.mkdir(parents=True, exist_ok=True)
        docs = [p for p in src_dir.rglob("*")
                if p.is_file() and not is_junk(p)
                and p.suffix.lower() in (".md", ".txt", ".rtf")]
        for p in dedup_documents(sorted(docs)):
            target = dest_dir / (p.stem + ".md")
            if p.suffix.lower() == ".rtf":
                target.write_text(rtf_to_text(p.read_text(errors="replace")), encoding="utf-8")
            else:
                shutil.copyfile(p, target)
            count += 1
    return count


if __name__ == "__main__":
    root = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path.home() / "Documents"
    n = import_tree(root)
    print(f"imported {n} corpus documents into {_CORPUS}")
