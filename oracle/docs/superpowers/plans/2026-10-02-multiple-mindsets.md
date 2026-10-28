> **HISTORICAL (dated plan/roadmap) — dated plan/spec, superseded as current status by `STATUS.md` + `ORACLE_DOCTRINE.md`.** Body kept as the record of intent at the time; verify any claim against code before citing.

# Multiple Mindsets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split Oracle's single fused mindset into three co-equal candidate generators — `mitre` (LLM), `paradox` (LLM, full un-flattened corpus), and `seam` (deterministic code lens that also cross-compares) — all feeding the one unchanged verifier.

**Architecture:** `OracleMindsetContext` gains a `mindset` parameter and builds a profile-specific LLM system prompt. A new focused module `oracle_mindsets.py` holds the pure orchestration helpers (profile resolution, deterministic seam generation, cross-comparison, report sorting). `cmd_hunt` runs the selected profiles, cross-compares their seams into an agreement signal, and hands every well-formed candidate to the existing `verify_seams` path. Agreement sorts/labels only; it never confirms or drops a seam.

**Tech Stack:** Python 3.12, pytest, existing modules `oracle_mindset_context.py`, `oracle_corpus.py`, `oracle_code_seam.py`, `oracle_deterministic.py`, `oracle_hunter.py`.

**Spec:** `docs/superpowers/specs/2026-10-02-multiple-mindsets-design.md`

## Global Constraints

- No hardcoded absolute paths; corpus is bundled under `oracle/corpus/` and read relative to the module. The one-time import reads `~/Documents/...` only as a build step, never at runtime.
- Fail loud, no silent fallbacks: invalid `--mindset` → `ValueError`; a hard backend failure surfaces the real error. (Project error-handling philosophy.)
- The verifier (`oracle_deterministic.verify_seam_card`) and its 5 gates are **frozen** — no task edits it.
- Agreement is ranking/confidence metadata only; it must never appear in the CONFIRMED/REJECTED decision path.
- Test runner: `python3 -m pytest` from the `oracle/` directory. The full suite is 92 passing today and must stay green.
- `--mindset` allowed values exactly: `mitre | paradox | seam | all`. `OracleMindsetContext(mindset=...)` allowed values exactly: `mitre | paradox` (the two LLM profiles).

## Review Focus

- **`--mindset seam` with no source on disk** → the seam generator must skip (return `[]`), the hunt continues and reports cleanly, no crash. (Test in Task 4.)
- **Invisible-seam engine not importable** (`SeamUnavailableError`) → the seam generator skips with a warning; LLM profiles still run. Not a hard hunt failure. (Test in Task 4.)
- **`cross_compare` with empty inputs** (one or all profiles produced nothing) → returns `[]` or the non-empty union; never raises. (Test in Task 5.)
- **Two genuinely different seams sharing one URL subject** → agreement inflates to 2 for unrelated findings. Accepted because agreement is rank-only, but behavior must be pinned so it is a known, tested property, not a surprise. (Test in Task 5.)
- **Paradox corpus larger than a selected backend's real context window** → the spec assumes 128K+ cloud context; nothing enforces it. Mitigation is observability: the built prompt size must be queryable/logged so an operator can see when it is large. (Test in Task 2.)

---

### Task 1: Import and un-flatten the corpus

**Files:**
- Create: `scripts/import_corpus.py`
- Test: `tests/test_import_corpus.py`
- Modify (data, by running the script): `corpus/` tree

**Interfaces:**
- Produces: `dedup_documents(paths: list[Path]) -> list[Path]` (keeps one path per identical basename-stem, first wins); `rtf_to_text(raw: str) -> str` (strips RTF control words to plain text); `is_junk(path: Path) -> bool` (True for `._*` AppleDouble and `.DS_Store`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_import_corpus.py
from pathlib import Path
import importlib.util, sys

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_import_corpus.py -v`
Expected: FAIL (module/file `scripts/import_corpus.py` does not exist).

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/import_corpus.py
"""One-time build step: import the un-flattened philosophy/paradox/impossible/
iPhone sources into the bundled corpus/, deduping overlap and converting RTF.
Runtime never reads the source dirs — only the bundled corpus/."""
from __future__ import annotations
import re, shutil, sys
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_import_corpus.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the import for real and inspect**

Run: `python3 scripts/import_corpus.py ~/Documents`
Then: `find corpus -type f -name '*.md' | wc -l` and `du -sh corpus`
Expected: corpus grows from 16 files (~92K) toward ~48 files (~290K); no `._*` files present (`find corpus -name '._*'` returns nothing).

- [ ] **Step 6: Commit**

```bash
git add scripts/import_corpus.py tests/test_import_corpus.py corpus/
git commit -m "feat(corpus): import un-flattened philosophy/paradox sources"
```

---

### Task 2: Profile-aware `OracleMindsetContext`

**Files:**
- Modify: `oracle_mindset_context.py` (`__init__` ~line 83, `_build()` corpus/TTP/framework layers ~lines 570–610)
- Test: `tests/test_mindset_profiles.py`

**Interfaces:**
- Consumes: existing `source_context(query, max_chars)` from `oracle_corpus`.
- Produces: `OracleMindsetContext(program=None, voice=True, ttp_mode="auto", ttp_tactic=None, mindset="paradox")`; `OracleMindsetContext.prompt_size() -> int` (character length of the built prompt). `mindset` accepts only `"mitre"` or `"paradox"`; any other value raises `ValueError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mindset_profiles.py
import pytest
from oracle_mindset_context import OracleMindsetContext

PROG = {"name": "Acme", "scope": "app.acme.com", "rules_text": "no DoS"}


def test_mitre_profile_has_ttp_omits_corpus():
    p = OracleMindsetContext(program=PROG, mindset="mitre").system_prompt()
    assert "TTP REFERENCE" in p          # MITRE block present
    assert "ORACLE TTP" in p
    assert "SOURCE CONTEXT" not in p     # corpus section omitted


def test_paradox_profile_has_corpus_omits_full_ttp():
    p = OracleMindsetContext(program=PROG, mindset="paradox").system_prompt()
    assert "SOURCE CONTEXT" in p         # corpus section present
    # compact TTP only: far smaller than the mitre profile's full block
    mitre = OracleMindsetContext(program=PROG, mindset="mitre").system_prompt()
    assert p.count("T10") <= mitre.count("T10")


def test_both_profiles_carry_program_brief():
    for m in ("mitre", "paradox"):
        p = OracleMindsetContext(program=PROG, mindset=m).system_prompt()
        assert "app.acme.com" in p        # scope wall present in both


def test_invalid_mindset_raises():
    with pytest.raises(ValueError):
        OracleMindsetContext(program=PROG, mindset="seam")  # seam is not an LLM profile


def test_paradox_prompt_larger_and_size_queryable():
    paradox = OracleMindsetContext(program=PROG, mindset="paradox")
    mitre = OracleMindsetContext(program=PROG, mindset="mitre")
    assert paradox.prompt_size() == len(paradox.system_prompt())
    assert paradox.prompt_size() > 12_000   # corpus cap is lifted, not the old 12K
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mindset_profiles.py -v`
Expected: FAIL (`__init__` has no `mindset` kwarg / no `prompt_size`).

- [ ] **Step 3: Write minimal implementation**

In `__init__`, add and validate the parameter:

```python
def __init__(self, program=None, voice=True, ttp_mode="auto",
             ttp_tactic=None, mindset="paradox"):
    if mindset not in ("mitre", "paradox"):
        raise ValueError(
            f"OracleMindsetContext mindset must be 'mitre' or 'paradox', got {mindset!r}")
    self.mindset = mindset
    # ... existing assignments unchanged ...
    self.program    = program or {}
    self.voice      = voice
    self.ttp_mode   = ttp_mode
    self.ttp_tactic = (ttp_tactic or "").upper().strip()
    self._prompt = None
```

Add `prompt_size`:

```python
def prompt_size(self) -> int:
    """Character length of the built system prompt (observability)."""
    return len(self.system_prompt())
```

In `_build()`, gate the three profile-specific layers. Replace the corpus block so it is paradox-only with the cap lifted, and the framework/TTP blocks so they match the profile:

```python
# Corpus: paradox profile only, full (cap lifted). mitre omits it.
if self.mindset == "paradox":
    from oracle_corpus import corpus_inventory, source_context
    selection_query = "\n".join([
        json.dumps(self.program, sort_keys=True),
        "\n".join(getattr(self, "_recon_hosts", [])),
        "\n".join(getattr(self, "_recon_endpoints", [])),
    ])
    parts.append("## SOURCE CONTEXT (verbatim corpus)")
    parts.append(corpus_inventory())
    parts.append(source_context(selection_query, max_chars=320_000))

# MITRE TTP block: full for mitre (ttp_mode as configured), compact for paradox.
effective_ttp_mode = self.ttp_mode if self.mindset == "mitre" else "compact"
ttp_block = self._ttp_block(mode=effective_ttp_mode)
if ttp_block:
    parts.append(ttp_block)
```

If `_ttp_block` does not already take a `mode` argument, thread the existing `self.ttp_mode` read through a parameter defaulting to `self.ttp_mode` so the compact override works; do not change its rendering otherwise. Ensure the framework philosophy layer is appended only when `self.mindset == "paradox"` (wrap the existing `ORACLE_FRAMEWORK` read in that condition); the system-prompt and voice layers stay unconditional.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_mindset_profiles.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the full suite (no regressions)**

Run: `python3 -m pytest -q`
Expected: all green (existing 92 + new).

- [ ] **Step 6: Commit**

```bash
git add oracle_mindset_context.py tests/test_mindset_profiles.py
git commit -m "feat(mindset): profile-aware system prompt (mitre vs paradox)"
```

---

### Task 3: `resolve_mindsets` — profile selection

**Files:**
- Create: `oracle_mindsets.py`
- Test: `tests/test_mindsets.py`

**Interfaces:**
- Produces: `resolve_mindsets(selector: str | None, config: dict) -> list[str]` returning an ordered subset of `["mitre", "paradox", "seam"]`. `None`/absent selector falls back to `config["hunt"]["mindset"]`, then to `"all"`. Invalid value raises `ValueError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mindsets.py
import pytest
import oracle_mindsets as om


def test_all_expands_to_three():
    assert om.resolve_mindsets("all", {}) == ["mitre", "paradox", "seam"]


def test_single_value():
    assert om.resolve_mindsets("paradox", {}) == ["paradox"]


def test_cli_overrides_config():
    assert om.resolve_mindsets("mitre", {"hunt": {"mindset": "all"}}) == ["mitre"]


def test_config_used_when_no_cli():
    assert om.resolve_mindsets(None, {"hunt": {"mindset": "seam"}}) == ["seam"]


def test_default_all_when_nothing_set():
    assert om.resolve_mindsets(None, {}) == ["mitre", "paradox", "seam"]


def test_invalid_raises():
    with pytest.raises(ValueError):
        om.resolve_mindsets("banana", {})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mindsets.py::test_all_expands_to_three -v`
Expected: FAIL (module `oracle_mindsets` does not exist).

- [ ] **Step 3: Write minimal implementation**

```python
# oracle_mindsets.py
"""Mindset orchestration: profile selection, deterministic seam generation,
and cross-comparison. Pure/standalone helpers — imports oracle_code_seam but
NOT oracle_hunter, to avoid a circular import."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit
import re

_VALID = ("mitre", "paradox", "seam")


def resolve_mindsets(selector: Optional[str], config: dict) -> List[str]:
    value = (selector or config.get("hunt", {}).get("mindset") or "all")
    value = str(value).strip().lower()
    if value == "all":
        return list(_VALID)
    if value in _VALID:
        return [value]
    raise ValueError(
        f"invalid mindset {value!r}; allowed: mitre, paradox, seam, all")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_mindsets.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_mindsets.py tests/test_mindsets.py
git commit -m "feat(mindset): resolve_mindsets selector with fail-loud validation"
```

---

### Task 4: `generate_seam_candidates` — the deterministic `seam` profile

**Files:**
- Modify: `oracle_mindsets.py`
- Modify: `tests/test_mindsets.py`

**Interfaces:**
- Consumes: `oracle_code_seam.scan_repository_seams(repo_path: Path, program: dict | None) -> list[dict]` (raises `SeamUnavailableError` when the engine is missing, `FileNotFoundError` when the path is absent; already applies program scope/rules).
- Produces: `generate_seam_candidates(repo_path: Path | None, program: dict | None) -> list[dict]`. Returns `[]` (skip, with a warning) when `repo_path` is `None`/missing or the engine is unavailable. Tags every returned seam `seam["mindset"] = "seam"`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_mindsets.py
import oracle_mindsets as om
import oracle_code_seam


def test_seam_candidates_tags_mindset(monkeypatch):
    monkeypatch.setattr(oracle_code_seam, "scan_repository_seams",
                        lambda repo_path, program=None: [{"n": 1, "check": "x"}])
    out = om.generate_seam_candidates(__import__("pathlib").Path("."), {"name": "Acme"})
    assert out and all(s["mindset"] == "seam" for s in out)


def test_seam_candidates_skip_when_no_path():
    assert om.generate_seam_candidates(None, {}) == []


def test_seam_candidates_skip_when_engine_unavailable(monkeypatch):
    def boom(repo_path, program=None):
        raise oracle_code_seam.SeamUnavailableError("engine missing")
    monkeypatch.setattr(oracle_code_seam, "scan_repository_seams", boom)
    assert om.generate_seam_candidates(__import__("pathlib").Path("."), {}) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mindsets.py -k seam_candidates -v`
Expected: FAIL (`generate_seam_candidates` not defined).

- [ ] **Step 3: Write minimal implementation**

```python
# append to oracle_mindsets.py
def generate_seam_candidates(repo_path: Optional[Path], program: Optional[dict]) -> List[dict]:
    """Run the deterministic Type-1 code lens, tagged as the 'seam' mindset.
    Skips (returns []) — never crashes the hunt — when there is no source on
    disk or the invisible-seam engine is unavailable."""
    import oracle_code_seam
    if repo_path is None or not Path(repo_path).exists():
        return []
    try:
        seams = oracle_code_seam.scan_repository_seams(Path(repo_path), program=program)
    except (oracle_code_seam.SeamUnavailableError, FileNotFoundError) as e:
        print(f"WARN: seam mindset skipped — {e}")
        return []
    for s in seams:
        s["mindset"] = "seam"
    return seams
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_mindsets.py -k seam_candidates -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_mindsets.py tests/test_mindsets.py
git commit -m "feat(mindset): deterministic seam generator with graceful skip"
```

---

### Task 5: `cross_compare` and `sort_confirmed`

**Files:**
- Modify: `oracle_mindsets.py`
- Modify: `tests/test_mindsets.py`

**Interfaces:**
- Produces:
  - `cross_compare(seam_sets: Dict[str, List[dict]]) -> List[dict]` — unions all seams, matches on shared subject identity, annotates the canonical member of each group with `corroborated_by: list[str]` and `agreement: int`, and returns the deduped union. Never drops a seam; never raises on empty input.
  - `sort_confirmed(confirmed: List[dict]) -> List[dict]` — sorts by `(agreement desc, severity rank, n asc)` using `seam["agreement"]` (default 1) and `seam["severity"]` (default "low").

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_mindsets.py
def test_cross_compare_empty_returns_empty():
    assert om.cross_compare({"mitre": [], "paradox": [], "seam": []}) == []


def test_cross_compare_two_way_agreement():
    a = {"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}
    b = {"n": 1, "check": "curl -i https://app.acme.com/api/", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    assert len(out) == 1
    assert out[0]["agreement"] == 2
    assert set(out[0]["corroborated_by"]) == {"mitre", "paradox"}


def test_cross_compare_lone_wolf_retained():
    a = {"n": 1, "check": "curl -i https://app.acme.com/x", "mindset": "mitre"}
    out = om.cross_compare({"mitre": [a], "paradox": []})
    assert len(out) == 1 and out[0]["agreement"] == 1


def test_cross_compare_code_seam_matches_on_file_function():
    a = {"n": 1, "file": "Vault.sol", "function": "withdraw", "mindset": "seam"}
    b = {"n": 2, "file": "Vault.sol", "function": "withdraw",
         "assertion_a_source": "Vault.sol", "mindset": "paradox"}
    out = om.cross_compare({"seam": [a], "paradox": [b]})
    assert len(out) == 1 and out[0]["agreement"] == 2


def test_cross_compare_distinct_urls_stay_separate():
    a = {"n": 1, "check": "curl -i https://app.acme.com/a", "mindset": "mitre"}
    b = {"n": 2, "check": "curl -i https://app.acme.com/b", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    assert len(out) == 2


def test_cross_compare_same_url_different_bugs_inflates_agreement():
    # Known, accepted property: subject identity is the URL, so two different
    # findings at the same URL corroborate. Documented so it is not a surprise.
    a = {"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}
    b = {"n": 2, "check": "curl -i https://app.acme.com/api", "mindset": "paradox"}
    out = om.cross_compare({"mitre": [a], "paradox": [b]})
    assert len(out) == 1 and out[0]["agreement"] == 2


def test_sort_confirmed_orders_by_agreement_then_severity():
    rows = [
        {"seam": {"n": 1, "agreement": 1, "severity": "high"}},
        {"seam": {"n": 2, "agreement": 3, "severity": "low"}},
        {"seam": {"n": 3, "agreement": 2, "severity": "high"}},
    ]
    order = [r["seam"]["n"] for r in om.sort_confirmed(rows)]
    assert order == [2, 3, 1]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_mindsets.py -k "cross_compare or sort_confirmed" -v`
Expected: FAIL (`cross_compare` not defined).

- [ ] **Step 3: Write minimal implementation**

```python
# append to oracle_mindsets.py
def _subject_key(seam: dict):
    check = seam.get("check") or ""
    m = re.search(r"https?://[^\s'\"<>`]+", check)
    if m:
        p = urlsplit(m.group(0))
        return ("url", p.netloc.lower(), p.path.rstrip("/").lower())
    f = (seam.get("file") or "").strip().lower()
    fn = (seam.get("function") or seam.get("subject") or "").strip().lower()
    if f or fn:
        return ("code", f, fn)
    src = (seam.get("assertion_a_source") or "").strip().lower()
    if src:
        return ("src", src)
    return ("id", id(seam))


def cross_compare(seam_sets: Dict[str, List[dict]]) -> List[dict]:
    groups: Dict[tuple, List[dict]] = {}
    order: List[tuple] = []
    for profile, seams in seam_sets.items():
        for s in seams or []:
            s.setdefault("mindset", profile)
            key = _subject_key(s)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(s)
    out: List[dict] = []
    for key in order:
        members = groups[key]
        profiles = sorted({m.get("mindset") for m in members if m.get("mindset")})
        # canonical = the member most likely to be verifiable (longest check cmd)
        canonical = max(members, key=lambda m: len(m.get("check") or ""))
        canonical["corroborated_by"] = profiles
        canonical["agreement"] = len(profiles)
        out.append(canonical)
    return out


_SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def sort_confirmed(confirmed: List[dict]) -> List[dict]:
    def rank(row: dict):
        seam = row.get("seam", {})
        return (-int(seam.get("agreement", 1)),
                _SEV_RANK.get(str(seam.get("severity", "low")).lower(), 3),
                int(seam.get("n", 0)))
    return sorted(confirmed, key=rank)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_mindsets.py -k "cross_compare or sort_confirmed" -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add oracle_mindsets.py tests/test_mindsets.py
git commit -m "feat(mindset): cross_compare agreement signal + report sort"
```

---

### Task 6: Wire the three mindsets into `cmd_hunt`

**Files:**
- Modify: `oracle_hunter.py` (`cmd_hunt` ~lines 3407–3836: the mindset build, the LLM reflex pass, the existing `scan_repository_seams` call ~3710, and the `verify_seams` hand-off ~3836; the argparse setup for the `hunt` subcommand)
- Modify: `oracle.config.json` (add `hunt.mindset`)
- Test: `tests/test_hunt_mindset_wiring.py`

**Interfaces:**
- Consumes: `oracle_mindsets.resolve_mindsets`, `cross_compare`, `sort_confirmed`; `OracleMindsetContext(mindset=...)`; existing `run_reflexes`, `_parse_seams`, `verify_seams`, and the already-computed `code_seams`. (Does not call `generate_seam_candidates` — see reconciliation note in Step 4.)
- Produces: a `hunt` run that, for each resolved profile, builds its candidate seams, cross-compares them, verifies the union unchanged, and reports CONFIRMED seams sorted by agreement.

- [ ] **Step 1: Add the config key**

In `oracle.config.json`, under `hunt`, add:

```json
"mindset": "all",
"_comment_mindset": "mitre | paradox | seam | all. all = run all three generators and cross-compare.",
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_hunt_mindset_wiring.py
import oracle_mindsets as om


def test_assemble_candidates_merges_llm_and_seam():
    """cmd_hunt builds a seam_sets dict then cross-compares; this pins the
    contract cmd_hunt relies on: three profiles union into agreement-tagged seams."""
    seam_sets = {
        "mitre":   [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}],
        "paradox": [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "paradox"}],
        "seam":    [{"n": 9, "file": "a.py", "function": "f", "mindset": "seam"}],
    }
    out = om.cross_compare(seam_sets)
    urls = [s for s in out if s.get("agreement") == 2]
    assert urls and set(urls[0]["corroborated_by"]) == {"mitre", "paradox"}
    assert any(s.get("mindset") == "seam" for s in out)   # seam retained
```

- [ ] **Step 3: Run test to verify it passes (helpers already exist)**

Run: `python3 -m pytest tests/test_hunt_mindset_wiring.py -v`
Expected: PASS — this test pins the contract the wiring depends on (the helpers were built in Tasks 3–5).

- [ ] **Step 4: Implement the wiring in `cmd_hunt`**

**Read `cmd_hunt` (≈ lines 3323–3836) first** — it is a long function and these are surgical changes. Confirmed anchors you are editing: the single `ctx = OracleMindsetContext(program=prog, voice=True, ttp_mode=_ttp_mode)` at line 3407; the LLM reflex pass that follows it; the code-lens block that computes `code_seams = scan_repository_seams(src, program=prog)` (≈ line 3710, where `src` is already defined); and the `verify_seams(...)` hand-off (≈ line 3836). Do not invent locals — reuse the ones already in scope (`prog`, `_ttp_mode`, `recon_dir`, `name`, `model`, `cloud`, `src`, `code_seams`).

(a) Resolve the profiles once, right after `prog`/`_ttp_mode` are available. Load `oracle.config.json` explicitly (there is no `oracle.config.json` global in this module — `_BACKEND_CONFIG` is the *routing* config, not this one):

```python
import json as _json
from oracle_mindsets import resolve_mindsets, cross_compare, sort_confirmed

def _oracle_config() -> dict:
    cfg_path = Path(__file__).resolve().parent / "oracle.config.json"
    try:
        return _json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

profiles = resolve_mindsets(getattr(args, "mindset", None), _oracle_config())
_info(f"Mindsets this hunt: {', '.join(profiles)}")
```

(b) Replace the single reflex pass with one pass per LLM profile. Build each profile's `ctx` exactly the way the current code builds its single `ctx` — same `program`, `voice`, and the **same recon-context injection the existing code already performs on `ctx`** — differing only by `mindset=profile`:

```python
seam_sets: dict[str, list[dict]] = {}
for profile in [p for p in profiles if p in ("mitre", "paradox")]:
    ctx = OracleMindsetContext(program=prog, voice=True,
                               ttp_mode=_ttp_mode, mindset=profile)
    # ... replicate here the recon-context injection the existing code does on ctx ...
    raw = run_reflexes(recon_dir, model=model, target=name, cloud=cloud,
                       mindset_system=ctx.system_prompt())
    parsed = _parse_seams(raw, recon_dir=recon_dir)
    for s in parsed:
        s["mindset"] = profile
    seam_sets[profile] = parsed
```

(c) Gate the existing code-lens block on the `seam` profile and **reuse its already-computed `code_seams`** (do not run the lens twice). Tag them and add to `seam_sets`; skip the `scan_repository_seams` call entirely when `seam` is not selected:

```python
if "seam" in profiles and code_seams:
    for cs in code_seams:
        cs["mindset"] = "seam"
    seam_sets["seam"] = code_seams
```

(d) Cross-compare into the candidate list and hand it to the existing verifier unchanged:

```python
candidates = cross_compare(seam_sets)
```

Pass `candidates` as the seam list into the existing `verify_seams(...)` call, preserving every other argument it already receives (`model`, `auto`, scope gate, etc.) — only the seam list changes. When rendering the confirmed report, pass the confirmed rows through `sort_confirmed(...)` before writing, so higher-agreement findings lead.

Reconciliation note: `cmd_hunt` reuses its own already-computed `code_seams` rather than calling `generate_seam_candidates` (Task 4). Both are kept and are not redundant — `generate_seam_candidates` is the single home of the skip logic and the reusable entry point for non-`cmd_hunt` callers (e.g. a future standalone `--mindset seam` path); `cmd_hunt` already has the seams in hand.

Add the argparse flag to the `hunt` subcommand (find where the `hunt` subparser is defined and add):

```python
hunt_parser.add_argument("--mindset", default=None,
    help="mitre | paradox | seam | all (default: config hunt.mindset, else all)")
```

- [ ] **Step 5: Run the full suite**

Run: `python3 -m pytest -q`
Expected: all green (existing 92 + all new tests).

- [ ] **Step 6: Manual end-to-end verification against the local benchmark**

Run: `python3 oracle_hunter.py hunt 127.0.0.1:3000 --mindset all` (the loopback benchmark already present under `targets/direct/127.0.0.1_3000/`).
Expected: log shows "Mindsets this hunt: mitre, paradox, seam"; the run completes; CONFIRMED seams in the report are ordered with higher-agreement findings first. Then `--mindset mitre` runs only one profile and emits no agreement>1.

- [ ] **Step 7: Commit**

```bash
git add oracle_hunter.py oracle.config.json tests/test_hunt_mindset_wiring.py
git commit -m "feat(hunt): run three mindsets, cross-compare, agreement-ranked report"
```

---

## Notes for the executor

- Tasks 1–5 are independent and individually testable. Task 6 depends on 2–5.
- If `_ttp_block` or `inject_recon_context` signatures differ slightly from those referenced, adapt the call site but keep the behavior described; do not change their internals beyond threading the compact-TTP mode in Task 2.
- Do not touch `oracle_deterministic.verify_seam_card` — the verifier is frozen by the spec.
