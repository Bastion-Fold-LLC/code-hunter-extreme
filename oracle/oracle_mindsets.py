# LAYER: think
# DEST: vortex
# ENDPOINTS: resolve_mindsets, effective_mindsets, require_mindsets, build_seam_sets, mindset_of_origin, redteam_challenge, redteam_challenge_by_lens, second_seam_pass, apply_mindset3_gates, cross_compare, seam_subject_key, seam_candidate_key, synthesize_seams  # noqa: E501
# TOPICS: none
"""Mindset orchestration: profile selection, cross-comparison, and
Mindset-3 synthesis. Pure/standalone helpers — imports neither
oracle_code_seam nor oracle_hunter, so no circular import is possible.

P1 doctrine (ORACLE_DOCTRINE.md §1): Mindset 1 = MITRE lens, Mindset 2 =
philosophy/corpus lens, Mindset 3 = SYNTHESIS of 1+2. The deterministic
candidate feed (code lens + template engine, run by the hunt path) is the
shared evidence both lenses reason with — not a fourth lens. It unifies
under the 'seam' profile because Mindset 3 owns the feed it unifies."""

from __future__ import annotations
from typing import Dict, List, Mapping, Optional
from urllib.parse import urlsplit
import hashlib
import re

_VALID = ("mitre", "paradox", "seam")


def resolve_mindsets(selector: Optional[str], config: dict) -> List[str]:
    """Resolve which mindset generators to run.

    Internal `selector` wins; then the optional config fallback; else
    "all". The product path passes an empty config: the operator CLI and
    oracle.config.json cannot narrow the three-mindset product. The
    selector/config path exists only for embedded callers and tests.
    "all" expands to all
    three profiles (P1: ORACLE_DOCTRINE.md §1):
      - mitre: Mindset 1 — MITRE ATT&CK TTPs embedded with offensive Red Teaming
      - paradox: Mindset 2 — 320k philosophy corpus & impossible problems
        with Red Teaming
      - seam: Mindset 3 — SYNTHESIS of mitre+paradox outputs plus the
        deterministic seam feed, with Adversarial Red-Team Synthesis & Chaining
    A single value runs only that one. 'redteam' maps to 'all'.
    Invalid → ValueError (fail loud, no silent default)."""
    value = selector or config.get("hunt", {}).get("mindset") or "all"
    value = str(value).strip().lower()
    if value == "all" or value == "redteam":
        return list(_VALID)
    if value in _VALID:
        return [value]
    raise ValueError(f"invalid mindset {value!r}; allowed: mitre, paradox, seam, all")


def effective_mindsets(
    profiles: List[str], cloud_up: bool, ollama_up: bool
) -> List[str]:
    """Filter requested profiles to the lenses that will actually execute.

    Mirrors the engine gates in cmd_hunt (disclose-fix: the hunt log used
    to report requested profiles as active):
      - paradox runs on Engine A (cloud reflex pass) or Engine B local pass;
      - mitre runs on Engine A (cloud) or Engine B (local tactic sweep);
      - seam (Mindset 3 synthesis + its deterministic code/template feed)
        always runs — the feed is engine-independent.
    Unknown names pass through untouched (resolve_mindsets already rejects
    them loudly; this filter must not second-guess it).
    """
    out = []
    for p in profiles or []:
        if p in ("paradox", "mitre") and not (cloud_up or ollama_up):
            continue
        out.append(p)
    return out


def require_mindsets(
    profiles: List[str],
    cloud_up: bool,
    ollama_up: bool,
    local_only: bool = False,
) -> List[str]:
    """Effective lenses, failing LOUD when a requested lens cannot run locally.

    P1: a --no-cloud hunt (local_only=True) must run every requested lens —
    paradox/seam must not silently drop. A lens with no local engine is a
    RuntimeError naming the lens and the missing engine, never a silent
    subset. Cloud mode (local_only=False) returns the runnable subset and
    the caller fails loud on any drop (see cmd_hunt #25) — this function's
    contract (subset return) is unchanged; only the caller's disclose
    path escalated from warn to die.
    """
    eff = effective_mindsets(profiles, cloud_up, ollama_up)
    if local_only:
        missing = [p for p in profiles or [] if p not in eff]
        if missing:
            raise RuntimeError(
                f"--no-cloud cannot run requested mindset(s) {missing}: "
                f"no local engine (ollama reachable={ollama_up}) — start "
                "ollama; the operator CLI has no partial-lens mode"
            )
    return eff


def build_seam_sets(
    effective: List[str],
    seams: List[dict],
    lens_outcomes: Optional[Dict[str, str]] = None,
) -> Dict[str, Optional[List[dict]]]:
    """Build the synthesize_seams input from SELECTED lenses, not observed keys.

    `effective`: lenses that were supposed to run (require_mindsets output).
    `seams`: merged candidate list (each tagged with its mindset).
    `lens_outcomes`: engine-origin → clean/empty/error/seams per pass.

    Returns lens → list | None with explicit markers:
      - non-empty list: the lens produced seams;
      - []: the lens ran and came back clean/empty (an explicit TARGET
        CLEAN counts), or its cards deduped into another lens's copies;
      - None: the lens was selected but produced NO output object (no
        passes submitted, or every pass errored/dropped) — synthesize
        raises loudly on this instead of unifying short a lens.
    Lenses not in `effective` are omitted (a missing key = not selected,
    which synthesize accepts). The deterministic 'seam' feed runs
    in-process, so an empty feed means ran-clean ([]), never missing.
    Pure + deterministic — no network, no models.
    """
    outcomes = lens_outcomes or {}
    by_lens: Dict[str, List[dict]] = {}
    for s in seams or []:
        lens = s.get("mindset") or mindset_of_origin(s.get("origin"))
        by_lens.setdefault(lens, []).append(s)
    out: Dict[str, Optional[List[dict]]] = {}
    for lens in effective or []:
        got = by_lens.get(lens, [])
        if got:
            out[lens] = got
            continue
        if lens == "seam":
            out[lens] = []  # deterministic feed: empty means ran-clean
            continue
        lens_passes = [v for o, v in outcomes.items() if mindset_of_origin(o) == lens]
        if not lens_passes or all(v == "error" for v in lens_passes):
            out[lens] = None  # selected but no output object — fail loud
        else:
            out[lens] = []  # ran clean/empty (or cards deduped away)
    return out


def mindset_of_origin(origin: Optional[str]) -> str:
    """Map an LLM-engine seam's pipeline origin tag to its mindset label.
    Deterministic generators (code lens, template seams) and adversarial synthesis
    set mindset='seam' directly at their source; this covers the engine origins."""
    o = (origin or "").lower()
    if "seam" in o or "redteam" in o or "synth" in o or "chain" in o:
        return "seam"
    if o.startswith("cloud-paradox") or "paradox" in o:
        return "paradox"
    if o.startswith("local") or "mitre" in o:
        return "mitre"  # local tactic sweep is organized by MITRE tactic
    return "mitre"  # cloud-mitre and any other LLM engine pass = technique lens


def _check_sig(check: str) -> str:
    """Probe signature: the check command with its URL span replaced by the
    normalized subject URL (lowercased, trailing slash stripped, query
    params sorted) and whitespace collapsed, hashed short.

    Same probe shape → same signature: trailing-slash and URL-case
    variants agree, and byte-identical checks always match. Different
    flags/method/body → different signature, so distinct findings at one
    URL no longer share a subject slot (#12). Claim prose is deliberately
    NOT part of this subject signature (it keys cross-mindset agreement);
    red-team verdicts use seam_candidate_key, which does include the
    card's own assertions so same-probe twins are judged separately.
    """
    text = " ".join((check or "").split())
    m = re.search(r"https?://[^\s'\"<>`]+", text)
    if m:
        p = urlsplit(m.group(0))
        q = "&".join(sorted(p.query.split("&"))) if p.query else ""
        norm_url = f"{p.netloc.lower()}{p.path.rstrip('/').lower()}"
        if q:
            norm_url += f"?{q}"
        text = text[: m.start()] + norm_url + text[m.end() :]
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def _subject_key(seam: dict):
    """Identity a seam is matched on across mindsets: normalized check URL for
    web seams (preserving query parameters) plus a probe signature over the
    full check command; file+function for code seams; assertion_a_source as a fallback.
    """
    check = seam.get("check") or ""
    m = re.search(r"https?://[^\s'\"<>`]+", check)
    if m:
        p = urlsplit(m.group(0))
        q_params = tuple(sorted(p.query.split("&"))) if p.query else ()
        return (
            "url",
            p.netloc.lower(),
            p.path.rstrip("/").lower(),
            q_params,
            _check_sig(check),
        )
    f = str(
        seam.get("file") or seam.get("source_b") or seam.get("source_a") or ""
    ).strip().lower()
    fn = str(seam.get("function") or seam.get("subject") or "").strip().lower()
    line = str(
        seam.get("line_b")
        or seam.get("line_a")
        or seam.get("line")
        or seam.get("source_line")
        or ""
    ).strip()
    if f or fn:
        return ("code", f, fn, line)
    src = (seam.get("assertion_a_source") or "").strip().lower()
    if src:
        return ("src", src)
    content = f"{seam.get('assertion_a', '')}:{seam.get('assertion_b', '')}:{seam.get('check', '')}"
    return ("content", hash(content))


def cross_compare(seam_sets: Dict[str, List[dict]]) -> List[dict]:
    """Annotate every seam with a cross-mindset agreement signal, keeping ALL of
    them. Seams sharing a subject identity (URL + probe signature, or
    file+function/claim-source) are flagged with the set of distinct mindsets
    that produced one there and the count. NEVER drops a seam — two different
    findings at the same URL both survive (same-probe cards still share the
    corroboration flag; accepted rank-only noise). Never raises on empty
    input. Agreement is ranking/confidence metadata only; it never decides
    a verdict."""
    all_seams: List[dict] = []
    for profile, seams in seam_sets.items():
        for s in seams or []:
            item = dict(s)
            item.setdefault("mindset", profile)
            all_seams.append(item)
    mindsets_at: Dict[tuple, set] = {}
    for s in all_seams:
        mindsets_at.setdefault(_subject_key(s), set()).add(s.get("mindset"))
    for s in all_seams:
        profiles = sorted(p for p in mindsets_at[_subject_key(s)] if p)
        s["corroborated_by"] = profiles
        s["agreement"] = len(profiles)
    return all_seams


def seam_subject_key(seam: dict) -> str:
    """Stable string identity for one seam, for red-team verdict lookup.

    Mirrors _subject_key (check-URL with sorted query params + probe
    signature → file+function → assertion_a_source → content digest) in
    a JSON-serializable string form so verdict maps stay writable by
    hand and by fixtures. The url form appends the probe signature
    after `~` (e.g. url:h.test/api~a1b2c3d4e5f6).
    """
    key = _subject_key(seam or {})
    kind = key[0]
    if kind == "url":
        _k, netloc, path, qparams, sig = key
        query = "&".join(qparams)
        base = f"url:{netloc}{path}?{query}" if query else f"url:{netloc}{path}"
        return f"{base}~{sig}"
    if kind == "code":
        return f"code:{key[1]}:{key[2]}:{key[3]}" if len(key) > 3 and key[3] else f"code:{key[1]}:{key[2]}"
    if kind == "src":
        return f"src:{key[1]}"
    content = f"{(seam or {}).get('assertion_a', '')}:{(seam or {}).get('assertion_b', '')}:{(seam or {}).get('check', '')}"
    digest = hashlib.md5(content.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
    return f"content:{digest}"


def seam_candidate_key(seam: dict) -> str:
    """Per-candidate red-team verdict identity: lens + subject + card content.

    S3 requires Mindset 1 and Mindset 2 to be red-teamed separately, so a
    verdict must belong to one lens's one card — never to a subject shared
    with a twin. The digest covers exactly the fields _challenge_one
    judges (assertions, expected, check, executed output), so two cards
    that challenge differently key differently, while synthesize_seams
    can recompute the same key from the seam dict it ranks.
    """
    seam = seam or {}
    lens = seam.get("mindset") or mindset_of_origin(seam.get("origin"))

    def _norm(value) -> str:
        return " ".join(str(value or "").lower().split())

    material = "\x1f".join(
        [
            _norm(seam.get("assertion_a")),
            _norm(seam.get("assertion_b")),
            _norm(seam.get("expected")),
            " ".join(str(seam.get("check") or "").split()),
            str(seam.get("check_output") or "").strip(),
        ]
    )
    digest = hashlib.md5(material.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
    return f"cand:{lens}:{seam_subject_key(seam)}#{digest}"


_SYNTH_SEV_RANK = {"critical": -1, "high": 0, "medium": 1, "low": 2}
_SYNTH_VERDICTS = {"confirmed": 0, "unreviewed": 1, "rejected": 2}

_CHALLENGE_STATUS_RE = re.compile(
    r"(?:status\s*|http/\d(?:\.\d)?\s+)(\d{3})\b", re.IGNORECASE
)
_CHALLENGE_URL_RE = re.compile(r"https?://[^\s'\"<>`]+")
# A seam is a binary conflict where wire behavior CONTRADICTS the claim.
# 401/403/530 confirm the boundary works — a card expecting one is no seam.
_CHALLENGE_NON_SEAM_STATUS = ("401", "403", "530")


def _challenge_one(seam: dict, in_scope=None) -> str:
    """Challenge one card; return confirmed | rejected | unreviewed.

    confirmed = survived static challenge: the card is verifiable
      as stated (check URL + status-bearing Expected, in scope when a
      scope oracle is given; or executed check_output on a
      code-anchored seam). Rank boost only — the 5-gate verifier
      stays the sole arbiter of truth.
    rejected = self-defeating as stated: identical assertions (no
      binary conflict), an Expected 401/403/530 (boundary works),
      or an out-of-scope check URL. Demotes rank, never drops.
    unreviewed = nothing testable to challenge, or not verifiable
      as stated. The honest default.
    """
    check = str(seam.get("check") or "")
    expected = str(seam.get("expected") or "")
    a = " ".join(str(seam.get("assertion_a") or "").lower().split())
    b = " ".join(str(seam.get("assertion_b") or "").lower().split())
    if a and a == b:
        return "rejected"
    m = _CHALLENGE_STATUS_RE.search(expected)
    if m and m.group(1) in _CHALLENGE_NON_SEAM_STATUS:
        return "rejected"
    um = _CHALLENGE_URL_RE.search(check)
    if um and in_scope is not None:
        try:
            if not in_scope(um.group(0)):
                return "rejected"
        except Exception as _scope_err:
            # Scope check failed: cannot confirm, must not reject either.
            # Log loudly so the failure is never silent (2A: loud-but-non-fatal).
            import warnings as _w
            _w.warn(
                f"_challenge_one: scope oracle raised {type(_scope_err).__name__} "
                f"for {um.group(0)!r} — treating as unreviewed: {_scope_err}",
                RuntimeWarning,
                stacklevel=2,
            )
            return "unreviewed"
    if seam.get("m3_seam_conflict"):
        # Mindset 3 found the same subject carrying contradictory
        # Assertion B / expected-result claims from different lenses.
        # That contradiction must be resolved by the wire verifier, so
        # the second red-team pass cannot keep an isolated confirmation.
        return "unreviewed"
    has_anchor = bool(um) or bool(
        str(
            seam.get("file")
            or seam.get("source_b")
            or seam.get("source_a")
            or seam.get("function")
            or seam.get("subject")
            or ""
        ).strip()
    )
    if not has_anchor and not check.strip():
        return "unreviewed"
    if um and _CHALLENGE_STATUS_RE.search(expected):
        return "confirmed"
    if not um and str(seam.get("check_output") or "").strip():
        return "confirmed"
    return "unreviewed"


def redteam_challenge(seams: List[dict], in_scope=None) -> Dict[str, str]:
    """Deterministic red-team challenger: the first real producer of
    redteam_verdicts for synthesize_seams.

    Every candidate gets its own verdict keyed by seam_candidate_key()
    (lens + subject + card content), so each mindset's cards are judged
    separately (S3) and a self-defeating twin can no longer drag a good
    same-probe card from another lens down with it. No seam defaults to
    unreviewed for lack of a review anymore (unreviewed means the
    challenger genuinely could not test the card). Pure + deterministic
    — no network, no models. in_scope(url)->bool is an optional scope
    oracle (the hunt passes its ProgramScopeGate).
    """
    verdicts: Dict[str, str] = {}
    for s in seams or []:
        verdicts[seam_candidate_key(s or {})] = _challenge_one(s or {}, in_scope)
    return verdicts


def redteam_challenge_by_lens(seams: List[dict], in_scope=None):
    """Run the challenger as one separate gate per lens (S3).

    Groups candidates by lens (mindset tag, else origin mapping — the
    same derivation build_seam_sets uses), challenges each lens's cards
    in its own redteam_challenge call, and returns (merged verdicts,
    per-lens verdict counts). Verdicts are candidate-keyed, so merging
    can never overwrite another lens's judgment. Pure + deterministic.
    """
    by_lens: Dict[str, List[dict]] = {}
    for s in seams or []:
        lens = (s or {}).get("mindset") or mindset_of_origin((s or {}).get("origin"))
        by_lens.setdefault(lens, []).append(s)
    verdicts: Dict[str, str] = {}
    counts: Dict[str, Dict[str, int]] = {}
    for lens in sorted(by_lens):
        lens_verdicts = redteam_challenge(by_lens[lens], in_scope=in_scope)
        verdicts.update(lens_verdicts)
        tally = {"confirmed": 0, "rejected": 0, "unreviewed": 0}
        for v in lens_verdicts.values():
            tally[v] = tally.get(v, 0) + 1
        counts[lens] = tally
    return verdicts, counts


_ENFORCED_ASSERTION_B_RE = re.compile(
    r"^(?:only\b|requires?\b|must\b)|"
    r"\b(?:only\s+(?:an?\s+)?(?:admin|owner|authorized|authenticated)|"
    r"cannot\b|can\s+not\b|denies\b|denied\b|blocks\b|blocked\b|"
    r"rejects\b|rejected\b|forbids\b|forbidden\b|reverts\b|"
    r"not\s+reachable\b|returns\s+(?:401|403|404|405)\b)",
    re.IGNORECASE,
)
_EXPECTED_DENIAL_RE = re.compile(
    r"\b(?:revert(?:ed|s)?|denied|forbidden|unauthorized|rejected|blocked)\b",
    re.IGNORECASE,
)


def _normalized_text(value) -> str:
    return " ".join(str(value or "").lower().split())


def _assertion_b_polarity(peer: dict) -> str:
    a = _normalized_text(peer.get("assertion_a"))
    b = _normalized_text(peer.get("assertion_b"))
    if not b:
        return ""
    if a and a == b:
        return "enforced"
    if _ENFORCED_ASSERTION_B_RE.search(b):
        return "enforced"
    return "violated"


def _expected_polarity(peer: dict) -> str:
    exp = _normalized_text(peer.get("expected"))
    if not exp:
        return ""
    m = re.search(r"(?:status\s*|http/\d(?:\.\d)?\s+)(\d{3})\b", exp, re.IGNORECASE)
    if not m:
        m = re.search(r"\b([1-5]\d{2})\b", exp)
    if m:
        return f"status:{m.group(1)}"
    if _EXPECTED_DENIAL_RE.search(exp):
        return "expected:denied"
    return "expected:confirmed"


def second_seam_pass(seams: List[dict]) -> List[dict]:
    """Mindset 3's second Invisible Seam pass over lens outputs.

    The first seam pass extracts candidate contradictions from target
    material. This pass treats Mindset 1/2 seam cards themselves as the
    material: cards sharing a subject must either corroborate one
    another or expose a second-order contradiction in Assertion B /
    the expected wire result. Different natural-language phrasing of the
    same violation across lenses is corroboration, whereas opposing
    enforcement/status claims on the same subject are flagged as
    conflicted. Annotates every input exactly once; never drops, merges,
    or invents a seam. Pure + deterministic.
    """
    items: List[dict] = []
    for raw in seams or []:
        item = dict(raw or {})
        item.setdefault(
            "mindset", mindset_of_origin(item.get("origin"))
        )
        items.append(item)

    grouped: Dict[tuple, List[dict]] = {}
    for item in items:
        grouped.setdefault(_subject_key(item), []).append(item)

    for item in items:
        peers = grouped[_subject_key(item)]
        sources = sorted(
            {
                str(peer.get("mindset") or mindset_of_origin(peer.get("origin")))
                for peer in peers
                if str(peer.get("mindset") or mindset_of_origin(peer.get("origin"))).strip()
            }
        )
        b_polarities = {
            _assertion_b_polarity(peer)
            for peer in peers
            if _assertion_b_polarity(peer)
        }
        exp_polarities = {
            _expected_polarity(peer)
            for peer in peers
            if _expected_polarity(peer)
        }
        conflict = len(b_polarities) > 1 or len(exp_polarities) > 1
        item["m3_seam_subject"] = seam_subject_key(item)
        item["m3_seam_sources"] = sources
        item["m3_seam_agreement"] = len(sources)
        item["m3_seam_conflict"] = conflict
        item["m3_seam_state"] = (
            "conflicted"
            if conflict
            else "corroborated"
            if len(sources) >= 2
            else "single-lens"
        )
    return items


def apply_mindset3_gates(seams: List[dict], in_scope=None):
    """Run Mindset 3's seam pass, then re-red-team every lens.

    This is deliberately a fresh challenge over all cards, including
    Mindset 1/2 cards that already passed their separate pre-M3 gates:
    the second seam pass may reveal a cross-lens contradiction that an
    isolated card could not show. Returns ``(annotated seams, verdicts,
    per-lens counts)`` and annotates each seam with
    ``m3_redteam_verdict``. Pure + deterministic.
    """
    annotated = second_seam_pass(seams)
    verdicts, counts = redteam_challenge_by_lens(annotated, in_scope=in_scope)
    for seam in annotated:
        seam["m3_redteam_verdict"] = verdicts.get(
            seam_candidate_key(seam), "unreviewed"
        )
    return annotated, verdicts, counts


def _synth_n_rank(seam: dict) -> int:
    try:
        return int(seam.get("n", 0))
    except (TypeError, ValueError):
        return 10**6


def synthesize_seams(
    seam_sets: Mapping[str, Optional[List[dict]]],
    redteam_verdicts: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """Mindset 3: unify both lenses' outputs + the seam feed into ONE ranked list.

    P1 synthesis (ORACLE_DOCTRINE.md §1). Consumes:
      - seam_sets: per-lens seam outputs keyed by mindset ("mitre",
        "paradox", "seam", ...). A MISSING key = lens not selected (fine).
        A None value = lens selected but produced no output object — fail
        loud (ValueError naming the lens), never silently proceed short a
        lens. An empty list = lens ran clean / TARGET CLEAN (fine).
      - redteam_verdicts: optional seam_candidate_key() → verdict map
        ("confirmed" | "rejected" | "unreviewed"), per-lens per-card as
        redteam_challenge produces. Legacy pooled subject keys are NOT
        consulted (they would verdict both same-probe twins at once,
        defeating the separate S3 gates). A seam with no candidate
        verdict is "unreviewed" — the stated honest default when no
        challenger ran on it. Confirmed boosts rank; rejected DEMOTES
        but never drops — the 5-gate verifier stays the sole arbiter.
        Unknown verdict strings → ValueError.
    Emits: every input seam exactly once, annotated (corroborated_by,
    agreement, the second-seam m3_seam_* fields, redteam_verdict,
    synthesis_sources, synthesis_rank) and ranked by (redteam verdict,
    second-seam conflict, agreement desc, severity, n asc).
    Pure + deterministic — no network, no models.
    """
    if not isinstance(seam_sets, dict):
        raise ValueError(
            f"synthesize_seams needs a mindset→seams dict, got {type(seam_sets).__name__}"
        )
    clean: Dict[str, List[dict]] = {}
    for lens, seams in seam_sets.items():
        if seams is None:
            raise ValueError(
                f"synthesize_seams: lens {lens!r} produced no output (None) — "
                "refusing to unify short a lens"
            )
        if not isinstance(seams, list):
            raise ValueError(
                f"synthesize_seams: lens {lens!r} output must be a list, "
                f"got {type(seams).__name__}"
            )
        clean[lens] = seams
    verdicts: Dict[str, str] = {}
    for raw_key, raw_verdict in (redteam_verdicts or {}).items():
        verdict = str(raw_verdict).strip().lower()
        if verdict not in _SYNTH_VERDICTS:
            raise ValueError(
                f"synthesize_seams: unknown red-team verdict {raw_verdict!r} "
                f"for {raw_key!r}; allowed: confirmed, rejected, unreviewed"
            )
        verdicts[str(raw_key)] = verdict

    united = second_seam_pass(cross_compare(clean))
    for seam in united:
        verdict = verdicts.get(seam_candidate_key(seam), "unreviewed")
        seam["redteam_verdict"] = verdict
        seam["synthesis_sources"] = list(
            seam.get("corroborated_by", [seam.get("mindset")])
        )

    def rank(seam: dict):
        return (
            _SYNTH_VERDICTS[seam["redteam_verdict"]],
            1 if seam.get("m3_seam_conflict") else 0,
            -int(seam.get("agreement", 1)),
            _SYNTH_SEV_RANK.get(str(seam.get("severity", "low")).lower(), 3),
            _synth_n_rank(seam),
        )

    united.sort(key=rank)
    for pos, seam in enumerate(united, start=1):
        seam["synthesis_rank"] = pos
    return united


_SEV_RANK = {"critical": -1, "high": 0, "medium": 1, "low": 2, "info": 3}


def sort_confirmed(confirmed: List[dict]) -> List[dict]:
    """Sort confirmed rows by (agreement desc, severity rank, n asc) so
    multi-mindset corroborated findings surface first."""

    def rank(row: dict):
        seam = row.get("seam", {})
        try:
            agreement = int(seam.get("agreement", 1))
        except (TypeError, ValueError):
            agreement = 1
        try:
            n = int(seam.get("n", 0))
        except (TypeError, ValueError):
            n = 0
        return (
            -agreement,
            _SEV_RANK.get(str(seam.get("severity", "low")).strip().lower(), 3),
            n,
        )

    return sorted(confirmed, key=rank)


# ── Full-service law (2026-10-21): every effective mindset is owed cards ────
# User law after the tinder run: 146 seam cards, 0 mitre cards, 0 paradox
# cards, and the run finished calling itself done. A mindset that produced
# nothing must be NAMED in the run's verdict; a lens TARGET CLEAN claim with
# no materials behind it is an unearned clean, not service.

MIN_SERVED_ENDPOINTS = 3


def mindset_yield_ledger(
    effective,
    seams,
    lens_outcomes=None,
    regime_receipts=None,
):
    """Per-mindset service ledger for a hunt's synthesized card set.

    Returns one entry per EFFECTIVE mindset with fields
    {"mindset", "minted", "cause"}; cause ∈
    {"minted", "qualified-clean", "unserved"}. Cause semantics:
      * minted           — n > 0 cards carry this mindset's origin lens;
      * qualified-clean  — lens explicitly claimed TARGET CLEAN AND regime
                           receipts prove materials (the authenticated regime
                           actually served >= MIN_SERVED_ENDPOINTS endpoints);
      * unserved         — everything else, including an unearned clean.
    Unknown mindset stamps count into no bucket — only effective names asked.
    """
    raw_outcomes = dict(lens_outcomes or {})
    regime_receipts = dict(regime_receipts or {})
    minted = {}
    for s in seams or []:
        m = str(s.get("mindset") or "").strip()
        if m:
            minted[m] = minted.get(m, 0) + 1
    # Lens outcomes are keyed by engine origin tag ("cloud-mitre",
    # "local-paradox", "local-tactic:X" — oracle_hunter futures), not by
    # mindset name; translate through the build_seam_sets law before the
    # cause chain reads them (mindset_of_origin handles unknown tags).
    lens_outcomes: Dict[str, str] = {}
    for k, v in raw_outcomes.items():
        if k in (effective or []):
            lens_outcomes[k] = v
        else:
            tail = str(k).split("-", 1)[1] if "-" in str(k) else ""
            if tail:
                tail = tail.split(":", 1)[0]
            lens_outcomes.setdefault(tail, v)

    ledger = []
    for m in effective or []:
        n = minted.get(m, 0)
        if n:
            cause = "minted"
        else:
            outcome = str(lens_outcomes.get(m, "")).strip().lower()
            rec = regime_receipts.get(m) or {}
            try:
                served = int(rec.get("endpoints_served_200", 0) or 0)
            except (TypeError, ValueError):
                served = 0
            sessioned = bool(rec.get("session_regime"))
            if outcome == "clean" and served >= MIN_SERVED_ENDPOINTS:
                cause = "qualified-clean" if sessioned else "unserved"
            else:
                cause = "unserved"
        ledger.append({"mindset": m, "minted": n, "cause": cause})
    return ledger


def yield_unserved(ledger):
    """Effective mindsets that minted nothing and hold no qualified clean."""
    return [e["mindset"] for e in ledger if e["cause"] == "unserved"]


def sut_format_lines(ledger):
    """One truth line per mindset for the finalize banner."""
    return [
        f"Mindset yield: {e['mindset']}={e['minted']} minted ({e['cause']})"
        for e in ledger
    ]
