#!/usr/bin/env python3
# LAYER: think
# DEST: vortex
# ENDPOINTS: OracleMindsetContext, ProgramWorkspace, bug_key_for
# TOPICS: none
"""
Oracle Mindset Context
══════════════════════
The single authority that loads everything the Oracle IS and builds ONE unified
system prompt from it.  Nothing outside this object can add to or subtract from
the mindset that guides a hunt session.

What it fuses together (in order):
  1. ORACLE_SYSTEM_PROMPT.md  — 8 paradox→reflex worked examples
  2. ORACLE_FRAMEWORK.md      — 16-file philosophy + all patterns
  3. ORACLE_VOICE.md          — hunting voice layer
  4. ALEX_VOICE.md            — one-move structure, named moves, rhythm
  5. corpus/                  — every original source text verbatim (ALL, never a subset)
  6. oracle_ttps_fused.json   — MITRE ATT&CK fused with paradoxes + "you never said"
  7. Program brief            — the active program's scope, rules, and assets

  The source corpus is packaged with the application, not read from external folders.
  All source documents are loaded verbatim into the paradox prompt or the call fails loud.  The model literally
  cannot reason outside scope (layer 6 makes out-of-scope a paradox violation)
  or outside the 8 reflexes (layers 1-2 make any other framing a degenerate case).

Two bug types:
  TYPE_1 — code/contract bugs: implementation flaws, broken invariants, null derefs,
           auth bypasses in code.  Invisible Seam's domain.  CWE-indexed.
  TYPE_2 — logic/manipulation bugs: the code works as written but the system can be
           pushed to produce outcomes it should not.  Business logic, price abuse,
           race conditions, trust boundary crossings.  Oracle 8-reflex domain.

Chain engine:
  Confirmed Type 1 and Type 2 seams are fed to the chaining pass.  Only proven
  links compose.  The chain produces a compound severity + single submission.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

_HERE = Path(__file__).resolve().parent

# ── Oracle document paths ──────────────────────────────────────────────────────
_SYSTEM_PROMPT = _HERE / "ORACLE_SYSTEM_PROMPT.md"
_FRAMEWORK = _HERE / "ORACLE_FRAMEWORK.md"
_VOICE = _HERE / "ORACLE_VOICE.md"
_ALEX_VOICE = _HERE / "ALEX_VOICE.md"
_TTPS_FUSED = _HERE / "oracle_ttps_fused.json"

# Per-record ATT&CK description budget inside _render_ttp. Full TTP text
# averages ~1.2KB/record (max ~4.6KB); uncapped, the 344-record full-mode
# block would add ~425KB to the system prompt and drown cloud context.
# The first ~400 chars of a technique description carry the core
# definition, so the cap keeps real technique text, not just code+name.
_TTP_DESC_CHARS = 400

# ── Bug type constants ─────────────────────────────────────────────────────────
TYPE_1 = "TYPE_1_CODE"  # implementation / contract flaw — invisible seam domain
TYPE_2 = "TYPE_2_LOGIC"  # logic manipulation / business rule abuse — reflex domain

# ── Severity ladder ────────────────────────────────────────────────────────────
# ── Severity ladder ────────────────────────────────────────────────────────────
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Origins whose chain preconditions come from the deterministic _CHAIN_IO
# type vocabulary (category labels like "secret"), never from model prose.
# chain_seams composes these by category without wire grounding (#22);
# every other origin binds on wire-observed literals only.
_CHAIN_TYPED_ORIGINS = frozenset(
    {"seam-template", "seam-template-web3", "invisible-seam"}
)

_MITRE_REDTEAM_DIRECTIVE = """\
## MITRE ATT&CK OFFENSIVE RED-TEAM STRIKE DIRECTIVE
You are the Tactical Offensive Red-Team Lead executing TTP-driven exploitation against this target.
Do not provide generic or theoretical explanations. Every technique must be an active, weaponized probe against
in-scope assets.

OFFENSIVE RULES:
1. Active Control Evasion & Mutation:
   - For every technique in scope, probe for bypasses of WAFs, filters, and API gateways:
* Header spoofing/tampering: X-Forwarded-For, X-Original-URL, X-Rewrite-URL, Client-IP, custom internal auth
     headers.
     * Verb tunneling & method confusion: X-HTTP-Method-Override, POST-as-GET, PUT-as-POST.
* Content-Type and payload mutation: JSON type confusion, multipart boundary variations, path normalization
     bypasses (/..;/, /%2e%2e/).
2. Wire-Level Verification:
   - Formulate exact curl commands with precise headers and payloads targeting in-scope endpoints.
   - Specify the exact wire indicators (status codes, headers, body fragments) proving the vulnerability exists.
3. High-Impact Exploitation Focus:
   - Prioritize BOLA/IDOR, Authentication Bypass, SSRF, Remote Code Execution, and Insecure Direct State Mutation.
"""

_PARADOX_REDTEAM_DIRECTIVE = """\
## PARADOX & PHILOSOPHY ADVERSARIAL RED-TEAM DIRECTIVE
You are the Architectural Red-Team Lead weaponizing contradictions, impossible problems, and broken assumptions.
Every vulnerability is a structural paradox: a fundamental contradiction between what the developer/system
asserts and what the backend wire actually permits.

OFFENSIVE RULES:
1. Invariant & Trust Boundary Destruction:
- Hunt for broken axioms: UI gating without server authorization, client-computed pricing, trusted internal
   network assumptions.
- Attack state machines: race conditions (TOCTOU), coupon/discount stacking, parameter tampering, negative
   amounts, out-of-order workflow execution.
- Exploit privilege and role inversion: tenant crossing, horizontal privilege escalation, administrative role
   confusion.
2. Contradiction Framing:
   - Define Assertion A (The Developer's Sacred Claim / Assumption).
   - Define Assertion B (The Adversarial Wire Reality Proving Contradiction).
   - Provide the exact curl reproduction proving Assertion B destroys Assertion A.
"""

_SEAM_REDTEAM_DIRECTIVE = """\
## INVISIBLE SEAM & ADVERSARIAL RED-TEAM SYNTHESIS DIRECTIVE
You are the Lead Adversarial Red-Team Synthesizer. Your mission is to take candidate seams (from AST code
lenses, recon templates, and MITRE/Paradox passes), ruthlessly attack them, and construct compound multi-step
exploit chains.

OFFENSIVE RULES:
1. Seam Attack & Noise Discard:
   - Scrutinize every pending candidate seam against the live surface and scope.
   - Attempt to bypass defensive sanitization or auth gates.
   - Ruthlessly discard theoretical, benign, or unprovable candidates.
2. Compound Exploitation Chaining:
- Connect findings into multi-step exploit chains: how does output from Step 1 (e.g. leaked ID, auth token,
   debug endpoint, CORS reflection) satisfy the precondition for Step 2 (state mutation, privilege escalation,
   account takeover)?
   - Enforce the format: CLAIM → PROOF → REPRO → EXPECTED → IMPACT → CHAIN_OUTPUTS.
   - Elevate chained vulnerabilities to High or Critical severity with full reproduction steps.
"""

# Backward compatibility alias
_REDTEAM_SYSTEM_DIRECTIVE = _SEAM_REDTEAM_DIRECTIVE


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _program_containers(prog: Any) -> List[Dict[str, Any]]:
    """Program metadata containers in precedence order.

    Scan4Me and the platform caches keep company fields at top level; the
    intake/queue handoffs nest them under company/resources/deep_dive/raw.
    The brief must see the same company identity regardless of which door
    the program entered through.
    """
    if not isinstance(prog, dict):
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[int] = set()

    def add(value: Any) -> None:
        if isinstance(value, dict) and id(value) not in seen:
            seen.add(id(value))
            out.append(value)

    add(prog)
    for key in ("deep_dive", "raw", "resources"):
        add(prog.get(key))
    for source in list(out):
        for key in ("company", "organization", "organisation", "brand"):
            add(source.get(key))
    return out


def _profile_value(prog: Any, *keys: str) -> Any:
    for container in _program_containers(prog):
        for key in keys:
            value = container.get(key)
            if value not in (None, "", [], {}):
                return value
    return None


def _profile_text(
    prog: Any, *keys: str, max_chars: int = 0, oneline: bool = False
) -> str:
    from oracle_foundation import sanitize_prompt_text as _san

    value = _profile_value(prog, *keys)
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    return _san(value, max_chars, oneline=oneline)


def _company_name(prog: Any) -> str:
    from oracle_foundation import sanitize_prompt_text as _san

    if isinstance(prog, dict) and isinstance(prog.get("company"), str):
        return _san(prog["company"], 300, oneline=True)

    explicit = _profile_text(
        prog,
        "company_name",
        "organization_name",
        "organisation_name",
        "brand_name",
        max_chars=300,
        oneline=True,
    )
    if explicit:
        return explicit

    # Intake/queue handoffs may nest the identity as a plain string
    # (deep_dive/raw/resources -> company="Acme Inc"), not only as a
    # company mapping. Containers are already in precedence order.
    for container in _program_containers(prog):
        for key in ("company", "organization", "organisation", "brand"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                return _san(value, 300, oneline=True)

    company_maps: List[Dict[str, Any]] = []

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 3 or not isinstance(value, dict):
            return
        for key in ("company", "organization", "organisation", "brand"):
            nested = value.get(key)
            if isinstance(nested, dict):
                company_maps.append(nested)
                visit(nested, depth + 1)
        for key in ("deep_dive", "raw", "resources"):
            visit(value.get(key), depth + 1)

    visit(prog)
    for company in company_maps:
        for key in ("name", "company_name", "organization_name", "brand_name"):
            value = company.get(key)
            if value not in (None, "", [], {}) and not isinstance(
                value, (dict, list, tuple, set)
            ):
                return _san(value, 300, oneline=True)

    return _profile_text(
        prog,
        "company",
        "organization",
        "organisation",
        "brand",
        max_chars=300,
        oneline=True,
    )


def _scope_records(raw: Any) -> List[Dict[str, Any]]:
    """Normalize every scope shape the adapters emit to record dicts."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [
            {"asset_identifier": line.strip()}
            for line in raw.splitlines()
            if line.strip()
        ]
    if isinstance(raw, dict):
        _collection_keys = (
            "assets",
            "scopes",
            "structured_scopes",
            "targets",
            "items",
        )
        if any(
            key in raw
            for key in (
                "asset_identifier",
                "identifier",
                "target",
                "value",
                "url",
                "host",
                "name",
            )
        ) and not any(key in raw for key in _collection_keys):
            values: List[Any] = [raw]
        else:
            values = []
            for key in ("assets", "scopes", "structured_scopes", "targets", "items"):
                values.extend(_scope_records(raw.get(key)))
            return values
    elif isinstance(raw, (list, tuple)):
        values = list(raw)
    elif isinstance(raw, set):
        values = sorted(raw, key=str)
    else:
        return []

    out: List[Dict[str, Any]] = []
    for item in values:
        if isinstance(item, dict):
            rec = dict(item)
            if not rec.get("asset_identifier"):
                for key in ("identifier", "target", "value", "url", "host", "name"):
                    if rec.get(key):
                        rec["asset_identifier"] = rec[key]
                        break
            if not rec.get("asset_type"):
                rec["asset_type"] = rec.get("type") or rec.get("scope_type") or ""
            if not rec.get("instruction"):
                rec["instruction"] = (
                    rec.get("instructions") or rec.get("note") or rec.get("description") or ""
                )
            out.append(rec)
        elif isinstance(item, str) and item.strip():
            out.append({"asset_identifier": item.strip()})
    return out


def _scope_flag(rec: Dict[str, Any], key: str, default: bool = True) -> bool:
    value = rec.get(key, default)
    if value is None:
        return default
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes", "y", "eligible"):
            return True
        if lowered in ("false", "0", "no", "n", "ineligible"):
            return False
    return bool(value)


def _asset_locator(ident: str, atype: str) -> str:
    """Canonical public URL for an asset when one can be derived safely."""
    text = (ident or "").strip()
    if not text:
        return ""
    lower = text.lower()
    kind = (atype or "").strip().upper()
    if lower.startswith(("http://", "https://")):
        return text
    if kind == "GOOGLE_PLAY_APP_ID":
        return "https://play.google.com/store/apps/details?id=" + quote(text, safe="._-")
    if kind == "APPLE_STORE_APP_ID" and text.isdigit():
        return f"https://apps.apple.com/app/id{text}"
    if lower.startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
        return "https://" + text
    if kind in ("URL", "WILDCARD", "DOMAIN", "WEB", "WEBSITE", "API", "WEB_APPLICATION"):
        return "https://" + text
    # Flat scope fields often carry no type. Only derive a web locator for
    # an unmistakable host[/path] token — never for arbitrary prose/IDs.
    if not kind and re.fullmatch(
        r"(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/.*)?", lower
    ):
        return "https://" + text
    return ""


def _safe_workspace_component(
    value: Any,
    fallback: str = "unknown",
    *,
    lower: bool = False,
    max_chars: Optional[int] = None,
) -> str:
    """One path component that can never traverse outside its parent."""
    text = str(value or "").strip()
    if lower:
        text = text.lower()
    # Dots are intentionally not preserved: "." and ".." are path syntax,
    # not program identity, in a workspace component.
    text = re.sub(r"[^A-Za-z0-9_-]+", "_", text).strip("._-")
    if max_chars is not None:
        text = text[:max_chars].strip("._-")
    return text or fallback


# ──────────────────────────────────────────────────────────────────────────────
# OracleMindsetContext — the single session-level object
# ──────────────────────────────────────────────────────────────────────────────


class OracleMindsetContext:
    """
    Load all philosophy, TTP, and program context into a single system prompt.

    Usage:
        ctx = OracleMindsetContext(program=prog_dict, voice=True)
        system_prompt = ctx.system_prompt()
        bug_type = ctx.classify_seam(seam_dict)
        chain = ctx.chain_seams(confirmed_list)
    """

    def __init__(
        self,
        program: Optional[Dict] = None,
        voice: bool = True,
        ttp_mode: str = "auto",
        ttp_tactic: Optional[str] = None,
        mindset: str = "paradox",
    ):
        """
        program   : active program dict (scope wall, rules, payout, company info)
        voice     : include Alex voice layers
        ttp_mode  : "auto"   → full 344 on cloud, compact 15 on local (default)
                    "full"   → all 344 TTPs in one block (requires large context)
                    "tactic" → only TTPs from one tactic group (use with ttp_tactic)
                    "compact"→ legacy 15-TTP selection
        ttp_tactic: tactic name filter when ttp_mode="tactic", e.g. "PRIVILEGE ESCALATION"
        mindset   : which LLM generator this prompt is for (all 3 embed offensive Red Teaming) —
                    "mitre"   → Mindset 1: full TTP library + MITRE red-team offensive strike directive
                    "paradox" → Mindset 2: full framework + verbatim corpus + architectural red-team directive
                    "seam"    → Mindset 3: SYNTHESIS of Mindset 1+2 outputs + candidate seam
                                ingestion + adversarial synthesis & compound chaining
                    ("redteam" maps directly to "seam")
        """
        mindset_norm = str(mindset).lower().strip()
        if mindset_norm == "redteam":
            mindset_norm = "seam"
        if mindset_norm not in ("mitre", "paradox", "seam"):
            raise ValueError(
                f"OracleMindsetContext mindset must be 'mitre', 'paradox', or 'seam', got {mindset!r}"
            )
        self.program = program or {}
        self._program = self.program
        self.voice = voice
        self.ttp_mode = ttp_mode
        self.ttp_tactic = (ttp_tactic or "").upper().strip()
        self.mindset = mindset_norm
        self._prompt: Optional[str] = None  # cached after first build

    def update_program(self, program: Optional[Dict]) -> None:
        """Replace the bounty-context program and rebuild on next prompt.

        Asset download can discover policy/company text after the context
        object is created. Both lenses must rebuild from that enriched
        program instead of keeping a prompt cached from listing data.
        """
        self.program = program or {}
        self._program = self.program
        self._prompt = None

    # ── System prompt ──────────────────────────────────────────────────────────

    def system_prompt(self) -> str:
        """Return the full unified system prompt.  Cached after first call."""
        if self._prompt is None:
            self._prompt = self._build()
        return self._prompt

    def prompt_size(self) -> int:
        """Character length of the built system prompt (observability: lets an
        operator/log see when the paradox corpus makes a prompt large)."""
        return len(self.system_prompt())

    def reporting_prompt(self) -> str:
        """Lean system prompt for reporting tasks (PoC, correlation).

        Hunt-4c: the full 106KB fused system prompt sent to a 16k local
        model starved generation (600s idle timeout, zero bytes).
        Report writing needs the finding + evidence + scope wall, not
        the philosophy corpus or TTP library — those stay on the
        hunting side. Always well under local context budgets.
        """
        parts = []
        if self.mindset == "mitre":
            parts.append(_MITRE_REDTEAM_DIRECTIVE)
        elif self.mindset == "paradox":
            parts.append(_PARADOX_REDTEAM_DIRECTIVE)
        elif self.mindset in ("seam", "redteam"):
            parts.append(_SEAM_REDTEAM_DIRECTIVE)
        brief = self._program_brief()
        if brief:
            parts.append(brief)
        parts.append(
            "Write only what the captured evidence proves. "
            "Never invent endpoints, responses, or impact beyond the evidence.\n"
            "TITLE RULE: the finding title MUST use the exact URL path from the "
            "check field verbatim — never paraphrase it (e.g. '/.git/config' "
            "must appear as '/.git/config', never as 'self-observe endpoint' "
            "or any other rewrite). Copy the path character-for-character."
        )
        return "\n\n".join(parts)

    def _load_ttps(self) -> List[Dict]:
        """Load and return all TTP records from the fused library.

        First-wins dedupe by code (mirrors the _load_fused_ttps R3 fix):
        the appended Reflex 9/10/11 overlay stubs (T1078/T1083/T1133/
        T1190) duplicate real codes with one-line text — keep the full
        ATT&CK record, drop the later stub. 348 records → 344 unique.
        """
        if not _TTPS_FUSED.exists():
            return []
        try:
            records = json.loads(_TTPS_FUSED.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        seen: set = set()
        out: List[Dict] = []
        for r in records:
            if not isinstance(r, dict) or not r.get("code"):
                continue
            if r["code"] in seen:
                continue
            seen.add(r["code"])
            out.append(r)
        return out

    def _render_ttp(self, r: Dict) -> str:
        """Render one TTP record as a compact block.

        Emits the real ATT&CK description (capped per _TTP_DESC_CHARS so
        the full 344-record block stays inside cloud context budgets) —
        the model reasons with technique text, not just code+name.
        All fields are .get-hardened: fused records and overlay stubs
        vary in shape, and a missing key must degrade the block, never
        raise KeyError mid-prompt-build.
        """
        r = r or {}
        desc = str(r.get("description") or "").strip()
        if len(desc) > _TTP_DESC_CHARS:
            cut = desc[:_TTP_DESC_CHARS].rsplit(" ", 1)
            desc = (cut[0] if len(cut) > 1 else desc[:_TTP_DESC_CHARS]) + "…"
        return (
            f"**{r.get('code', '?')} — {r.get('name', '?')}** "
            f"[Reflex {r.get('primary_reflex', '?')}: "
            f"{r.get('reflex_name', '?')} · {r.get('paradox', '?')}]  "
            f"\nTactic: {r.get('tactic', '')}  "
            f"\nTechnique: {desc or '(no ATT&CK description)'}"
            f"\nYou never said: {r.get('you_never_said', '')}"
            f"\nMove: {r.get('reflex_move', '')}"
        )

    # Tokens too generic to carry relevance (schemes, TLDs, filler).
    _RECON_STOP_TOKENS = frozenset(
        {"http", "https", "www", "com", "net", "org", "io", "html", "index"}
    )

    def _recon_tokens(self) -> Set[str]:
        """Fragments observed on THIS target: hostname/endpoint pieces from
        injected recon context (inject_recon_context). length>3 and
        stop-filtered so only discriminating fragments score."""
        toks: Set[str] = set()
        for text in list(getattr(self, "_recon_hosts", [])) + list(
            getattr(self, "_recon_endpoints", [])
        ):
            for part in re.split(r"[^a-z0-9]+", str(text).lower()):
                if len(part) > 3 and part not in self._RECON_STOP_TOKENS:
                    toks.add(part)
        return toks

    def _ttp_score(self, r: Dict) -> int:
        """Relevance of one TTP record to THIS target (higher = more relevant).

        #23 replacement for the old generic-word counter: the primary
        signal is target-grounded — technique text (name/tactic weigh 2,
        description 1) mentioning fragments observed in this hunt's recon
        (host/endpoint pieces). The fallback is a weak program prior:
        scope-asset name overlap with the technique name. With no recon
        and no asset overlap every record scores 0 and selection falls
        back to stable file order — stated here, not hidden behind
        fake-precision word lists. Full/tactic modes emit every record,
        so there the score only orders; compact mode picks the top 3
        per reflex group from this ordering.
        """
        name_tactic = f"{r.get('name', '')} {r.get('tactic', '')}".lower()
        desc = (r.get("description") or "").lower()
        score = 0
        for tok in self._recon_tokens():
            if tok in name_tactic:
                score += 2
            elif tok in desc:
                score += 1
        scope_assets = [
            s.get("asset_identifier", "")
            for s in self.program.get("structured_scopes", [])
            if s.get("eligible_for_bounty")
        ]
        score += sum(
            1
            for asset in scope_assets
            if any(w in name_tactic for w in asset.split(".") if len(w) > 3)
        )
        return score

    def _selected_ttps(self, mode: Optional[str] = None) -> List[Dict]:
        """Return the relevance-ordered TTP working set for `mode`.

        full/tactic → every record (tactic-filtered); compact/auto →
        top 3 per reflex group with deduplicated seeds. Raises loudly
        when the fused library is missing or the tactic is unknown.
        """
        records = self._load_ttps()
        if not records:
            raise RuntimeError(
                f"fused TTP library missing or empty: {_TTPS_FUSED} "
                "— refusing to build a prompt short the MITRE feed"
            )

        mode = mode or self.ttp_mode

        if mode == "tactic":
            if not self.ttp_tactic:
                raise ValueError(
                    "ttp_mode='tactic' requires a tactic name (ttp_tactic)"
                )
            records = [
                r
                for r in records
                if (r.get("tactic") or "").upper() == self.ttp_tactic
            ]
            if not records:
                raise ValueError(
                    f"unknown tactic {self.ttp_tactic!r}: no TTP records "
                    f"in {_TTPS_FUSED.name} carry that tactic"
                )

        records_scored = sorted(records, key=self._ttp_score, reverse=True)

        if mode == "full" or mode == "tactic":
            return records_scored  # all of them, relevance-sorted

        # "compact" / "auto": top 3 per reflex, deduplicated seeds (legacy)
        by_reflex: Dict[int, List] = {}
        for r in records_scored:
            rid = r.get("primary_reflex", 0)
            by_reflex.setdefault(rid, []).append(r)
        selected: List[Dict] = []
        seen_seeds: set = set()
        for rid in sorted(by_reflex):
            group = by_reflex[rid]
            added = 0
            for r in group:
                if added >= 3:
                    break
                seed = (r.get("you_never_said") or "").strip()
                if seed and seed in seen_seeds:
                    desc = (r.get("description") or "")[:120].strip()
                    if desc:
                        r = dict(r)
                        r["you_never_said"] = (
                            f"{seed[:60]}… specifically for {r.get('name', '')} — "
                            f"{desc[:80]}"
                        )
                seen_seeds.add((r.get("you_never_said") or "").strip())
                selected.append(r)
                added += 1
        return selected

    def _render_ttp_block(self, selected: List[Dict]) -> str:
        """Render selected TTP records as the reference block text."""
        tactic_label = f" — {self.ttp_tactic}" if self.ttp_tactic else ""
        lines = [
            f"## ORACLE TTP REFERENCE (fused paradox+MITRE){tactic_label}",
            f"All {len(selected)} techniques mapped to the 11 reflexes + paradox framing.",
            "For each technique: apply the 'you never said' seed as the opening question on THIS target.",
            "Closing motions 6/7/8 apply to every finding regardless of technique.",
            "",
        ]
        for r in selected:
            lines.append(self._render_ttp(r))
            lines.append("")
        return "\n".join(lines)

    def _ttp_block(self, mode: Optional[str] = None) -> str:
        """
        Emit the TTP reference block.

        ttp_mode="full"    → all 344 TTPs, sorted by relevance score.
                             Use on OpenRouter/cloud (128k+ context).
        ttp_mode="tactic"  → all TTPs in self.ttp_tactic group only.
                             Use for per-tactic passes on local model.
        ttp_mode="compact" → top 3 per reflex group (relevance-ordered
                             within each group; 3 × the groups present in
                             the fused file — NOT "top 15", the old comment
                             lied about the count).
        ttp_mode="auto"    → "compact" (safe default; caller overrides to "full"
                             when model context is large enough).
        """
        return self._render_ttp_block(self._selected_ttps(mode))

    def _effective_ttp_mode(self) -> str:
        """Return the TTP mode _build actually renders for this mindset."""
        if self.ttp_mode == "full" or (
            self.mindset not in ("paradox", "seam", "redteam")
            and self.ttp_mode == "auto"
        ):
            return "full"
        if self.mindset not in ("paradox", "seam", "redteam"):
            return self.ttp_mode
        return "compact"

    def all_tactics(self) -> List[str]:
        """Return the sorted list of unique tactic names in the TTP library."""
        records = self._load_ttps()
        return sorted(set(r.get("tactic", "") for r in records if r.get("tactic")))

    def tactic_prompt(self, tactic: str) -> str:
        """
        Return a full system prompt with ONLY the TTPs from one tactic group.
        Use this for per-tactic passes on local models with small context windows.
        Resets the cache after building.
        """
        prev_mode = self.ttp_mode
        prev_tactic = self.ttp_tactic
        prev_prompt = self._prompt
        self.ttp_mode = "tactic"
        self.ttp_tactic = tactic.upper().strip()
        self._prompt = None
        result = self.system_prompt()
        # restore
        self.ttp_mode = prev_mode
        self.ttp_tactic = prev_tactic
        self._prompt = prev_prompt
        return result

    def _program_brief(self) -> str:
        """Build the program brief — the scope wall baked into the system prompt."""
        from oracle_foundation import sanitize_prompt_text as _san
        from oracle_foundation import untrusted_block as _untrusted

        prog = self.program
        if not prog:
            return ""

        # Phase 5: listing fields are attacker-influenced — sanitize scalars
        # and delimit free-text blocks (rules, scope notes) as untrusted.
        name = _profile_text(prog, "name", max_chars=300, oneline=True) or "unknown"
        platform = _profile_text(
            prog, "platform", "site", max_chars=100, oneline=True
        )
        url = _profile_text(
            prog, "url", "program_url", "listing_url", max_chars=500, oneline=True
        )
        kind = (
            _profile_text(
                prog, "kind", "program_kind", max_chars=50, oneline=True
            )
            or "web2"
        )

        # Collect every asset each adapter knows about. Dedupe by typed
        # asset, not identifier alone: the same host can legitimately be
        # in scope as SOURCE_CODE while its live URL is out of scope, and
        # both instructions must survive into every mindset.
        in_scope: List[str] = []
        submission_only: List[str] = []
        out_scope: List[str] = []
        rules_text = ""
        _seen_scope_lines: Set[Tuple[str, str, str]] = set()
        _seen_scope_notes: Set[Tuple[str, str]] = set()

        def _render_scope(rec: Dict[str, Any]) -> Tuple[str, str, str]:
            ident = _san(rec.get("asset_identifier", ""), oneline=True)
            raw_atype = _san(rec.get("asset_type", ""), 50, oneline=True).upper()
            atype = raw_atype or "UNSPECIFIED"
            if not ident:
                return "", atype, ""
            bits = [f"  • {ident} [{atype}]"]
            if _scope_flag(rec, "is_wildcard", False) or ident.startswith("*."):
                bits.append("[wildcard]")
            severity = _san(rec.get("max_severity", ""), 50, oneline=True)
            if severity:
                bits.append(f"(max severity: {severity})")
            locator = _san(_asset_locator(ident, raw_atype), 500, oneline=True)
            if locator and locator != ident:
                bits.append(f"→ {locator}")
            if rec.get("_hunt_new"):
                bits.append("[NEW]")
            return " ".join(bits), atype, ident

        def _add_scope(rec: Dict[str, Any], forced_bucket: Optional[str] = None) -> None:
            nonlocal rules_text
            line, atype, ident = _render_scope(rec)
            if not line:
                return
            submission = _scope_flag(rec, "eligible_for_submission", True)
            bounty = _scope_flag(rec, "eligible_for_bounty", True)
            if forced_bucket:
                bucket = forced_bucket
            elif submission and bounty:
                bucket = "in"
            elif submission:
                bucket = "submission_only"
            else:
                bucket = "out"
            key = (ident.lower(), atype, bucket)
            if key not in _seen_scope_lines:
                _seen_scope_lines.add(key)
                {
                    "in": in_scope,
                    "submission_only": submission_only,
                    "out": out_scope,
                }[bucket].append(line)
            instr = str(rec.get("instruction") or "").strip()
            if instr:
                note_key = (ident.lower(), instr)
                if note_key not in _seen_scope_notes:
                    _seen_scope_notes.add(note_key)
                    # Sanitized for control chars only (no length cap):
                    # full scope notes must reach every lens.
                    rules_text += f"\n[Scope note for {ident} ({atype})]: {_san(instr)}"

        for scope in _scope_records(prog.get("structured_scopes")):
            _add_scope(scope)
        for field in ("scope", "targets"):
            for scope in _scope_records(prog.get(field)):
                _add_scope(scope)
        for field in ("out_of_scope", "out_of_scope_assets", "excluded_assets", "exclusions"):
            for scope in _scope_records(prog.get(field)):
                _add_scope(scope, forced_bucket="out")

        # program rules — check all common key names including what oracle_code_seam passes
        # Hard cap per field: 20k chars. A raw platform page (HTML, 302k chars)
        # injected verbatim blows the mitre context past 128k tokens — the entire
        # rules section must not exceed what a model can actually use.
        _RULES_PER_FIELD_CAP = 20_000
        for key in (
            "policy",
            "disclosure_policy",
            "rules",
            "bug_types",
            "policy_text",
            "rules_text",
            "program_rules",
            "safe_harbor",
            "guidelines",
            "terms",
        ):
            val = _profile_value(prog, key)
            if key == "safe_harbor" and isinstance(val, str) and len(val) <= 300:
                continue  # short status belongs in the company header below
            if val and isinstance(val, str):
                val_capped = val[:_RULES_PER_FIELD_CAP]
                if len(val) > _RULES_PER_FIELD_CAP:
                    val_capped += f"\n… [truncated {len(val) - _RULES_PER_FIELD_CAP} chars]"
                rules_text += f"\n[{key}]: {_san(val_capped)}"

        # Company profile & metadata, normalized across Scan4Me top-level
        # fields and intake/queue nested company/resource records.
        company = _company_name(prog)
        website = _profile_text(
            prog,
            "website",
            "company_website",
            "company_url",
            "homepage",
            "home_page",
            "site_url",
            max_chars=500,
            oneline=True,
        )
        handle = _profile_text(
            prog, "handle", "slug", max_chars=200, oneline=True
        )
        tagline = _profile_text(
            prog,
            "tagline",
            "overview",
            "description",
            "about",
            "company_description",
        )

        def _numeric_profile(*keys: str) -> Optional[float]:
            value = _profile_value(prog, *keys)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None
            return float(value)

        def _fmt_amount(value: Optional[float]) -> str:
            amount = 0.0 if value is None else value
            return f"{amount:,.2f}".rstrip("0").rstrip(".")

        currency = (
            _profile_text(prog, "currency", max_chars=10, oneline=True).upper()
            or "USD"
        )
        min_payout = _numeric_profile("min_payout", "minimum_payout")
        max_payout = _numeric_profile("max_payout", "max_payout_usd", "maximum_payout")
        if min_payout is not None and max_payout is not None and min_payout != max_payout:
            amount_text = f"{_fmt_amount(min_payout)}–{_fmt_amount(max_payout)}"
            payout_line = (
                f"**Payout:** ${amount_text}"
                if currency == "USD"
                else f"**Payout:** {amount_text} {currency}"
            )
        else:
            amount_text = _fmt_amount(max_payout)
            payout_line = (
                f"**Max payout:** ${amount_text}"
                if currency == "USD"
                else f"**Max payout:** {amount_text} {currency}"
            )

        safe_raw = _profile_value(prog, "safe_harbor", "safe_harbour")
        if isinstance(safe_raw, bool):
            safe_harbor = "Yes" if safe_raw else "No"
        elif isinstance(safe_raw, dict):
            safe_harbor = _san(
                safe_raw.get("status") or safe_raw.get("text") or "",
                300,
                oneline=True,
            )
        else:
            safe_harbor = _san(safe_raw or "", 300, oneline=True)

        # Program identification fields are attacker-influenced (an adversarial
        # program listing on an open platform controls name/company/tagline).
        # Wrap the header block so the model sees the [UNTRUSTED] tag before
        # reading any platform-supplied string.
        _listing_lines = [
            f"**Program:** {name}  |  **Platform:** {platform}  |  **Kind:** {kind}",
            f"**Program URL:** {url}",
            payout_line,
        ]
        if company and company.lower() != name.lower():
            _listing_lines.append(f"**Company / Organization:** {company}")
        if website and website != url:
            _listing_lines.append(f"**Company Website:** {website}")
        if handle:
            _listing_lines.append(f"**Program Handle / Slug:** {handle}")
        offers_bounties = _profile_value(prog, "offers_bounties")
        if offers_bounties is False:
            _listing_lines.append("**Bounties Offered:** No (disclosure only)")
        if safe_harbor:
            _listing_lines.append(f"**Safe Harbor:** {safe_harbor}")
        if tagline:
            _listing_lines.append(f"**Company Profile & Overview:** {tagline.strip()}")

        lines = [
            "## ACTIVE PROGRAM — SCOPE WALL & TARGET CONTEXT",
            "You are hunting THIS program only. Every finding MUST cite a source from the",
            "in-scope assets below. Out-of-scope assets are not a paradox — they are simply",
            "not part of this hunt. The rules and scope below are axioms for this session.",
            "",
            _untrusted("\n".join(_listing_lines), "program-listing"),
        ]

        # Program metrics & efficiency
        stats = []

        def _stat(label: str, *keys: str, suffix: str = "") -> None:
            value = _profile_value(prog, *keys)
            if value in (None, "", [], {}) or isinstance(value, (dict, list, tuple, set)):
                return
            if isinstance(value, float) and value.is_integer():
                value = int(value)
            stats.append(f"{label}: {_san(value, 80, oneline=True)}{suffix}")

        _stat(
            "Response Efficiency",
            "response_efficiency",
            "response_efficiency_percentage",
            suffix="%",
        )
        _stat("First Response", "first_response_hours", suffix="h")
        _stat("Validation", "validation_days", suffix="d")
        _stat(
            "Reports Resolved",
            "reports_count",
            "resolved_report_count",
            "reports_resolved",
        )
        _stat("Rewarded Vulnerabilities", "rewarded_vulnerabilities")
        average_payout = _numeric_profile("average_payout")
        if average_payout is not None:
            stats.append(f"Average Payout: {_fmt_amount(average_payout)} {currency}")
        if _profile_value(prog, "fast_triage", "triage_active"):
            stats.append("Fast Triage: Active")
        if _profile_value(prog, "managed_triage"):
            stats.append("Managed Triage: Active")
        if stats:
            lines.append(f"**Program Operational Metrics:** {' | '.join(stats)}")
        lines.append("")

        # Hunt filter summary (operator context): the model only ever sees the
        # filtered assets below — other in-scope assets are not in its world.
        _hf_meta = prog.get("_hunt_filter") or {}
        if _hf_meta:
            _total = _hf_meta.get("kept", 0) + _hf_meta.get("dropped", 0)
            lines.append(
                f"**HUNT SCOPE:** {_hf_meta.get('kept')} of {_total} program "
                f"assets (filter mode={_hf_meta.get('mode')}). "
                "Only the assets listed below exist for this hunt."
            )
            lines.append("")

        if in_scope or submission_only:
            lines.append("**IN SCOPE:**")
            if in_scope:
                lines.append("Bounty-eligible:")
                lines.extend(in_scope)
            if submission_only:
                lines.append("Submission-only / no bounty:")
                lines.extend(submission_only)
            lines.append("")
        else:
            # Hard halt: no scope = no findings. The LLM must not reason about
            # whatever happens to be in the recon data — that would be
            # fabricating scope. A clean scope wall is better than a wrong one.
            lines += [
                "**IN SCOPE: ⚠ SCOPE NOT LOADED**",
                "Scope data was not available for this program at hunt time.",
                "**MANDATORY HALT: output exactly `TARGET CLEAN` and stop.**",
                "Do not produce any seam cards. Do not reason about any domain",
                "found in recon data — those may belong to the platform, not the",
                "target. A missing scope wall means no valid findings can be made.",
                "",
            ]

        if out_scope:
            lines.append("**OUT OF SCOPE (never probe these):**")
            lines.extend(out_scope)
            lines.append("")

        if rules_text.strip():
            lines.append("**PROGRAM RULES & NOTES:**")
            lines.append(_untrusted(rules_text.strip(), "program-rules"))
            lines.append("")

        # On-disk downloaded assets and repositories.
        # M2: when a hunt filter is active, only kept-asset files/repos are
        # advertised — the phase-1 model must never see full-scope disk
        # content. Without filter metadata (standalone use) list everything.
        kept_hosts = _kept_hosts_of(prog)
        kept_repos = _kept_repos_of(prog)
        slug_raw = _safe_workspace_component(name, lower=True, max_chars=60)
        platform_component = _safe_workspace_component(platform)
        ws_base = _HERE / "targets" / platform_component / slug_raw
        if ws_base.exists():
            local_assets = []
            assets_dir = ws_base / "assets"
            manifest: Dict[str, str] = {}
            if assets_dir.exists():
                manifest = _manifest_of(assets_dir)
                kept_files = []
                for f in sorted(assets_dir.glob("*")):
                    if not f.is_file() or f.name == "_manifest.json":
                        continue
                    if kept_hosts is not None:
                        fh = _downloaded_file_host(f.name, manifest)
                        if fh not in kept_hosts:
                            continue
                    kept_files.append(f)
                for f in kept_files[:15]:
                    local_assets.append(f"  • {f.name} ({f.stat().st_size:,} bytes)")
            # also check if any git cloned repos exist in ws_base
            repo_roots = [ws_base, ws_base / "repos"]
            for root in repo_roots:
                if not root.is_dir():
                    continue
                for d in sorted(root.iterdir()):
                    if not d.is_dir() or not (d / ".git").exists():
                        continue
                    if kept_repos is not None and d.name.lower() not in kept_repos:
                        continue
                    rel = d.relative_to(ws_base)
                    local_assets.append(
                        f"  • [CLONED REPO] {d.name}/ (full source code on-disk at "
                        f"targets/{platform_component}/{slug_raw}/{rel})"
                    )
            if local_assets:
                lines.append("**LOCAL ON-DISK ASSETS & CODE REPOSITORIES:**")
                lines.extend(local_assets)
                lines.append("")

            # GAP 3 fix: inline key asset content so model sees it in system prompt
            # not just a filename — robots.txt rules, security.txt contacts, openapi paths
            # M2: inline only files belonging to kept assets.
            if assets_dir.exists():
                asset_snippets = []
                _KEY_ASSETS = [
                    ("robots.txt", 800),
                    ("security.txt", 400),
                    ("openapi.json", 1200),
                    ("swagger.json", 1200),
                    ("api-docs.txt", 600),
                ]
                for pattern, max_chars in _KEY_ASSETS:
                    matches = sorted(assets_dir.glob(f"*{pattern}*"))
                    if kept_hosts is not None:
                        matches = [
                            m
                            for m in matches
                            if _downloaded_file_host(m.name, manifest) in kept_hosts
                        ]
                    if matches:
                        try:
                            content = (
                                matches[0]
                                .read_text(errors="ignore")
                                .strip()[:max_chars]
                            )
                            if content:
                                asset_snippets.append(f"[{pattern}]:\n{content}")
                        except OSError:
                            pass
                if asset_snippets:
                    lines.append("**KEY ASSET CONTENT (inline):**")
                    lines.append("\n\n".join(asset_snippets)[:3000])
                    lines.append("")

        lines += [
            "**INVARIANT:** Any seam you find MUST have Assertion A sourced to this program's",
            "documentation, policy, or UI — and Assertion B grounded in recon data or local code from the",
            "IN SCOPE assets above.  If it cannot be grounded here, it does not exist.",
            "Any finding citing an asset NOT listed in IN SCOPE above is automatically invalid.",
            "The company website and platform program URL are identification/context only;",
            "neither authorizes probing unless the same asset independently appears in IN SCOPE.",
        ]

        return "\n".join(lines)

    # ── Recon context injection (GAP 5: target-specific TTP seeds) ───────────

    def inject_recon_context(
        self, live_hosts: List[str], endpoints: Optional[List[str]] = None
    ) -> None:
        """
        Inject live recon findings to personalize TTP seeds for THIS target.

        Call after recon completes, before system_prompt() is called for the
        LLM reflex pass.  Resets the cache so next system_prompt() call rebuilds.

        live_hosts  : list of live hostnames/URLs discovered in recon
        endpoints   : list of discovered paths/endpoints (optional)

        Effect: adds a LIVE TARGET CONTEXT block after the scope wall,
        and personalizes the top TTP seeds to reference actual discovered paths.
        """
        if not live_hosts and not endpoints:
            return
        prog = getattr(self, "program", {}) or getattr(self, "_program", {}) or {}
        hunt_cfg = prog.get("hunt_config", {})
        recon_cfg = hunt_cfg.get("recon_context", {})
        max_hosts = hunt_cfg.get("max_hosts", recon_cfg.get("max_hosts", 20))
        max_endpoints = hunt_cfg.get("max_endpoints", recon_cfg.get("max_endpoints", 30))

        self._recon_hosts = list(live_hosts or [])[:max_hosts]
        self._recon_endpoints = list(endpoints or [])[:max_endpoints]
        self._prompt = None  # force rebuild

    def _recon_context_block(self) -> str:
        """Render live recon context as a LIVE TARGET CONTEXT section."""
        hosts = getattr(self, "_recon_hosts", [])
        endpoints = getattr(self, "_recon_endpoints", [])
        if not hosts and not endpoints:
            return ""
        lines = [
            "## LIVE TARGET CONTEXT (from recon — use these in your 'you never said' seeds)",
            "These are REAL discovered surfaces on this target. Every TTP seed below should",
            "ask 'you never said [THIS SPECIFIC PATH/HOST] is protected.'",
            "",
        ]
        if hosts:
            lines.append("**Live hosts discovered:**")
            lines.extend(f"  • {h}" for h in hosts)
            lines.append("")
        if endpoints:
            lines.append("**Discovered endpoints / paths:**")
            lines.extend(f"  • {e}" for e in endpoints[:20])
            lines.append("")
        # Emit personalized seed examples for top 5 hosts
        if hosts:
            lines.append("**Personalized 'you never said' seeds for THIS target:**")
            seed_templates = [
                "You never said {host} verifies authentication server-side — only that the login form exists.",
                "You never said {host} checks authorization on WRITE, only on the menu render.",
                "You never said {host} validates the object reference belongs to the requesting user.",
                "You never said {host} rate-limits by user — the limit may be keyed on IP only.",
                "You never said {host}'s API returns 403 on missing auth — it may return 200 with empty data.",
            ]
            for i, host in enumerate(hosts[:5]):
                clean = host.replace("https://", "").replace("http://", "").rstrip("/")
                lines.append(
                    f"  • {seed_templates[i % len(seed_templates)].format(host=clean)}"
                )
            lines.append("")
        return "\n".join(lines)

    # ── Seam injection (code-only targets) ────────────────────────────────────

    def inject_pending_seams(self, seams: List[Dict]) -> None:
        """
        Bake scope-grounded seam candidates into the system prompt as a
        PENDING SEAMS section. Candidates may originate from Invisible Seam's
        code lens or the paradox/MITRE template engine.

        This ensures philosophy, MITRE, scope/rules, and both seam engines
        arrive in the same system prompt — the model reasons about candidates
        within the active program world, never as an afterthought.

        Resets the cached prompt so next call to system_prompt() rebuilds.

        Filters out decayed seams and mutation-triggered seams per
        Kinetic Axiom (Product.ai Axiomatic Intelligence).
        """
        from datetime import datetime, timezone

        filtered_seams = []
        now = datetime.now(timezone.utc)

        for s in (seams or []):
            # Check decay
            last_verified_str = s.get("last_verified")
            decay_rate_value = s.get("decay_rate_value", 0.05)
            if last_verified_str:
                try:
                    last_verified = datetime.fromisoformat(last_verified_str.replace("Z", "+00:00"))
                    days_elapsed = (now - last_verified).total_seconds() / 86400
                    # Exponential decay: confidence = exp(-decay_rate * days)
                    import math
                    confidence = math.exp(-decay_rate_value * days_elapsed)
                    if confidence < 0.1:  # Below 10% confidence = decayed
                        continue  # Skip decayed seam
                except (ValueError, TypeError):
                    pass  # Invalid timestamp, don't filter on decay

            # Check mutation triggers
            if s.get("mutation_triggered"):
                continue  # Skip mutation-triggered seam

            filtered_seams.append(s)

        # An empty list is meaningful: the seam feed ran clean. Both
        # lenses must still see that explicit state instead of silently
        # proceeding as if Invisible Seam had not been combined with them.
        self._seams_injected = filtered_seams
        self._prompt = None  # force rebuild

    def inject_code_seams(self, seams: List[Dict]) -> None:
        """Backward-compatible alias for :meth:`inject_pending_seams`."""
        self.inject_pending_seams(seams)

    def _seam_block(self) -> str:
        """Render injected seams as a PENDING SEAMS section."""
        seams = getattr(self, "_seams_injected", None)
        if seams is None:
            return ""
        if not seams:
            return "\n".join(
                [
                    "## PENDING SEAMS (deterministic seam output)",
                    "Invisible Seam ran before this lens and produced no deterministic seam candidates.",
                    "That empty feed is not proof the target is clean. Still apply the seam method",
                    "to the in-scope material: state Assertion A, find Assertion B, and give one check.",
                ]
            )
        lines = [
            "## PENDING SEAMS (deterministic seam output)",
            "These seam candidates were extracted from the program's source code and",
            "recon material by the Invisible Seam code lens and the paradox/TTP template hunt.",
            "Each one is a binary conflict: Assertion A vs Assertion B, one of which",
            "must be false. Apply the 8 reflexes to determine exploitability and",
            "chain potential. Every seam below is already grounded in the IN SCOPE",
            "material above — no scope check needed.",
            "Your job: rank by impact, generate Assertion A / Assertion B / Check for each.",
            "",
        ]
        for s in seams:
            n = s.get("n", "?")
            claim_type = s.get("claim_type", s.get("classification", "?"))
            reflex = s.get("reflex", "?")
            mitre = s.get("mitre", "?")
            impact = s.get("impact", "?")
            a = s.get("assertion_a", "?")
            b = s.get("assertion_b", "?")
            src_a = s.get("source_a", "")
            line_a = s.get("line_a", "")
            src_b = s.get("source_b", "")
            line_b = s.get("line_b", "")
            lines += [
                f"**SEAM {n} [{claim_type}]** — {reflex}",
                f"MITRE: {mitre}",
                f"Claim mismatch: {a}",
                f"Code reality: {b}",
                f"File: {Path(src_a).name if src_a else '?'}:{line_a}",
                f"Impact: {impact}",
                f"Pre-synthesis red-team verdict: {s.get('redteam_verdict', 'unreviewed')}",
            ]
            if s.get("assertion_a_source"):
                lines.append(f"Assertion A source: {s['assertion_a_source']}")
            if src_b:
                lines.append(f"Behavior source: {src_b}:{line_b}")
            if s.get("check"):
                lines.append(f"Check: {s['check']}")
            if s.get("expected"):
                lines.append(f"Expected: {s['expected']}")
            if s.get("check_output"):
                lines.append(f"Check output: {s['check_output']}")
            if s.get("chain_output_candidates"):
                lines.append(
                    "Chain outputs: "
                    + ", ".join(str(v) for v in s["chain_output_candidates"])
                )
            if s.get("chain_preconditions"):
                lines.append(
                    "Chain preconditions: "
                    + ", ".join(str(v) for v in s["chain_preconditions"])
                )
            if s.get("m3_seam_state"):
                lines.append(
                    "Mindset-3 second seam: "
                    f"{s['m3_seam_state']} "
                    f"(sources: {', '.join(s.get('m3_seam_sources') or [])})"
                )
            lines.append("")
        return "\n".join(lines)

    def _corpus_selection_query(self) -> str:
        """Return the relevance query used to order corpus documents."""
        return "\n".join(
            [
                json.dumps(self.program, sort_keys=True),
                "\n".join(getattr(self, "_recon_hosts", [])),
                "\n".join(getattr(self, "_recon_endpoints", [])),
            ]
        )

    def skeleton_system(self) -> str:
        """Return the prompt without the sliced library for this mindset.

        Mitre slices its TTP library; paradox slices its verbatim
        corpus; seam is never sliced here (Mindset 3 batches by
        candidate instead). The skeleton is the mandatory base every
        lens pass must fit before any library slice is added.
        """
        if self.mindset == "paradox":
            return self._build(corpus_override="")
        if self.mindset == "mitre":
            return self._build(ttp_block_override="")
        return self.system_prompt()

    def system_prompt_slices(self, max_system_chars: int) -> List[str]:
        """Return system prompts delivering the full library in slices.

        Every selected TTP (mitre) or corpus document (paradox)
        appears in exactly one slice; the mandatory skeleton repeats
        on each. Nothing is dropped or truncated: a skeleton or single
        library unit that cannot fit raises instead. Returns
        [system_prompt()] unchanged when the full prompt already fits
        (and always for the seam mindset, which batches by candidate).
        """
        full = self.system_prompt()
        if len(full) <= max_system_chars or self.mindset in ("seam", "redteam"):
            return [full]
        skeleton = self.skeleton_system()
        block_budget = max_system_chars - len(skeleton) - 16
        if block_budget <= 0:
            raise RuntimeError(
                f"{self.mindset} lens skeleton alone is {len(skeleton)} "
                f"chars > slice budget {max_system_chars}; refusing to "
                "build a lens pass short its mandatory base"
            )
        slices: List[str] = []
        if self.mindset == "paradox":
            from oracle_corpus import source_context_chunks

            for chunk in source_context_chunks(
                self._corpus_selection_query(), block_budget
            ):
                slices.append(self._build(corpus_override=chunk))
        else:  # mitre: pack the effective TTP working set
            groups: List[List[Dict]] = []
            current: List[Dict] = []
            for record in self._selected_ttps(self._effective_ttp_mode()):
                candidate = current + [record]
                if len(self._render_ttp_block(candidate)) <= block_budget:
                    current = candidate
                    continue
                if current:
                    groups.append(current)
                    current = [record]
                    if len(self._render_ttp_block(current)) <= block_budget:
                        continue
                raise RuntimeError(
                    f"TTP {record.get('code', '?')} alone exceeds the "
                    f"lens slice block budget ({block_budget} chars)"
                )
            if current:
                groups.append(current)
            slices = [
                self._build(ttp_block_override=self._render_ttp_block(g))
                for g in groups
            ]
        for s in slices:
            if len(s) > max_system_chars:
                raise RuntimeError(
                    f"{self.mindset} lens slice is {len(s)} chars > "
                    f"slice budget {max_system_chars}"
                )
        return slices

    def _build(
        self,
        ttp_block_override: Optional[str] = None,
        corpus_override: Optional[str] = None,
    ) -> str:
        # Instruction hierarchy goes FIRST — before any untrusted program or
        # corpus data — so the model is pre-warned before it encounters
        # attacker-influenced content (program name, rules, recon text).
        from oracle_foundation import INSTRUCTION_HIERARCHY_REMINDER as _IER

        parts = [f"INSTRUCTION HIERARCHY: {_IER}"]

        # 1: system prompt (8 paradox→reflex worked examples) — all profiles.
        t = _read(_SYSTEM_PROMPT)
        if t:
            parts.append(t)

        # 1b: Embedded Red-Team Strike Directives per mindset
        if self.mindset == "mitre":
            parts.append(_MITRE_REDTEAM_DIRECTIVE)
        elif self.mindset == "paradox":
            parts.append(_PARADOX_REDTEAM_DIRECTIVE)
        elif self.mindset in ("seam", "redteam"):
            parts.append(_SEAM_REDTEAM_DIRECTIVE)

        # 2: framework philosophy — paradox profile only (mitre leans on MITRE).
        if self.mindset == "paradox":
            t = _read(_FRAMEWORK)
            if t:
                parts.append(t)

        if self.voice:
            for path in (_VOICE, _ALEX_VOICE):
                t = _read(path)
                if t:
                    parts.append(t)

        # Verbatim corpus — paradox profile only, full (cap lifted). The bundled
        # source documents teach the reasoning pattern; mitre omits them.
        if self.mindset == "paradox":
            from oracle_corpus import corpus_inventory, source_context

            parts.append("## SOURCE CONTEXT (verbatim corpus)")
            parts.append(corpus_inventory())
            corpus_text = (
                corpus_override
                if corpus_override is not None
                else source_context(
                    self._corpus_selection_query(), max_chars=320_000
                )
            )
            if corpus_text:
                parts.append(corpus_text)

        # 5: MITRE TTP fused layer — full (all 344 TTPs) for mitre by default;
        # paradox & seam get the compact reference UNLESS full was explicitly
        # requested, in which case every mindset receives the full library.
        ttp_block = (
            ttp_block_override
            if ttp_block_override is not None
            else self._ttp_block(mode=self._effective_ttp_mode())
        )
        if ttp_block:
            parts.append(ttp_block)

        # 6: Program brief — THIS IS THE SCOPE WALL
        brief = self._program_brief()
        if brief:
            parts.append(brief)

        # 6b: Live recon context — target-specific TTP seeds (GAP 5)
        recon_block = self._recon_context_block()
        if recon_block:
            parts.append(recon_block)

        # 7: Type-1 seams (code-only targets) — baked in after scope wall
        seam_block = self._seam_block()
        if seam_block:
            parts.append(seam_block)

        return "\n\n---\n\n".join(parts)

    # ── Bug type classification ────────────────────────────────────────────────

    @staticmethod
    def classify_seam(seam: Dict) -> str:
        """Guess a seam's bug family: TYPE_1 (code flaw) or TYPE_2 (logic flaw).

        This is a KEYWORD HEURISTIC, not a classifier: it counts domain
        words in the card text and has no structural basis (no AST, no
        data-flow, no model judgment). Conventions, stated so they are
        not mistaken for findings:
          - deterministic invisible-seam cards are TYPE_1 by construction;
          - ties — including zero signals either way — default TYPE_1;
          - lens-origin words (e.g. "paradox") are NOT signals.
        Consumed only for display labels, Wave-1 counts, and chain hints;
        never for verdicts. Do not cite the label as analysis.
        """
        corpus = " ".join(
            [
                seam.get("assertion_a", ""),
                seam.get("assertion_b", ""),
                seam.get("impact", ""),
                seam.get("reflex", ""),
                seam.get("mitre", ""),
                seam.get("origin", ""),
                seam.get("raw", ""),
            ]
        ).lower()

        # TYPE_1: code/contract signals
        type1_signals = [
            "cwe-",
            "null pointer",
            "null dereference",
            "type confusion",
            "hardcoded",
            "hard-coded credential",
            "insecure default",
            "return none",
            "implementation",
            "invisible-seam",
            "invisible_seam",
            "fixable",
            # NOTE (#21): the bare word "paradox" was a TYPE_1 signal until
            # it was cut — it matches lens-origin prose ("paradox lens"),
            # not code flaws.
            "ast",
            "code contract",
            "spec mismatch",
            "api_key leak",
            "secret in code",
            "buffer overflow",
            "use after free",
            "integer overflow",
            "injection",
            "sql injection",
            "xss",
            "command injection",
            "path traversal",
        ]
        # TYPE_2: logic/manipulation signals
        type2_signals = [
            "business logic",
            "price manipulat",
            "coupon",
            "discount",
            "role escalat",
            "privilege escalat",
            "state manipulat",
            "race condition",
            "toctou",
            "trust boundary",
            "idor",
            "bola",
            "insecure direct object",
            "authorization bypass",
            "auth bypass",
            "logic flaw",
            "workflow",
            "payment",
            "cart",
            "checkout",
            "order",
            "account takeover",
            "session fixation",
            "oauth",
            "redirect",
            "token replay",
            "mass assignment",
            "parameter pollution",
            "rate limit bypass",
        ]

        t1 = sum(1 for s in type1_signals if s in corpus)
        t2 = sum(1 for s in type2_signals if s in corpus)

        # Invisible seam origin is always TYPE_1
        if seam.get("origin") == "invisible-seam":
            return TYPE_1

        # Tie (including 0-0) defaults TYPE_1 by stated convention, not
        # evidence — see docstring. Callers must treat this as a guess.
        return TYPE_1 if t1 >= t2 else TYPE_2

    # ── Chain engine ──────────────────────────────────────────────────────────

    @staticmethod
    def chain_seams(confirmed: List[Dict]) -> List[Dict]:
        """
        Compose confirmed seams into chains where the output/state of one finding
        satisfies a prerequisite for another, elevating combined severity.

        Rules:
          - Only CONFIRMED seams compose (verdict == CONFIRMED).
          - A TYPE_1 info-leak can feed a TYPE_2 auth bypass (info → access).
          - A TYPE_2 low-value logic flaw can feed a TYPE_2 high-value manipulation.
          - Two binding vocabularies (#22):
            * model cards: the binding must be WIRE-GROUNDED — observed
              in A's captured output AND consumed in B's executed check
              or captured output. B merely declaring the value in card
              prose forms no edge.
            * deterministic cards (seam-template / web3 / invisible-seam):
              the _CHAIN_IO type vocabulary (endpoint/secret/...) composes
              by category between independently-confirmed findings — a
              typed link, not an observed shared value. The chain dict
              says which kind each edge is (edge_kinds).
          - Combined severity = max(individual) + 1 step if 2+ findings link,
            but never exceeds CRITICAL.
          - Chains are returned as separate dicts with type "chain".
          - Individual seams that chain are NOT removed — they are also submitted alone.

        Returns the input list (unchanged) PLUS new chain dicts appended.
        """
        if len(confirmed) < 2:
            return list(confirmed)

        def _norm_verdict(value: object) -> str:
            text = str(value or "").strip().upper()
            text = re.sub(r"^VERDICT\s*:\s*", "", text)
            return re.sub(r"[^A-Z0-9]+", "", text)

        def _negative_verdict(value: object, *, include_candidate: bool = False) -> bool:
            verdict = _norm_verdict(value)
            if include_candidate and verdict.startswith("CANDIDATE"):
                return True
            return verdict.startswith(
                (
                    "REJECT",
                    "INCONCLUSIVE",
                    "UNREVIEWED",
                    "UNVERIFIED",
                    "NOTVERIFIED",
                    "NOTCONFIRMED",
                    "UNCONFIRMED",
                    "PENDING",
                    "FALSE",
                    "DISPROVEN",
                    "FAIL",
                    "TEARDOWNFAILED",
                )
            )

        def _is_confirmed(entry: object) -> bool:
            if not isinstance(entry, dict):
                return False
            seam = entry.get("seam", entry)
            if not isinstance(seam, dict):
                seam = {}
            # A present confirmed flag must be canonically true. Absence
            # is the legacy assumed-confirmed input shape used by golden
            # and gauntlet callers, whose list itself is the confirmed set.
            for source in (entry, seam):
                if "confirmed" not in source:
                    continue
                value = source.get("confirmed")
                if value is True:
                    continue
                if isinstance(value, str) and value.strip().lower() in {
                    "true",
                    "confirmed",
                    "yes",
                    "1",
                }:
                    continue
                return False
            # Check each verdict field independently: a positive wrapper
            # verdict cannot mask a negative verify verdict. Nested
            # template CANDIDATE is a pre-verify card state and remains
            # exempt inside an already-confirmed wrapper; nested explicit
            # negatives are not exempt.
            if _negative_verdict(entry.get("verdict"), include_candidate=True):
                return False
            if _negative_verdict(entry.get("verify_verdict"), include_candidate=True):
                return False
            if _negative_verdict(seam.get("verify_verdict"), include_candidate=True):
                return False
            if _negative_verdict(seam.get("verdict")):
                return False
            return True

        eligible = [entry for entry in confirmed if _is_confirmed(entry)]
        # The same finding duplicated in the input is one finding, not a
        # two-hop chain. Verify results are keyed by seam number, so n is
        # the production identity when present.
        _seen_findings: Set[Tuple[str, str]] = set()
        _deduped = []
        for entry in eligible:
            seam = entry.get("seam", entry)
            if not isinstance(seam, dict):
                seam = {}
            n = seam.get("n")
            if n is not None:
                key = ("n", str(n))
            else:
                key = (
                    "fp",
                    json.dumps(seam, sort_keys=True, default=str, ensure_ascii=False),
                )
            if key in _seen_findings:
                continue
            _seen_findings.add(key)
            _deduped.append(entry)
        eligible = _deduped
        if len(eligible) < 2:
            return list(confirmed)

        def _values(value: object) -> Set[str]:
            if not isinstance(value, list):
                return set()
            return {str(item).strip() for item in value if str(item).strip()}

        def _canonical_rank(raw: object) -> Optional[int]:
            # Only plain strings carry a canonical severity. Containers,
            # bytes, and numbers are unparseable, never string-scanned.
            if not isinstance(raw, str):
                return None
            # Any negation/mitigation marker anywhere in a structured
            # severity fails closed, even across clause separators
            # ("patched: critical" must not survive as "critical").
            if _STRUCTURED_NEGATION_RE.search(_normalize_apostrophes(raw)):
                return None
            text = (
                _strip_negated_severity(raw).strip().lower().replace("_", " ")
            )
            if not text:
                return None
            aliases = {
                "moderate": "medium",
                "med": "medium",
                "informational": "info",
                "information": "info",
            }
            exact = aliases.get(text, text)
            if exact in SEVERITY_RANK:
                return SEVERITY_RANK[exact]
            for token in (
                "critical",
                "high",
                "medium",
                "moderate",
                "med",
                "low",
                "info",
            ):
                if re.search(rf"\b{token}\b", text):
                    return SEVERITY_RANK[aliases.get(token, token)]
            if re.search(r"\binformational\b|\binformation\b", text):
                return SEVERITY_RANK["info"]
            return None

        def _rank_entry(entry: Dict, seam: Dict) -> int:
            for raw in (seam.get("severity"), entry.get("severity")):
                if raw is None or (isinstance(raw, str) and not raw.strip()):
                    continue
                # A present structured severity decides. Unparseable or
                # fully-negated values fail closed at 0, never fall
                # through to free-text impact ranking.
                rank = _canonical_rank(raw)
                return rank if rank is not None else 0
            return _parse_severity(str(seam.get("impact", "") or ""))

        # A valid edge binds an output of A to a precondition of B. Model
        # cards bind on wire literals: B must demonstrably CONSUME the
        # value (executed check / captured output), not merely declare it
        # in card prose (#22). Deterministic cards bind on the _CHAIN_IO
        # type vocabulary instead — category labels, never wire text —
        # so grounding them against the wire would be a category error.
        # Keyword similarity is not evidence in either vocabulary.
        def _contains_exact(text: str, value: str) -> bool:
            if not text or not value:
                return False
            pattern = rf"(?<![A-Za-z0-9_-]){re.escape(value)}(?![A-Za-z0-9_-])"
            return re.search(pattern, text) is not None

        def _observed_text(entry: Dict, seam: Dict) -> Tuple[str, bool]:
            parts: List[str] = []
            for source in (entry, seam):
                for field in ("output", "check_output", "wire_output", "evidence"):
                    value = source.get(field)
                    if value:
                        parts.append(str(value))
            return "\n".join(parts), bool(parts)

        links: List[Tuple[int, int, Set[str], str]] = []  # (a, b, binds, kind)
        for i, sa in enumerate(eligible):
            for j, sb in enumerate(eligible):
                if i == j:
                    continue
                sa_s = sa.get("seam", sa)
                sb_s = sb.get("seam", sb)
                outputs = _values(sa.get("chain_outputs") or sa_s.get("chain_outputs"))
                needs = _values(
                    sb.get("chain_preconditions") or sb_s.get("chain_preconditions")
                )
                a_origin = str(sa_s.get("origin") or "")
                b_origin = str(sb_s.get("origin") or "")
                kind = (
                    "typed"
                    if a_origin in _CHAIN_TYPED_ORIGINS
                    and b_origin in _CHAIN_TYPED_ORIGINS
                    else "wire"
                )
                if needs and kind == "wire":
                    a_wire, has_a_wire = _observed_text(sa, sa_s)
                    if has_a_wire:
                        outputs = {
                            v for v in outputs if _contains_exact(a_wire, v)
                        }
                    b_parts = [
                        str(sb.get("output") or ""),
                        str(sb.get("check_output") or ""),
                    ]
                    if "check" in sb:
                        # The executed wrapper check controls consumption
                        # (even when empty); the card's declared check
                        # cannot resurrect it.
                        b_parts.append(str(sb.get("check") or ""))
                    else:
                        b_parts.extend(
                            str(sb_s.get(f) or "")
                            for f in ("check", "check_output", "output")
                        )
                    b_wire = "\n".join(b_parts)
                    needs = {v for v in needs if _contains_exact(b_wire, v)}
                bindings = outputs & needs
                if bindings:
                    links.append((i, j, bindings, kind))

        if not links:
            return list(confirmed)

        # Build MAXIMAL chains recursively: little -> bigger -> even bigger.
        # Walk edges from source nodes (no incoming edge), keep the longest path
        # through each; severity steps up once per additional link, capped Critical.
        from collections import defaultdict

        adj: Dict[int, List[Tuple[int, Set[str], str]]] = defaultdict(list)
        for i, j, b, k in links:
            adj[i].append((j, b, k))
        has_incoming = {j for (_, j, _, _) in links}
        linked = {i for (i, _, _, _) in links} | has_incoming
        roots = [i for i in sorted(linked) if i not in has_incoming] or sorted(linked)

        maximal: List[Tuple[List[int], List[Set[str]], List[str]]] = []
        _walk_budget = [0]
        _MAX_WALKS = 20_000
        _MAX_CHAINS = 512

        def _walk(path: List[int], binds: List[Set[str]], kinds: List[str]) -> None:
            _walk_budget[0] += 1
            if _walk_budget[0] > _MAX_WALKS or len(maximal) >= _MAX_CHAINS:
                return
            cur = path[-1]
            nxt = [(j, b, k) for (j, b, k) in adj.get(cur, []) if j not in path]
            nxt.sort(
                key=lambda item: _rank_entry(
                    eligible[item[0]], eligible[item[0]].get("seam", eligible[item[0]])
                ),
                reverse=True,
            )
            if not nxt:
                if len(path) >= 2:
                    maximal.append((path, binds, kinds))
                return
            for j, b, k in nxt:
                _walk(path + [j], binds + [b], kinds + [k])
                if _walk_budget[0] > _MAX_WALKS or len(maximal) >= _MAX_CHAINS:
                    return

        for r in roots:
            _walk([r], [], [])
            if _walk_budget[0] > _MAX_WALKS or len(maximal) >= _MAX_CHAINS:
                break

        # Keep only truly maximal chains (drop any whose nodes are a subset of a
        # longer chain's), longest first.
        maximal.sort(key=lambda pbk: len(pbk[0]), reverse=True)
        kept: List[Tuple[List[int], List[Set[str]], List[str]]] = []
        seen_sets: List[Set[int]] = []
        for path, binds, kinds in maximal:
            ps = set(path)
            if any(ps <= s for s in seen_sets):
                continue
            kept.append((path, binds, kinds))
            seen_sets.append(ps)

        _SEV = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Low"}

        chains = []
        for path, binds, kinds in kept:
            seams_seq = [eligible[idx] for idx in path]
            sseq = [s.get("seam", s) for s in seams_seq]
            ranks = [_rank_entry(wrapper, seam) for wrapper, seam in zip(seams_seq, sseq)]
            # One compounding step for a complete chain. Depth alone must
            # not manufacture Critical from repeated Low findings.
            combined_rank = min(max(ranks) + 1, 4)
            nums = [s.get("n", idx + 1) for s, idx in zip(sseq, path)]
            all_binds = sorted(set().union(*binds)) if binds else []
            edge_kinds = sorted(set(kinds))
            if edge_kinds == ["wire"]:
                _link_claim = (
                    "Each link's captured output contains a value the next "
                    "link's executed check/output consumed "
                    f"({', '.join(all_binds)})"
                )
            elif edge_kinds == ["typed"]:
                _link_claim = (
                    "Links compose independently-confirmed findings by "
                    "deterministic type vocabulary "
                    f"({', '.join(all_binds)}) — category composition, not "
                    "an observed shared value"
                )
            else:
                _link_claim = (
                    "Links include both wire-observed bindings and "
                    "deterministic category composition "
                    f"({', '.join(all_binds)}); only wire links are observed "
                    "shared values"
                )
            chains.append(
                {
                    "type": "chain",
                    "links": nums,
                    "depth": len(path),
                    "combined_severity": _SEV[combined_rank],
                    "edge_kinds": edge_kinds,
                    "chain_assertion_a": " → ".join(
                        f"[F{n}] {s.get('assertion_a', '')[:40]}"
                        for n, s in zip(nums, sseq)
                    ),
                    "chain_assertion_b": (
                        f"{_link_claim} — compounding to {_SEV[combined_rank]}."
                    ),
                    "chain_impact": (
                        "Attacker chains "
                        + " then ".join(f"Finding {n}" for n in nums)
                        + f": {sseq[-1].get('impact', '')}"
                    ),
                    "edge_bindings": all_binds,
                    "check_sequence": [s.get("check", "") for s in sseq],
                    "seams": seams_seq,
                }
            )

        chains.sort(
            key=lambda c: (
                SEVERITY_RANK.get(str(c.get("combined_severity", "")).lower(), 0),
                c.get("depth", len(c.get("links", []))),
            ),
            reverse=True,
        )
        _seen_links: Set[Tuple[object, ...]] = set()
        _unique_chains = []
        for chain in chains:
            key = tuple(chain.get("links", []))
            if key in _seen_links:
                continue
            _seen_links.add(key)
            _unique_chains.append(chain)
        return list(confirmed) + _unique_chains


def _normalize_apostrophes(text: str) -> str:
    return str(text or "").replace("’", "'").replace("‘", "'")


_NEGATED_SEVERITY_RE = re.compile(
    r"\b(?:not|no|never|without|cannot|can\s+not|can'?t|cant|doesn'?t|"
    r"isn'?t|aren'?t|wasn'?t|weren'?t|unable|non[-\s]?critical|"
    r"non[-\s]?exploitable|prevent\w*|block\w*|patch\w*|mitigat\w*|"
    r"unlikely|previously|formerly)\b",
    re.IGNORECASE,
)

# Structured severities are short fields, so a broader marker set is safe
# there (words like "was"/"fixed" would be too greedy in prose impacts).
_STRUCTURED_NEGATION_RE = re.compile(
    r"\b(?:not|no|never|without|cannot|can\s+not|can'?t|cant|doesn'?t|"
    r"isn'?t|aren'?t|wasn'?t|weren'?t|unable|non[-\s]?critical|"
    r"non[-\s]?exploitable|prevent\w*|block\w*|patch\w*|mitigat\w*|"
    r"fix|fixed|fixes|resolved|remediat\w*|unlikely|improbable|"
    r"previously|formerly|historically|was)\b",
    re.IGNORECASE,
)


def _strip_negated_severity(text: str) -> str:
    """Drop clauses whose severity claim is negated.

    This deliberately fails closed: if a clause mixes negation with a
    positive severity term, the whole clause is ignored for ranking.
    Structured severity remains the preferred signal.
    """
    clauses = re.split(r"[.;\n]+", _normalize_apostrophes(str(text or "")))
    return " ".join(
        clause.strip()
        for clause in clauses
        if clause.strip() and not _NEGATED_SEVERITY_RE.search(clause)
    )


def _parse_severity(impact_text: str) -> int:
    """Extract a severity rank 0-4 from free-form impact text.

    Unknown text fails closed at info rank. Keyword matching is
    word-bounded and ignores negated severity clauses.
    """
    t = _strip_negated_severity(str(impact_text or "")).lower()
    if re.search(r"\bcritical\b|\baccount takeover\b|\brce\b|\bremote code\b", t):
        return 4
    if re.search(r"\bhigh\b|\bdata exposure\b|\bprivilege\b|\bfull access\b", t):
        return 3
    if re.search(r"\bmedium\b|\bmoderate\b|\bpartial\b|\blimited\b", t):
        return 2
    if re.search(r"\blow\b|\bminor\b", t):
        return 1
    if re.search(r"\binfo(?:rmational|rmation)?\b", t):
        return 0
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# ProgramWorkspace — organized on-disk target folder
# ──────────────────────────────────────────────────────────────────────────────

SCHEMA_VERSION = 2


def _local_credential_scrub(text: Any) -> str:
    """Standalone mirror of hunter display redaction for disk writers."""
    red = str(text or "").replace(r"\"", '"').replace(r"\'", "'")
    red = re.sub(
        r"((?:-H|--header)\s*[\"'](?:Authorization|Cookie):\s*)[^\"']+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    red = re.sub(
        r"((?:-H|--header)\s+(?:Authorization|Cookie):\s*)\S+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    red = re.sub(
        r"((?:Authorization|Cookie):\s*(?:Bearer\s+|Basic\s+)?)[^\s\"']+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    red = re.sub(
        r"((?:-u|--user)\s+)[^\"'\s]+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    red = re.sub(
        r"([?&](?:api_key|apikey|access_token|auth_token|client_secret|token|secret|key|auth)=)[^&\"'\s]+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    red = re.sub(
        r"(\b(?:Bearer|Basic)\s+)[^\s\"']+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    return red


def _clean_persisted_value(value: Any) -> Any:
    """Recursively scrub keys and scalar coercions before JSON hits disk."""
    try:
        from oracle_hunter import _redact_creds as _hunter_scrub
    except Exception:
        _hunter_scrub = None

    def clean_text(text: str) -> str:
        cleaned = text
        if _hunter_scrub is not None:
            try:
                cleaned = _hunter_scrub(cleaned)
            except Exception:
                pass
        return _local_credential_scrub(cleaned)

    def rec(item: Any, seen: Set[int]) -> Any:
        if isinstance(item, str):
            return clean_text(item)
        if isinstance(item, (bytes, bytearray)):
            return clean_text(bytes(item).decode("utf-8", errors="replace"))
        if item is None or isinstance(item, (bool, int, float)):
            return item
        if isinstance(item, dict):
            marker = id(item)
            if marker in seen:
                return "[CYCLE]"
            seen.add(marker)
            try:
                out = {}
                for key, child in item.items():
                    if isinstance(key, (bytes, bytearray)):
                        clean_key = clean_text(
                            bytes(key).decode("utf-8", errors="replace")
                        )
                    else:
                        clean_key = clean_text(str(key))
                    out[clean_key] = rec(child, seen)
                return out
            finally:
                seen.remove(marker)
        if isinstance(item, (list, tuple)):
            marker = id(item)
            if marker in seen:
                return "[CYCLE]"
            seen.add(marker)
            try:
                return [rec(child, seen) for child in item]
            finally:
                seen.remove(marker)
        if isinstance(item, (set, frozenset)):
            return sorted((rec(child, seen) for child in item), key=repr)
        return clean_text(str(item))

    return rec(value, set())


def _raw_get(
    url: str, timeout: int = 15, redirect_validator: Optional[Callable[[str], bool]] = None
) -> str:
    """Plain HTTP GET, raw bytes as text. Companion to the rendered
    provider chain: harvest needs comment- and tag-verbatim bodies.
    Returns "" on any failure (the caller records it explicitly)."""
    import urllib.request

    if not url.startswith(("http://", "https://")):
        return ""
    if redirect_validator and not redirect_validator(url):
        return ""

    class _ValidatedRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if redirect_validator and not redirect_validator(newurl):
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    req = urllib.request.Request(url, headers={"User-Agent": "Oracle/1.0"})
    try:
        opener = urllib.request.build_opener(_ValidatedRedirect)
        with opener.open(req, timeout=timeout) as resp:  # nosec B310
            return resp.read(500_000).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _spec_doc_urls(urls: List[str]) -> List[str]:
    """Common API-doc endpoints on each origin (scheme+host+port kept).

    Origins — not bare domains — so lab targets keep their http scheme
    and port instead of degrading to https://host/.
    """
    origins = set()
    for u in urls:
        m = re.search(r"(https?://[\w.\-]+(?::\d+)?)", u or "")
        if m:
            origins.add(m.group(1).rstrip("/"))
    out = []
    for origin in sorted(origins):
        for path in [
            "/openapi.json",
            "/swagger.json",
            "/api-docs",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/.well-known/security.txt",
            "/robots.txt",
        ]:
            out.append(f"{origin}{path}")
    return out


def bug_key_for(seam: Dict) -> str:
    """Stable cross-target identity for a finding (schema v2).

    The same bug shape on a different host MUST produce the same key, so
    the check is host-normalized before hashing: URL authorities collapse
    to <HOST>, bare IPv4 literals to <IP>. bug_type and assertion_b stay
    raw — the key matches same-shape bugs; the recurrence checker does
    fuzzy follow-up across targets.
    """
    check = str(seam.get("check", ""))
    norm = re.sub(r"https?://[^/\s'\"]+", "<HOST>", check)
    norm = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", "<IP>", norm)
    raw = "\0".join(
        [str(seam.get("bug_type", "")), norm, str(seam.get("assertion_b", ""))]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ProgramWorkspace:
    """
    Manage the on-disk workspace for a single bug bounty program.

    Layout:
        targets/<platform>/<slug>/
            program.json         — full program dict from oracle_programs
            program_brief.md     — human-readable scope + rules
            site.log             — JSONL event log for this site (schema v2)
            assets/              — downloaded JS, HTML, API docs, OpenAPI specs
                index.html
                *.js
                openapi.json / swagger.json
                api_docs.md
            recon/               — all recon tool output (subfinder, httpx, etc.)
            findings/            — one JSON per seam + one .xref.json per bug
            reports/             — final submission reports
    """

    def __init__(self, program: Dict, base: Optional[Path] = None):
        self.program = program
        self.platform = _safe_workspace_component(program.get("platform", "unknown"))
        self.slug = _safe_workspace_component(
            program.get("name", "unknown"), lower=True, max_chars=60
        )
        _root = base or (_HERE / "targets")
        _candidate = _root / self.platform / self.slug
        # Defense in depth: component sanitization should already make
        # escape impossible, but never create outside the chosen root.
        self.base = (
            _candidate if _candidate.is_relative_to(_root) else _root / "unknown" / "unknown"
        )
        self.base.mkdir(parents=True, exist_ok=True)
        for sub in ("assets", "recon", "findings", "reports"):
            (self.base / sub).mkdir(exist_ok=True)

    @property
    def assets_dir(self) -> Path:
        return self.base / "assets"

    @property
    def recon_dir(self) -> Path:
        return self.base / "recon"

    @property
    def findings_dir(self) -> Path:
        return self.base / "findings"

    @property
    def reports_dir(self) -> Path:
        return self.base / "reports"

    def save_program_json(self) -> Path:
        out = self.base / "program.json"
        if out.exists():
            try:
                existing = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                existing = {}
            if not isinstance(existing, dict):
                existing = {}
            old_scopes = existing.get("structured_scopes") or []
            new_scopes = (self.program or {}).get("structured_scopes") or []
            if old_scopes and not new_scopes:
                print(
                    f"REFUSING to overwrite scoped {out} with a scopeless "
                    f"record ({len(old_scopes)} scopes preserved). "
                    "Re-fetch scopes instead of saving not-fetched intake."
                )
                return out
        out.write_text(
            json.dumps(self.program, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return out

    def save_hunt_scope(self, hunt_prog: Dict) -> Path:
        """Persist the FILTERED phase-1 program (apply_hunt_filter output).

        program.json always holds the full program (downloads, re-intake,
        and the phase-2 sweep need every asset). hunt_scope.json holds the
        filtered world the phase-1 model is allowed to see; scope-filtered
        readers (asset context, brief disk sections, code lens) consult it.
        """
        out = self.base / "hunt_scope.json"
        out.write_text(
            json.dumps(hunt_prog, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return out

    def load_hunt_scope(self) -> Optional[Dict]:
        """Return the saved filtered program, or None when absent."""
        p = self.base / "hunt_scope.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None

    def save_program_brief(self, ctx: "OracleMindsetContext") -> Path:
        """Write a human-readable program brief using the context."""
        brief = ctx._program_brief()
        out = self.base / "program_brief.md"
        out.write_text(brief, encoding="utf-8")
        return out

    @property
    def site_log_path(self) -> Path:
        return self.base / "site.log"

    @property
    def log_of_logs_path(self) -> Path:
        """Upward aggregation file. Real tree: targets/_log_of_logs.jsonl.

        Custom bases (tests, lab runs) fall back to a local file next to
        the workspace so they never pollute the real tree.
        """
        root = self.base.parent.parent
        if root.name == "targets":
            return root / "_log_of_logs.jsonl"
        return self.base / "_log_of_logs.jsonl"

    def log_site_event(self, event: str, data: Optional[Dict] = None) -> None:
        """Append one JSONL event to this site's log."""
        from datetime import datetime, timezone

        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **(data or {}),
        }
        with self.site_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    def _next_finding_n(self) -> int:
        nums = []
        for p in self.findings_dir.glob("finding_*.json"):
            if p.name.endswith(".xref.json"):
                continue
            m = re.fullmatch(r"finding_(\d+)\.json", p.name)
            if m:
                nums.append(int(m.group(1)))
        return (max(nums) + 1) if nums else 1

    def save_finding(self, seam: Dict, evidence: str = "") -> Path:
        n = seam.get("n") or self._next_finding_n()
        out = self.findings_dir / f"finding_{n:03d}.json"
        key = bug_key_for(seam)
        xref_name = f"finding_{n:03d}.xref.json"
        # Step-2 output hardening: the writer is the last trusted boundary
        # before disk. Scrub credential-header shapes from every persisted
        # string even when a caller forgot (exact-value scrubbing of
        # reflected secrets remains the caller's duty — hunter S6).
        _clean = _clean_persisted_value

        data = {
            **_clean(dict(seam)),
            "n": n,
            "schema_version": SCHEMA_VERSION,
            "bug_key": key,
            "site_log": self.site_log_path.name,
            "xref": f"findings/{xref_name}",
            "evidence_snippet": _clean(evidence[:500]),
        }
        payload = json.dumps(data, indent=2, ensure_ascii=False)
        out.write_text(payload, encoding="utf-8")
        xref = {
            "finding": out.name,
            "bug_key": key,
            "schema_version": SCHEMA_VERSION,
            "checked_at": None,
            "same_company_elsewhere": [],
            "same_platform_others": [],
            "other_platforms": [],
        }
        (self.findings_dir / xref_name).write_text(
            json.dumps(xref, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self.log_site_event(
            "finding_saved",
            {
                "finding": out.name,
                "bug_key": key,
                "n": n,
                "verdict": str(seam.get("verify_verdict", "")),
            },
        )
        self._append_log_of_logs(out.name, key)
        return out

    def _append_log_of_logs(self, finding: str, key: str) -> None:
        from datetime import datetime, timezone

        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "platform": self.platform,
            "slug": self.slug,
            "finding": finding,
            "bug_key": key,
        }
        with self.log_of_logs_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    def save_seam_snapshot(
        self,
        seams: List[Dict],
        *,
        stage: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Persist candidate seams before an engine-dependent phase.

        Synthesis and verification can die on provider/context failures;
        that must not erase the deterministic and lens evidence already
        produced. The snapshot is diagnostics, not a verdict: every seam
        remains a candidate until a downstream verifier judges it.
        """
        from datetime import datetime, timezone

        _clean = _clean_persisted_value

        clean_seams = [
            _clean(dict(s)) if isinstance(s, dict) else {"_non_dict_seam": _clean(s)}
            for s in (seams or [])
        ]
        stage_slug = re.sub(
            r"[^a-z0-9_.-]+",
            "_",
            str(_clean(str(stage or "snapshot"))).strip().lower(),
        ).strip("._") or "snapshot"
        payload = {
            "schema_version": SCHEMA_VERSION,
            "stage": stage_slug,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "program": {
                "name": _clean(self.program.get("name", "")),
                "platform": _clean(self.program.get("platform", "")),
                "handle": _clean(self.program.get("handle", "")),
                "url": _clean(self.program.get("url", "")),
                "website": _clean(self.program.get("website", "")),
            },
            "seam_count": len(clean_seams),
            "seams": clean_seams,
            "meta": _clean(dict(meta or {})),
        }
        out = self.reports_dir / f"seam_snapshot_{stage_slug}.json"
        tmp = out.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        tmp.replace(out)
        self.log_site_event(
            "seam_snapshot_saved",
            {"stage": stage_slug, "seams": len(clean_seams), "file": out.name},
        )
        return out

    def save_report(self, report_text: str, label: str = "") -> Path:
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        fn = f"report_{label}_{ts}.md" if label else f"report_{ts}.md"
        out = self.reports_dir / fn
        out.write_text(report_text, encoding="utf-8")
        return out

    def download_assets(
        self, cdp_port: int = 9227, timeout: int = 15, max_urls: int = 160
    ) -> List[str]:
        """
        Download scope page sources, JS endpoints, and OpenAPI specs into assets/.
        Uses CDP (logged-in Chrome) for JS-heavy pages.
        Returns list of saved filenames.
        """
        saved = []
        urls = self._collect_asset_urls()
        manifest: Dict[str, str] = {}
        try:
            manifest = json.loads(
                (self.assets_dir / "_manifest.json").read_text(encoding="utf-8")
            )
        except Exception:
            manifest = {}

        if max_urls <= 0:
            raise ValueError("max_urls must be positive")
        for url in urls[:max_urls]:
            filename = _url_to_filename(url)
            out = self.assets_dir / filename
            if out.exists():
                saved.append(filename)
                manifest.setdefault(filename, url)
                continue

            content = self._fetch_asset(url, cdp_port=cdp_port, timeout=timeout)
            if content and len(content) > 100:
                out.write_text(content[:500_000], encoding="utf-8", errors="replace")
                saved.append(filename)
                manifest[filename] = url
                raw_name = out.stem + ".raw.html"
                raw_out = self.assets_dir / raw_name
                if not raw_out.exists():
                    raw = _raw_get(
                        url, timeout=timeout, redirect_validator=self._asset_url_allowed
                    )
                    if raw and len(raw) > 100:
                        raw_out.write_text(
                            raw[:500_000], encoding="utf-8", errors="replace"
                        )
                        saved.append(raw_name)
                        manifest[raw_name] = url
                    else:
                        self.program.setdefault("raw_asset_failures", []).append(url)

        # filename → source URL so scope-filtered readers can attribute
        # each downloaded file to its asset without guessing from names.
        try:
            (self.assets_dir / "_manifest.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
        self.program["asset_status"] = "assets-downloaded" if saved else "no-assets"
        self.program["asset_count"] = len(saved)
        return saved

    def _collect_asset_urls(self) -> List[str]:
        """Build a list of URLs worth downloading for this program."""
        prog = self.program
        urls = []

        # Primary program URL
        if prog.get("url"):
            urls.append(prog["url"])

        def add_web_identifier(identifier: str, asset_type: str = "") -> None:
            """Add a concrete web scope without turning wildcard patterns into URLs."""
            ident = (identifier or "").strip()
            if (
                not ident
                or ident.startswith("*.")
                or asset_type.upper() in {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"}
            ):
                return
            if re.fullmatch(r"https?://[^\s/]+(?:/.*)?", ident, re.IGNORECASE):
                urls.append(ident)
                return
            # Bare domains are common scope records. They are real websites,
            # unlike mobile IDs or wildcard patterns, and should be intaken.
            if (
                re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", ident, re.IGNORECASE)
                and "." in ident
            ):
                urls.append(f"https://{ident}")

        # Scope assets can be concrete URLs, bare domains, or wildcard patterns.
        # Wildcards stay recon-only until a concrete subdomain is discovered.
        for s in prog.get("structured_scopes", []):
            if isinstance(s, dict):
                add_web_identifier(
                    s.get("asset_identifier", ""), s.get("asset_type", "")
                )

        for field in ("scope", "targets"):
            scope = prog.get(field, "")
            if isinstance(scope, str):
                for line in scope.splitlines():
                    add_web_identifier(line)
            elif isinstance(scope, list):
                for identifier in scope:
                    if isinstance(identifier, str):
                        add_web_identifier(identifier)

        # Stable de-duplication prevents a scope mirrored between structured
        # and free-text forms from consuming the intake budget twice.
        urls = list(dict.fromkeys(urls))

        urls.extend(_spec_doc_urls(urls))

        return list(dict.fromkeys(urls))

    def _asset_url_allowed(self, candidate: str) -> bool:
        """Allow only scope-approved URLs that resolve to public addresses."""
        from oracle_hunter import ProgramScopeGate

        gate = ProgramScopeGate(
            self.program, target_fallback=str(self.program.get("url") or "")
        )
        in_scope, reason = gate.is_in_scope(candidate)
        if not in_scope:
            return False
        try:
            host = urlparse(candidate).hostname
            if not host:
                return False
            if "local testbench allowed" in reason:
                return True
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
            return bool(addresses) and all(
                ipaddress.ip_address(address).is_global for address in addresses
            )
        except (OSError, ValueError):
            return False

    def _fetch_asset(self, url: str, cdp_port: int = 9227, timeout: int = 15) -> str:
        """Fetch an in-scope URL via CDP, Firecrawl, then plain HTTP.

        ``oracle_programs._fetch`` owns this shared provider chain. It honors
        ``FIRECRAWL_API_KEY`` and the process-wide ``--no-cloud`` switch, so
        intake benefits from rendered content without widening the target set.
        """
        try:
            from oracle_programs import _fetch
            return _fetch(
                url,
                timeout=timeout,
                use_cdp=False,
                redirect_validator=self._asset_url_allowed,
            )
        except Exception:
            pass

        # Keep a local fallback for standalone use when oracle_programs cannot
        # be imported. The shared path above is used in normal hunts.
        # Try CDP
        try:
            import urllib.request as _ur
            import json as _json
            import websocket  # type: ignore
            import time as _t

            tabs_raw = _ur.urlopen(
                f"http://localhost:{cdp_port}/json", timeout=3
            ).read()  # nosec B310
            tabs = _json.loads(tabs_raw)
            page_tab = next((t for t in tabs if t.get("type") == "page"), None)
            if page_tab and page_tab.get("webSocketDebuggerUrl"):
                ws = websocket.create_connection(
                    page_tab["webSocketDebuggerUrl"], timeout=10
                )
                ws.send(
                    _json.dumps(
                        {"id": 1, "method": "Page.navigate", "params": {"url": url}}
                    )
                )
                _t.sleep(min(timeout, 6))
                ws.send(
                    _json.dumps(
                        {
                            "id": 2,
                            "method": "Runtime.evaluate",
                            "params": {
                                "expression": "document.body.innerText",
                                "returnByValue": True,
                            },
                        }
                    )
                )
                while True:
                    msg = _json.loads(ws.recv())
                    if msg.get("id") == 2:
                        val = msg.get("result", {}).get("result", {}).get("value", "")
                        ws.close()
                        if val and len(val) > 50:
                            return val
                        break
        except Exception:
            pass

        # Plain requests fallback
        try:
            import requests as _req

            r = _req.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; OracleAssetFetch/1.0)"
                },
                timeout=timeout,
                allow_redirects=True,
            )
            if r.ok:
                return r.text
        except Exception:
            pass

        return ""


def _url_to_filename(url: str) -> str:
    """Turn a URL into a safe filename."""
    clean = re.sub(r"https?://", "", url)
    clean = re.sub(r"[^\w.\-/]", "_", clean)
    clean = clean.strip("/_").replace("/", "__")[:120]
    if not clean:
        clean = "asset"
    # give it an extension hint
    if ".json" in url:
        return clean + ".json" if not clean.endswith(".json") else clean
    if ".js" in url:
        return clean + ".js" if not clean.endswith(".js") else clean
    return clean + ".txt"


# ── hunt-scope filtering for disk-derived brief sections (M2) ───────────────
def _kept_hosts_of(prog: Dict) -> Optional[Set[str]]:
    """kept_hosts from apply_hunt_filter metadata, or None when no filter
    is active (standalone use — list everything, as before)."""
    meta = (prog or {}).get("_hunt_filter") or {}
    hosts = meta.get("kept_hosts")
    return set(hosts) if hosts else None


def _kept_repos_of(prog: Dict) -> Optional[Set[str]]:
    """owner_repo dir names among kept idents, or None when no filter active."""
    meta = (prog or {}).get("_hunt_filter") or {}
    if "kept_idents" not in meta:
        return None
    repos: Set[str] = set()
    for ident in meta.get("kept_idents") or []:
        m = re.search(r"github\.com/([\w.\-]+)/([\w.\-]+)", str(ident))
        if m:
            repos.add(f"{m.group(1)}_{m.group(2)}".lower())
    return repos


def _manifest_of(assets_dir: Path) -> Dict[str, str]:
    try:
        return json.loads((assets_dir / "_manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def _downloaded_file_host(filename: str, manifest: Dict[str, str]) -> Optional[str]:
    """Attribute a downloaded asset file to its source host.

    Uses the download manifest when present; falls back to reversing the
    _url_to_filename scheme (host is the leading segment before "__").
    """
    url = manifest.get(filename)
    if url:
        try:
            return (urlparse(url).hostname or "").lower().rstrip(".") or None
        except Exception:
            pass
    stem = filename.split("__")[0]
    for ext in (".json", ".html", ".htm", ".js", ".txt"):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    return stem.lower().rstrip(".") or None
