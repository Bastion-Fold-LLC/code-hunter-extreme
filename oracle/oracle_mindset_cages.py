#!/usr/bin/env python3
# LAYER: think
# DEST: vortex
# ENDPOINTS: validate_mindset_card, admit_seam_card, resolve_mindset_pools
# TOPICS: none
"""Mindset cages — structural enforcement for OmniCLI output.

User architecture (2026-10-21): a mindset is never a suggestion for the
model; it is a CAGE. OmniCLI may only produce cards that satisfy the
mindset's cage: required fields, frame identity, observation basis, wire
prediction, rule compliance — or the card does not exist.

Three cages:
  * mitre     — technique-indexed (T-code required on the face)
  * paradox   — philosophy frames: paradox / impossible / iphone
  * synthesis — M3: must merge both parent mindsets

And the parallel execution law: provider lanes are assigned by config —
roughly half caged into M1, half into M2, all converging on M3.

CONTRACT STATUS (E1.2b): validate/admit are wired into cmd_hunt's M1/M2
lens parse path (initial pass and retry ladder): such cards enter the
deck only with a cage receipt. NOT yet wired: Mindset-3 synthesis
admission, deterministic template producers, and the standalone analyze
path. No live hunt has run against a caged build yet.
"""

import re
import shlex
import urllib.parse
from typing import Dict, List, Optional, Tuple

VALID_FRAMES = ("paradox", "impossible", "iphone")
VALID_CAGES = ("mitre", "paradox", "synthesis")

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_TECHNIQUE_LEAD_RE = re.compile(r"^\s*(T\d{4}(?:\.\d{3})?)\b", re.I)
_EXPECTED_STATUS_RE = re.compile(
    r"^(?:expected\s*[:\-]\s*)?"
    r"(?:status|http(?:/\d(?:\.\d)?)?)\s*[:=]?\s*(\d{3})\b",
    re.I,
)
_EXPECTED_CONTAINS_RE = re.compile(
    r"contains?\s*[\"']([^\"']{1,200})[\"']", re.I
)
_CONTAINS_CLAIM_RE = re.compile(r"\bcontains?\b", re.I)
_VAGUE_RE = re.compile(
    r"\b(?:maybe|perhaps|possibly|might|could|unclear)\b", re.I
)
_FRAME_LEAD_RE = re.compile(r"^\s*(paradox|impossible|iphone)\b", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"<>`]+", re.I)
_FILE_SOURCE_RE = re.compile(
    r"^[\w./-]+\.(?:md|txt|json|html?|pdf|ya?ml|csv|log|xml|"
    r"js|jsx|ts|tsx|py|go|java|php|rb|sh|conf|ini|toml)"
    r"(?::\d+)?$",
    re.I,
)
_GENERIC_SOURCES = {
    "",
    "n/a",
    "na",
    "none",
    "unknown",
    "model knowledge",
    "inferred",
    "assumed",
    "not stated",
}
_DESTRUCTIVE_RE = re.compile(
    r"(?:-x|--request)[=\s]*['\"]?\$?delete\b"
    r"|\bdrop\s+table\b"
    r"|\btruncate\s+table\b"
    r"|\bdelete\s+from\b"
    r"|\b_?method\s*[=:]\s*['\"]?delete\b"
    r"|\brm\s+-rf\b"
    r"|\bmass[-\s]?create\b"
    r"|\bmass[-\s]?account\b",
    re.I,
)
# Program policy/disclosure pages live on the platform, outside the
# target scope wall by design; they are still valid Assertion A sources.
_DOC_SOURCE_HOSTS = (
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
)


def _url_host(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _host_is_doc(host: str) -> bool:
    h = (host or "").lower()
    if h.startswith("www."):
        h = h[4:]
    return h in _DOC_SOURCE_HOSTS


def _url_in_scope(url: str, in_scope, out_of_scope=None) -> bool:
    """Scope-check a full URL (gate mode keeps path-scoped rules)."""
    if in_scope is not None and not isinstance(
        in_scope, (list, tuple, set)
    ):
        result = in_scope.is_in_scope(url)
        return bool(result[0] if isinstance(result, tuple) else result)
    return _in_scope(_url_host(url), in_scope, out_of_scope)


def _source_grounded(source: str, in_scope, out_of_scope=None) -> bool:
    """Assertion A must come from scope or a platform program asset.

    Every URL in the source must be grounded (no smuggling an in-scope
    URL first and an out-of-scope one second). Without a URL, the source
    must be a local evidence file or a hostname-shaped token that the
    scope gate covers; a bare out-of-scope hostname is not evidence.
    """
    urls = _URL_RE.findall(source or "")
    if urls:
        return all(
            _url_in_scope(u, in_scope, out_of_scope)
            or _host_is_doc(_url_host(u))
            for u in urls
        )
    words = (source or "").strip().strip("*`").split()
    if not words:
        return False
    token = words[0].rstrip(".,;:)")
    if _FILE_SOURCE_RE.match(token):
        return True
    if _HOST_RE.match(token.lower().rstrip(".")):
        return _url_in_scope(
            "https://" + token, in_scope, out_of_scope
        )
    return False


def _decode_payload(text: str) -> str:
    """Percent/HTML-ish decode for rule scanning (never for execution)."""
    decoded = str(text or "")
    for _ in range(2):
        nxt = urllib.parse.unquote_plus(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    decoded = re.sub(r"/\*.*?\*/", " ", decoded)
    return re.sub(r"\s+", " ", decoded).strip()


def _curl_method(check: str) -> str:
    """Recover the effective curl method through shell quoting tricks."""
    text = str(check or "").replace("\\\n", " ")
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    method = ""
    for i, token in enumerate(tokens):
        if token in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1]
        elif token.startswith("--request="):
            method = token.split("=", 1)[1]
        elif token.startswith("-X") and len(token) > 2:
            method = token[2:]
    return method.strip().strip("'\"").lstrip("$").upper()


def _scan_rule_violations(check: str) -> List[str]:
    """Deterministic destructive-action scan; never model-declared."""
    violations: List[str] = []
    decoded = _decode_payload(check)
    for match in _DESTRUCTIVE_RE.finditer(decoded):
        violations.append(
            f"destructive tactic in check: {match.group(0)}"
        )
    method = _curl_method(check)
    if method in {"DELETE", "PURGE"}:
        violations.append(
            f"destructive HTTP method in check: {method}"
        )
    return list(dict.fromkeys(violations))


_TEXT_REQUIRED = ("asset", "claim", "evidence_basis")
_PREDICTION_KEYS = ("status", "contains", "header", "body")

# Hostname labels: alnum/underscore edges, hyphen allowed inside. Stricter
# than the gate's [A-Za-z0-9_-]+ (fail-closed: rejects leading/trailing
# hyphens the gate would allow, but never accepts what the gate rejects).
_HOST_LABEL = r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?"
_HOST_RE = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*$")


def _normalize_asset(asset) -> str:
    """Reduce a host/URL to a validated lowercase host token, fail-closed.

    Paths are dropped for *assets* (a card names a host; the check carries
    the path). Hostile URL text (query/fragment/userinfo/semicolon/non-
    numeric ports, wildcard chars), numeric-only identifiers (the gate
    drops them: oracle_hunter.py:786), malformed labels and IPv6 literals
    make the token invalid rather than letting suffix matching smuggle an
    out-of-scope host. Non-host asset types must go through the live gate.
    """
    a = str(asset or "").strip().lower()
    for scheme in ("https://", "http://"):
        if a.startswith(scheme):
            a = a[len(scheme):]
    a = a.split("/")[0]
    if not a or "*" in a:
        return ""
    if any(ch in a for ch in "?#@;,%\\\"'<> "):
        return ""
    if ":" in a:
        host, _, port = a.rpartition(":")
        if port.isdigit():
            a = host
        else:
            return ""  # non-numeric port / IPv6 literal: fail closed
    if a.isdigit() or not _HOST_RE.match(a):
        return ""
    return a


def _normalize_pattern(pattern) -> Tuple[str, bool]:
    """Return (host token, wildcard?) for a raw in-scope entry.

    Path-scoped grants are unsupported at this layer and fail closed: a
    host-only card cannot prove a path constraint, and widening
    ``https://wolt.com/en/x`` to ``wolt.com`` is exactly the nuke the
    ProgramScopeGate forbids.
    """
    p = str(pattern or "").strip().lower()
    for scheme in ("https://", "http://"):
        if p.startswith(scheme):
            p = p[len(scheme):]
    if "/" in p:
        return "", False
    wildcard = p.startswith("*.") or p.startswith(".")
    if p.startswith("*."):
        p = p[2:]
    elif p.startswith("."):
        p = p[1:]
    return _normalize_asset(p), wildcard


def _matches_out_of_scope(asset: str, out_of_scope) -> bool:
    """OOS rules fail closed and cover subdomains (gate subdomains=True).

    An unusable OOS rule (path-scoped, malformed) rejects every asset:
    silently skipping it would fail open, which is a policy violation.
    """
    a = _normalize_asset(asset)
    if not a:
        return True  # unusable asset: never admitted
    for pattern in out_of_scope or []:
        p, _wildcard = _normalize_pattern(pattern)
        if not p:
            return True  # unusable exclusion: fail closed
        if a == p or a.endswith("." + p):
            return True
    return False


def _in_scope(asset: str, scope, out_of_scope=None) -> bool:
    """Scope wall for cage admission, never broader than ProgramScopeGate.

    Accepts either a raw list of scope identifiers (this function mirrors
    the gate's host semantics) or a live gate object exposing
    ``is_in_scope`` (production wiring must pass the real gate, which
    carries path constraints and out-of-scope rules).

    Raw-list semantics (host rules only):
    * ``*.example.com`` / ``.example.com`` covers apex + subdomains.
    * a bare host is exact: no implicit subdomain grant.
    * suffix-boundary attacks never match.
    * path-scoped grants fail closed; OOS rules reject apex+subdomains.
    """
    if scope is not None and not isinstance(scope, (list, tuple, set)):
        result = scope.is_in_scope(asset)
        ok = result[0] if isinstance(result, tuple) else result
        return bool(ok)
    a = _normalize_asset(asset)
    if not a:
        return False
    if _matches_out_of_scope(a, out_of_scope):
        return False
    for pattern in scope or []:
        p, wildcard = _normalize_pattern(pattern)
        if not p:
            continue
        if wildcard:
            if a == p or a.endswith("." + p):
                return True
        elif a == p:
            return True
    return False


def _check_prediction(prediction) -> Optional[str]:
    if not isinstance(prediction, dict) or not prediction:
        return "prediction must be a non-empty wire expectation object"
    if not any(k in prediction for k in _PREDICTION_KEYS):
        return (
            "prediction must contain at least one of "
            + "/".join(_PREDICTION_KEYS)
        )
    if "status" in prediction:
        status = prediction["status"]
        # bool is a subclass of int: True must never pass as a status
        if isinstance(status, bool) or not isinstance(status, int):
            return "prediction.status must be an int"
    for key in ("contains", "body"):
        if key not in prediction:
            continue
        value = prediction[key]
        if not isinstance(value, str) or not value.strip():
            return f"prediction.{key} must be a non-empty string"
    if "header" in prediction:
        header = prediction["header"]
        if isinstance(header, dict):
            if not header:
                return "prediction.header must be non-empty"
        elif not isinstance(header, str) or not header.strip():
            return "prediction.header must be a non-empty string or object"
    return None


def validate_mindset_card(
    mindset: str,
    card: Dict,
    in_scope,
    out_of_scope: Optional[List[str]] = None,
) -> Tuple[bool, List[str]]:
    """Cage gate: does this card exist inside the mindset's cage?

    ``in_scope`` may be a raw identifier list or the live
    ``ProgramScopeGate`` (preferred at wiring time: it carries path
    constraints and out-of-scope rules). Returns (ok, reasons). A
    suggestion-shaped payload (prose, missing prediction/basis, unchecked
    rules, out-of-scope asset) never passes.
    """
    reasons: List[str] = []
    if mindset not in VALID_CAGES:
        return False, [f"unknown mindset cage {mindset!r}"]
    if not isinstance(card, dict):
        return False, ["card must be an object"]

    for field in _TEXT_REQUIRED:
        value = card.get(field)
        if not isinstance(value, str) or not value.strip():
            reasons.append(f"missing required cage field {field!r}")
    for field in ("prediction", "rule_compliance"):
        if card.get(field) is None:
            reasons.append(f"missing required cage field {field!r}")

    pred_reason = _check_prediction(card.get("prediction"))
    if pred_reason:
        reasons.append(pred_reason)

    compliance = card.get("rule_compliance")
    if not isinstance(compliance, dict):
        if not any("'rule_compliance'" in r for r in reasons):
            reasons.append("rule_compliance must be an object")
    else:
        if compliance.get("checked") is not True:
            reasons.append("rule_compliance.checked must be True (rules read)")
        violations = compliance.get("violations") or []
        if violations:
            joined = ", ".join(map(str, violations))
            reasons.append("card violates program rules: " + joined)

    if not _in_scope(card.get("asset"), in_scope, out_of_scope):
        reasons.append(
            f"asset {card.get('asset')!r} is outside the program scope wall"
        )

    if mindset == "mitre":
        technique = str(card.get("technique") or "").strip()
        if not _TECHNIQUE_RE.match(technique):
            reasons.append(
                "mitre cage requires a technique code like T1190 on the face"
            )
    elif mindset == "paradox":
        frame = str(card.get("frame") or "").strip().lower()
        if frame not in VALID_FRAMES:
            reasons.append(
                "paradox cage requires frame in "
                + "/".join(VALID_FRAMES)
            )
    elif mindset == "synthesis":
        merged = card.get("merged_from") or []
        if not isinstance(merged, (list, tuple, set)):
            reasons.append("synthesis cage requires merged_from list")
        else:
            parents = {str(m).strip().lower() for m in merged}
            missing = {"mitre", "paradox"} - parents
            if missing:
                reasons.append(
                    "synthesis cage requires both parent mindsets; missing "
                    + ", ".join(sorted(missing))
                )

    return (not reasons), reasons


def _parse_expected(expected) -> Tuple[Optional[Dict], Optional[str]]:
    text = str(expected or "").strip()
    if _VAGUE_RE.search(text.split(",", 1)[0]):
        return None, "prediction must be definite (vague language found)"
    match = _EXPECTED_STATUS_RE.match(text)
    if not match:
        return None, (
            "prediction must start with an explicit status code "
            "(Expected: status 200 ...)"
        )
    status = int(match.group(1))
    if not 100 <= status <= 599:
        return None, f"prediction.status {status} is not an HTTP status"
    prediction: Dict = {"status": status}
    if _CONTAINS_CLAIM_RE.search(text):
        contains = _EXPECTED_CONTAINS_RE.search(text)
        if not contains or not contains.group(1).strip():
            return None, (
                "prediction.contains must be a quoted non-empty marker"
            )
        prediction["contains"] = contains.group(1).strip()
    return prediction, None


def admit_seam_card(
    mindset: str,
    seam: Dict,
    in_scope,
    out_of_scope: Optional[List[str]] = None,
    packet: Optional[Dict] = None,
) -> Tuple[bool, List[str], Optional[Dict]]:
    """Bridge a parsed SEAM card into the cage and admit or reject it.

    The existing SEAM format already carries the ingredients; this function
    *verifies* them instead of trusting prose: check URL -> asset, Expected
    -> machine prediction, Assertion A source -> evidence basis, MITRE ->
    technique, Frame -> paradox frame. Rule compliance is computed here by
    the admission scanner (never self-declared by the model). A card that
    cannot be grounded is rejected with reasons — it does not exist.

    Returns (ok, reasons, receipt). ``receipt`` is None on rejection.
    """
    reasons: List[str] = []
    if not isinstance(seam, dict):
        return False, ["seam card must be an object"], None

    claim = str(seam.get("assertion_a") or "").strip()
    observed = str(seam.get("assertion_b") or "").strip()
    source = str(seam.get("assertion_a_source") or "").strip()
    check = str(seam.get("check") or "").strip()
    expected = str(seam.get("expected") or "").strip()

    if not claim:
        reasons.append("card has no Assertion A (claim)")
    if not observed:
        reasons.append("card has no Assertion B (observed wire conflict)")
    _source_clean = source.strip().strip("*`").strip(".").lower()
    if _source_clean in _GENERIC_SOURCES:
        reasons.append("evidence basis is unsourced (Assertion A source)")
    elif not _source_grounded(source, in_scope, out_of_scope):
        reasons.append(
            "evidence source is not a program asset "
            "(out-of-scope host)"
        )

    check_urls = _URL_RE.findall(check)
    host = ""
    if not check_urls:
        reasons.append(
            "check carries no explicit URL (asset cannot be grounded)"
        )
    else:
        host = _url_host(check_urls[0])
        for url in check_urls:
            uhost = _url_host(url)
            if not uhost:
                reasons.append(
                    f"check URL is malformed: {url[:120]!r}"
                )
            elif not _url_in_scope(url, in_scope, out_of_scope):
                reasons.append(
                    f"check URL {url[:160]!r} is outside the program "
                    "scope wall"
                )

    prediction, pred_reason = _parse_expected(expected)
    if pred_reason:
        reasons.append(pred_reason)

    violations = _scan_rule_violations(check)
    rule_basis = "admission-scanner"
    if packet is not None:
        if not isinstance(packet, dict):
            violations.append("program packet is malformed")
        elif packet.get("verified") is not True:
            violations.append("program packet is not verified")
        elif packet.get("rules_sha256"):
            rule_basis = f"packet:{str(packet['rules_sha256'])[:16]}"

    technique = ""
    t_match = _TECHNIQUE_LEAD_RE.match(str(seam.get("mitre") or ""))
    if t_match:
        technique = t_match.group(1).upper()
    frame = ""
    f_match = _FRAME_LEAD_RE.match(str(seam.get("frame") or ""))
    if f_match:
        frame = f_match.group(1).lower()

    cage_card = {
        "asset": check_urls[0] if check_urls else "",
        "claim": claim,
        "prediction": prediction or {},
        "evidence_basis": source,
        "rule_compliance": {
            "checked": True,
            "violations": violations,
            "basis": rule_basis,
        },
        "technique": technique,
        "frame": frame,
        "merged_from": list(seam.get("merged_from") or []),
    }
    ok, cage_reasons = validate_mindset_card(
        mindset, cage_card, in_scope, out_of_scope
    )
    reasons.extend(cage_reasons)
    if not ok or reasons:
        return False, reasons, None

    receipt = {
        "mindset": mindset,
        "asset": host,
        "claim": claim,
        "prediction": prediction,
        "evidence_basis": source,
        "rule_compliance": cage_card["rule_compliance"],
        "technique": technique if mindset == "mitre" else "",
        "frame": frame if mindset == "paradox" else "",
        "check": check,
    }
    return True, [], receipt


def resolve_mindset_pools(
    lanes: List[str], config: Optional[Dict] = None
) -> Dict[str, List[str]]:
    """Allocate provider lanes to mindset cages (parallel execution law).

    Default: halves — M1 gets the first half, M2 the second, M3 gets all.
    Config override (``mindset_pools``) wins per mindset, unknown lanes are
    filtered, and an override that resolves to zero lanes is an error —
    a cage with no provider is not a declared regime, it is a hole.
    """
    seen = set()
    ordered: List[str] = []
    for lane in lanes or []:
        if lane in seen:
            continue
        seen.add(lane)
        ordered.append(lane)
    if not ordered:
        raise ValueError("resolve_mindset_pools: no provider lanes available")
    overrides = dict((config or {}).get("mindset_pools") or {})

    def _filter(requested: List[str]) -> List[str]:
        filtered: List[str] = []
        seen_lanes = set()
        for lane in requested:
            if lane in ordered and lane not in seen_lanes:
                seen_lanes.add(lane)
                filtered.append(lane)
        return filtered

    pools: Dict[str, List[str]] = {}
    if "mitre" in overrides:
        pools["mitre"] = _filter(list(overrides["mitre"]))
    if "paradox" in overrides:
        pools["paradox"] = _filter(list(overrides["paradox"]))

    if "mitre" in pools and "paradox" in pools:
        pass
    elif "mitre" in pools:
        remainder = [lane for lane in ordered if lane not in pools["mitre"]]
        pools["paradox"] = []
        for lane in remainder:
            pools["paradox"].append(lane)
    elif "paradox" in pools:
        pools["mitre"] = []
        for lane in ordered:
            if lane not in pools["paradox"]:
                pools["mitre"].append(lane)
    else:
        if len(ordered) == 1:
            # declared single-lane regime: the one provider is caged into
            # both producers (never a silent empty pool)
            pools["mitre"] = list(ordered)
            pools["paradox"] = list(ordered)
        else:
            cut = (len(ordered) + 1) // 2
            pools["mitre"] = ordered[:cut]
            pools["paradox"] = ordered[cut:]

    for name in ("mitre", "paradox"):
        if not pools[name]:
            raise ValueError(
                f"mindset pool for {name} resolved to zero lanes "
                f"(lanes={ordered})"
            )

    if "synthesis" in overrides:
        pools["synthesis"] = _filter(list(overrides["synthesis"]))
        if not pools["synthesis"]:
            raise ValueError(
                "mindset pool for synthesis resolved to zero lanes "
                f"(lanes={ordered})"
            )
    else:
        pools["synthesis"] = list(ordered)

    return pools


if __name__ == "__main__":  # tiny self-check, no side effects
    print(resolve_mindset_pools(["a", "b", "c", "d"]))
