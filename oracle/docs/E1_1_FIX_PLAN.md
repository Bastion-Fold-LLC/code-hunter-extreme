# E1.1 Fix Plan

**Created:** 2026-10-21  
**Status:** OPEN — five gaps, sequential fix order below  
**Rule:** Every fix gets a RED receipt (failing test) before the code change.  
**Baseline:** HEAD `66f5e8a` — 1228 tests collected, 1184 passed + 32 subtests, 0 failures.

---

## Background

The tinder live hunt (2026-10-21) returned honest zero. Post-mortem named five structural
gaps that would have produced bad output on *any* unauthenticated session-gated target.
These are not opinion — each maps to an exact failing code line.

The session-gate detection fix (`451809e`) and full-service mindset law (`d8d1dd2`)
already shipped. The five items below are what remain.

---

## Fix E — Scope-empty fail-closed

**Do this first.** A hunt with no scope wall sends the model a prompt that cannot
name what is in-scope. It will hallucinate targets.

### What the code does now

`oracle_hunter.py:6404-6423` attempts a live scope auto-fetch when `structured_scopes`
is empty. If the fetch returns nothing it `_warn()`s and continues:

```python
_warn(
    f"Scope intake: no assets (status={_status}) — gate will fall "
    f"back to target name; run scope download or check the session"
)
```

There is no `sys.exit()` or `RuntimeError` after this. The hunt proceeds with
an empty scope wall.

### What must change

After the auto-fetch attempt, if `structured_scopes` is still empty AND the
target is not `"direct"` (loopback/testnet), raise a hard `RuntimeError` that
names the program and tells the user exactly how to fix it:

```
SCOPE EMPTY — cannot hunt testprog: no in-scope assets.
Run: oracle-hunter download testprog
Or pass a direct target: oracle-hunter hunt https://example.com
```

### Files

- **`oracle_hunter.py`** — block at line ~6422, after the failed intake branch
- **`tests/test_live_failure_regression.py`** — add `test_scope_empty_blocks_hunt()`
  that patches `intake_program_scopes` to return `([], "no_assets")` and asserts
  a `RuntimeError` (or `SystemExit`) is raised, not a warning

### RED receipt target

```
RuntimeError: SCOPE EMPTY — cannot hunt testprog
```

---

## Fix A — Carry-through tags (lens + L-seed + T-code on card faces)

**Do this second.** Every tinder card showed `MITRE: ?` in the report. The tags
exist in the template definition but are not reliably surfaced in the `raw` text
shown in reports, and the `mitre` field parsed from LLM output is `"N/A"` on
nearly all cards because the model does not always emit a `MITRE:` label.

### What the code does now

**Template cards** (`oracle_seam_templates.py:2078-2132`): `_card()` writes
`"mitre": t["mitre"]` and `"claim_type": t["tid"]` onto the dict. The `raw`
field includes `MITRE: {t['mitre']}` and `TEMPLATE: {t['tid']}`. These fields
ARE set correctly for deterministic cards.

**LLM-generated cards** (`oracle_hunter.py:4899-4935`): `_parse_seams()` sets
`"mitre"` by regex from the model output. If the model does not write a `MITRE:`
label the field defaults to `"N/A"`. There is no fallback to the lens origin.
The `"mindset"` field is set later by `build_seam_sets()` / `cross_compare()`,
not by `_parse_seams()`.

**Attribution** (`oracle_hunter.py:4950-4973`): `_attribute_candidate_lenses()`
adds `"reasoning_lenses"` but does NOT add a `"lens"` tag or a `"template_id"`.

**Report rendering** (`_format_chain_report` in `oracle_hunter.py`): reads
`seam.get("mitre")` — shows `?` when `"N/A"`.

### What must change

Three small changes, no new fields invented:

1. **`oracle_hunter.py` — `_parse_seams()`**: After parsing, if `mitre` is `"N/A"`,
   attempt a secondary regex for a bare T-number anywhere in the block:
   `re.search(r'\b(T\d{4}(?:\.\d{3})?)\b', card)`. This already exists at line
   4900 as a fallback — verify it fires correctly and that the field is not
   overwritten to `"N/A"` after the fact.

2. **`oracle_hunter.py` — seam tagging after `_parse_seams()`**: When a seam
   is produced by an LLM pass, stamp `"lens"` = the engine origin string
   (`"cloud-mitre"`, `"cloud-paradox"`, etc.) and `"template_id"` = `""` (LLM
   cards have no template ID). This happens at the point where `mindset` is set
   in `cross_compare()` / `build_seam_sets()`. The simplest fix: in
   `_attribute_candidate_lenses()`, set `seam.setdefault("lens", seam.get("origin", ""))`.

3. **`oracle_seam_templates.py` — `_card()`**: The `"lens"` field is already
   implicitly `"seam-template"` via `origin`. Set it explicitly:
   `"lens": "seam-template"` so report rendering has a uniform field name.

### Files

- **`oracle_hunter.py`** — `_parse_seams()` T-code fallback (verify line 4900 works)
- **`oracle_hunter.py`** — `_attribute_candidate_lenses()` add `lens` field
- **`oracle_seam_templates.py`** — `_card()` add `"lens": "seam-template"`
- **`tests/test_live_failure_regression.py`** — add `test_mitre_tag_not_na_on_template_cards()`
  asserting `card["mitre"] != "N/A"` and `card["lens"]` is set for every
  `scan_template_seams()` output card

### RED receipt target

```
AssertionError: template card T001 has mitre='N/A'
```

---

## Fix B — Auth-feasibility filter (kill 502-class predictions at mint)

**Do this third.** In the tinder run 864/892 wire checks returned 502. Every
single one of those cards was minted and sent to wire. The session-gate block
(`451809e`) now aborts the hunt when 60% of *hosts* are 502. But cards can still
be minted against a 502 wall if the threshold is not met (e.g., 50% 502 hosts),
and the check still fires at wire even if the host was seen 502 in recon.

### What the code does now

`scan_template_seams()` (`oracle_seam_templates.py:2135-2192`) generates a card
for every path the template function returns. There is no filter on whether the
check URL's host returned a wall code in `live_hosts.txt`.

`_build_material()` reads `live_hosts` from `clean_live_hosts.txt` /
`live_hosts.txt` but does not parse status codes — it only provides the raw
lines as a list of strings.

### What must change

In `scan_template_seams()`, after `_card(t, p, program, len(out)+1)` is built,
extract the check URL's host and cross-reference it against a wall-host set
derived from `live_hosts.txt`. If the host has a 502/401/403/530/000 status in
recon AND no `auth`/`cookie` was passed, drop the card with a counter.

Specifically:

1. `_build_material()` — add `"wall_hosts": set()` populated by parsing
   `live_hosts.txt` lines for `[502]`, `[401]`, `[403]`, `[530]`, `[000]`.

2. `scan_template_seams()` — accept an optional `auth: Optional[str] = None`
   parameter. After building each card, if the check URL's host is in
   `mat["wall_hosts"]` and `not auth`, skip the card (increment a local
   `wall_drops` counter).

3. Call site in `oracle_hunter.py` (`seam_prepass` / wherever
   `scan_template_seams` is called) — pass `auth=getattr(args, "auth", None)`
   or the merged auth string.

4. Log: `_info(f"Auth-filter: dropped {wall_drops} card(s) — host returned wall code in recon")`

### Files

- **`oracle_seam_templates.py`** — `_build_material()` add `wall_hosts`;
  `scan_template_seams()` add `auth` param + drop loop
- **`oracle_hunter.py`** — pass `auth` to `scan_template_seams()` at call site
- **`tests/test_live_failure_regression.py`** — add
  `test_auth_filter_drops_wall_host_cards()`: build a `live_hosts.txt` with
  502-status hosts, call `scan_template_seams()` without auth, assert zero
  cards for those hosts; call with `auth="Bearer x"`, assert cards survive

### RED receipt target

```
AssertionError: expected 0 cards for 502 host, got 3
```

---

## Fix C — Mint-cap (prevent per-template-family monoculture)

**Do this fourth.** All 146 tinder cards came from one template family
(`router-spelling` / auth-bypass class). The verifier rejected all 1100
attempts. No diversity = no signal.

### What the code does now

`scan_template_seams()` iterates `TEMPLATES` in order, appending every card
every template produces. There is no limit on how many cards one template (or
template family) can contribute.

The `TEMPLATES` list is in `oracle_seam_templates.py`. Templates have a `"tid"`
field (e.g., `"_t_beautiful_liar"`, `"_t_deathless"`, `"_t_self_observing"`)
but no `"family"` field. Template families are implicit in the `tid` prefix.

### What must change

1. **Define a family key**: `_family(tid: str) -> str` — strips the terminal
   `_N` numeric suffix from `tid` (e.g., `"_t_sqli_1"` → `"_t_sqli"`,
   `"_t_self_observing"` → `"_t_self_observing"`). This groups variants together.

2. **Add `max_per_family` parameter to `scan_template_seams()`** (default `20`,
   configurable via `program.get("hunt_config", {}).get("max_cards_per_family")`
   or the Oracle config). When a family reaches its cap, skip further cards from
   that family with a counter.

3. **Log**: `_info(f"Mint-cap: capped {N} template families at {max_per_family} cards/family")`

### Files

- **`oracle_seam_templates.py`** — `_family()` helper; `scan_template_seams()`
  `max_per_family` parameter + family counter dict
- **`oracle_hunter.py`** — pass `max_per_family` from config/args at call site
- **`tests/test_live_failure_regression.py`** — add
  `test_mint_cap_prevents_monoculture()`: build recon with 100 endpoints in one
  template's domain (e.g., 100 fuzzed paths that all fire `_t_self_observing`),
  call `scan_template_seams()` with `max_per_family=5`, assert total cards ≤ 5
  for that family

### RED receipt target

```
AssertionError: expected ≤5 cards from _t_self_observing family, got 87
```

---

## Fix D — Slice-cap config (expose 20-host / 30-endpoint caps)

**Do this fifth.** Only 5% of tinder's 580 JS endpoints reached the mindset
injection. The caps are hardcoded in two places and have no config escape hatch.

### What the code does now

- `oracle_mindset_context.py:779` — `self._recon_hosts = list(live_hosts or [])[:20]`
- `oracle_mindset_context.py:780` — `self._recon_endpoints = list(endpoints or [])[:30]`
- `oracle_hunter.py:6724` — `_live_endpoints = _live_endpoints[:30]`
- `oracle_hunter.py:6641-6647` — `_live_hosts` (no explicit cap line, but
  `inject_recon_context` will cap at 20 anyway)

These caps exist to prevent context overflow. They are reasonable defaults
but must be overridable for targets with large surfaces.

### What must change

1. **`oracle_mindset_context.py`** — `inject_recon_context()` reads
   `max_hosts` and `max_endpoints` from `self._program.get("hunt_config", {})`
   with defaults `20` and `30`. Replace the hardcoded slices with these values.

2. **`oracle_hunter.py`** — The `:30` slice at line 6724 reads from
   `oracle.config.json` → `hunt.recon_context_max_endpoints` (default 30).
   Plumb the config value through. Same for the host list.

3. **`oracle.config.json`** — Add:
   ```json
   "recon_context": {
     "max_hosts": 20,
     "max_endpoints": 30
   }
   ```
   under the existing `"hunt"` key.

4. No change to the existing defaults — behaviour is identical unless the user
   overrides. This is a config escape hatch, not a behaviour change.

### Files

- **`oracle_mindset_context.py`** — `inject_recon_context()` parameterize caps
- **`oracle_hunter.py`** — read config, pass caps to `inject_recon_context()`
- **`oracle.config.json`** — add `recon_context` block under `hunt`
- **`tests/test_live_failure_regression.py`** — add
  `test_slice_cap_config_respected()`: pass `hunt_config={"max_hosts": 5,
  "max_endpoints": 7}` into `OracleMindsetContext`, call `inject_recon_context()`
  with 50 hosts and 100 endpoints, assert `len(ctx._recon_hosts) == 5` and
  `len(ctx._recon_endpoints) == 7`

### RED receipt target

```
AssertionError: expected 5 hosts after cap, got 20
```

---

## Adversarial Torture Test Suite

**After E, A, B, C, D are fixed.** Build a test suite that probes the decision
space, not the answer key. Separate file: `tests/test_adversarial_e1_1.py`.

Tests to include (at minimum):

| Test | What it probes |
|---|---|
| `test_scope_empty_hunt_blocked` | Hunt refuses on empty scope after failed intake |
| `test_scope_single_wildcard_accepted` | One wildcard scope is sufficient to proceed |
| `test_mitre_n_a_never_on_template_card` | All `scan_template_seams()` output has `mitre != "N/A"` |
| `test_lens_field_set_on_all_cards` | Every card (template + LLM-parsed) has a non-empty `lens` field |
| `test_auth_filter_empty_live_hosts` | Empty `live_hosts.txt` → no cards dropped (no false-filter) |
| `test_auth_filter_200_host_not_dropped` | 200-status host → card survives even without auth |
| `test_auth_filter_wall_host_with_auth` | Wall host + auth provided → card survives |
| `test_auth_filter_50pct_wall_not_blocked` | 50% wall hosts → session-gate does not trip (below 60%) |
| `test_mint_cap_uniform_across_families` | 10 families × 100 cards each, cap=5 → 50 total |
| `test_mint_cap_one_family_zero` | Family that produces 0 cards is unaffected by cap |
| `test_slice_cap_default_20_30` | Default caps produce ≤20 hosts and ≤30 endpoints |
| `test_slice_cap_override_100` | Override to 100 produces ≤100 (bounded by input size) |
| `test_no_cards_from_session_gated_wall` | 100% wall hosts + no auth + no auth filter → zero cards survive |
| `test_yield_ledger_unserved_on_zero_mint` | Ledger reports both LLM lenses unserved when templates return 0 after auth filter |

---

## Execution order

```
E → A → B → C → D → adversarial suite → superbet run
```

Each fix:
1. Write failing test (RED receipt).
2. Make the minimal code change.
3. Run `pytest tests/test_live_failure_regression.py tests/test_adversarial_e1_1.py -q` — all must pass.
4. Run full suite `pytest -q` — 0 new failures.
5. Commit with message `fix(e1.1-X): <one line description>` and note the RED receipt.

---

## Success criteria

- All five gaps have a committed fix with a RED receipt.
- Full suite still passes (no regressions).
- `scan_template_seams()` on a 100%-502 target with no auth returns 0 cards.
- `scan_template_seams()` on the same target with `auth="Bearer x"` returns cards.
- `inject_recon_context()` with `max_hosts=5` stores 5 hosts, not 20.
- Every card from `scan_template_seams()` has `card["mitre"] != "N/A"`.
- `oracle-hunter hunt testprog` with empty scope raises `RuntimeError` and exits.
- Superbet end-to-end run completes without overflow, session-gate death, or monoculture.
