> **SUPERSEDED 2026-10-20 — the 2026-10-02 matrix below is a dated snapshot.**
> Current scope-adapter state (`oracle_bulk_download.intake_program_scopes`):
> registered adapters (`_SCOPE_ADAPTERS`) cover Bugcrowd, Cantina, CodeHawks,
> HackenProof, **HackerOne**, Huntr, Immunefi, **Intigriti**
> (`_fetch_intigriti_scopes`, API token only — returns `[]` with no token;
> CDP covers page retrieval separately), Patchstack, Sherlock (public
> bug-bounty HTML scrape), YesWeHack. **Bugbase** has no scope
> adapter by design (listing-only discovery). **Hats Finance is excluded**
> (no account). Live evidence (2026-10-19): the Intigriti pipeline completed
> download+recon for Here Technologies, and its program page renders via
> the saved-session CDP path. Read the matrix below as history only.

# Platform Conformance Matrix

This matrix records read-only platform/program scope checks. A successful row
means Oracle retrieved scope metadata from a cached sample program. It does
not mean the platform is ready for active hunting; workspace persistence,
asset intake, program profiles, and authorized verification remain separate
gates.

## First Read-Only Scope Pass — 2026-10-02

| Platform | Cached sample | Scope result | Scope assets | Status |
|---|---|---:|---:|---|
| Bugcrowd | Vinted Bug Bounty | `ok` | 15 | Pass |
| Cantina | Uniswap | `ok` | 13 | Pass |
| Code4rena | — | — | — | No cached sample |
| CodeHawks | BattleChain Confidence Pools | `ok` | 1 | Pass |
| HackenProof | BTSE Bug Bounty Program | `ok` | 6 | Pass |
| HackerOne | — | — | — | No cached sample |
| Huntr | View details | `ok` | 1 | Pass; sample identity needs quality review |
| Immunefi | SSV Network | `ok` | 3 | Pass |
| Patchstack | Elementor Pro | `ok` | 1 | Pass |
| Sherlock | Usual Labs | `empty` | 0 | Explicit empty scope; requires parser/browser follow-up |
| YesWeHack | harman-international-web-applications | `ok` | 35 | Pass |

## Explicit Scope-Unsupported Discovery Adapters

| Platform | Current state |
|---|---|
| Bugbase | `no-adapter` |
| Hats Finance | `no-adapter` |
| Intigriti | `no-adapter` |

## Next Checks

1. Obtain fresh cached samples for HackerOne and Code4rena, then repeat the
   same read-only scope test.
2. Investigate Sherlock's explicit empty result without treating it as
   hunt-ready.
3. For each passing row, persist `scope-fetched` program metadata and run the
   asset/workspace save check.
4. Add browser-needed and fallback outcomes to the matrix when a public scope
   reader cannot retrieve a program's authoritative scope.
