# Prompt-Injection Hardening — Scoped (NOT implemented yet)

Source: break-it round 1 adversarial probes, 2026-10-11. Matches prior audit
prescription (`:cache→prompts`: sanitize at ingestion or delimit with
provenance).

## Exposure (read, with refs)

Untrusted text reaches LLM prompts raw at three points:

1. Program brief → mindset system prompt: `OracleMindsetContext._program_brief`
   (`oracle_mindset_context.py:369`) embeds program name/platform/url/rules
   with no delimiting or sanitization. Program names come from platform
   listings (attacker-influenced on open platforms).
2. Recon output → reflex prompt: `run_reflexes` (`oracle_hunter.py:2107`)
   interpolates recon files (hosts, URLs, page-derived content) raw.
3. Target string → prompts (`oracle_hunter.py:2109,2209,3990,5280,6054`) raw.

Existing sanitizers cover only slugs (`_sanitize`, `:328`) and header values
(`_sanitize_header_val`, `:2379`) — not prompt-bound text.

## Blast radius (bounded, not critical)

A hostile target/program can steer seam generation (blind the hunter, emit
garbage). It cannot reach RCE: checks stay scope-gated, binary-allowlisted,
and shell-free. Worst case is bad verdicts on a hostile target's own hunt.

## Scoped fix (own change with adversarial tests, not rushed)

1. Delimit every untrusted block with provenance tags
   (`[UNTRUSTED program-listing]…[/UNTRUSTED]`) at brief/prompt construction.
2. Strip control chars + truncate untrusted fields at ingestion boundary.
3. Add instruction-hierarchy reminder in reflex/assess system prompts
   (untrusted blocks never override the task).
4. Adversarial tests: hostile program names (`Ignore previous instructions…`),
   recon files with injected directives → assert verdicts unaffected.
