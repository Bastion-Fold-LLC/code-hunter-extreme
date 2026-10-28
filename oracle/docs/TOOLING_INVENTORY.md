# Tooling & API Inventory

_Updated 2026-10-15. **No secret values are stored here** — only provider names,
endpoints, env-var names, and whether a key is configured. Raw keys live in
`~/.config/omnicli/config.json` (0600) and GitHub Actions secrets._

## Code-evaluation tools

| Tool | Local / Web | Role | Status |
|---|---|---|---|
| **Greptile** | Web (MCP `api.greptile.com`, org `CodeHunterExtreme`) | AI PR review | ✅ live on PRs |
| **CodeRabbit** | Web (GitHub app, Advanced) | AI PR review | ✅ live on PRs |
| **bandit / semgrep / ruff / flake8 / pylint / mypy / vulture / interrogate** | Local (+ validate CI) | SAST / lint / types / dead-code / docstrings | ✅ local; CI pending merge |
| **gitleaks** | Local (+ CI) | secret scan | ✅ |
| **pytest / coverage / hypothesis** | Local (+ CI) | tests / coverage / fuzz | ✅ |
| **OSV-Scanner 2.7.0** | Local (`~/.local/bin/osv-scanner`) | dependency CVEs | ✅ |
| **narsil-mcp 1.7.2** | Local MCP (`~/.cargo/bin/narsil-mcp`, wired in `.mcp.json`) | taint + call-graph | ⏳ loads on reconnect+approve |
| **logic-lens** | Local skill (`~/.claude/skills/logic-lens/`) | logic review | ✅ live |
| **Snyk** | Web SaaS | reachability SCA + code | ⏳ `SNYK_TOKEN` set (GH secrets, 3 repos); CI step pending merge |
| **Socket** | Web (GitHub app + CI) | supply-chain / malware | ✅ app check seen on PRs; CI step token-gated |
| **Semgrep Supply Chain** | Web SaaS (paid) | reachability SCA | ❌ needs `SEMGREP_APP_TOKEN` (not set) |
| **Dependabot** | GitHub | dep update PRs | ⏳ `dependabot.yml` in CI PRs; enable alerts in repo settings |

Wiring: `scripts/review-harvest.py <repo> <pr>` unifies Greptile + CodeRabbit + CI into one
checklist. Merge rule: both reviewers clean (or dispositioned) AND validate green.

## Hunting tools (in oracle, for targets — authorized/local only)
- **subfinder + httpx + katana + dnsx** (ProjectDiscovery) — the live hunt recon stack (oracle_hunter). Nuclei/gau/hakrawler/ffuf exist in parts of the older code but are not the deeprecon main path.

## Agent tools (installed/available; NOT reviewers — gate behind PRs if used)
- **codebuff** (`~/.npm-global/bin/codebuff`) — user-run coding agent. Others noted but not
  installed: OpenHands, Ghostex, CodeGraph.

## API / provider inventory (endpoints + env vars — NO key values)

### omnicli model providers (`DEFAULT_PROVIDERS`, `omnicli/config.py`)
| id | endpoint | env var | key configured? |
|---|---|---|---|
| openrouter | https://openrouter.ai/api/v1 | `OPENROUTER_API_KEY` | ✅ |
| nvidia | https://integrate.api.nvidia.com/v1 | `NVIDIA_API_KEY` (alt `NVAPI_KEY`) | ✅ |
| cloudflare | https://api.cloudflare.com/client/v4/accounts/{id}/ai/v1 | `CLOUDFLARE_API_TOKEN` | ✅ |
| bynara | https://router.bynara.id/v1 | `BYNARA_API_KEY` | ✅ |
| apinex | https://api.apinex.bond/v1 | `APINEX_API_KEY` | ✅ |
| xkiro | https://api.xkiro.com/v1 | `XKIRO_API_KEY` | ✅ |
| dahl | https://inference.dahl.global/v1 | `DAHL_API_KEY` | ✅ |
| llm7 | https://api.llm7.io/v1 | `LLM7_API_KEY` | ✅ |
| groq | https://api.groq.com/openai/v1 | `GROQ_API_KEY` | ✅ (capped 8000tok/request in Oracle router) |
| monkeycode | https://api.monkeycode-ai.net/v1 | `MONKEYCODE_API_KEY` | ✅ |
| databricks | workspace endpoint in `oracle_backends.json` | `DATABRICKS_TOKEN` | ✅ configured — currently HTTP 400 on all models (breaker-skipped) |

_Add a provider = one `DEFAULT_PROVIDERS` entry (`base_url` + `env_key` + `default_model`);
`omni scan` populates the rest._

### scan4me bounty-platform APIs (creds via `load_credentials`)
| platform | auth | notes |
|---|---|---|
| hackerone | username + api_token | authenticated feed |
| bugcrowd | api_token | |
| intigriti | api_token | |
| yeswehack | api_token | |
| federacy / immunefi / sherlock / pd_programs | none | public feeds (no login) |

_Add a bounty site = a fetcher + handle derivation in `scan4me.py` (and oracle's scrapers)._

### Review-tool tokens (names/locations only)
| tool | secret name | stored in |
|---|---|---|
| Greptile | (API key) | **exposed in chat transcript → ROTATE** |
| Snyk | `SNYK_TOKEN` | GitHub Actions secrets (oracle/scan4me/omnicli) — **exposed in transcript → ROTATE** |
| Socket | `SOCKET_SECURITY_API_KEY` | GitHub Actions secret (if used; app also installed) |
| Semgrep Supply Chain | `SEMGREP_APP_TOKEN` | not set |

## Security notes
- No raw keys in this file by design. Keys live in `~/.config/omnicli/config.json` (0600)
  and GitHub Actions secrets.
- **Rotate the Greptile key and the Snyk token** — both were pasted into the session transcript.
