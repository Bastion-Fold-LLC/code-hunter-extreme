# Oracle Fleet API & Service Registry

*Document Version:* 1.0  
*Updated:* 2026-10-04  
*Location:* `/home/phantomcore/oracle/docs/FLEET_API_REGISTRY.md`

---

## 1. Overview

This registry documents every external API, web service, and LLM provider integrated into the Oracle hunting ecosystem. It details authentication mechanisms, base endpoints, rate limits, active roles, and fallback behaviors.

---

## 2. Bug Bounty & Target Intake APIs

| Platform | Primary Endpoint | Auth Method | Rate Limit / Quota | Purpose in Oracle |
| :--- | :--- | :--- | :--- | :--- |
| **Intigriti** | `https://api.intigriti.com/external/researcher/v1` | `Authorization: Bearer <INTIGRITI_TOKEN>` | Standard REST | Official v1 program listing, bounty ranges, structured domain & wildcard scope intake. |
| **HackerOne** | `https://hackerone.com/graphql` | None (Public GraphQL) | Paced (4s delay + exp backoff) | Structured asset and scope intake for all public HackerOne programs. |
| **HackerOne API** | `https://api.hackerone.com/v1/hackers` | HTTP Basic Auth (`HACKERONE_USERNAME`, `HACKERONE_API_KEY`) | Standard REST | Direct hacker program directory and bounty reward inquiry. |
| **YesWeHack** | `https://api.yeswehack.com/programs` | Unauthenticated / Public | None enforced | Complete program catalog, in-scope domains/APIs, and out-of-scope boundaries. |
| **HackenProof** | `https://hackenproof.com/api` | Bearer Token / CDP Browser Session | Cloudflare Dynamic | Program intake and smart contract/Web3 bounty tracking. |
| **Code4rena** | `https://code4rena.com/api/v1/audits/<slug>` | — | **REMOVED per operator (platform dead)** | skipped in code (`oracle_programs.py`, `oracle_bulk_download.py`) | Historical row; not fetched. |
| **Cantina** | `https://cantina.xyz/bounties/<uuid>` | Public Flight-Data JSON | Standard HTTP | Smart contract addresses, GitHub target repos, and prize pool tracking. |
| **Immunefi** | `https://immunefi.com/bug-bounty/<slug>/information/` | Public Next.js Hydration JSON | Standard HTTP | Web3 bug bounty scopes, contract addresses, and out-of-scope rules. |
| **Huntr** | `https://huntr.com/challenges` | Public HTML Card Parsing | Standard HTTP | AI model/agent targets and challenge interface scopes. |

---

## 3. Scraping, Reconnaissance & LLM Providers

> Latency/status values in this table are a one-time dated snapshot
> (2026-10-19 probes: 9 of 13 lanes answered; Databricks returned HTTP 400
> on all models and is circuit-broken while down; Apinex HTTP 402 daily
> check-in). Routing order and caps below reflect `oracle_backends.json`
> at 2026-10-20. Gemini is configured as a lane but deliberately absent
> from every route list (unrouted, not "standby worker").

| Provider | Base Endpoint | Auth Variable | Status / Latency | Models / Quotas | Role in Oracle |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Databricks** | (workspace endpoint in `oracle_backends.json`) | `DATABRICKS_TOKEN` | **DOWN (HTTP 400 all models, 2026-10-19)** | 9 configured models | First in route order; skipped by circuit breaker while down. |
| **Groq (LPU)** | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` | snapshot | `openai/gpt-oss-120b`, `openai/gpt-oss-20b` | Fast lane for SMALL prompts only: `max_request_tokens: 8000` pre-skips it for mindset passes (TPM). Second in route order — not primary. |
| **NVIDIA NIM** | `https://integrate.api.nvidia.com/v1` | `NVIDIA_API_KEY` | **ONLINE (0.79s)** | `meta/llama-3.2-11b-vision-instruct` (40 RPM) | High-speed LLM reasoning and code analysis lane. |
| **Bynara** | `https://router.bynara.id/v1` | `BYNARA_API_KEY` | **ONLINE (~3.0s)** | `nemotron-3.5-lightning-free`, `nemotron-3-super-free` | Free multi-model routing gateway with reasoning tokens. |
| **OpenRouter** | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | **ONLINE (~2.5s)** | `nvidia/nemotron-3.5-lightning:free`, `qwen/qwen3.8-27b:free` | Free open-source fleet rotation lane. |
| **Cloudflare** | `https://api.cloudflare.com/.../ai/v1` | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | **ONLINE (0.74s)** | `@cf/meta/llama-3.3-70b-instruct-fp8-fast`, `@cf/qwen/qwen2.5-coder-32b-instruct` | High-speed edge LLM reasoning lane. |
| **xKiro** | `https://api.xkiro.com/v1` | `XKIRO_API_KEY` | **ONLINE (~15s)** | `qwen/qwen3-coder-plus:free`, `qwen/qwen3.6-max-preview:free` | Extended reasoning & code verification lane. |
| **APInex** | `https://api.apinex.bond/v1` | `APINEX_API_KEY` | **ONLINE (~18s)** | `free/deepseek-v4.1-flash`, `free/deepseek-v4-pro-0813` | DeepSeek and GLM reasoning lane. |
| **Google Gemini** | `https://generativelanguage.googleapis.com` | `GEMINI_API_KEY` | *Configured, UNROUTED* | lane exists in config, absent from every route list | Not used by the router (deliberate). |
| **Firecrawl** | `https://api.firecrawl.dev/v1` | `FIRECRAWL_API_KEY` | **ONLINE** | Paid balance credits | Cloud JS-rendered web crawler for SPA target pages. |
| **Jina Reader** | `https://r.jina.ai/<url>` | `JINA_API_KEY` | **ONLINE** | Zero-cost LLM scraper | Converts complex web pages into token-dense Markdown for model ingestion. |
| **Tavily AI** | `https://api.tavily.com/search` | `TAVILY_API_KEY` | **ONLINE** | 1,000 monthly credits | Real-time web search fallback for unknown programs and newly disclosed assets. |
| **Crawl4AI** | Local (`localhost`) | None | **ONLINE** | Unlimited local execution | Autonomous local browser crawling (zero cloud dependencies). |
| **Local Ollama** | `http://localhost:11434` | None | **ONLINE** | Unlimited hardware execution | Hardware floor fallback (`qwen3-coder:30b-16k`) when running `--no-cloud`. |

---

## 4. Routing & Failover Architecture

Every outbound request follows strict fail-closed cascading rules configured in [`oracle_backends.json`](file:///home/phantomcore/oracle/oracle_backends.json) (fixed route order; round-robin rotation implemented but OFF, `round_robin: false`):

```mermaid
flowchart TD
    Task([Inference / Analysis Request]) --> Gate{Is --no-cloud set?}
    Gate -- Yes --> LocalOnly[Local Ollama Hardware Floor]
    Gate -- No --> RR[Round-robin over 13 lanes<br/>databricks → groq → nvidia → dahl → monkeycode →<br/>bynara → openrouter → llm7 → cloudflare → xkiro →<br/>apinex → omnicli → local]
    RR --> Fit{Prompt fits lane?<br/>context + max_request_tokens}
    Fit -- No --> Skip[Skip fast, no API call]
    Fit -- Yes --> Down{Lane circuit-broken<br/>(600s cooldown)?}
    Down -- Yes --> Skip
    Down -- No --> Call[Call lane within remaining<br/>TOTAL router budget]
    Call -- Success --> Done([Return, lane cleared])
    Call -- Failure --> Mark[Mark down unless sole lane /<br/>starved slice / deadline cut / size reject]
    Mark --> RR
    Skip --> RR
```

### Failover Safeguards & Network Hardening
1. **IPv4 Dual-Stack Enforcement:** Linux hosts with unroutable IPv6 interfaces suffer 20-second TCP SYN drop penalties per request. The pipeline hard-pins `urllib3.util.connection.HAS_IPV6 = False`, dropping provider latency by 97% across all HTTP adapters.
2. **No Silent Drops:** If all API backends are exhausted, the router raises a descriptive `RuntimeError`—it never returns empty mock data or hallucinated payloads.
3. **Credential Containment:** API keys are loaded via `.env` / `ORACLE_KEYS.env` into memory (placeholder-looking values rejected). No tokens are written to git commits or exported reports. Transient upstreams can echo auth headers into log files — treat raw hunt logs as sensitive.
4. **Owner-Only Sessions:** Active browser session cookies are stored under permissions `0600` in the user profile directory.
