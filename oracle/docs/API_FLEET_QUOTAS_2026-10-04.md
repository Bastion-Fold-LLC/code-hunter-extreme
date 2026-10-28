> **HISTORICAL (2026-10-04) — superseded by `docs/FLEET_API_REGISTRY.md`** (dated snapshots both; quotas drift).

# Oracle AI Provider Fleet & Quota Audit (2026-10-04)

This document details the exact token allowances, credit quotas, rate limits, and verification status for every provider in Oracle's multi-backend routing pool.

---

## 1. Provider Fleet Summary Table

| Provider | Purpose in Oracle | Endpoint / Host | Daily Token / Request Allowance | Verified Live Status |
| :--- | :--- | :--- | :--- | :--- |
| **APInex** | LLM Seam Reasoning | `https://api.apinex.bond/v1` | **~10,000,000 tokens/day**<br>• Burst: 30 req/min | **ACTIVE & VERIFIED**<br>(Tested on `free/deepseek-v4.1-flash`) |
| **xKiro** | LLM Code & Invariant Analysis | `https://api.xkiro.com/v1` | **~5,000,000 tokens/day**<br>• Context up to 1M tokens | **ACTIVE & VERIFIED**<br>(Tested on `qwen/qwen3-coder-plus:free`) |
| **Bynara** | LLM Secondary Pool | `https://router.bynara.id/v1` | **~7,000,000 tokens/day** | **PENDING TELEGRAM LINK**<br>(Action: link telegram in settings) |
| **OpenRouter** | LLM Fallback | `https://openrouter.ai/api/v1` | **50 free requests/day**<br>(48 remaining today) | **ACTIVE & VERIFIED**<br>(Free models: Nemotron, Gemma, etc.) |
| **NVIDIA NIM** | Heavy Reasoning & Validation | `https://integrate.api.nvidia.com/v1` | **40 Requests / Minute (RPM)** | **ACTIVE & VERIFIED**<br>(Tested on `nemotron-3-super-120b-a12b`) |
| **Jina Reader** | Cloud Web & Markdown Scraping | `https://r.jina.ai` | **10,000,000 tokens free**<br>• 200 req/min | **ACTIVE & VERIFIED**<br>(Tested on Hacker News: 16k chars) |
| **Crawl4AI** | Local Headless JS Scraper | Local Playwright Engine | **100% FREE & UNLIMITED**<br>• Local Chromium/Firefox | **ACTIVE & VERIFIED**<br>(Local headless test: 1.2s) |
| **Crawlee** | Scaled Crawling & Spidering | Local Engine (Apify) | **100% FREE & OPEN SOURCE** | **INSTALLED & CONFIGURED** |
| **Firecrawl** | Cloud Scrape Fallback | `https://api.firecrawl.dev/v1` | **1,000 scrape credits/month**<br>(**1,022 remaining** through Oct 28) | **ACTIVE & VERIFIED**<br>(Scrape test passed: HTTP 200) |
| **Groq** | Fast Interface Controller | `https://api.groq.com/openai/v1` | **Free Tier (~6,000–30,000 TPM)** | Needs key in `.env` (`GROQ_API_KEY`) |
| **Gemini** | Backup LLM | `generativelanguage.googleapis.com` | N/A | Project denied (HTTP 403) |

---

## 2. NVIDIA NIM: Rate Limits & High-Throughput Capacity

- **Rate Limit:** **40 requests per minute (RPM)**.
- **Throughput:** Capable of handling high-speed bursts for heavy validation passes and reasoning without running into artificial token depletion caps.
- **Models Verified:** High-parameter foundation models like `nvidia/nemotron-3-super-120b-a12b`.
- **Role in Oracle:** Serves as the deep-reasoning verification lane for complex multi-turn exploit-chain analysis.

---

## 3. Firecrawl: Exact Usage & Remaining Balance

Firecrawl is used by Oracle for deep JavaScript rendering, web crawling, and dynamic page extraction during target reconnaissance.

- **Current Balance:** **1,022 remaining credits** (out of 1,000 plan baseline + carryover/bonus).
- **Billing Period:** Reset occurs on **October 28, 2026**.
- **Credit Cost:**
  - 1 credit = 1 full webpage scrape (including JavaScript execution, dynamic DOM extraction, and clean markdown generation).
  - 1,022 credits allows Oracle to deeply scrape **>1,000 in-scope web application targets** without any local headless browser overhead.

---

## 4. Daily Combined Throughput Capacity

With APInex, xKiro, NVIDIA NIM, and OpenRouter active:
- **Daily Token Ceiling:** **>15,000,000 tokens/day** (expanding to **>22,000,000 tokens/day** when Bynara is linked).
- **Zero Local Hardware Requirement:** The entire pipeline executes in the cloud at sub-second response times without loading 30B models into local RAM/VRAM.
- **Failover Order:**
  ```
  groq (if key set) -> xkiro -> apinex -> nvidia -> openrouter -> cloudflare -> local
  ```
