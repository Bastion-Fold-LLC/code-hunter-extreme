# Qwen asset list + cost analysis (2026-10-01)

Source: https://huggingface.co/Qwen/collections (37 collections, verified live)
Pricing: https://openrouter.ai/api/v1/models (verified live, 54 Qwen models)

## Qwen3-Coder family (what Alex asked for)

| HF model | Size | OpenRouter ID | In / Out per 1M | Context |
|---|---|---|---|---|
| Qwen3-Coder-480B-A35B-Instruct | 480B MoE | qwen/qwen3-coder | $0.30 / $1.00 | 262k |
| Qwen3-Coder-30B-A3B-Instruct | 30B MoE | qwen/qwen3-coder-30b-a3b-instruct | $0.07 / $0.28 | 262k |
| Qwen3-Coder-Next | 80B MoE | qwen/qwen3-coder-next | $0.12 / $0.80 | 262k |
| Qwen3-Coder-Flash | — | qwen/qwen3-coder-flash | $0.20 / $0.97 | 1M |
| Qwen3-Coder-Plus | — | qwen/qwen3-coder-plus | $0.65 / $3.25 | 1M |
| Qwen2.5-Coder-32B-Instruct | 32B | qwen/qwen-2.5-coder-32b-instruct | $0.66 / $1.00 | 32k |

No free coder variant exists. Only free Qwen on OpenRouter: qwen/qwen3.8-27b:free (not a coder model).

## All 37 HF collections

Qwen3.8-Flash-Next, Qwen-AgentWorld, WebWorld, Qwen3.6, Qwen3-Coder-Next,
Qwen3-TTS, Qwen3-VL-Embedding, Qwen3Guard, Qwen3-Next, Qwen3-Coder,
Qwen3-Reranker, WorldPM, Qwen2.5-VL, QVQ, Qwen2.5-Coder, Qwen2.5, Qwen2-Audio,
Qwen2, Qwen, Qwen3.8, Qwen-Image-Bench, Qwen-Scope, Qwen3.5, Qwen3-ASR,
Qwen3-VL-Reranker, Qwen3-VL, Qwen3-Omni, Qwen-Image, Qwen3, Qwen3-Embedding,
Qwen2.5-Omni, Qwen2.5-1M, QwQ, Qwen2.5-Math, Qwen2-VL, Qwen2-Math, Qwen1.5

## Cost per hunt (estimate)

A full hunt runs ~8 reflex passes + analysis/finalize against the big mindset
system prompt. Rough: ~150–250k input tokens, ~20–40k output tokens per hunt.

| Model | Est. cost/hunt | Hunts on $10 key |
|---|---|---|
| qwen3-coder-30b-a3b-instruct | ~$0.02–0.03 | ~300–500 |
| qwen/qwen3-coder (480B) | ~$0.07–0.10 | ~100–140 |

Estimates, not guarantees — real usage varies with recon volume.

## Wiring (oracle_backends.json)

Current: `allow_paid_openrouter: false` → free models only (why we got qwen2.5:3b).
To use Qwen3-Coder:
1. Set `allow_paid_openrouter: true`
2. Add `openrouter: {reflex_preferred: ["qwen/qwen3-coder-30b-a3b-instruct"]}`
   (or `qwen/qwen3-coder` for the flagship)
Router tries preferred first, falls back to discovery order. Local backend stays
in the route as backup.
