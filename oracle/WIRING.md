# Wiring the Oracle into a model

The Oracle is a **system prompt** (`ORACLE_SYSTEM_PROMPT.md` — the 8 paradox→reflex worked
examples; code-loaded at runtime, treat as source). "Wiring it in" = loading that as the
model's system message, then handing it a target. `oracle.py` generates the prompt and, for
local, drives the model for you. For the full hunting pipeline (prescan/scan/queue/hunt
with wire verification) use `oracle_hunter.py` — see README §"The production pipeline".

---

## Path A — Claude (me), right now, zero setup
Best reasoning, no install. Two ways:

1. **Paste:** `python3 oracle.py --output-system-prompt` → paste into a Claude project's custom
   instructions (or the top of a chat). Then paste a target's recon and say "run the 8 reflexes."
2. **Feed rei directly:** `python3 oracle.py --feed ../rei/recon_data` → copy the whole output into
   Claude. It already contains the Oracle stance + your rei endpoints/forms + the task.

In this CLI you don't even need to paste — just tell me "be the Oracle on rei" and I load the file.

---

## Path B — Gemini (API or AI Studio)
Gemini takes a dedicated system instruction — put the Oracle there, target in the user turn.

```python
import google.generativeai as genai
genai.configure(api_key="...")
system = open("ORACLE_SYSTEM_PROMPT.md").read()
model = genai.GenerativeModel("gemini-2.5-pro", system_instruction=system)
recon = open("../rei/recon_data/RECON_REPORT.md").read()
print(model.generate_content(
    "Run the 8 reflexes on this in-scope target. For each seam: Assertion A, "
    "Assertion B, one curl. Rank by user harm.\n\n" + recon[:20000]
).text)
```
AI Studio: paste `ORACLE_SYSTEM_PROMPT.md` into the "System instructions" box, recon into the chat.

---

## Path C — Local model on your 64GB HP laptop (private, no API, no rate limit)

64GB RAM runs a real reasoning model on CPU. One-time setup:

```bash
curl -fsSL https://ollama.com/install.sh | sh            # install Ollama
ollama pull qwen2.5:32b-instruct-q4_K_M                  # ~20GB, the sweet spot
```

Then the Oracle drives it for you:

```bash
# One question, Oracle-minded:
python3 oracle.py --ask "Target claims /account/orders is auth-only. Where is that never enforced?"

# Feed rei recon straight into the local model and get ranked seams + curls:
python3 oracle.py --feed ../rei/recon_data --local
```

### Which model for 64GB (CPU)
| Model (Ollama tag) | RAM | Speed on CPU | Use |
|---|---|---|---|
| `qwen2.5:14b-instruct-q4_K_M` | ~10GB | fast (~8-15 tok/s) | quick passes, iteration |
| **`qwen2.5:32b-instruct-q4_K_M`** | ~20GB | usable (~3-6 tok/s) | **default — best reasoning that stays responsive** |
| `llama3.3:70b-instruct-q4_K_M` | ~42GB | slow (~1-2 tok/s) | deep dives when you can wait |

If the HP has an NVIDIA GPU, Ollama uses it automatically and every tier jumps 5-10×.
Change tiers with `--model`, e.g. `python3 oracle.py --feed ../rei/recon_data --local --model qwen2.5:14b-instruct-q4_K_M`.

### Hybrid (best value)
Local 14B does the wide pass over recon → isolates 2-3 candidate binary conflicts → send only those
isolated conflicts to Claude/Gemini for the exploit + PoC. Minimal cloud tokens, maximum reach.

In the hunt stack this hybrid is built in: API lanes run first (route order, caps,
total budgets, circuit breaker — Doctrine §2), and the shipped local floor is
`qwen3-coder:30b-16k` (heavy) / `qwen2.5-coder:14b-16k` (light) per
`oracle_backends.json`. The qwen2.5 tiers in the table above are `oracle.py`
prompt-feeder guidance, not the hunt stack's models.
