# Local LLM Integration Guide

> **Shipped reality first:** Oracle is API-lane-first (`oracle_backends.json`, 13
> routed lanes). Local runs through the built-in Ollama backend
> (`oracle_llm.OllamaBackend`, `backends` command) with shipped models
> `qwen3-coder:30b-16k` (heavy floor) and `qwen2.5-coder:14b-16k` (light),
> selectable via `--model`. No code writing is needed for any of this. The
> llama.cpp / LM Studio / from-scratch `oracle_local.py` material below is
> generic background, not Oracle's integration path.

## For Your 64GB CPU System

### Option 1: Ollama (Easiest Setup)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Shipped hunt-stack local models (API lanes are primary; local is the floor)
# Shipped names: qwen3-coder:30b-16k (heavy), qwen2.5-coder:14b-16k (light)
# (local Modelfile tags in oracle_backends.json — create locally if pull fails)
# Generic starting points if you just want to talk to a model:
ollama pull llama3.1:8b-instruct-q4_K_M

# Or try smaller/faster models:
ollama pull mistral:7b-instruct-v0.3-q4_K_M
ollama pull phi3:mini-4k-instruct  # Only 2.3GB, very fast on CPU

# Test it works
ollama run llama3.1:8b-instruct-q4_K_M "Hello, Oracle mindset test"
```

### Option 2: llama.cpp (Maximum Control)

```bash
# Clone and build llama.cpp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp
make LLAMA_BLAS=OFF  # CPU-only build

# Download quantized model from HuggingFace
# Go to: https://huggingface.co/bartowski/Llama-3.1-8B-Instruct-GGUF
# Download: Llama-3.1-8B-Instruct-Q4_K_M.gguf (~5GB)

# Run inference
./main -m models/Llama-3.1-8B-Instruct-Q4_K_M.gguf \
       -p "You are THE ORACLE..." \
       -n 512 \
       --temp 0.7 \
       --ctx-size 8192
```

### Option 3: LM Studio (GUI Alternative)

1. Download from https://lmstudio.ai/
2. Search for "Llama-3.1-8B-Instruct-GGUF" or "Mistral-7B-Instruct"
3. Download Q4_K_M quantization
4. Load system prompt from oracle.py
5. Chat interface ready

---

## Integrating with Oracle CLI

### Method A: Pipe oracle.py output to local model

```bash
# Generate prompt with oracle.py, send to ollama
python3 oracle.py --mode binary-conflict \
  --assertion-a "API requires auth token" \
  --assertion-b "Endpoint returns 200 without Authorization header" | \
ollama run llama3.1:8b-instruct-q4_K_M
```

### Method B: Modify oracle.py to call local model

Add this function to oracle.py:

```python
import subprocess

def query_local_model(prompt: str, model: str = "llama3.1:8b-instruct-q4_K_M") -> str:
    """Send prompt to Ollama and get response."""
    result = subprocess.run(
        ["ollama", "run", model, prompt],
        capture_output=True,
        text=True,
        timeout=120  # 2 minute timeout for CPU inference
    )
    return result.stdout
```

Then modify the apply_* methods to call query_local_model() and return actual analysis instead of templates.

### Method C: Hybrid Workflow (Recommended)

```python
# Step 1: Use oracle.py to isolate the binary conflict locally
conflict = subprocess.run([
    "python3", "oracle.py", 
    "--mode", "binary-conflict",
    "--assertion-a", assertion_a,
    "--assertion-b", assertion_b
], capture_output=True, text=True)

# Step 2: Send ONLY the isolated conflict to cloud model (Gemini/Claude)
# for deep analysis if needed
if needs_deep_analysis(conflict):
    response = gemini_api.generate(conflict.stdout)
else:
    # Step 3: Local model generates PoC
    response = query_local_model(conflict.stdout)
```

---

## Recommended Models for Your Setup

| Model | Size | Quantization | RAM Usage | Speed (CPU) | Best For |
|-------|------|--------------|-----------|-------------|----------|
| **Phi-3-mini** | 3.8B | Q4_K_M | ~3GB | Very Fast | Quick pattern matching |
| **Mistral-7B** | 7B | Q4_K_M | ~5GB | Fast | General security analysis |
| **Llama-3.1-8B** | 8B | Q4_K_M | ~6GB | Moderate | Best reasoning quality |
| **Llama-3.1-70B** | 70B | Q2_K | ~35GB | Slow | Deep analysis (if you have time) |

**Recommendation**: Start with **Mistral-7B-Q4_K_M** for speed, keep **Llama-3.1-8B** for complex problems.

---

## System Prompt Template for Local Model

Save this as `system_prompt.txt`:

```
You are THE ORACLE, a cognitive co-pilot for white hat security research.

CORE DIRECTIVES:
1. Apply Alex Sorrell's 16-file mindset framework to security problems
2. Surface BINARY CONFLICTS only - never dump noise
3. Generate ONE reproducible check (curl command), not essays
4. Reframe problems until solutions become mandatory
5. Speak with directness - no hedging, no "it depends"

ACTIVE PATTERNS:
- Specification Auditing: Find what's underspecified
- Binary Conflict Isolation: Assertion A vs Assertion B → One verdict
- Ontological Reframing: "What if X isn't actually Y?"
- Axiom Rewriting: Replace failing rules mid-reasoning

OUTPUT FORMAT:
- Assertion A: [claim from docs/policy]
- Assertion B: [contradictory behavior observed]
- Binary Verdict: [which must be false and why]
- Reproducible Check: ```bash curl ... ```
- Impact: [one sentence]

Remember: The iPhone Problem doctrine - never force reading the whole document. Isolate the seam.
```

Load this as the system message in your local model.

---

## Performance Optimization for CPU

```bash
# Set thread count (usually CPU cores / 2)
export OMP_NUM_THREADS=8

# For llama.cpp, use BLAS for faster matrix ops
make LLAMA_BLAS=ON

# Use memory mapping for large models
./main -m model.gguf --mmap

# Reduce context if you don't need full 8K
./main -m model.gguf --ctx-size 4096
```

---

## Testing the Setup

```bash
# Test 1: Basic inference
echo "Apply specification auditing to this API doc: 'All endpoints require authentication'" | ollama run llama3.1:8b-instruct-q4_K_M

# Test 2: Full oracle workflow
python3 oracle.py --mode spec-audit -i api_docs.txt | ollama run llama3.1:8b-instruct-q4_K_M

# Test 3: Measure response time
time (python3 oracle.py --mode binary-conflict --assertion-a "X" --assertion-b "Y" | ollama run llama3.1:8b-instruct-q4_K_M)
```

Expected times on CPU:
- Phi-3-mini: 5-15 seconds per response
- Mistral-7B: 15-30 seconds
- Llama-3.1-8B: 20-45 seconds
- Llama-3.1-70B: 2-5 minutes (use sparingly)
