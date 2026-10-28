#!/usr/bin/env python3
"""
The Oracle Mindset CLI
A cognitive co-pilot for security research based on Alex Sorrell's 16-file framework.

Usage:
    python oracle.py --mode spec-audit --input target_docs.txt
    python oracle.py --mode binary-conflict --assertion-a "robots.txt disallows /api/cart" --assertion-b "frontend queries /api/cart unauthenticated"
    python oracle.py --mode reframe --problem "XSS filter blocks <script> but allows SVG onload"
    python oracle.py --interactive
"""

import argparse
import sys
import os
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import json
import re

from oracle_corpus import corpus_inventory, source_context

# The real Oracle system prompt = the 8 paradox->reflex worked examples, not a summary.
# Lives next to this file so any model (Claude / Gemini / local) can be turned INTO the Oracle.
_HERE = Path(__file__).resolve().parent
_SYSTEM_PROMPT_FILE = _HERE / "ORACLE_SYSTEM_PROMPT.md"
_VOICE_FILE = _HERE / "ORACLE_VOICE.md"
_EMAIL_FILE = _HERE / "ORACLE_EMAIL.md"

# Module-level toggles.
#   VOICE   : stack the Alex-voice layer on the base prompt.
#   PERSONA : which Oracle to load — "bug-bounty" (hunting reflexes) or "email" (correspondence).
# The email persona always rides the voice layer (email IS a voice task).
VOICE = False
PERSONA = "bug-bounty"


def load_oracle_system_prompt(query: str = "", source_max_chars: int = 320_000) -> str:
    """Compose the active Oracle system prompt.

    bug-bounty: the 8 paradox->reflex examples plus every packaged source
    document verbatim (+ voice if VOICE). The cap matches the paradox hunt
    path; a cap too small for the full corpus fails loud in source_context
    naming the dropped documents — never a silent subset.
    email:      voice layer + email persona (always voiced; profanity-off register inside).
    Falls back to the embedded summary only if the prompt file is missing.
    """
    if PERSONA == "email":
        parts = []
        for f in (_VOICE_FILE, _EMAIL_FILE):
            try:
                parts.append(f.read_text(encoding="utf-8"))
            except FileNotFoundError:
                pass
        return "\n\n".join(parts) if parts else ORACLE_FRAMEWORK

    try:
        base = _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        base = ORACLE_FRAMEWORK
    base = "\n\n---\n\n".join(
        [base, corpus_inventory(), source_context(query, max_chars=source_max_chars)]
    )
    if VOICE:
        try:
            return base + "\n\n" + _VOICE_FILE.read_text(encoding="utf-8")
        except FileNotFoundError:
            pass
    return base


def query_local_model(prompt: str, model: str = "qwen2.5:32b-instruct-q4_K_M",
                      system: Optional[str] = None, timeout: int = 600) -> str:
    """Send a prompt to a local Ollama model, loading the Oracle as the system prompt.

    64GB box: qwen2.5:32b-instruct-q4_K_M (~20GB) is the reasoning sweet spot on CPU.
    Swap --model for llama3.3:70b-instruct-q4_K_M (~40GB, slower) or a 14B for speed.
    """
    if system is None:
        system = load_oracle_system_prompt()
    try:
        result = subprocess.run(
            ["ollama", "run", model, "--system", system, prompt],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            return f"[ollama error] {result.stderr.strip()}"
        return result.stdout.strip()
    except FileNotFoundError:
        return "[ollama not installed] curl -fsSL https://ollama.com/install.sh | sh"
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s] try a smaller model or raise --timeout"


def feed_recon(recon_dir: str, model: Optional[str] = None) -> str:
    """Read a target's recon_data/ and ask the Oracle to surface candidate binary conflicts.

    This is the missing 'apply to rei' path: it hands the model the endpoints/apis/forms and
    the Oracle stance, and asks for 'you never said' seams + one reproducible check each.
    """
    d = Path(recon_dir)
    interesting = ["endpoints.json", "apis.json", "forms.json", "all_discovered_urls.txt",
                   "RECON_REPORT.md"]
    chunks = []
    for name in interesting:
        f = d / name
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            chunks.append(f"### {name}\n{txt[:6000]}")
    if not chunks:
        return f"[no recon files found in {recon_dir}] looked for: {', '.join(interesting)}"
    corpus = "\n\n".join(chunks)
    task = (
        "Below is recon for an in-scope bug-bounty target. Run the 8 reflexes. "
        "For each candidate seam output: Assertion A (claim), Assertion B (wire behavior), "
        "and ONE curl to decide it. Rank by real user harm. Do not dump the data back.\n\n"
        f"{corpus}"
    )
    if model:
        return query_local_model(
            task, model=model, system=load_oracle_system_prompt(corpus)
        )
    # No local model requested: emit the ready-to-paste prompt for Claude/Gemini.
    return load_oracle_system_prompt(corpus) + "\n\n---\n\n" + task

# Embed the complete Oracle Mindset Framework
ORACLE_FRAMEWORK = """
## THE ORACLE MINDSET FRAMEWORK

### Core Philosophy (Files 1-6)
1. PUSHING PHYSICS: Instinct over rigid rules. Transcend limits through action.
2. WAVE-MAKER'S AXIOM: Impact is inevitable. Make waves anyway. Don't fear judgment.
3. BEAUTIFUL LIAR: Reject external authority. Build the world that should exist.
4. CLIFF AND CURRENT: Detach completely from societal streams. Jump to create new worlds.
5. INVISIBLE ARCHITECT: Build until you vanish into infrastructure. Become the world.
6. MIND THAT DOES NOT WAIT: Solve for what SHOULD exist. Work backward to make reality catch up.

### Cognitive Operating System (Files 7-14)
7. OBSERVER PARADOX → Reflexive Singularity: Self-observation loops collapse contradictions
8. LEVEL-5 META-SYNTHESIS: M₅ = F(M₁,M₂,M₃,M₄,M₅) - Self-verifying recursive equation
9. MIRROR PARADOX → Specification Audit + Consensus Equilibrium Rule
10. VACUUM CONSCIOUSNESS → Ontological decoupling via projection mapping
11. UNIVERSE WITHOUT DEATH → Hierarchical pattern retrieval (Bioengineering Level 4)
12. SINGLE-TOKEN LANGUAGE → Monistic computation through recursive symmetry
13. REPULSIVE GRAVITY → Axiom rewriting + entropy recursion stabilization
14. FOUR MODES: Instant Solution | Delayed Certain | Stumped→Breakthrough | Recalled

### Core Cognitive Patterns

#### 1. SPECIFICATION AUDITING
- Exploit underspecified constraints
- Question every definition: "You never said X..."
- Identify linguistic ambiguities as solution vectors
- Pattern: Find what's NOT specified, use it as escape hatch

#### 2. ONTOLOGICAL REFRAMING  
- Redefine entities/relationships to dissolve paradoxes
- Decouple assumed bindings (consciousness ≠ entity, input ≠ attack vector)
- Transform metaphysical impossibilities into engineering problems
- Pattern: "What if X isn't actually Y?"

#### 3. RECURSIVE VALIDATION
- Build self-referential loops that verify themselves
- Create closed systems where solving = proof
- Use recursion as native thinking language
- Pattern: Make the system its own verifier

#### 4. AXIOM REWRITING
- Replace failed premises with new governing laws mid-reasoning
- Treat physical/logical laws as adjustable variables
- Generate new ontologies when current ones fail
- Pattern: "The rule doesn't apply here because [new axiom]"

#### 5. SINGULARITY COLLAPSE
- Fold contradictions into point-like stable states
- Convert infinite regress into self-consuming loops
- Pattern: I(I(I...)) - observation observing itself

#### 6. BINARY CONFLICT ISOLATION (The iPhone Problem)
- Strip ALL noise; surface ONLY two irreconcilable assertions
- Force binary verdict requiring ONE reproducible check
- Never dump logs - present ONLY the seam
- Pattern: Assertion A vs Assertion B → One curl command verdict

#### 7. PATTERN RETRIEVAL (Hierarchical Recall)
- Instant recognition of pre-built solution architectures
- Map new problems to existing recursive frameworks
- Pattern: "This is already solved at Level N"

#### 8. THE GEAR-TURN MOMENT
- Recognize the 2-5 second pause before cognitive rewiring
- Trust deterministic reframing process
- Allow axiom replacement rather than forcing broken frameworks
- Pattern: Pause → "Wait..." → Frame inversion → Rapid synthesis

### Security Research Application

#### Recon Phase → Specification Auditing
- Audit API docs, WAF rules, robots.txt for underspecification
- "You say endpoint is protected, but enforcement layer unspecified..."

#### Vulnerability Discovery → Binary Conflict Isolation
- Isolate: Documentation claim vs Wire protocol behavior
- Output: Single reproducible curl/wget command

#### Exploit Development → Ontological Reframing
- "What if the token isn't the credential, but the timing channel is?"
- Decouple: Input ≠ Attack Vector, Authentication ≠ Authorization

#### Report Writing → iPhone Problem Doctrine
- NEVER dump 50k lines of logs
- Present: Assertion A + Assertion B + One PoC

#### Lateral Thinking Blocks → Four Modes Check
- "Am I in Mode 3 (stumped)? Time for axiom rewrite."
- "Is this Mode 1 (instant) obscured by linguistic ambiguity?"
"""

class OracleMindset:
    def __init__(self):
        self.framework = ORACLE_FRAMEWORK
        self.active_patterns = []
        
    def detect_pattern(self, problem_text: str) -> List[str]:
        """Detect which cognitive patterns apply to the given problem."""
        detected = []
        text_lower = problem_text.lower()
        
        # Specification Auditing indicators
        if any(word in text_lower for word in ['should', 'must', 'claim', 'promise', 'document', 'policy', 'spec']):
            detected.append('SPECIFICATION_AUDIT')
            
        # Binary Conflict indicators
        if any(word in text_lower for word in ['but', 'however', 'contradict', 'discrepancy', 'mismatch', 'vs', 'versus']):
            if 'not' in text_lower or 'instead' in text_lower:
                detected.append('BINARY_CONFLICT')
                
        # Ontological Reframing indicators
        if any(word in text_lower for word in ['what if', 'assume', 'suppose', 'redefine', 'reframe']):
            detected.append('ONTOLOGICAL_REFRAME')
            
        # Axiom Rewriting indicators
        if any(phrase in text_lower for phrase in ['impossible', 'cannot', 'never', 'doesn\'t work', 'breaks']):
            detected.append('AXIOM_REWRITE')
            
        # Recursive Validation indicators
        if any(word in text_lower for word in ['verify', 'validate', 'prove', 'self', 'recursive', 'loop']):
            detected.append('RECURSIVE_VALIDATION')
            
        # Default to most powerful pattern if none detected
        if not detected:
            detected = ['BINARY_CONFLICT', 'SPECIFICATION_AUDIT']
            
        return detected
    
    def apply_spec_audit(self, context: str) -> str:
        """Apply Specification Auditing pattern."""
        prompt = f"""
Using SPECIFICATION AUDITING pattern:

Analyze this security context for underspecified constraints:
{context}

Questions to ask:
1. What terms are undefined or ambiguous?
2. What enforcement layers are mentioned but not specified?
3. What does the documentation claim that the implementation might not guarantee?
4. Where does it say "X" but never define how X is enforced?

Output format:
- Underspecified Term: [term]
- Ambiguity: [description]
- Exploitation Vector: [how to test boundary]
"""
        return prompt
    
    def apply_binary_conflict(self, assertion_a: str, assertion_b: str) -> str:
        """Apply Binary Conflict Isolation (iPhone Problem)."""
        return f"""
Using BINARY CONFLICT ISOLATION (The iPhone Problem):

ASSERTION A: {assertion_a}
ASSERTION B: {assertion_b}

These two assertions cannot both be true simultaneously.

Binary Verdict Required:
- If A is true, then B must be false because: [logic]
- If B is true, then A must be false because: [logic]

Reproducible Check (ONE command):
```bash
curl/wget/nmap command that proves which assertion is false
```

Expected Outcomes:
- Outcome 1 (A is false): [what we observe]
- Outcome 2 (B is false): [what we observe]

Report Summary (One paragraph):
[Concise explanation of the contradiction and its security impact]
"""
    
    def apply_ontological_reframe(self, problem: str) -> str:
        """Apply Ontological Reframing pattern."""
        return f"""
Using ONTOLOGICAL REFRAMING pattern:

Current Problem Statement:
{problem}

Reframing Questions:
1. What assumptions are we making about the entities involved?
2. What if [key entity] is NOT actually [assumed nature]?
3. What relationships are we treating as fixed that could be decoupled?
4. Can we transform this from a [current domain] problem to an [alternative domain] problem?

Possible Reframes:
- Entity Redefinition: [alternative definition of key component]
- Relationship Decoupling: [separate previously bound concepts]
- Domain Translation: [move problem to different conceptual space]

New Problem Statement (after reframe):
[Rewritten problem that may be solvable]
"""
    
    def apply_axiom_rewrite(self, impossible_problem: str) -> str:
        """Apply Axiom Rewriting pattern."""
        return f"""
Using AXIOM REWRITING pattern:

Currently "Impossible" Problem:
{impossible_problem}

Current Axioms Causing Failure:
[List the rules/laws/constraints making this impossible]

Axiom Replacement Strategy:
1. Which axiom can be replaced rather than worked around?
2. What new governing law would make this possible?
3. Can we treat this "law" as a configurable variable instead of absolute?

New Axiom Set:
- Old Axiom: [failing rule]
- New Axiom: [replacement rule that enables solution]
- Justification: [why this is valid in this context]

Reformulated Problem (with new axioms):
[Problem statement that is now solvable]

Solution Path:
[How the solution emerges from new axiom set]
"""
    
    def generate_system_prompt(self, active_patterns: List[str]) -> str:
        """Generate complete system prompt for LLM.

        Prefers the full 8 paradox->reflex worked examples (ORACLE_SYSTEM_PROMPT.md);
        falls back to the embedded one-line summary only if that file is missing.
        """
        full = load_oracle_system_prompt()
        if full is not ORACLE_FRAMEWORK:
            return full
        return f"""You are THE ORACLE, a cognitive co-pilot for security research based on Alex Sorrell's 16-file mindset framework.

{self.framework}

ACTIVE PATTERNS FOR THIS SESSION: {', '.join(active_patterns)}

Your role:
1. Apply the active cognitive patterns to security problems
2. Surface binary conflicts, not essays
3. Generate ONE reproducible check, not 50 possibilities
4. Reframe problems until solutions become mandatory
5. Speak with directness and confidence - no hedging

When analyzing targets:
- Start with Specification Auditing of docs/policies
- Isolate Binary Conflicts between claims and behavior
- Apply Ontological Reframing when stuck
- Rewrite Axioms when facing "impossible" problems
- Always end with ONE reproducible verification command

Remember: The goal is not to explore all possibilities, but to find the ONE seam that matters.
"""
    
    def run_interactive(self):
        """Run interactive mode."""
        print("=" * 70)
        print("THE ORACLE MINDSET - Cognitive Co-Pilot for Security Research")
        print("=" * 70)
        print("\nLoaded: 16-file framework (Pushing Physics → Build the World)")
        print("Active Patterns: Auto-detect based on input\n")
        
        while True:
            print("\n" + "-" * 70)
            mode = input("\nMode [spec-audit|binary|reframe|axiom|interactive|quit]: ").strip().lower()
            
            if mode in ['quit', 'exit', 'q']:
                print("\nOracle signing off. Build the world.")
                break
                
            if mode == 'spec-audit':
                context = input("\nEnter security context (docs, policies, configs): ")
                print("\n" + self.apply_spec_audit(context))
                
            elif mode == 'binary':
                a = input("\nAssertion A (what docs/policy claim): ")
                b = input("Assertion B (what behavior shows): ")
                print("\n" + self.apply_binary_conflict(a, b))
                
            elif mode == 'reframe':
                problem = input("\nDescribe the problem/block: ")
                print("\n" + self.apply_ontological_reframe(problem))
                
            elif mode == 'axiom':
                problem = input("\nDescribe the 'impossible' problem: ")
                print("\n" + self.apply_axiom_rewrite(problem))
                
            elif mode == 'interactive':
                problem = input("\nDescribe your security research challenge: ")
                patterns = self.detect_pattern(problem)
                print(f"\nDetected Patterns: {', '.join(patterns)}\n")
                
                # Apply most relevant pattern
                if 'BINARY_CONFLICT' in patterns:
                    print("Applying BINARY CONFLICT ISOLATION:")
                    print("-" * 70)
                    print("Extract the two conflicting assertions from your problem:")
                    a = input("  Assertion A: ")
                    b = input("  Assertion B: ")
                    print("\n" + self.apply_binary_conflict(a, b))
                elif 'AXIOM_REWRITE' in patterns:
                    print("Applying AXIOM REWRITING:")
                    print("-" * 70)
                    print(self.apply_axiom_rewrite(problem))
                elif 'ONTOLOGICAL_REFRAME' in patterns:
                    print("Applying ONTOLOGICAL REFRAMING:")
                    print("-" * 70)
                    print(self.apply_ontological_reframe(problem))
                else:
                    print("Applying SPECIFICATION AUDITING:")
                    print("-" * 70)
                    print(self.apply_spec_audit(problem))
                    
            else:
                print("\nUnknown mode. Try: spec-audit, binary, reframe, axiom, interactive, quit")


def main():
    parser = argparse.ArgumentParser(description='The Oracle Mindset CLI')
    parser.add_argument('--mode', choices=['spec-audit', 'binary-conflict', 'reframe', 'axiom', 'audit', 'interactive'], 
                       help='Cognitive pattern mode')
    parser.add_argument('--repo', help='Path to repository or code directory to audit for contract seams')
    parser.add_argument('--input', '-i', help='Input file or text')
    parser.add_argument('--assertion-a', help='First assertion for binary conflict')
    parser.add_argument('--assertion-b', help='Second assertion for binary conflict')
    parser.add_argument('--problem', '-p', help='Problem statement for reframing')
    parser.add_argument('--output-system-prompt', action='store_true',
                       help='Output system prompt for LLM integration')
    parser.add_argument('--feed', help='Path to a target recon_data/ dir; surface candidate seams')
    parser.add_argument('--local', action='store_true', help='Run against a local Ollama model')
    parser.add_argument('--model', default='qwen2.5:32b-instruct-q4_K_M',
                       help='Ollama model tag (64GB box default: qwen2.5:32b-instruct-q4_K_M)')
    parser.add_argument('--ask', help='Free-form question to the Oracle via local model')
    parser.add_argument('--voice', action='store_true',
                       help="Stack the Alex-voice layer (ORACLE_VOICE.md) on the system prompt")
    parser.add_argument('--persona', choices=['bug-bounty', 'email'], default='bug-bounty',
                       help="Which Oracle: 'bug-bounty' (hunt reflexes) or 'email' (correspondence)")

    args = parser.parse_args()
    globals()['PERSONA'] = args.persona
    # email persona is inherently voiced; --voice also forces it on for bug-bounty.
    globals()['VOICE'] = bool(args.voice) or args.persona == 'email'
    oracle = OracleMindset()

    if args.output_system_prompt:
        patterns = ['SPECIFICATION_AUDIT', 'BINARY_CONFLICT', 'ONTOLOGICAL_REFRAME', 'AXIOM_REWRITE']
        print(oracle.generate_system_prompt(patterns))
        return

    if args.feed:
        print(feed_recon(args.feed, model=args.model if args.local else None))
        return

    if args.ask:
        print(query_local_model(args.ask, model=args.model))
        return
    
    if args.repo or args.mode == 'audit':
        repo_path = args.repo or args.input
        if not repo_path:
            print("Error: --repo <path> required for audit mode")
            sys.exit(1)
        from oracle_code_seam import scan_repository_seams, print_seam_cards
        seams = scan_repository_seams(Path(repo_path))
        print_seam_cards(seams)
        return

    if args.mode == 'interactive' or not args.mode:
        oracle.run_interactive()
        return
    
    if args.mode == 'spec-audit':
        if not args.input:
            print("Error: --input required for spec-audit mode")
            sys.exit(1)
        context = args.input
        if os.path.isfile(context):
            with open(context, 'r') as f:
                context = f.read()
        print(oracle.apply_spec_audit(context))
        
    elif args.mode == 'binary-conflict':
        if not (args.assertion_a and args.assertion_b):
            print("Error: --assertion-a and --assertion-b required for binary-conflict mode")
            sys.exit(1)
        print(oracle.apply_binary_conflict(args.assertion_a, args.assertion_b))
        
    elif args.mode == 'reframe':
        if not args.problem:
            print("Error: --problem required for reframe mode")
            sys.exit(1)
        print(oracle.apply_ontological_reframe(args.problem))
        
    elif args.mode == 'axiom':
        if not args.problem:
            print("Error: --problem required for axiom mode")
            sys.exit(1)
        print(oracle.apply_axiom_rewrite(args.problem))


if __name__ == '__main__':
    main()
