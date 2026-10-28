# The Forgetting Ledger

**Category:** Impossible Problem  
**Type:** 4 actually couldn't → broke through (reframed via reading the hole + trajectory closure + fading residue)  
**Status:** Solved  
**Posed:** 2026-08-28 (v1 initial seed) · Hardened: 2026-09-08 (v2 dual-sine) · Final Resolution: 2026-09-28 (v3 fading residue + chain trace fusion)  

---

## 🧩 The Prompt

> **Design a ledger where sixteen entries are written to forty-eight slots, and half of those slots are destroyed as the write happens. The order of destruction is driven by a hidden carry state that is never stored: no entry value, no carry state, and no digest of either survives in public data.**  
>  
> **Later, an untrusted party asserts what a past entry was at index $pos$. The verifier holds zero copies of the entry. Given only the surviving mask, the asserted claim, and the index, decide per row whether the assertion is genuine or forged.**  
>  
> **The system must be fair: naive value prediction must fail at the no-information floor ($F_1 \le 0.6749$), while a principled solver reading the absence can achieve confident deterministic verification.**

---

## 🎙️ Live Reasoning & Evolution

- **[Phase 1 — The Seed & The Initial Collapse]:**  
  Alex: *"We don't need to store the value. Store a relation the value satisfied, and let the destruction itself carry the rest."*  
  Initial attempts to implement this hit an information-theoretic barrier: raw mask features couldn't learn the state. Solvers scored $0.487$ (worse than a coin flip). If the carry wraps chaotically via modulo arithmetic, the state is folded onto a circle and cannot be recovered downstream.  

- **[Phase 2 — The Boreal Attack & Dual-Sine Hardening]:**  
  An adversary running Anthropic's RL agents (`claude-fable-5-1`) analyzed the generator and noticed a single harmonic warp ($1.0 + 0.45 \sin(s)$). Boreal extracted the write-center using a 1st-harmonic circular Fourier centroid ($\text{arctan2}$ of sine/cosine components) and scored $0.6975$, threatening a bypass.  
  Alex's response: *"The correct response to an adversarial crack is never to loosen the grader; it is to harden the generator."* He injected a 2nd harmonic ($0.45 \sin(s) + 0.30 \sin(2s)$). The dual-sine warp destroyed linear Fourier inversion (Boreal AUC dropped to $0.5029$, pure chance) while nonlinear temporal convolutions preserved signal.

- **[Phase 3 — The Fading Residue & Final Closure (v3)]:**  
  Pure downstream trajectory alone caused generic learners to stall at the floor. In v3, Alex introduced the *fading residue*: committing an entry directly biases the damage logits of the subsequent 4 writes through a fixed basis, decaying at $0.6$ per write.  
  Alex: *"The residue gives the task a learnable local footprint without making the full trajectory unnecessary. You fuse the chain path with the direct-trace head."*  
  Result: Reference challenge $F_1 = 0.865$, $\text{AUC} = 0.899$. Clean separation over baselines achieved.

---

## 🧠 The Move

- **What made it feel impossible:**  
  An external information-theoretic rule: conventional data science asserts that once data is erased and the carry state is wiped, verification without an authentic digest is mathematically impossible.  

- **The pivot:**  
  *Absence is not a void; absence has geometry.* A write does not occur in isolated space. It perturbs a stateful medium. The destruction mask is a physical boundary condition, and the writes that follow it are coupled through time.  

- **The resolution:**  
  **Dual-channel structural fusion:**  
  1. *The Trajectory Channel:* Ten writes following the claimed entry form a continuous nonlinear trajectory (nine edge records + tenth terminal state). Genuine claims close the trajectory; forged claims compound divergence.  
  2. *The Fading Residue Channel:* The immediate four writes retain a decaying physical bias from the entry's commitment.  
  By reading the hole together with the downstream ripple, the verifier establishes deterministic closure without ever needing an archived copy of the original data.

---

## Classification

- **Type 4 → Breakthrough:** Stalled in v1 across several QA rollouts due to modulo state-folding and contract mismatches; broken through in v2/v3 by designing the coupled nonlinear trajectory and decaying residue.  
- **Impossible problem vs. paradox:** Impossible Problem. The constraint ("you cannot verify without storage") was an external dogma of database architecture and cryptography. The rule was rewritten by turning destruction into an active carrier of relational proof.  
- **Crossover note:** Strongly validates [`The_Mind_That_Does_Not_Wait`](../../The_Mind_That_Does_Not_Wait.md.txt) (*"If the rule stands in the way, the rule moves"*). Instead of accepting that information loss destroys auditability, the architecture forces the universe to preserve truth in the geometry of the damage.

---

*Authored by Alexander Sorrell.*  
*Origin: `alignerr-ml-tasks/problems/absence-ledger`.*  
