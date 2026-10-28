# Codex #01: AI is a relevance engine, not a truth oracle

- **Original Source URL**: [https://product.ai/research/relevance-engine-not-truth-oracle/](https://product.ai/research/relevance-engine-not-truth-oracle/)
- **Author**: Michael Quoc
- **Description**: Deconstructing the "pure automation" myth and the game-theoretic architecture of our "Human Compute Moat."
- **Archived Date**: 2026-10-22

---

## The Comfortable Lie We Tell Ourselves About AI

There is a seductive myth spreading through our industry: the myth of “pure automation.”

This story, peddled by hype cycles and wishful thinking, tells us that AI is a truth oracle. That with enough data and a large enough model, we can fully automate data validation. That Human-in-the-Loop (HITL) is just a temporary crutch, a set of training wheels we’ll discard as soon as the AI gets “smart enough.”

This is fundamentally, axiomatically false.

An LLM’s core function is to calculate probabilistic relevance. It is engineered to determine the next most likely token in a sequence, `P(token|context)`. It is a relevance engine.

A truth engine’s function is to perform deterministic validation. It must ascertain `P(statement is true|evidence)`.

These two objectives are mathematically independent. Optimizing for one does not optimize for the other.

“Hallucination” is not a bug or a flaw in the system; it is the system’s core function operating exactly as designed. When an LLM doesn’t know an answer, it generates the _most plausible-sounding_ one. For a relevance engine, this is a feature. For any system requiring verifiable truth, it is a catastrophic failure.

This creates a crisis for any high-stakes application. For an agentic shopping assistant to be trusted, it cannot be _mostly_ right. It must be _verifiably_ right. Building the future of agentic AI on a foundation of pure, unverified LLM output is like building a skyscraper on a foundation of mist. It is an architecture of brittleness.

## The “Messy” Reality: Why Data Truth at Scale is an Unsolved Problem

This isn’t a theoretical problem. This is the “data-work” no one wants to talk about.

At [Demand.io](http://Demand.io), we are building systems that require verifiable truth at the scale of the internet. **Our systems must test and verify millions of real-time e-commerce data points** —like coupon codes—across hundreds of thousands of merchants, in real-time. The public perception is that this is an automation problem. We are asked, “Why don’t you just use AI?”

We tried. We threw out the “automation-only” playbook years ago because it was a dead end.

We learned an “earned secret,” one that came from the messy work of failure: **Data truth at scale is not an automation problem; it is a human-compute problem.**

We realized that trust cannot be algorithmically generated. It must be socially constructed. The only way to validate truth at scale is to build a system that can manage a network of human verifiers and force them to converge on an objective truth.

We had to stop thinking like software engineers and start thinking like game theorists and micro-economists.

![](/research/relevance-engine-not-truth-oracle/assets/img-01.png)

## Architecting the “Human Compute Moat”

What we built is not “Human-in-the-Loop.” HITL is a simple tactic. What we built is an _architecture_.

We call it a **Byzantine-Fault-Tolerant (BFT) social system.**

This is a concept borrowed from cryptography and distributed systems. A BFT system is designed to achieve consensus on a single truth, even when a portion of the participants in the network (up to 1/3) are malicious, inaccurate, or have failed.

We didn’t just “add humans” to our system. We built a complex, gamified micro-economy with its own reputation ledgers and social incentives. This system is designed to programmatically scale _trust_.

Here is how the symbiosis works:

  1. **AI is the Relevance Engine:** Our AI systems scan the entire internet, scaling _relevance_. They identify millions of _potential_ codes, anomalies, and data points that need to be checked. The AI’s job is to ask the right questions and filter the noise.
  2. **The BFT Network is the Truth Engine:** Our human network, governed by game-theoretic rules, scales _trust_. The system routes the AI’s “questions” to multiple, independent human verifiers. These verifiers “stake” their reputation (which has real economic value in our system) on their answer. The system then seeks BFT consensus.



![](/research/relevance-engine-not-truth-oracle/assets/img-02.png)

When a verifier is correct, their reputation and earning power increase. When they are wrong—or worse, attempt to cheat—their reputation is slashed, and they are economically purged from the network.

![](/research/relevance-engine-not-truth-oracle/assets/img-03.png)

This is not a “community.” This is a decentralized, adversarial network engineered to produce a single, verifiable output: Truth. This is our “Human Compute Moat.”

## The Implications of Verifiable Truth

This architecture is about more than just coupon codes. That is merely the first high-stakes application.

This is the foundational component for all truly useful agentic AI.

The agentic systems of the future—the shopping assistants, the travel agents, the financial advisors—cannot function on a foundation of plausible hallucinations. They will require a “Proof-of-Human-Work” signal. They will need to plug into an engine that provides verifiable, deterministic truth.

In an agentic economy flooded with low-cost, plausible AI-generated content, verifiable truth becomes the single scarcest and most valuable economic resource. As the AI models themselves become commoditized, the economic value will migrate from the agent to the verifier.

The real moat isn’t the data itself. Data is ephemeral. The real, compounding, unassailable moat is the **engine that verifies it.**

## This is The Work

This system—this “Human Compute Moat”—is not a theoretical model. It is the engine we are actively building. It is the verifiable foundation for the agentic future of commerce.

Our core philosophy is public. Our axioms are the source code.

We believe high-friction, high-signal work is the only work worth doing.

* * *

This BFT “Human Compute Moat” is our architecture for scaling trust.

But this model—a symbiotic, BFT-governed network of AI and humans—feels like a primitive for something much larger. It’s an engine for verifying truth in one domain (commerce), but the applications are systemic.

This leads me to the open question I am currently deconstructing:

**If “Proof-of-Human-Work” becomes the ultimate source of value in an agentic economy, where else will this “Human Compute Moat” architecture be required? What other high-stakes systems (e.g., finance, law, science) will be forced to adopt a similar BFT social system to defend against a flood of AI-generated “plausible” data?**

I am deeply interested in your thoughts in the comments.
