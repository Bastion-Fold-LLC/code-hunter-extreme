# Oracle & The Vortex System: Comprehensive Architecture, Mechanics, and Triad Guide

---

## Executive Summary

The autonomous security research ecosystem is structured around two high-leverage frameworks designed to discover, verify, and prove payable vulnerabilities at scale—**with a planned grand convergence where all of Oracle will fold directly into the Vortex System**:

1. **Oracle**: A deterministic-core, multi-platform bug bounty pipeline for Web2, Web3, and AI application surfaces. It couples an automated sensor intake with a **Three-Mindset Cognitive Operating System** (MITRE ATT&CK tactics, 16 paradox/impossible-problem philosophy lenses, and adversarial synthesis), a dual-engine analysis phase (Type-1 deterministic code/spec seams and Type-2 LLM-driven logic reflexes), and a **5-gate deterministic wire-verifier** that strictly enforces reproducible binary conflicts before chaining findings into high-severity submission packages.
2. **The Vortex System**: A specialized Web3 smart-contract vulnerability discovery, adversarial court, and exploit-synthesis framework spanning eight blockchain ecosystems. Built around three decoupled organs that can run standalone or orchestrated as a triad:
   - **Basilisk (FIND)**: Purely deterministic, keyless, networkless vulnerability hunter combining external engine wrappers and native tree-sitter AST/per-chain structural detectors over a reactive neuron mesh. **Strictly zero LLMs.**
   - **CodeCrusher (PROVE / JUDGE / SEAL)**: The adversarial proving ground where LLMs operate under strict constraints. It funnels candidates through a 5-role adversarial court with a deterministic, non-LLM Judge (capped at `PLAUSIBLE`), and mints `CONFIRMED` exploits exclusively via a deterministic local blockchain fork simulator (`fork_replay.py` / Anvil). Every stage produces tamper-evident, cross-language Keccak receipts anchored on-chain.
   - **Vortex Anchor (CONDUCTOR & EYES)**: The thin conductor that manages authenticated platform ingestion (`api-maker` via Playwright and logged-in browser profiles—no exposed API keys), enforces out-of-band scope and bounty policy filters, and routes data across a tree of discovery-based ZeroMQ (SZMQ/VZMQ) sockets with zero hardcoded paths and zero silent fallbacks.

3. **The Grand Convergence (Section 7)**: The definitive end-state architecture where Oracle's sensor intake folds into **Vortex Anchor**, the Type-1 Invisible Seam folds into **Basilisk**, and the Three-Mindset Cognitive OS & 5-Gate Wire Verifier fold into **CodeCrusher**, unifying all Web2, API, and Web3 hunting over a shared ZeroMQ event bus.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                ORACLE PIPELINE                                   │
│  Scan4Me Sensors ──► Prescan ──► Live Scope Verify ──► Queue ──► Targeted Recon  │
│                                                                        │         │
│  ┌─────────────────────────────────────────────────────────────────────▼──────┐  │
│  │                    THREE-MINDSET COGNITIVE OS                              │  │
│  │  Mindset 1: MITRE ATT&CK         Mindset 2: 16 Paradoxes / Spec Inversion   │  │
│  │  ├─ TTP playbooks & tactics      ├─ "You never said..." ontological moves │  │
│  │  └─ Protocol/API logic vectors   └─ Binary Conflict Isolation (iPhone)    │  │
│  │                                                                           │  │
│  │                     Mindset 3: Adversarial Synthesis                      │  │
│  │                     (Attack, discard noise, rank & chain)                 │  │
│  └─────────────────────────────────────┬─────────────────────────────────────┘  │
│                                        │                                         │
│            ┌───────────────────────────┴───────────────────────────┐             │
│            ▼                                                       ▼             │
│   Type-1: Invisible Seam                                  Type-2: 8 Reflexes     │
│   (Claim vs Reality in Code)                              (Logic / Auth Vectors) │
│            │                                                       │             │
│            └───────────────────────────┬───────────────────────────┘             │
│                                        ▼                                         │
│                        5-Gate Deterministic Wire Verifier                        │
│                   (Grounding · Scope · Spec · Citations · Wire Match)            │
│                                        │                                         │
│                                        ▼                                         │
│                        Small-to-Money Severity Chaining                          │
│                                        │                                         │
│                                        ▼                                         │
│                        Submission-Ready Report Drafting                          │
└────────────────────────────────────────┼─────────────────────────────────────────┘
                                         │ (Web3 Smart Contract Findings)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               THE VORTEX SYSTEM                                  │
│                                                                                  │
│    VORTEX ANCHOR (Conductor & Eyes)                                              │
│    ├─ Headless authenticated platform ingestion (api-maker / saved creds)       │
│    ├─ Scope boundaries & company bounty rule gate                                │
│    └─ Pure ZMQ event bus (VZMQ ──► BZMQ / CCZMQ)                                 │
│                 │                                                                │
│                 ▼                                                                │
│    BASILISK (The FIND Half) — Deterministic, NO LLMs                             │
│    ├─ Shared Spine (Finder registry, Finding schema, bus)                        │
│    ├─ Multi-Chain Adapters (EVM, Solana, Move, TON, Cairo, NEAR, ink!, Wasm)     │
│    ├─ Manifest Tool Wrappers (Slither, Mythril, Aderyn, Semgrep, Echidna)        │
│    ├─ Chain-Specific Structured Detectors (PDA bumps, abilities, cell bits)      │
│    └─ Reactive Neuron Mesh (small-to-money composition)                          │
│                 │                                                                │
│                 ▼ Candidate Findings (Zero Confirmation)                         │
│    CODECRUSHER (The PROVE / JUDGE / SEAL Half) — First LLM Entry                 │
│    ├─ Scanners & Claim Verification (Robotruth)                                  │
│    ├─ 5-Role Adversarial Court (Hexbreaker: Prosecutor, Defender, Judge, etc.)   │
│    │  └─ Deterministic Non-LLM Judge (Verdicts capped strictly at PLAUSIBLE)     │
│    ├─ Fork Replay Prover (Argus / Anvil / Foundry)                               │
│    │  └─ ONLY entity permitted to mint "CONFIRMED" upon real execution           │
│    ├─ Tamper-Evident Keccak Hash Receipts & On-Chain Anchors (Glass-Box)         │
│    └─ Enclave / TEE Governance & Hardware Budget Caps (Terminal3)                │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Oracle: Autonomous Bug Hunting & The Three-Mindset Architecture

### 1.1 Core Epistemology & Doctrine

Oracle is built on non-negotiable principles defined in its authoritative doctrine:

- **"All code has bugs."** A hunt that yields 0 findings never proves that a target is secure; it proves only that the current tooling, reflexes, or depth were insufficient. A miss is a sharpening task, never a pass.
- **The AI Proposes, Deterministic Code Proves.** Language models are creative hypothesis generators, but they are never permitted to confirm findings. Confirmation requires physical evidence: a live HTTP interaction proving a binary conflict or an on-chain execution trace.
- **Small-to-Money Chaining.** Single low-severity findings (e.g., informative disclosures or missing headers) have negligible commercial value. Real rewards come from composing multiple minor seams (a leaked route + an unvalidated role header + a state desynchronization) into an unbreakable Critical exploit chain.

### 1.2 The Three Mindsets

Rather than relying on basic prompt engineering, Oracle injects a structured cognitive operating system into its analytical passes:

```
                  ┌────────────────────────────────────────┐
                  │          Raw Recon & Asset Feed        │
                  └───────────────────┬────────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
  ┌───────────────────────┐                       ┌───────────────────────┐
  │       MINDSET 1       │                       │       MINDSET 2       │
  │     MITRE ATT&CK      │                       │   PARADOX & INVERSION │
  ├───────────────────────┤                       ├───────────────────────┤
  │ Full-weight tactics:  │                       │ 16 Philosophy Texts:  │
  │ Initial Access, Priv  │                       │ Specification Audit,  │
  │ Escalation, Defense   │                       │ Ontological Reframing,│
  │ Evasion, Credential   │                       │ Binary Conflict,      │
  │ Access, Exfiltration  │                       │ "You never said..."   │
  └───────────┬───────────┘                       └───────────┬───────────┘
              │                                               │
              └───────────────────────┬───────────────────────┘
                                      ▼
                          ┌───────────────────────┐
                          │       MINDSET 3       │
                          │ ADVERSARIAL SYNTHESIS │
                          ├───────────────────────┤
                          │ Cross-evaluates L1+L2 │
                          │ Discards ungrounded   │
                          │ Chains compound links │
                          │ Ranks highest impact  │
                          └───────────────────────┘
```

1. **Mindset 1: MITRE ATT&CK (Full Weight)**
   - Operates with real enterprise and cloud technique definitions (e.g., T1190 Exploit Public-Facing App, T1078 Valid Accounts, T1552 Unsecured Credentials).
   - Evaluates technical trust boundaries, API gateway rules, and authorization tokens against systematic threat actor procedures.

2. **Mindset 2: Philosophy & Paradox Inversion**
   - Grounded in 16 core philosophical texts (e.g., *The Wave-Maker's Axiom*, *The Beautiful Liar*, *The Cliff and the Current*, *The Invisible Architect*, *The iPhone Problem*).
   - Employs the **"You never said..."** inversion pattern to find unstated assumptions:
     - *Vacuum Consciousness*: "You never said the path name is the enforcement layer."
     - *The Beautiful Liar*: "You never said the server validated the role claim; you only proved the client trusts it."
     - *Mirror Paradox*: "You never said the deprecated v1 API stopped processing transactions under the old rules."
     - *The iPhone Problem (Binary Conflict Isolation)*: Strips away narrative noise until exactly two contradictory assertions remain (e.g., "Documentation asserts authentication is mandatory" vs. "Wire trace reveals unauthenticated OPTIONS bypass").

3. **Mindset 3: Adversarial Synthesis**
   - Ingests candidate seams from Mindset 1, Mindset 2, and the deterministic Type-1 code seam engine.
   - Executes an internal red-team audit: aggressively attacks assumptions, prunes hallucinations, and constructs compound attack paths. Mindset 3 never fabricates findings that neither lens nor deterministic feeds discovered.

### 1.3 The 8 Security Reflexes

Oracle organizes its automated analytical sweeps through 8 disciplined reflexes:

| Reflex | Method | Execution Target |
|---|---|---|
| **1. SPEC-AUDIT** | Question underspecified constraints in documentation and API schemas. | Undefined default behaviors, missing error handlers. |
| **2. DECOUPLE** | Separate conflated concerns (Identity ≠ Authority; Authentication ≠ Authorization). | IDOR, privilege escalation, multi-tenant leakage. |
| **3. AXIOM-REWRITE** | Treat blocking rules or system boundaries as mutable variables. | WAF bypass, alternate encodings, path traversal. |
| **4. AMBIGUITY VECTOR** | Target linguistic or semantic discrepancies between systems. | HTTP request smuggling, parser differential bugs. |
| **5. HIERARCHICAL RECALL**| Map current structures to known historical vulnerability topologies. | Prototype pollution, mass assignment, race windows. |
| **6. CLEAN vs NOT-FOUND** | Enforce intellectual honesty: unobserved vulnerabilities are not absent. | Deeper fuzzing, secondary route discovery. |
| **7. RECURSIVE VALIDATION**| Structure exploit hypotheses so that command execution yields self-evident proof. | Single curl output demonstrating sensitive extraction. |
| **8. BINARY CONFLICT** | Isolate two irreconcilable facts requiring exactly one test. | "Header required" vs "Header stripped by reverse proxy". |

### 1.4 Dual Bug Engines

Oracle splits vulnerability analysis into two distinct engines:

- **Type-1: Code Bugs (Invisible Seam)**: Purely deterministic, AST and regex-driven inspection of source code (Python, Solidity, Cairo). It checks developer claims (NatSpec `@notice`, docstrings, type annotations, `require()` assertions) against implementation reality. Because no LLM is in the verdict loop, hallucination is mathematically zero.
- **Type-2: Logic Bugs (8-Reflex Engine)**: LLM-driven analysis applied to recon telemetry (endpoints, parameters, headers, JavaScript bundles). It isolates business logic flaws, state machine desynchronization, and authentication bypasses, producing machine-parsable Seam Cards.

### 1.5 The End-to-End Operational Pipeline

```
[1. Prescan] ──► [2. Scan & Verify] ──► [3. Queue & Download] ──► [4. Targeted Recon] ──► [5. 5-Gate Verify] ──► [6. Report]
```

1. **Prescan (`oracle-hunter prescan`)**: Interfaces with **Scan4Me** (a synchronized local SQLite store of ~13 platforms including HackerOne, Bugcrowd, Immunefi, Cantina, Patchstack). Evaluates programs against `triage.yaml` floors (payout floors, launch recency, report resolution velocity).
2. **Scan & Scope Verification (`oracle-hunter scan`)**: Conducts an active probe to verify that shortlisted programs remain active, scope URLs resolve, and bounty rules have not drifted.
3. **Queue & Asset Intake (`oracle-hunter queue` & `oracle_bulk_download.py`)**: Schedules targets while strictly enforcing per-platform rate limits. Downloads target git repositories, API documentation, and JavaScript bundles into isolated `targets/<Platform>/<Program>/` workspaces.
4. **Reconnaissance (`oracle-hunter recon`)**: Runs passive and active subdomain enumeration, web probing, URL harvesting, and parameter extraction (`subfinder`, `httpx`, `katana`, `ffuf`).
5. **The 5-Gate Deterministic Wire Verifier**: Every candidate seam must satisfy five gates before confirmation:
   - *Gate 1 (Grounding)*: Target host must exist in verified recon telemetry.
   - *Gate 2 (Scope)*: Target asset must fall strictly within the program scope wall.
   - *Gate 3 (Specification)*: Candidate must define expected HTTP method, headers, payload, and status code.
   - *Gate 4 (Citation)*: Finding must cite the exact claim source (doc, schema, or endpoint).
   - *Gate 5 (Wire Match)*: Live response must match the predicted conflict (e.g., unauthenticated 200 OK returning user data).
6. **Reporting**: Assembles confirmed seams into an end-to-end impact summary with minimal reproducible PoCs (`curl` or script) and platform-ready remediation advice. Auto-submission is forbidden; human review is mandatory.

---

## 2. The Vortex System: Multi-Chain Smart Contract Exploit Triad

The Vortex System (`/media/phantomcore/AI_DRIVE/VORTEX_SYSTEM`) is engineered specifically for deep smart-contract auditing and exploit generation. Unlike traditional scanners that generate noisy alerts, Vortex focuses on producing **unfakeable, on-chain-anchored proofs of exploit** (the `CONFIRMED` mint).

The architecture consists of three decoupled components: **Basilisk**, **CodeCrusher**, and **Vortex Anchor**.

```
                   ┌────────────────────────────────────────┐
                   │             VORTEX ANCHOR              │
                   │  - Express / Playwright api-maker      │
                   │  - ~/.creds-profile session store      │
                   │  - Scope & bounty rules filter         │
                   │  - ZeroMQ Router (VZMQ)                │
                   └───────────────────┬────────────────────┘
                                       │
                      ZeroMQ Message Bus (Non-hardcoded)
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
┌─────────────────────────────────┐         ┌─────────────────────────────────┐
│            BASILISK             │         │           CODECRUSHER           │
│         (The FIND Half)         │         │     (The PROVE / SEAL Half)     │
├─────────────────────────────────┤         ├─────────────────────────────────┤
│ • Pure Deterministic / NO LLMs  │         │ • Where LLMs First Enter        │
│ • Keyless, Networkless, Local   │         │ • 5-Role Adversarial Court      │
│ • Manifest Tool Wrapper (ROW)   │         │ • Non-LLM Deterministic Judge   │
│ • Native AST / structured packs │         │ • Anvil Fork-Replay Prover      │
│ • 8 Supported Blockchains       │         │ • ONLY Minter of "CONFIRMED"    │
│ • Small-to-Money Neuron Mesh    │         │ • Tamper-Evident Keccak Receipts│
│ • Output: Finding Candidates    │         │ • TEE Hardware Governance       │
└─────────────────────────────────┘         └─────────────────────────────────┘
```

---

## 3. Basilisk: The Deterministic FIND Engine

### 3.1 Role & Epistemic Boundaries
Basilisk's sole function is candidate generation. It produces `Finding` objects and counterexamples.
- **Strictly Zero LLMs**: Enforced by automated determinism tests. Identical source code input must produce byte-identical output across runs.
- **Keyless and Networkless**: Basilisk never makes outbound network calls and holds no secrets. All assets are prepared locally by Vortex Anchor.
- **Never Confirms**: Basilisk cannot mark a finding as confirmed. It leaves proving to CodeCrusher.

### 3.2 Dual-Engine Architecture on a Shared Spine
Basilisk avoids the trap of rebuilding parsers by hosting two engines on a single spine:

1. **Manifest-Driven Wrapper Engine (ROW)**:
   - External tools (e.g., Slither, Mythril, Aderyn, Semgrep, Echidna, Halmos) are integrated as declarative rows in a manifest rather than custom Python wrappers.
   - Normalized findings map directly into `basilisk_core.schema.Finding`.

2. **Universal Own-Detector Engine (DET)**:
   - Executes custom detectors over parsed source representations.
   - Base class: `base.Finder` registering via `_REGISTRY`.

### 3.3 The Architecture Correction: Shared Spine vs. Per-Chain AST
Prior systems failed by attempting to force all blockchains into a single mandatory abstract syntax tree (AST). A normalized AST strips away chain-specific constructs where high-severity vulnerabilities reside (e.g., Solana PDA seeds/bumps, Move abilities and `&signer`, TON cell bit-packing and bounce flags, Cairo `felt` arithmetic wrapping at `PRIME`).

Basilisk resolves this through a hybrid model:
- **Shared Spine**: Universal `Finding` schema, central plugin registry, determinism harness, and taint tables.
- **Additive BNAST Index**: Non-lossy, generalized index utilized only by ~11 universal detectors (e.g., basic unchecked return, naming conventions, dead code).
- **Per-Chain Adapters (8 Ecosystems)**:
  - **EVM**: Solidity / Vyper (Tree-sitter, Slither AST).
  - **Solana**: Rust / Anchor (account ownership, discriminator validation, PDA bump checks).
  - **Aptos / Sui Move**: `&signer` capabilities, resource groups, acquire locks.
  - **TON**: FunC / Tact (slice parsing, send-mode-128, gas reservation, bounce handlers).
  - **StarkNet**: Cairo (felt overflow vs modulo PRIME, system calls, storage packing).
  - **Polkadot**: ink! / Substrate (weight accounting, cross-contract reentrancy).
  - **NEAR**: Async promise call-backs, prepaid gas exhaustion.
  - **CosmWasm**: Rust / Actor model (CW20/CW721 execution flow, sub-message replies).

Chain-physical detectors read their chain's native parser index and `raw_decl` directly, preventing cross-chain regression.

### 3.4 Small-to-Money Reactive Neuron Mesh
Basilisk detectors do not execute as isolated, one-shot passes. Instead, they interact via a reactive mesh (`engine/mesh.py`):
- Detector A's output acts as a signal that triggers higher-order Detectors B and C.
- This compounds minor signals (e.g., missing slippage parameter + public unprotected external call) into a composite exploit candidate, providing CodeCrusher with the blueprint for a multi-step exploit.

---

## 4. CodeCrusher: The PROVE / JUDGE / SEAL Engine

### 4.1 Role & Epistemic Boundaries
CodeCrusher receives unconfirmed candidates from Basilisk and determines whether they are real, exploitable, and payable.
- **Where LLMs Enter**: CodeCrusher uses large language models for exploit synthesis, code comprehension, and adversarial argument generation.
- **Non-LLM Deterministic Adjudication**: While LLMs generate claims and exploits, they are strictly barred from delivering verdicts. A model cannot confirm its own hypothesis.

### 4.2 The Seven Unified Sub-Programs
CodeCrusher integrates the capabilities of seven specialized sub-systems:

| Sub-Program | Operational Identity | Role in CodeCrusher |
|---|---|---|
| **Argus** | Splunk-native cross-chain security ops; fork validation | Provides the Anvil/Foundry fork execution runner (`validate/fork_validator.py`). |
| **Hexbreaker** | Adversarial DFIR court; cryptographic HMAC case chaining | 5-role deliberation (Prosecutor, Defender, Witness, Provocateur, non-LLM Judge). |
| **Robotruth** | Claim-vs-action verification ("Did the AI lie?") | Verifies that proposed patches or exploit scripts execute what they claim. |
| **Agent-Colosseum**| Multi-slot Nemotron cognitive cluster | Diverse model perspectives under a strict fail-closed security gatekeeper. |
| **Glass-Box-Alpha**| Verifiable multi-agent consensus | Cross-language canonical Keccak-256 receipts and on-chain hash anchoring. |
| **Terminal3** | Hardware-attested TEE enclave governance | Enforces non-bypassable spend and execution limits in silicon. |
| **Ghost-Reviews** | Provenance scoring via self-written baseline mirrors | Dual-baseline methodology to measure deviation from honest code patterns. |

### 4.3 The Escalating Verdict Funnel
CodeCrusher processes findings through a strict four-stage pipeline:

```
[Candidate Finding]
         │
         ▼
┌──────────────────┐
│   1. SCAN STAGE  │ ──► Static rule enforcement & initial claim extraction (Robotruth).
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  2. COURT STAGE  │ ──► 5-Role adversarial debate (Hexbreaker).
│                  │     Deterministic Judge caps verdict strictly at "PLAUSIBLE".
└────────┬─────────┘     (Zero LLM in the Judge path; cannot confirm).
         │
         ▼
┌──────────────────┐
│  3. ARGUS STAGE  │ ──► PoC deployed to live-fork RPC (Anvil / Foundry fork_replay.py).
│  (FORK REPLAY)   │     Real state modification / fund extraction executed on-chain.
└────────┬─────────┘     ★ THE ONLY ENTITY AUTHORIZED TO MINT "CONFIRMED" ★
         │
         ▼
┌──────────────────┐
│  4. SEAL STAGE   │ ──► Generates cryptographic receipt chain (Glass-Box Keccak-256).
└──────────────────┘     Anchors hash on-chain; prepares patch recommendation.
```

### 4.4 The Anvil Fork Replay Gate (`fork_replay.py`)
The defining feature of CodeCrusher is the **forge-gated CONFIRMED mint**.
- An exploit hypothesis generated by an LLM is compiled into an executable test contract against a local Anvil fork of the target blockchain.
- If the exploit executes successfully (`PASS` on fork) and drains tokens or triggers the unauthorized state change, the verdict is upgraded to `CONFIRMED`.
- If the test fails, reverts, or fails to execute, the finding is discarded or demoted. No LLM argument can overturn a failed on-chain execution trace.

---

## 5. Vortex Anchor: Conductor, Eyes, and Transport

### 5.1 The "Eyes" (Platform Ingestion Without Leaked Keys)
Traditional bounty automation relies on fragile public APIs or risks leaking sensitive API keys. Vortex utilizes `api-maker`:
- Runs Express + Playwright headless browser automation using authenticated profile directories (`~/.creds-profile`).
- Interacts with bounty platforms (Immunefi, Code4rena, Cantina, HackerOne) as an authenticated human user.
- Ingests private scope rules, contract repositories, and scope amendments directly, writing normalized local targets for Basilisk.
- **Zero API keys or tokens are passed to Basilisk**, keeping the find engine strictly local and offline.

### 5.2 Out-of-Band Scope & Policy Filtering
A key architectural principle of Vortex is:
> *"Scope and bounty-rules filtering lives in Vortex, not the hunter."*

Neither Basilisk nor CodeCrusher is burdened with interpreting whether an asset is in-scope or eligible for payout. Vortex Anchor parses platform terms, checks KYC exclusions and asset domains, and filters the target queue before handoff. The hunting engines operate with complete focus on technical vulnerability discovery.

### 5.3 The SZMQ Bus Topology
Communication across Vortex components is governed by an asynchronous, decoupled ZeroMQ (SZMQ/VZMQ) tree:

```
                        ┌──────────────┐
                        │  VZMQ Router │
                        │  (Anchor)    │
                        └──────┬───────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       ┌───────────────┐               ┌───────────────┐
       │   BZMQ Host   │               │  CCZMQ Host   │
       │  (Basilisk)   │               │ (CodeCrusher) │
       └───────┬───────┘               └───────┬───────┘
               │                               │
               ▼                               ▼
       ┌───────────────┐               ┌───────────────┐
       │ BCZMQ Workers │               │ CCCZMQ Court  │
       └───────────────┘               └───────────────┘
```

- **No Traditional Paths**: Socket endpoints are discovered dynamically rather than hardcoded to specific IP addresses or local file paths.
- **Fail Fast, Scream Loudly**: If any socket, worker, or pipeline organ becomes unreachable, the process halts immediately with diagnostic telemetry. Silent fallbacks, default values, and masking try/except blocks are strictly forbidden.
- **IDZMQ Provenance**: Every finding, deliberation transcript, execution trace, and receipt is tracked under a unified, immutable session UUID.

---

## 6. System Comparison: Oracle vs. The Vortex System

| Dimension | Oracle | The Vortex System (Basilisk + CodeCrusher) |
|---|---|---|
| **Primary Domain** | Web2, Web3, and AI application surfaces (APIs, web routing, business logic, codebases). | Web3 smart contracts (Solidity, Rust, Move, FunC, Cairo, ink!, Wasm). |
| **Cognitive Framework** | Three-Mindset Architecture (MITRE ATT&CK + 16 Paradoxes + Adversarial Synthesis). | Deterministic static analysis coupled with a 5-role adversarial DFIR court. |
| **LLM Strategy** | Bounded LLM analytical passes in Mindsets 1-3; deterministic checks elsewhere. | Strictly Zero LLMs in Basilisk (FIND); LLMs allowed in CodeCrusher (PROVE). |
| **Verification Gate** | 5-Gate Wire Verifier (Grounding, Scope, Spec, Citations, live HTTP conflict). | Anvil/Foundry local fork execution (`fork_replay.py`). |
| **Confirmation Authority** | Live wire conflict matching predicted machine-readable behavior. | Deterministic `PASS` on local chain fork. |
| **Proof Artifact** | Reproducible `curl` commands, parameter payloads, traffic traces. | Tamper-evident Keccak-256 hash receipts, on-chain anchors, Foundry test suites. |
| **Data Ingestion** | Scan4Me database synchronizer across 13 public/private platforms. | `api-maker` authenticated headless browser sessions (`~/.creds-profile`). |
| **Inter-Process Comm** | Direct subprocesses, local file handoffs, and target directories. | Dynamic ZeroMQ socket hierarchy (VZMQ, BZMQ, CCZMQ, IDZMQ). |

---

## 7. The Grand Convergence: Folding Oracle into the Vortex System

### 7.1 Strategic Vision & Rationale
The overarching architectural roadmap dictates that **all of Oracle will eventually be folded into the Vortex System**, establishing a single unified autonomous vulnerability discovery and exploit-proving powerhouse. 

Historically, Oracle developed as a full-spectrum Web2/Web3 application bounty hunter with high-level cognitive reasoning, while the Vortex System developed as a specialized, multi-chain smart-contract exploitation triad. Uniting them creates an all-encompassing system that operates seamlessly across the entire attack surface—from cloud APIs, web application logic, and developer specification mismatches down to low-level byte-manipulation and on-chain smart-contract exploits.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               THE CONVERGED VORTEX SYSTEM                                       │
│                                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              VORTEX ANCHOR & EYES (Conductor)                             │  │
│  │  • Unified Platform Ingestion: Scan4Me (13 Platforms) + api-maker (Headless Browser)     │  │
│  │  • Authenticated Profiles (~/.creds-profile) — Zero exposed API keys / URL tokens         │  │
│  │  • Target Workspace Preparation & Shared Triage (triage.yaml)                             │  │
│  │  • Out-of-band Scope Boundaries & Company Bounty Rules Gating                             │  │
│  │  • Wave Queue Scheduler: Concurrency, Per-Site Rate Limits, Failure Isolation            │  │
│  └─────────────────────────────────────────────┬─────────────────────────────────────────────┘  │
│                                                │                                                │
│                               ZeroMQ Event Bus Tree (VZMQ ──► BZMQ / CCZMQ)                     │
│                                                │                                                │
│                 ┌──────────────────────────────┴──────────────────────────────┐                 │
│                 ▼                                                             ▼                 │
│  ┌───────────────────────────────────────────┐ ┌─────────────────────────────────────────────┐  │
│  │         BASILISK (The FIND Half)          │ │       CODECRUSHER (PROVE / JUDGE / SEAL)    │  │
│  │  • Pure Deterministic — STRICTLY ZERO LLM │ │  • Where LLMs Live (PoC & Analysis Swarm)  │  │
│  │  • Keyless, Networkless, Local-Only       │ │  • Cognitive OS: Oracle Three Mindsets      │  │
│  │  • Manifest Tool Wrappers (Slither, etc.) │ │    - Mindset 1: MITRE ATT&CK Full Sweep     │  │
│  │  • 8-Chain Structured Adapters & BNAST    │ │    - Mindset 2: 16 Paradoxes & Inversions   │  │
│  │  • Oracle Type-1 Engine (Invisible Seam): │ │    - Mindset 3: Adversarial Synthesis       │  │
│  │    - Spec-vs-Code Claim Matcher           │ │  • 8 Security Reflexes Reasoning Engine     │  │
│  │    - NatSpec, Type Hints, Docstrings      │ │  • 5-Role Adversarial Court (Hexbreaker)    │  │
│  │  • Small-to-Money Reactive Neuron Mesh    │ │    - Deterministic Non-LLM Judge (PLAUSIBLE)│  │
│  │  • Candidate Findings (NO Confirmation)   │ │  • Dual Deterministic Proving Foundry:      │  │
│  │                                           │ │    - Web3: Anvil/Foundry Fork Replay        │  │
│  │                                           │ │    - Web2: 5-Gate Wire Verifier (HTTP Match)│  │
│  │                                           │ │    ★ EXCLUSIVE MINTERS OF "CONFIRMED" ★     │  │
│  │                                           │ │  • Keccak-256 Receipts & On-Chain Anchors   │  │
│  │                                           │ │  • TEE Hardware Governance & Budget Caps    │  │
│  └───────────────────────────────────────────┘ └─────────────────────────────────────────────┘  │
│                                                │                                                │
│                                                ▼                                                │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                            UNIFIED SUBMISSION & SEALING                                   │  │
│  │  • Small-to-Money Severity Compounder (Chains Web2 Auth + Web3 Contract Flaws)            │  │
│  │  • Unfakeable Cryptographic Exploit Proofs & Self-Contained PoC Scripts                   │  │
│  │  • Human-in-the-Loop Review Gate — Zero Hallucinations, Zero Unverified Reports           │  │
│  └───────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 7.2 Lessons from Prior Attempts: The Anti-Pattern to Avoid
Earlier integration efforts attempted to fold Oracle prematurely into Vortex by slicing up source files and forcing rigid header tags (`# LAYER: find|think|seal` and `# DEST: basilisk|codecrusher|vortex`) across `oracle_*.py`. This created several critical anti-patterns:
1. **Treating Oracle as a Narrow Static AST Scanner**: Attempting to force Oracle's broad cognitive model into Basilisk's per-language detector framework broke Oracle's high-level reasoning and produced brittle language extractors (e.g., hardcoded SQL regexes).
2. **Severing the Mindsets from the Evidence**: Oracle's strength lies in feeding full asset context, scope policies, and deterministic code seams directly into its Three-Mindset cognitive engine. Stripping these out damaged both finding precision and recall.
3. **Conflating Scope Boundaries**: In Vortex, scope filtering lives strictly *outside* the hunting organs; in early Oracle scripts, scope was checked ad-hoc across multiple layers.

**The Golden Rule of the Fold**:
> Do not carve up Oracle into fragmented scripts. Fold whole, mature functional organs into their natural home in the Vortex triad: **Sensors/Intake ──► Vortex Anchor; Deterministic Claim Auditing ──► Basilisk; Cognitive Reasoning & Proving ──► CodeCrusher.**

---

### 7.3 Detailed Component Convergence Mapping

#### 1. Ingestion, Intake, and Queue ──► VORTEX ANCHOR & EYES
* **Current Oracle Modules**: `oracle_scan4me.py`, `oracle_intake.py`, `oracle_queue.py`, `oracle_bulk_download.py`, `triage.yaml`.
* **Vortex Target**: `vortex/anchor/` and `tools/api-maker/`.
* **Integrated Mechanics**:
  - **Single Discovery Sensor**: Vortex Anchor absorbs the Scan4Me sync engine, querying listings across 13 bug bounty platforms (HackerOne, Bugcrowd, Immunefi, Cantina, Code4rena, Patchstack, etc.) into its local database.
  - **Zero-Key Headless Fetching**: Combines public listing synchronization with `api-maker` (Playwright-driven sessions running out of `~/.creds-profile`). The conductor fetches assets, private scopes, and repositories as an authenticated user without exposing API keys or tokens.
  - **Out-of-Band Policy Gate**: Enforces bounty rules, payout minimums, and asset scope *before* targets reach Basilisk or CodeCrusher.
  - **Wave Scheduling & Download Engine**: Manages rate-limited downloads into isolated target workspaces (`targets/<Platform>/<Program>`), applying concurrency limits and failure isolation.

#### 2. Deterministic Code & Spec Analysis ──► BASILISK (FIND)
* **Current Oracle Modules**: `oracle_code_seam.py`, `invisible-seam/`.
* **Vortex Target**: `basilisk/finders/`, `basilisk_core/`.
* **Integrated Mechanics**:
  - **Universal Specification Checker**: Oracle's **Invisible Seam** engine folds directly into Basilisk's own-detector registry (`base.Finder`).
  - **Strict Determinism Gate**: Because the Invisible Seam relies entirely on AST inspection, docstrings, type annotations, and NatSpec matching against code implementation, it operates with **zero LLM dependencies**, perfectly adhering to Basilisk's determinism mandate.
  - **Multi-Language Expansion**: Augments Basilisk's smart-contract detectors with deterministic code-seam detection in Python, Rust, Go, JavaScript, and Cairo.
  - **Neuron Mesh Integration**: Seam candidates feed directly into Basilisk's reactive neuron mesh (`engine/mesh.py`), allowing a code/spec discrepancy to trigger downstream structural and security-reflex detectors.

#### 3. Cognitive Operating System & Reasoning ──► CODECRUSHER (PROVE / JUDGE / SEAL)
* **Current Oracle Modules**: `oracle_mindsets.py`, `oracle_mindset_context.py`, `oracle_corpus.py`, `ORACLE_FRAMEWORK.md`, `ORACLE_SYSTEM_PROMPT.md`, `oracle_ttps_fused.json`.
* **Vortex Target**: `codecrusher/court/`, `codecrusher/agents/`.
* **Integrated Mechanics**:
  - **Cognitive Court Engine**: CodeCrusher is the designated organ where LLMs operate. Oracle's **Three Mindsets** become the cognitive brain of CodeCrusher's adversarial court:
    - **Mindset 1 (MITRE ATT&CK)** fuels the *Prosecutor*, framing vulnerabilities through real adversary attack techniques.
    - **Mindset 2 (Paradox & Inversion)** fuels the *Provocateur*, deploying the 16 philosophical lenses ("You never said...") to find unorthodox exploitation paths.
    - **Mindset 3 (Adversarial Synthesis)** fuels the *Defender* and court deliberation, rigorously challenging assumptions, eliminating noise, and synthesizing multi-vector attacks.
  - **8 Security Reflexes**: The 8 reflexes (SPEC-AUDIT, DECOUPLE, AXIOM-REWRITE, etc.) govern the deliberation structure, ensuring LLMs reason systematically rather than generating freeform prose.
  - **Deterministic Judge**: The non-LLM Judge uses Oracle's Binary Conflict Isolation (The iPhone Problem) to evaluate whether claims represent verifiable conflicts. The court ceiling remains strictly capped at `PLAUSIBLE`.

#### 4. Verification & Confirmation Foundries ──► CODECRUSHER VALIDATION
* **Current Oracle Modules**: `oracle_deterministic.py`, `oracle_evidence.py`.
* **Vortex Target**: `codecrusher/validate/`, `fork_replay.py`.
* **Integrated Mechanics**:
  - **Dual Execution Verification**: CodeCrusher expands into a dual-engine execution foundry—the **only** authority permitted to mint `CONFIRMED`:
    1. **Web3 Execution Foundry (`fork_replay.py`)**: Executes compiled Solidity/Foundry or Anchor exploit contracts against local Anvil forks. A passing test that drains funds or alters state mints `CONFIRMED (On-Chain)`.
    2. **Web2 Execution Foundry (Oracle 5-Gate Wire Verifier)**: Executes real HTTP probes against target endpoints. A live response that satisfies all 5 gates (Grounding, Scope, Specification, Citation, Wire Match) mints `CONFIRMED (Wire)`.
  - **Cryptographic Receipts**: Both execution paths emit tamper-evident, cross-language Glass-Box Keccak-256 receipts, chaining the finding to its cryptographic proof and anchoring the hash.

#### 5. Shared Bus & Transport ──► NON-HARDCODED ZeroMQ (SZMQ / VZMQ / IDZMQ)
* **Transport Architecture**:
  - Replaces Oracle's file-based script chaining with the Vortex dynamic ZeroMQ bus tree.
  - Sockets are discovered dynamically with zero hardcoded IPs or fixed filesystem paths.
  - Adheres strictly to **Rule 1 (NO TRADITIONAL PATHS)** and **Rule 2 (NO FALLBACKS)**: components communicate over message schemas; if a component fails or crashes, the system screams loudly and halts rather than masking errors with default states.
  - **IDZMQ Binding**: Every event—from the initial Scan4Me listing to Basilisk detection, Court transcript, Wire/Fork proof, and final draft—is permanently bound under a unified, immutable session UUID.

---

### 7.4 Unified Target Lifecycle Walkthrough

```
[Target Discovery: Vortex Anchor]
       │ (13 platforms synced via Scan4Me + api-maker headless browser)
       ▼
[Out-of-Band Scope Filter]
       │ (Target scoped, filtered, assets downloaded to local workspace)
       ▼
[Discovery: Basilisk FIND] ◄── [SZMQ / BZMQ]
       │ • Manifest wrappers (Slither, Aderyn, Semgrep)
       │ • Native 8-chain AST detectors
       │ • Oracle Invisible Seam (Spec-vs-Code AST audit)
       │ • Reactive Small-to-Money Neuron Mesh
       ▼
[Unconfirmed Candidate Findings]
       │
       ▼
[Adjudication: CodeCrusher COURT] ◄── [SZMQ / CCZMQ]
       │ • Three-Mindset Cognitive Engine (MITRE + Paradox Inversion)
       │ • 8 Security Reflexes reasoning pass
       │ • 5-Role Adversarial Court (Prosecutor vs Defender vs Provocateur)
       │ • Deterministic non-LLM Judge (Verdicts capped at PLAUSIBLE)
       ▼
[Verification: CodeCrusher PROVE]
       ├─► If Web3 Contract: Anvil/Foundry Fork Replay (fork_replay.py) ──► PASS ──┐
       │                                                                           │
       └─► If Web2 / API: 5-Gate Wire Verifier (oracle_deterministic)  ──► MATCH ──┤
                                                                                   ▼
                                                                           [CONFIRMED MINT]
                                                                                   │
                                                                                   ▼
                                                                       [SEAL & ANCHOR (Glass-Box)]
                                                                       • Keccak-256 Receipt Chain
                                                                       • On-Chain Hash Anchoring
                                                                       • Small-to-Money Compounder
                                                                       • Final Submission Report
```

---

### 7.5 Phased Migration Roadmap

| Phase | Milestone | Deliverable | Status |
|---|---|---|---|
| **Phase 1** | **Oracle Mindset & Seam Hardening** | Complete Three-Mindset specification, language-agnostic evidence spine, and 5-gate wire verification in `/home/phantomcore/oracle`. | **COMPLETED ✅** |
| **Phase 2** | **Vortex Triad Baseline** | Pin standalone `basilisk`, `codecrusher`, and `vortex-anchor` under the `vortex-system` super-repository with green ground-truth test gates. | **COMPLETED ✅** |
| **Phase 3** | **ZeroMQ Schema Unification** | Define unified JSON/protobuf schemas for `Finding`, `SeamCard`, `CourtTranscript`, and `ProofReceipt` over the SZMQ/VZMQ bus. | **NEXT ▶** |
| **Phase 4** | **Intake & Eyes Fusion** | Move `Scan4Me` and `oracle_intake.py` into Vortex Anchor, unifying API-maker and headless profile sessions. | **PLANNED** |
| **Phase 5** | **Find Engine Convergence** | Register Oracle's `invisible-seam` extractors into Basilisk's `base.Finder` registry as deterministic spec-auditing plugins. | **PLANNED** |
| **Phase 6** | **Court & Prover Fusion** | Embed the Three-Mindset cognitive OS and the 5-Gate Wire Verifier into CodeCrusher's court and validation rungs. | **PLANNED** |
| **Phase 7** | **The Unified Super-Repo** | Retire legacy standalone scripts; pin the single, unified Vortex System executing the full end-to-end autonomous bounty lifecycle. | **FINAL GOAL** |

---

## 8. Conclusion: The Power of Determinism-Gated Autonomous Intelligence

The ultimate convergence of Oracle into the Vortex System represents the culmination of a single core philosophy:
> **The AI proposes, deterministic computation proves.**

By strictly separating the creative, generative capabilities of large language models from the immutable, reproducible requirements of vulnerability confirmation:
- **Basilisk** guarantees that discovery remains fast, deterministic, and free of hallucination;
- **CodeCrusher** ensures that arguments are tested adversarially and confirmed only through genuine execution (Anvil fork replay or live HTTP wire proofs);
- **Vortex Anchor** safeguards credentials, isolates network dependencies, and enforces non-negotiable scope policies;
- **Oracle's Cognitive Engine** equips the entire system with deep, human-grade strategic insight, paradox inversion, and compound exploit chaining.

The resulting converged architecture is not merely a scanner—it is an autonomous, self-verifying, proof-generating security institution.
