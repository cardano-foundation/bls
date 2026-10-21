# zkVM on Cardano

## Goal

Run an Aiken program — a "hello world" validator — inside a zkVM, and have the proof of that execution verified **on Cardano**, by an Aiken script, on a real transaction.

## Why

A zkVM lets an off-chain prover execute *any* program and emit a succinct proof that it did so correctly. On Cardano the proof has to be checkable by a Plutus V3 script, which means the proof must ultimately live on **BLS12-381** — the curve Cardano's builtins expose. Neither of the two zkVMs we are looking at produces a BLS12-381 proof today: both aggregate over **BN254**. So this directory exists to answer one question with experiments, not opinions:

> *What is the shortest path from "an Aiken program ran correctly" to "a Cardano node accepted a transaction because of it"?*

Two candidates, deliberately picked as different points on the design space:

- **OpenVM** (`openvm-org/openvm`) — production-leaning, GPU-accelerated, audited, already has a recursive/on-chain story (for EVM).
- **Jolt** (`a16z/jolt`) — the newest one: lookup-based, 64-bit, fast on CPU, but alpha and with an on-chain verifier still on the roadmap.

The demo is the same in both cases, so the comparison is apples-to-apples.

---

## Plan

- [ ] **Phase 0 — Baselines.** Build both zkVMs, run a plain Rust "hello world" guest in each, and record the numbers we will compare on: guest ISA, proving time (CPU and, if available, GPU), proof size, verifier time, peak memory. Output: `zkVM/openvm/README.md`, `zkVM/jolt/README.md`.
- [ ] **Phase 1 — The Aiken hello world.** Write one Aiken program (`zkVM/hello-world/`) that the *same* source of truth feeds to (a) the on-chain validator and (b) the zkVM guest. Two routes, in increasing ambition: **(1a)** port the logic to a RISC-V guest and prove the port by differential testing; **(1b)** compile the Aiken program to UPLC (`aiken build` → `.plc`) and run the *actual compiled artifact* inside the zkVM via a small UPLC interpreter written in the guest.
- [ ] **Phase 2 — Proof plumbing.** Host-side verification for both, a common "proof envelope" carrying the public outputs, and the public output bound to the Aiken program's result (e.g. the digest the hello world computes).
- [ ] **Phase 3 — On Cardano.** *(3a, MVP)* an Aiken validator that checks the committed public output — proves the transaction flow, with the prover trusted. *(3b, sound)* aggregate the zkVM proof into a **BLS12-381 Groth16** proof and verify it on-chain with the Groth16 verifier we already have in `aiken/groth16`. This is where the BLS12-381 support has to be added.
- [ ] **Phase 4 — Compare and decide.** Same workload, same metrics, same on-chain cost; write up the results here and pick a direction (or conclude that a zkVM is the wrong tool for Cardano and say why).

**Definition of done.** One transaction on a Cardano testnet whose redeemer carries a zkVM proof, and an Aiken validator that rejects a tampered proof and accepts the honest one — with the full command sequence written up in this directory.

---

<details>
<summary><b>The pipeline we are building (click to expand)</b></summary>

## The pipeline we are building

```
   Aiken source  ──aiken build──►  UPLC (.plc)  ──┐
                                                   │  (route 1b: interpreter in the guest)
   Rust port of the same logic  ────────────────────┤  (route 1a: direct guest program)
                                                   ▼
                                     RISC-V guest program
                                                   │
                                       ┌───────────┴───────────┐
                                       ▼                       ▼
                              OpenVM (RV32IM)             Jolt (RV64IMAC)
                                       │                       │
                                  zkVM proof              zkVM proof
                                    (BN254)                (BN254)
                                       │                       │
                              ┌────────┴────────┐              │
                              ▼                 ▼              ▼
                    aggregate / wrap   (same shape)   aggregate / wrap
                              │                 │              │
                              └────────┬────────┴──────────────┘
                                       ▼
                          BLS12-381 Groth16 proof (small, constant size)
                                       │
                                       ▼
                          Aiken validator (aiken/groth16) ──► Cardano node
```

Two properties make the last hop possible at all:

1. **Cardano's curve is BLS12-381.** Aiken exposes `bls12_381_miller_loop` / `bls12_381_final_verify`, so a BLS12-381 Groth16 proof is checkable on-chain.
2. **We already have the checker.** `aiken/groth16` in this repo is a parameterized BLS12-381 Groth16 verifier (plus batch verification), cross-checked against Sage. The zkVM work only has to produce a *proof in that shape*; the on-chain side is done.

So the zkVM-specific problem is: **turn a BN254 zkVM proof into a BLS12-381 Groth16 proof**, and **make an Aiken program executable inside a RISC-V VM**.

</details>

<details>
<summary><b>OpenVM vs Jolt (click to expand)</b></summary>

## OpenVM vs Jolt

| | **OpenVM** | **Jolt** |
|---|---|---|
| Repo | `openvm-org/openvm` (MIT / Apache-2.0) | `a16z/jolt` (MIT / Apache-2.0) |
| Status | v2.0.2 released; v2.1 preview. Audited (Cantina v1, zkSecurity v2.0); RV32IM formally verified in Lean (Nethermind, Feb 2026) | alpha, unaudited, explicitly "not suitable for production" |
| Guest ISA | RV32IM (v2.0); RV64IM_Zicclsm in v2.1 preview | RV64IMAC (64-bit since Oct 2025) |
| Proof system | SWIRL (v2.0): multilinear, list-decoding, fast recursion, 100-bit provable security | Lookup/sumcheck core (Lasso, Shout, Twist-and-Shout) + Dory commitments; Akita lattice backend (post-quantum, non-ZK) |
| Aggregation curve | Halo2 over **BN254** → `OpenVmHalo2Verifier.sol`, ~316K gas on EVM (2.0 Beta) | **BN254** (`jolt-dory` depends on `ark-bn254`); no shipped on-chain verifier |
| Recursion | Yes: `openvm-verify-stark` guest lib, "deferral" framework, agg VMs | Roadmap only (`Roadmap → Recursion`, `Roadmap → On-chain verifier` are stubs in the book) |
| Performance | 139 MHz RISC-V proving on 16× RTX 5090; real-time Ethereum block proving; proofs < 300 kB | ~1M RISC-V cycles/s on a 32-core CPU, ~500k/s on a laptop; proofs ~50 kB (6× faster after the Aug 2025 rewrite) |
| Guest crypto | Keccak, SHA-2, int256, modular arithmetic, ECC (secp256k1/p256), **pairing check on BN254 *and* BLS12-381** | No equivalent acceleration extensions; guest is plain RISC-V |
| Zero-knowledge | Yes (BlindFold-style) | Yes (BlindFold) on the Dory backend; Akita is non-ZK |
| Tooling | `cargo openvm init/build/keygen/prove app/verify app`, `cargo openvm prove stark`; Rust frontend, guest libs | `jolt new`, `#[jolt::provable]` macro; compile → preprocess → prove → verify; `jolt-platform`, profiling tools |

### Where each one hurts

- **OpenVM** is the mature one but its on-chain target is the EVM: the aggregation is Halo2-over-BN254, and its on-chain verifier is Solidity. Getting to Cardano means a BLS12-381 aggregation path. The good news is that the *guest* already supports BLS12-381 pairings, and the SWIRL design explicitly optimizes recursion. The bad news is that a 32-bit guest (v2.0) is an awkward target for a UPLC interpreter, and v2.1 (64-bit) is still preview and unaudited.
- **Jolt** is the interesting research bet: 64-bit, CPU-friendly, ~50 kB proofs, and an architecture (lookups) that is much friendlier to in-circuit verification. But *both* on-chain-relevant pieces are missing: recursion and an on-chain verifier are roadmap items, and the Dory backend is BN254 today. The a16z position is that the Jolt verifier can be expressed as a circuit and wrapped in Groth16 for on-chain use — that has to be validated, not assumed.

### The "add BLS12-381" assumption

Your instinct — *for OpenVM we would need to add support for BLS12-381 and it should be fine* — is right in shape but applies to **both** projects, and the work is on the *aggregation* side, not the guest side:

- OpenVM already does BLS12-381 pairings **in the guest** (the pairing extension). What is missing is a BLS12-381 *aggregation* curve: Halo2-over-BN254 → something over BLS12-381 (or, alternatively, keep BN254 inside and add one more wrap: verify the BN254-aggregated proof inside a circuit and emit BLS12-381 Groth16 — the same trick `aiken/groth16` already plays for Circom proofs).
- Jolt's Dory backend is BN254 today (`jolt-dory` → `ark-bn254`). Dory itself is curve-parameterized, so a BLS12-381 instantiation is plausible, but it means re-tuning the sumcheck arithmetic and the opening proofs.

The "wrap twice" option (BN254 inside, BLS12-381 Groth16 outside) is the pragmatic one and is worth trying **first**, because it does not require touching either zkVM's proof system: it only requires a circuit that verifies the inner proof.

</details>

<details>
<summary><b>What this repository already gives us (click to expand)</b></summary>

## What this repository already gives us

| Asset | Where | Why it matters here |
|---|---|---|
| BLS12-381 Groth16 verifier in Aiken (parameterized, plus batch verification) | `aiken/groth16` | The on-chain checker for whatever we produce in Phase 3b. Cross-checked against Sage. |
| Circom → Groth16 → Aiken pipeline (trusted setup CLI, `export-vk`, validator) | `clis/groth16`, `clis/trusted-setup`, `circom/` | The template for "prove off-chain, verify on-chain" — including the VK export step a wrapped zkVM proof would need. |
| Aiken toolchain, Plutus V3, BLS12-381 builtins | `aiken/*` (local Aiken v1.1.19) | The hello world and the validator. `bls12_381_final_verify` is available. |
| Aiken programs with real logic (not toys) | `aiken/kdf`, `aiken/vrf`, `aiken/selective-disclosure` | A step up from "hello world" if the demo works: the same machinery would carry a KDF or a selective-disclosure step. |
| Rust workspace conventions, CLI style, test style | `clis/*`, `nova-prover`, `lattice-prover` | The hosts/guests we write should look like the rest of the repo. |

</details>

<details>
<summary><b>Open questions and risks (click to expand)</b></summary>

## Open questions

1. **What exactly is "an Aiken program inside a zkVM"?** Aiken compiles to UPLC, not RISC-V. Options: (a) port the logic to a guest program and argue equivalence by differential testing; (b) write a UPLC interpreter in the guest and run the *actual* `.plc` artifact. (b) is the honest version of the demo and is the bigger chunk of work — but it is the only one where "the same program ran on-chain and in the zkVM" is literally true.
2. **Does the UPLC interpreter agree with the Plutus VM?** Our interpreter is new code; the Plutus VM is the reference. Mitigation: differential testing against `aiken check` / the off-chain emulator over a corpus of datums, plus restricting the interpreter to the subset of builtins the hello world uses. Residual risk stays and must be stated in the write-up.
3. **Can a BLS12-381 Groth16 verification fit in one Cardano transaction?** The verifier does 4 Miller loops + 1 final exponentiation plus a G1 MSM over the public inputs. That is affordable in principle, but Cardano's per-transaction script budget is the binding constraint. Measure, don't assume; `aiken/groth16` gives us the baseline cost to compare against.
4. **Which curve for the inner layer?** If the wrap-twice trick works, we never need to touch either zkVM's aggregation. If it does not (e.g. the inner proof is too large for a circuit), we are back to adding BLS12-381 to OpenVM's SWIRL aggregation or to Jolt's Dory.
5. **Proof size on-chain.** A 50–300 kB proof does not fit in a redeemer. Whatever we verify on-chain must be the *wrapped* proof (constant size, ~300 bytes for Groth16), with the inner proof verified off-chain but inside the circuit that produces the wrap. That means the inner verification cost is paid by the prover, not by the chain — which is exactly the right trade, but it needs to be stated.

## Risks

- **Prover cost.** OpenVM wants GPUs for anything non-trivial; Jolt is CPU-friendly but still slow. The demo is small, so this is a nuisance, not a blocker — but it shapes what "hello world" can grow into.
- **Maturity.** Jolt is alpha and unaudited; OpenVM 2.1 (the 64-bit target we would prefer) is preview and unaudited. Any conclusion we draw is a conclusion about *today's* code.
- **Scope creep.** A UPLC interpreter + a proof wrapper + an on-chain validator is three projects. Phase 1a exists precisely so that a smaller slice (port → prove → verify off-chain → check output on-chain) lands first.
- **32-bit vs 64-bit.** If we do route 1b, the interpreter has to fit in OpenVM's 32-bit guest or we must build against the 2.1 preview.

</details>

<details>
<summary><b>Planned layout (click to expand)</b></summary>

## Planned layout

```
zkVM/
├── README.md            ← this plan and, later, the results
├── hello-world/         ← the Aiken program (validator + lib), shared input for both zkVMs
├── uplc-guest/          ← UPLC interpreter crate (guest-side), used by both zkVMs
├── openvm/
│   ├── guest/           ← Rust guest (RISC-V) for OpenVM
│   ├── host/            ← prover/verifier driver
│   └── README.md        ← Phase 0 numbers, setup, quirks
├── jolt/
│   ├── guest/           ← Rust guest (RISC-V) for Jolt
│   ├── host/            ← prover/verifier driver
│   └── README.md        ← Phase 0 numbers, setup, quirks
└── onchain/             ← Aiken validator that consumes the wrapped proof
```

Everything here is disposable except the conclusions: the point of the directory is to *measure and compare*, then keep what earned its place.

</details>

<details>
<summary><b>Sources (click to expand)</b></summary>

## Sources

Research snapshot: October 2026.

- OpenVM: [book.openvm.dev](https://book.openvm.dev/) (introduction, quickstart, recursive verification, Solidity SDK, elliptic curve pairing), [blog: OpenVM 2.0 / SWIRL](https://blog.openvm.dev/2.0), [blog: OpenVM 2.1 preview (RV64)](https://blog.openvm.dev/2.1), [blog: formal verification in Lean](https://blog.openvm.dev/fv), [openvm-org/openvm](https://github.com/openvm-org/openvm), [SWIRL whitepaper](https://openvm.dev/swirl.pdf).
- Jolt: [Jolt Book](https://jolt.a16zcrypto.com/) (quickstart, hosts, architecture, roadmap: recursion / on-chain verifier), [a16z/jolt](https://github.com/a16z/jolt) (README, workspace `Cargo.toml`, `crates/jolt-dory/Cargo.toml`), [blog: 6× speedup](https://a16zcrypto.com/posts/article/jolt-6x-speedup/), [blog: 64-bit proving](https://a16zcrypto.com/posts/article/64-bit-proving-jolt/), papers: [Jolt (eprint 2023/1217)](https://eprint.iacr.org/2023/1217), [Twist and Shout](https://eprint.iacr.org/2025/105), [Lasso](https://eprint.iacr.org/2023/1216).
- Aiken / Cardano: local Aiken v1.1.19, [aiken-lang/aiken](https://github.com/aiken-lang/aiken), and this repo's `aiken/groth16`.

</details>
