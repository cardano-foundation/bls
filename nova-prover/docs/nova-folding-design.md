# Nova Folding Design

## Overview

This document explains the Nova folding scheme as applied in the `nova-prover` project. It covers the core concepts, the IVC architecture, the comparison with alternatives, and the design decisions specific to this project's stack (BLS12-381, Circom, arkworks, Aiken).

> **Status:** the NIFS folding + compression scheme described here is **implemented** (Implementation 9, POC): `nova-prover/src/nifs.rs`, `nova-prover/src/compression.rs`, and the `nova` CLI (`fold --nifs` / `compress` / `verify --compression-proof`). Sections below marked *design* are the design as-built; measured numbers come from the same-run benchmark in [`nova-prover/README.md`](../README.md).

## Background: The Recursion Problem

Groth16 is the most efficient general-purpose SNARK for R1CS circuits, but it has a fundamental limitation: verifying a proof requires a pairing check, and embedding a pairing check inside a circuit (to make proofs recursive) costs ~100K–500K constraints per nesting level. For a computation with N steps, naive recursion means N nested proofs, each requiring its own trusted setup and re-proving everything above it. The verification cost and proof bundle both grow with N.

## Nova's Key Innovation: Folding

Nova avoids re-verification entirely. Instead of sealing proofs inside proofs, it **folds** two instances of the same step circuit into a single instance that is valid exactly when both inputs were. The fold is a transparent (no trusted setup), linear-time algebraic operation that produces a "relaxed" running accumulator — like a tally updated after every step, without ever re-checking the old steps.

### The Folding Equation

A Relaxed-R1CS instance is `U = (x, u, W̄, Ē)` where:
- `x` is the public input
- `u` is a scalar slack variable
- `W̄` is a Pedersen commitment to the witness `W`
- `Ē` is a Pedersen commitment to the error term `E`

The relaxed equation is:

```
(AZ) ∘ (BZ) = u·(CZ) + E
```

where `Z = (W, x, u)` and `∘` denotes element-wise multiplication. The error term `E` absorbs the difference between the left and right sides, allowing the folded instance to be satisfiable even when the individual instances are not exactly satisfied.

Folding two instances `U₁` and `U₂` into a new instance `U₃` involves:
1. Computing a Fiat-Shamir challenge `r = H(acc ‖ step)` from the transcript
2. Combining the commitments: `W̄₃ = W̄₁ + r·W̄₂`, `Ē₃ = Ē₁ + r·Ē₂`
3. Combining the witnesses and scalars accordingly

The fold is a linear-time operation (two group scalar multiplications and a few field operations). No SRS is required.

### The IVC Architecture

```
state_0 ──▶ [step₀: f(step₀, state₀)] ──▶ state_1 ──▶ [step₁] ──▶ … ──▶ state_N
              │ NIFS fold (two O(step) MSMs)     │ NIFS fold
              └──────────────▶ one Relaxed-R1CS running instance U_N
                                        │
                                        ▼
                        compression circuit (2·n_constraints, Rust-built)
                                        │ Groth16
                                        ▼
                              one proof, one pairing check
```

Each step's witness is folded into a running Relaxed-R1CS instance `U` with a NIFS (linear-time, no trusted setup, **off-circuit** — no curve cycle needed). At the end, a **compression circuit** proves the final relaxed instance is satisfiable and is Groth16-compressed into a single proof verified with one pairing check. The Fiat-Shamir challenge is `r = H("groth16-prover-nova-fold-v1" ‖ acc ‖ U1 ‖ U2)`, domain-separated from the `"groth16-prover-nova-transcript-v1"` state-chain transcript.

### Properties

| Property | Monolithic Groth16 | Nova IVC (with compression) |
|----------|-------------------|-----------------------------|
| Total constraints | C | N × (step_size + overhead) ≈ C + N·overhead |
| Per-step constraints | C (all at once) | ~40K–60K |
| Trusted setup | Per-circuit, SRS ∝ C | None for folding; one small ceremony for compression SNARK |
| Memory peak | O(C) | O(step_size) |
| Proof size | 192 bytes | ~500 bytes (IVC) + 192 bytes (compression) |
| Verifier cost | One pairing | One pairing + accumulator check |
| On-chain verification | O(1) | O(1) (after compression) |

## Comparison with Alternatives

| | Naive recursion (verifier-in-circuit) | N independent proofs | Nova folding |
|---|---|---|---|
| What each step adds | A proof that the previous verifier ran | A full standalone proof | A linear-time fold of the running accumulator |
| Trusted setup | New for every nesting level | One per circuit | One small, circuit-agnostic, reusable setup (compression) |
| Proof size after N steps | Grows with nesting depth | N proofs — bundle is O(N) | Constant (~500 B IVC + one 192 B compression proof) |
| Verifier cost | Grows with nesting depth | N pairing checks | One pairing check |
| Prover memory | O(total) at the top level | O(N · step) stored | O(step) — only the current step + running instance |
| Why it's hard | Pairing + non-native field arithmetic in a circuit | Verifier work grows linearly with N | Per-step circuit embeds a small fold verifier (~10K–30K constraints) |

## Design Decisions for This Project

### Why Relaxed-R1CS (not SuperNova)

Relaxed-R1CS (Nova) is the simplest folding scheme and matches our existing R1CS constraint system from Circom. SuperNova supports non-uniform steps (different circuits per step) but adds significant complexity. Our step circuits are identical (same shape, different inputs), so Relaxed-R1CS is the right choice.

### Why Pedersen Commitments

Pedersen commitments over G1 are the standard choice for Nova folding on BLS12-381. They are additively homomorphic, have O(1)-sized commitments, and are natively supported by arkworks. The trade-off is that Pedersen commitments are DLOG-based and broken by Shor's algorithm — this is the motivation for the post-quantum path (Implementation 10).

### Why BLAKE2b512 for the Transcript

The Fiat-Shamir challenge `r = H(acc ‖ step)` requires a hash function that is:
- Collision-resistant (for soundness)
- Available in Circom (for the compression circuit)
- Fast in practice

BLAKE2b512 is already used in the project's transcript binding and is available as a Circom gate. SHA-256 would also work but BLAKE2b is faster.

### Why Off-Circuit Folding (No Curve Cycle)

Folding runs **outside** any verifier circuit — it is a prover-side operation, not an on-chain or in-circuit operation. This means no curve cycle is needed. The folding operation is transparent and does not require a pairing check inside a circuit. The only on-chain verification is the compression SNARK's single pairing check.

### Why the Compression SNARK is Groth16

The compression circuit proves that the final relaxed instance satisfies the Relaxed-R1CS equation. This is a standard R1CS circuit of size ≈ one step (~100K constraints). Groth16 is the most efficient SNARK for this size range, and our existing `FftQapEngine`, `PippengerProver`, and `FullProvingKey` ceremony all apply unchanged.

### On-Chain Verifier Extension

The Aiken verifier currently checks a single Groth16 pairing. For Nova IVC, it needs to additionally check the accumulator consistency (2–3 group additions). This is small enough to fit in Plutus V3 and does not change the verification model fundamentally.

## Non-Goals

- **In-circuit IVC recursion (SuperNova-style):** Not buildable on BLS12-381 — requires a 2-cycle (Pasta / BN254–Grumpkin) or non-native `Fq1`-in-`Fr1` emulation (~1M+ gates/scalar mult).
- **SuperNova non-uniform steps:** Implementation 9 assumes one repeated step circuit. Supporting different circuits per step is deferred.
- **CycleFold:** The closest published route toward in-circuit recursion near BLS12-381, but whether a curve over `Fr1` (e.g., Bandersnatch) instantiates it is an open research question.

## Implementation 9 — Concrete Design (NIFS + compression)

### NIFS module (`nova-prover/src/nifs.rs`)

Relaxed-R1CS instance `U = (x, u, W̄, Ē)`, witness `W' = (W, E)`, relaxed equation `(AZ)∘(BZ) = u·(CZ) + E` with `Z = (W, x, u)`. Step instances are ordinary R1CS (`u = 1`, `E = 0`).

- **Folding params (transparent, no SRS):** two deterministic G1 bases `G_W` (n_vars points) and `G_E` (n_constraints points) by hash-to-curve from a fixed seed; `com(v) = Σ v_i·G_i`.
- **Fold** (`r = BLAKE2b512("fold" ‖ acc ‖ U1 ‖ U2)`, domain-separated from the `"chain"` transcript):
  - `x3 = x1 + r·x2`, `u3 = u1 + r·u2`
  - `W̄3 = W̄1 + r·W̄2`, `Ē3 = Ē1 + r·Ē2 + r·Ē_cross`
  - `W3 = W1 + r·W2`, `E3 = E1 + r·E2 + r·E_cross`
  - cross-term `E_cross = (AZ1)∘(BZ2) + (AZ2)∘(BZ1) − u1(CZ2) − u2(CZ1)`
- Per-step prover work: two O(step) MSMs (commitments of the new instance + `E_cross`). Folding is off-circuit → **no curve cycle**.

### Compression circuit (`nova-prover/src/compression.rs`)

Proves final `U_N` satisfiable. The circuit is built **in Rust** (no circom needed): it reuses the step circuit's sparse A/B/C matrices and checks the relaxed equation `(AZ)∘(BZ) = u·(CZ) + E` row by row, with `Z`, `u` and `E` all public. Size is **`2 · n_constraints` constraints** ("size ≈ one step"), measured:

| Step circuit | Step constraints | Compression constraints | Compression wires |
|---|---|---|---|
| `ed25519_verify_nova` / `cardano_ed25519_ownership_nova` | 7,724 | 15,448 | 23,108 |
| `anonymous_airdrop_nova` | 1,207 | 2,414 | 3,626 |
| `eddsa_jubjub_nova` | 9 | 18 | 35 |

**Design change vs the original plan: the Pedersen commitments `W̄`, `Ē` are NOT checked inside the circuit.** An in-circuit re-commitment would require non-native G1-in-Fr arithmetic (~30K–190K constraints per wire — infeasible at step scale). Instead the verifier recomputes `com(W)`, `com(E)` natively with an O(step) MSM (milliseconds) and compares against the bundle instance. Binding holds because the circuit makes `(x, u, W, E)` public, so the Groth16 proof and the native MSM check are anchored to the same witness. This removes the estimated 2–6M-gate cost driver entirely and shrinks the ceremony to the `2·n_constraints` circuit.

### CLI

- `nova fold --nifs [--compression-r1cs compression.r1cs]` — fold N step instances → one relaxed instance; optionally emits the compression circuit `.r1cs`. `params` / `ceremony` / step circuits unchanged.
- `trusted-setup ceremony-dev --sparse --circuit compression.r1cs` — one-time ceremony for the compression circuit (reusable for any step shape).
- `nova compress` — Groth16-compress the final instance (re-folds the witnesses deterministically to recover the private final witness).
- `nova verify --compression-proof ... --compression-vk ...` — transcript check + **one** pairing check (vs N today).

### Shared with groth16-prover (reused unchanged)

`FftQapEngine`, `PippengerProver::prove_with_full_pk_sparse`, `single_party_ceremony_full_from_tw_sparse`, `FullProvingKey`/`VerifyingKey` serialization + `verify_with_vk`, `SparseCircomCircuit` parsing. New code is nova-prover-only: `nifs.rs`, transcript prefixes, CLI wiring.

### E2E demo + benchmark

- Demo: `nova fold --nifs` → `trusted-setup ceremony-dev --sparse` on the emitted compression `.r1cs` → `nova compress` → `nova verify --compression-proof` (one pairing). Worked end to end on all four step circuits (255-step `cardano_ed25519_ownership_nova` / `ed25519_verify_nova`, 254-step `eddsa_jubjub_nova`, 5-step `anonymous_airdrop_nova`) — see the [E2E flow](README.md#e2e-flow--implementation-9-nifs) and [Benchmarks](README.md#benchmarks--nova-ivc-implementation-8-step-chain-vs-implementation-9-nifs).
- Measured (single run): NIFS fold 230 ms/step for the 7.7K-constraint steps vs 700 ms/step Groth16 fold (3.1×); single-pairing verify ~8.8 s for 255 steps (MSM-dominated); compression ceremony 6.2 s; bundle constant in N (579.6 KiB, dominated by the revealed `Z`/`E`).

## References

1. Abhiram Kothapalli, Srinath Setty, Ioanna Tzialla. *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes.* CRYPTO 2022. IACR ePrint [2021/370](https://eprint.iacr.org/2021/370).
2. Dan Boneh, Binyi Chen. *LatticeFold: A Lattice-based Folding Scheme and its Applications to Succinct Proof Systems.* IACR ePrint [2024/257](https://eprint.iacr.org/2024/257).
3. Giacomo Fenzi, Christian Knabenhans, Ngoc Khanh Nguyen, Duc Tu Pham. *Lova: Lattice-Based Folding Scheme from Unstructured Lattices.* ASIACRYPT 2024. IACR ePrint [2024/1964](https://eprint.iacr.org/2024/1964).
4. Cyprian Omukhwaya Sakwa, Anyembe Andrew Omala, Fagen Li. *A Survey of Folding-Based Zero-Knowledge Proofs.* Information Sciences 724 (2026) 122698. DOI [10.1016/j.ins.2025.122698](https://doi.org/10.1016/j.ins.2025.122698).
5. Abhiram Kothapalli, Srinath Setty. *CycleFold: Folding-Scheme-Based Recursive Arguments over a Cycle of Elliptic Curves.* IACR ePrint [2023/1192](https://eprint.iacr.org/2023/1192).
6. Abhiram Kothapalli, Srinath Setty. *HyperNova: Recursive Arguments for Customizable Constraint Systems.* CRYPTO 2024. IACR ePrint [2023/573](https://eprint.iacr.org/2023/573).
7. David Balbás, Anca Nitulescu, Maxime Plançon. *ProtogaLattice: Constant-Round Lattice-based Folding for General Polynomial Relations.* IACR ePrint [2026/1317](https://eprint.iacr.org/2026/1317).
8. Wilson Nguyen, Srinath Setty. *Neo: Lattice-based Folding Scheme for CCS over Small Fields and Pay-per-Bit Commitments.* IACR ePrint [2025/294](https://eprint.iacr.org/2025/294).
