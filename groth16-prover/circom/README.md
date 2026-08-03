# Circom circuits for Groth16 prover

This directory contains Circom circuits that can be loaded by the Rust prover via the `circom_adapter` module.

## Available circuits

| Directory | What it proves | Constraints | Status |
|-----------|---------------|-------------|--------|
| [`SimpleExample/`](SimpleExample/README.md) | 3-gate multiplication chain | 3 | ✅ Working e2e |
| [`SumOfProducts/`](SumOfProducts/sum_of_products.circom) | 4-gate sum-of-products | 5 | ✅ Complete |
| [`Privacy/`](Privacy/README.md) | Merkle membership — shielded spend with MiMC(x⁷) | 1,107 | ✅ Working e2e |
| [`PoseidonPreimage/`](PoseidonPreimage/README.md) | Poseidon hash pre-image knowledge | ~300 | ✅ Working e2e |
| [`PoseidonMerkle/`](PoseidonMerkle/README.md) | Merkle membership with PoseidonBLS12_381 hashing | 737 (depth 2) | ✅ Working e2e |
| [`RangeProof/`](RangeProof/README.md) | Range proof + Poseidon commitment (`value ∈ [0, 2^n)`) | ~`n + 250` | ✅ Working e2e |
| [`Blake2b224Preimage/`](Blake2b224Preimage/README.md) | Blake2b-224 hash pre-image (Cardano key hash) | ~79K | ✅ Working e2e |
| [`EdDSAJubJub/`](EdDSAJubJub/README.md) | EdDSA-JubJub signature verification (deterministic nonce, Poseidon challenge) | 12 601 | ✅ Working e2e |
| [`Ed25519Verify/`](Ed25519Verify/README.md) | Ed25519 signature verification in-circuit | ~4M | ✅ Working e2e |
| [`CardanoKeyOwnership/`](CardanoKeyOwnership/README.md) | Key ownership: JubJub variant | ~4K | ✅ Working e2e |
| [`CardanoKeyOwnership/`](CardanoKeyOwnership/README.md) | Key ownership: Ed25519 variant (real Cardano wallet key) | ~1.97M | ✅ Working e2e |
| [`AnonymousAirdrop/`](AnonymousAirdrop/README.md) | SMT membership + score threshold — anonymous reputation-gated airdrop | 1,561 (depth 2) | ✅ Working e2e |

---

## The Circom pipeline (what each tool does)

The standard Circom workflow involves three distinct steps, each with a dedicated tool:

| Tool | Input | Output | What it does |
|------|-------|--------|--------------|
| **circom** (compiler) | `.circom` file | `.r1cs` + `.wasm` | Compiles the circuit into a **Rank-1 Constraint System** (sparse matrices A, B, C) and a **WebAssembly witness calculator** that knows how to solve every wire value given concrete inputs |
| **snarkjs** (or any WASM runtime) | `.wasm` + `input.json` | `.wtns` | Executes the compiled WASM to compute the full **witness vector** — every input, intermediate, and output wire value |
| **Our Rust prover** | `.r1cs` + `.wtns` | Groth16 proof | Parses the constraints and witness, builds the QAP, and assembles a valid proof |

### Why three separate tools?

1. **Compilation is one-time.** The `.circom` file is compiled once to `.r1cs` + `.wasm`. The `.r1cs` captures the *structure* of the circuit (which gates exist and how they connect). The `.wasm` captures the *computation* (how to fill in the wires).

2. **Witness generation is per-proof.** Each time you want to prove something, you provide concrete inputs (`input.json`), run the WASM calculator, and get a `.wtns` file. The witness is simply the assignment of every wire.

3. **Proving is independent.** The prover does not need to know how the witness was computed — it only checks that the witness satisfies the constraints in `.r1cs`. This is why our Rust crate can replace `snarkjs`'s prover entirely while still reusing Circom's compiler and witness generator.

> **Note:** `snarkjs` is **not** required for proving. It is only a convenience wrapper for running the Circom-generated WASM witness calculator. In principle you could replace it with any WASM runtime (or even re-implement the witness computation in Rust) as long as it outputs a valid `.wtns` file.

---

## Prerequisites

Install the Circom compiler (see [Circom installation docs](https://docs.circom.io/getting-started/installation/)):

```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```

Also install `snarkjs` for witness generation:

```bash
npm install -g snarkjs
```

---

## Compiling a circuit

```bash
cd groth16-prover/circom/SimpleExample

# Compile to BLS12-381 (must match the Rust prover curve; BN254 is not supported)
circom multiplier.circom --r1cs --wasm --sym --prime bls12381

# This produces:
#   multiplier.r1cs   — binary R1CS constraint system
#   multiplier.wasm   — WebAssembly witness calculator
#   multiplier.sym    — signal name map (human-readable)
```

## Generating the witness

Create `input.json` with the private inputs, then run the WASM witness calculator via `snarkjs`:

```bash
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
```

## Using in the Rust prover

The Rust crate can load `.r1cs` and `.wtns` directly:

```rust
use groth16_prover::circom_adapter::CircomCircuit;

let circuit = CircomCircuit::from_r1cs("circom/SimpleExample/multiplier.r1cs").unwrap();
circuit.load_witness("circom/SimpleExample/witness.wtns").unwrap();
```

The parsed `L`, `R`, `O` matrices and witness vector are then fed into any `QapEngine` + `Prover` combination, producing a proof.

---

## End-to-end pipeline (CLI)

Each circuit README documents its own full e2e flow. The common CLI steps after compilation and witness generation are:

```bash
cd groth16-prover/cli

# 1. Single-party trusted setup (dev only). Use --sparse for large circuits.
cargo run --release -- ceremony-dev \
  --circuit ../circom/<Circuit>/<circuit>.r1cs \
  --proving-key /tmp/<circuit>.pk \
  --verifying-key /tmp/<circuit>.vk

# 2. Produce the proof
cargo run --release -- prove \
  --circuit ../circom/<Circuit>/<circuit>.r1cs \
  --witness ../circom/<Circuit>/witness.wtns \
  --proving-key /tmp/<circuit>.pk \
  --out /tmp/<circuit>.proof

# 3. Verify off-chain
cargo run --release -- verify \
  --proof /tmp/<circuit>.proof \
  --public /tmp/<circuit>.pub \
  --verifying-key /tmp/<circuit>.vk
# → Verification result: VALID

# 4. Export the verifying key as an Aiken source file (for on-chain verification)
cargo run --release -- export-vk \
  --verifying-key /tmp/<circuit>.vk \
  --out /tmp/<circuit>_vk.ak
```
