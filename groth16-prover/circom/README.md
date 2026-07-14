# Circom circuits for Groth16 prover

This directory contains Circom circuits that can be loaded by the Rust prover via the `circom_adapter` module.

## Available circuits

| Directory | What it proves | Status |
|-----------|---------------|--------|
| [`SimpleExample/`](SimpleExample/README.md) | 3-gate multiplication chain (`a = x1·x2·x3·x4`) | ✅ Complete |
| [`Privacy/`](Privacy/README.md) | Merkle membership — shielded spend with MiMC(x⁷) | ✅ Complete |
| [`PoseidonPreimage/`](PoseidonPreimage/README.md) | Poseidon hash pre-image knowledge | ✅ Complete |

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

## Interesting Groth16 problems on Cardano

Full pipeline for each item: **Circom → groth16-prover (dev ceremony) → Aiken on-chain validator**.

### Completed

- **0. SimpleExample Multiplier** (3 constraints, 2 public inputs) — validated the entire toolchain end-to-end.
- **1. Merkle Membership / Privacy Coin Spend** (1107 constraints, all-private inputs) — ZCash-style shielded UTXO spending on Cardano. See [`Privacy/README.md`](Privacy/README.md).
- **2. Poseidon Hash Pre-image** — prove knowledge of a secret whose Poseidon hash equals a public commitment. See [`PoseidonPreimage/README.md`](PoseidonPreimage/README.md).

### Pending

- **3. Range Proof / Comparison** — prove a committed value lies in range `[0, 2^n)` without revealing the value. Use case: confidential transaction amounts.
- **4. Blake2b-224 Hash Pre-image (Cardano Key Hash)** — prove knowledge of a pre-image that hashes to a given Cardano key hash. Use case: proving ownership / linking proofs to on-chain Cardano addresses.
- **5. Private Key → Public Key Ownership Proof** — prove knowledge of the private scalar that generates a given public key / address. Use case: wallet ownership proof without revealing the private key.
- **6. EdDSA / Ed25519 Signature Verification In-Circuit** — verify a standard Ed25519 signature inside a Groth16 circuit. Use case: attest to off-chain events signed by standard Ed25519 keys (SSH, TLS, other blockchains).

---

## Compiling a circuit

```bash
cd groth16-prover/circom/SimpleExample

# Compile to BLS12-381 (must match the Rust prover curve)
circom multiplier.circom --r1cs --wasm --sym

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
