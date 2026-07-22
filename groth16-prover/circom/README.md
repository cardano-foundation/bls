# Circom circuits for Groth16 prover

This directory contains Circom circuits that can be loaded by the Rust prover via the `circom_adapter` module.

## Available circuits

| Directory | What it proves | Constraints | Status |
|-----------|---------------|-------------|--------|
| [`SimpleExample/`](SimpleExample/README.md) | 3-gate multiplication chain (`a = x1·x2·x3·x4`) | 3 | ✅ Complete |
| [`Privacy/`](Privacy/README.md) | Merkle membership — shielded spend with MiMC(x⁷) | 1,107 | ✅ Complete |
| [`PoseidonPreimage/`](PoseidonPreimage/README.md) | Poseidon hash pre-image knowledge | ~300 | ✅ Complete |
| [`PoseidonMerkle/`](PoseidonMerkle/README.md) | Merkle membership with PoseidonBLS12_381 hashing | 737 (depth 2) | ✅ Complete |
| [`RangeProof/`](RangeProof/README.md) | Range proof + Poseidon commitment (`value ∈ [0, 2^n)`) | ~`n + 250` | ✅ Complete |
| [`Blake2b224Preimage/`](Blake2b224Preimage/README.md) | Blake2b-224 hash pre-image (Cardano key hash) | ~79K | ⚠️ Circuit + witness validated; proving blocked by RAM |
| [`Ed25519Verify/`](Ed25519Verify/README.md) | Ed25519 signature verification in-circuit | ~4M | ✅ **Witness works** — proving blocked by memory (dense), sparse prover should unblock |
| [`EdDSAJubJub/`](EdDSAJubJub/README.md) | EdDSA-JubJub signature verification (deterministic nonce, Poseidon challenge) | 12 601 | ✅ Complete — full e2e pass |
| [`CardanoKeyOwnership/`](CardanoKeyOwnership/README.md) | Private key → public key ownership proof (JubJub) | ~4K | ✅ Complete — full e2e pass |

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
  **Key insight:** A critical bug in the `.r1cs` parser was fixed where only the first byte of 32-byte field coefficients was read, causing `-1` (used by Circom for output wires) to be read as `255` instead of being mapped to `1`. This corrupted R1CS matrices and made public-input commitment points collapse to identity.

- **1. Merkle Membership / Privacy Coin Spend** (1107 constraints, all-private inputs) — ZCash-style shielded UTXO spending on Cardano. See [`Privacy/README.md`](Privacy/README.md).  
  **Key insight:** Because all user-facing inputs in the depth-2 wrapper are `private`, the only public variable is the constant wire (`1`). The on-chain verifier only needs **one** `ic` entry and the public-input list is just `[1]`. Verification cost is therefore identical to the 3-gate `SimpleExample` — roughly **20 % of the Cardano script CPU budget** — despite the circuit having 1107 constraints. This is the fundamental power of Groth16: verifier cost is constant regardless of circuit size.

- **2. Poseidon Hash Pre-image** — prove knowledge of a secret whose Poseidon hash equals a public commitment.  
  **Public input:** `hash_commitment`  
  **Private input:** `secret`  
  **Use case:** Sealed-bid auctions, passwordless authentication.  
  See [`PoseidonPreimage/README.md`](PoseidonPreimage/README.md).

- **3. Range Proof / Comparison** — prove a committed value lies in range `[0, 2^n)` without revealing the value.  
  **Public input:** `value_commitment`  
  **Private inputs:** `value`, `blinding_factor`  
  **Use case:** Confidential transaction amounts.  
  **Status:** ✅ **Complete.** Two circuits in `circom/RangeProof/`: `RangeProofSimple(n)` and `RangeProofCommitted(n)`. Both compile, generate witnesses, and produce valid Groth16 proofs end-to-end on BLS12-381. See [`RangeProof/README.md`](RangeProof/README.md).

- **5. EdDSA-JubJub Signature Verification** (12 601 constraints, 7 public inputs) — deterministic EdDSA-JubJub signature proof over the JubJub curve embedded in BLS12-381's scalar field.  
  Full e2e pipeline passes: compile → witness gen → ceremony-dev → prove → verify.  
  See [`EdDSAJubJub/README.md`](EdDSAJubJub/README.md).  
  **Optimisation applied:** Circuit reduced from 18 112 wires to 12 601 wires (31 % reduction) via two structural changes documented in [Optimisation measures](#optimisation-measures-eddsa-jubjub) below.

- **6. Private Key → Public Key Ownership Proof** — prove knowledge of the private scalar that generates a given public key / address.  
  **Public input:** `public_key`  
  **Private input:** `private_scalar`  
  **Use case:** Wallet ownership proof without revealing the private key. This is the core key-derivation step used in Cardano wallets: given a private scalar `x`, show that `pub = x · G`.  
  **Status:** ✅ **Implemented end-to-end.** A working JubJub-based ownership circuit (`cardano_key_ownership.circom`) compiles, generates witnesses, and produces valid Groth16 proofs verified by the Rust prover CLI. It proves `[sk]·G_JubJub == pk` using fixed-base scalar multiplication over 254 bits (~4K constraints). A Curve25519 ownership proof would require the same chunked-arithmetic templates used in `Ed25519Verify` (~4M constraints) and is feasible but not yet implemented.  
  **Reference:** [IntersectMBO/cardano-crypto `generate`](https://github.com/IntersectMBO/cardano-crypto/blob/develop/src/Cardano/Crypto/Wallet.hs#L161) for the derivation logic.

### Circuit validated, proving blocked by memory

- **4. Blake2b-224 Hash Pre-image (Cardano Key Hash)** — prove knowledge of a pre-image that hashes to a given Cardano key hash.  
  **Public input:** `blake2b_224_hash`  
  **Private input:** `pre_image`  
  **Use case:** Proving ownership / linking proofs to on-chain Cardano addresses.  
  **Status:** Circuit compiles (79K constraints) and witness generates correctly, but the dense-matrix ceremony requires ~200 GB RAM — blocked on memory. Implementation 6 (sparse-matrix prover) theoretically unblocks this; see [`Blake2b224Preimage/README.md`](Blake2b224Preimage/README.md) for scaling analysis.  
  **Reference repo:** [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) provides the upstream Blake2b Circom circuit (MIT License).

### Circuit validated, proving blocked by memory

- **7. EdDSA / Ed25519 Signature Verification In-Circuit** — verify a standard Ed25519 signature inside a Groth16 circuit.  
  **Public inputs:** `msg[n]`, `A[256]`, `R8[256]`  
  **Private inputs:** `S[255]`, `PointA[4][3]`, `PointR[4][3]`  
  **Use case:** Attest to off-chain events signed by standard Ed25519 keys (SSH, TLS, other blockchains).  
  **Status:** ✅ **Witness generation works.** The `Ed25519Verify` circuit in `circom/Ed25519Verify/` compiles to ~4M non-linear + ~1.5M linear constraints on BLS12-381. Contrary to earlier assessment, **witness generation succeeds** with valid Ed25519 signatures. The chunked-arithmetic templates (`ChunkedMul`, `ModulusWith25519Chunked51`, `BigModInv51`) use standard integer arithmetic in `<--` witness hints that is field-agnostic; the `===` constraints enforce correctness modulo the native BLS12-381 scalar field, which is large enough to hold all 85-bit limb values without overflow.  
  **Important caveat:** Earlier reports of "field incompatibility" were incorrect. The circuit works on BLS12-381 without template modifications.  
  **Memory:** The dense-matrix ceremony would require ~512 TB RAM. The sparse prover (Implementation 6) is the path forward — projected ~1.2 GiB RAM for 4M constraints.  
  See [`Ed25519Verify/README.md`](Ed25519Verify/README.md) for full analysis and path forward.

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

---

## Optimisation measures — EdDSA-JubJub circuit

The EdDSA-JubJub circuit was reduced from **18 112 wires** (original design)
to **12 601 wires** (31 % reduction) via two structural changes. Both
trade redundant computation for fewer constraints — acceptable because the
prover runs offline.

### Measure 1: Remove public key derivation (pkMul)

**Original:** The circuit computed `pk = [sk]·G` internally via a second
fixed-base scalar multiplication, then used the derived `pk` in both the
challenge hash and the verification equation.

**Problem:** `EscalarMulFixJubJub` at 253 bits costs ~4 119 wires per
instantiation. Computing `pk` internally is redundant when `pk` is already
a public input — the verifier binds it via the challenge hash `k`.

**Fix:** Removed `JubJubPbk` / `EscalarMulFixJubJub` for pk computation.
Instead, `pk = (pku, pkv)` is passed directly as a public input. The
circuit now has two fixed-base muls (`[r]·G` and `[S]·G`) and one
variable-base mul (`[k]·pk`), saving ~4 119 wires.

**Cost:** The prover must supply the `pk` public input externally. This is
not a security concern — `pk` is public — but the circuit no longer proves
"this pk is derived from the same sk". Instead, knowledge of `sk` is
implicit: the challenge `k` binds `pk`, and the verification equation
`[S]·G = R + [k]·pk` is only satisfiable if the prover knows `sk`.

### Measure 2: Single Poseidon T6 instead of 4× Poseidon T3

**Original:** The challenge hash used four sequential Poseidon T3 invocations:
`Poseidon(Poseidon(Poseidon(R.u, R.v), pk.u, pk.v), msg)`.

**Problem:** Each Poseidon T3 adds ~276 constraints (5 rounds × ~55
constraints per round). Four invocations cost ~1 104 constraints plus
inter-component wiring.

**Fix:** Replaced with a single `PoseidonBLS12_381_T6` invocation:
`PoseidonT6(R.u, R.v, pk.u, pk.v, msg, 0)` — five inputs, one hash.
The t=6 Poseidon with RF=8, RP=60 has ~1 632 constraints, but eliminates
three intermediate hash outputs and their wiring overhead, yielding a net
reduction.

**Constants:** Poseidon T6 round constants (408 values) and the 6×6 MDS
matrix were generated with `generate_parameters_grain.sage` and are
inlined directly into `poseidon_bls12_381_t6.circom`. All three security
algorithms (counting, interpolation, side-channel) pass.

### Combined effect

| Metric | Original | Optimised | Reduction |
|--------|----------|-----------|-----------|
| Wires | 18 112 | 12 601 | –31 % |
| Constraints | ~12 600 | 12 600 | ~0 % (bottleneck is fixed-base muls) |
| Dense matrix memory | ~20 GiB | ~14.2 GiB | –29 % |
| Prover peak RAM | ~32 GiB (OOM) | ~14.2 GiB | –56 % |

The constraint count did not drop proportionally because the two fixed-base
scalar multiplications (`[r]·G` and `[S]·G`, each 254-bit) dominate: each
instantiation contributes ~6 300 constraints regardless of the other
circuit components. The memory reduction comes from fewer wires, which
directly reduces the dense matrix dimensions (`n_wires × n_constraints ×
32 bytes × 3 matrices`).

### Prover-side memory fix

Even with the optimised circuit, the original `prove_with_full_pk`
implementation stored all 12 601 per-variable QAP polynomials (each
16 384 × 32 bytes = 512 KiB) simultaneously alongside the dense matrices,
peaking at ~32.7 GiB and OOM-killing at 12 601 wires.

The fix (in `engine.rs` and `prover.rs`) builds each per-variable
polynomial on-the-fly, accumulates it into the witness polynomial, and
immediately drops it. The `domain_size()` method was added to the
`QapEngine` trait so the prover knows the FFT domain size without
materialising the full QAP. Peak RAM dropped to ~14.2 GiB (the dense
matrices alone).
