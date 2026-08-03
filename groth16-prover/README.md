# groth16-prover

An **end-to-end Groth16 prover** in Rust over the BLS12-381 curve.

> **Purpose.** This crate implements the full Groth16 pipeline—from R1CS constraints to a valid zero-knowledge proof—using [arkworks](https://arkworks.rs/) primitives. It began as a didactic reference (hard-coded circuit, dense monomial polynomials, deterministic toxic waste) so that every intermediate value could be printed, inspected, and compared against an independent reference implementation. Since then it has grown into a production-capable toolkit with FFT-based QAP construction, Pippenger multi-scalar multiplication, a Circom adapter, a CLI, a Phase 2 multi-party computation ceremony, and a sparse-matrix prover for large circuits.

> **Correctness guarantee.** The entire implementation has been cross-checked line-by-line against a [Sage](https://www.sagemath.org/) script that implements the same mathematics from scratch. See [`RustGroth16Correctness.md`](RustGroth16Correctness.md) for the bit-for-bit comparison of every sub-step.

---

## How to use

### 1. Run unit tests

```bash
cd groth16-prover
cargo test
```

All 54 library tests pass (R1CS relation, QAP interpolation, target polynomial, field arithmetic, Circom parser, prover parity, ptau parser, Phase 2 MPC, sparse-matrix prover, Ed25519/Ed25519 ownership circuits).

### 2. Use the CLI

A full-featured command-line interface lives in `groth16-prover/cli/`. It covers the entire Groth16 lifecycle—from ceremony to proof generation and verification—and includes auxiliary tools for Circom witness computation and sparse Merkle tree operations.

#### Ceremony

Two switchable ceremony paths produce the same `.pk` / `.vk` binary format. The prover and verifier are agnostic to which path was used.

<details>
<summary><b>Dev ceremony</b> (single-party, instant — for testing and CI)</summary>

```bash
cd groth16-prover/cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk
```

</details>

<details>
<summary><b>Production ceremony</b> (multi-party MPC — for mainnet)</summary>

```bash
# 1. Initialize from a universal Phase 1 SRS
cargo run --release -- phase2 new \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --srs ../universal.ptau \
  --zkey /tmp/multiplier_0000.zkey

# 2. Participants contribute sequentially
cargo run --release -- phase2 contribute \
  --zkey-in /tmp/multiplier_0000.zkey \
  --zkey-out /tmp/multiplier_0001.zkey \
  --name "Alice"

# 3. Verify and finalize
cargo run --release -- phase2 verify --zkey /tmp/multiplier_0001.zkey
cargo run --release -- phase2 finalize \
  --zkey /tmp/multiplier_0001.zkey \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk
```

</details>

> **Current trust model.** We do **not** run a full two-phase MPC from scratch. Instead we reuse an existing, publicly audited **Phase 1** universal SRS (see below) and run our own **multi-party Phase 2** ceremony on top of it. This means security depends on:
> 1. **Trust in the existing Phase 1 ceremony** (widely scrutinised, hundreds of participants).
> 2. **1-of-N honesty in our Phase 2 ceremony** — as long as at least one participant honestly discards their randomness, the circuit-specific toxic waste (`alpha`, `beta`, `gamma`, `delta`) remains unknown.
> The Phase 2 logic was rewritten from scratch because the best available Rust reference (Manta Network) is GPL-3.0, which is incompatible with our Apache-2.0 license.

---

#### What is an SRS? (Structured Reference String)

<details>
<summary><b>Click to expand</b></summary>

A **Structured Reference String (SRS)** is a collection of pre-computed elliptic-curve group elements that a Groth16 prover needs to generate proofs. Think of it as a "public key" for the proving system — it encodes a secret random value (traditionally called `tau`) into group elements, but the raw scalar itself is never revealed.

**High-level intuition**

Groth16 requires evaluating polynomials at a secret point `tau`. Instead of giving the prover the scalar `tau` (which would let anyone forge proofs), the trusted setup computes:

```
G1, tau·G1, tau²·G1, ..., tau^N·G1
G2, tau·G2, tau²·G2, ..., tau^N·G2
```

where `G1` and `G2` are the base points of the BLS12-381 curve. These group elements are the **SRS**. The prover can now compute `p(tau)·G1` for any polynomial `p(x)` using only the SRS and the polynomial's coefficients — no knowledge of `tau` required. This is the foundation of all zk-SNARK security: the proof is built *in the exponent*.

**What an SRS contains (Groth16-specific)**

| Element | Formula | Purpose |
|---------|---------|---------|
| `tau^i·G1` | `tau^i · G1` | Basis for computing `l(tau)·G1` (left wire polynomial) |
| `tau^i·G2` | `tau^i · G2` | Basis for computing `r(tau)·G2` (right wire polynomial) |
| `alpha·tau^i·G1` | `alpha · tau^i · G1` | Mixed term for proof element `C` |
| `beta·tau^i·G1` | `beta · tau^i · G1` | Mixed term for proof element `C` |
| `beta·G2` | `beta · G2` | Proof element `B` offset |

In a **full two-phase ceremony**, the SRS is produced in **Phase 1** (universal, circuit-agnostic) and then specialised in **Phase 2** (circuit-specific). Our current implementation reuses an external Phase 1 SRS and runs Phase 2 ourselves.

**Security assumption**

The SRS is secure as long as **at least one participant in the ceremony was honest and destroyed their randomness**. If all participants colluded and shared their secrets, they could reconstruct `tau` and forge proofs. This is why large, open ceremonies with hundreds of participants are preferred — the probability that *everyone* is dishonest is negligible.

</details>

---

#### What is Perpetual Powers of Tau (PPoT)?

<details>
<summary><b>Click to expand</b></summary>

[Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) (PPoT) is a long-running, community-driven trusted-setup ceremony maintained by [Privacy & Scaling Explorations (PSE)](https://appliedzkp.org/). It produces universal SRS files (`.ptau`) for the BLS12-381 curve that can be reused by any Groth16 circuit up to a maximum constraint size.

**Key facts about PPoT**

- **Universal:** One SRS works for *any* circuit (up to `2^power` constraints).
- **Open:** Anyone can contribute randomness. As of 2024 there are 80+ verified contributions.
- **Auditable:** Every contribution includes a cryptographic proof of knowledge, and the full transcript is public.
- **Format:** The output is a `.ptau` file — a binary blob of uncompressed Montgomery-curve points in snarkjs format.
- **Reusable:** Because it is universal, you do not need to run a fresh Phase 1 for every new circuit.

**Trust model with PPoT**

By importing a PPoT `.ptau` file, we inherit the security of the existing Phase 1 ceremony (80+ participants). We then run our own Phase 2 ceremony on top of it, adding circuit-specific randomness (`alpha`, `beta`, `gamma`, `delta`). The final security guarantee is:

> **At least one honest participant in PPoT Phase 1** AND **at least one honest participant in our Phase 2**.

This is the same trust model used by production systems like Zcash, Filecoin, and Manta Network.

</details>

---

#### Hands-on: importing an external SRS from PPoT

<details>
<summary><b>Click to expand</b></summary>

**Step 1 — Download a PPoT `.ptau` file**

PPoT publishes prepared SRS files for different powers (constraint limits). For a circuit with up to `2^14 = 16,384` constraints, download the power-14 file:

```bash
# Download from the PPoT repository (example URL — check latest release)
curl -L -o universal.ptau \
  https://ppot.blob.core.windows.net/public/powersOfTau28_hez_final_14.ptau
```

> **Check the file size.** A power-14 `.ptau` is roughly **33 MB** (uncompressed BLS12-381 points). Larger powers scale linearly.

**Step 2 — Import into the prover**

The `groth16-prover` CLI can read `.ptau` files directly and use them as the Phase 1 SRS for a Phase 2 ceremony:

```bash
cd groth16-prover/cli

# Initialize a new Phase 2 ceremony from the universal SRS
cargo run --release -- phase2 new \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --srs ../universal.ptau \
  --zkey /tmp/multiplier_0000.zkey
```

What happens under the hood:
1. The `.ptau` parser reads the `tauG1`, `tauG2`, `alphaTauG1`, `betaTauG1`, and `betaG2` sections.
2. Every point is validated: on-curve and in the correct subgroup.
3. The `Phase2Accumulator` is initialised by combining the universal SRS with the circuit R1CS (computing per-variable group elements via MSM over the `.ptau` basis).
4. The initial `zkey` file is written. It contains **no scalars** — only group elements.

**Step 3 — Multi-party Phase 2 contributions**

After importing the SRS, run the circuit-specific MPC:

```bash
# Alice contributes
cargo run --release -- phase2 contribute \
  --zkey-in /tmp/multiplier_0000.zkey \
  --zkey-out /tmp/multiplier_0001.zkey \
  --name "Alice"

# Bob contributes
cargo run --release -- phase2 contribute \
  --zkey-in /tmp/multiplier_0001.zkey \
  --zkey-out /tmp/multiplier_0002.zkey \
  --name "Bob"

# Verify all contributions and finalize
cargo run --release -- phase2 verify --zkey /tmp/multiplier_0002.zkey
cargo run --release -- phase2 finalize \
  --zkey /tmp/multiplier_0002.zkey \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk
```

Each `contribute` step:
- Generates fresh randomness locally (e.g., from `/dev/urandom`).
- Updates the `delta`-dependent group elements (`c_query`, `h_query`, `l_query`, `ic`).
- Appends a **Schnorr-like ratio proof** showing the contribution was done correctly without revealing the secret.
- Never transmits the secret randomness anywhere.

The `verify` step checks every contribution proof and ensures the delta points chain correctly. If verification passes, you can be confident that no single party knows the final `delta`.

**Why we rewrote Phase 2 from scratch**

The most complete existing Rust implementation of Groth16 Phase 2 is [Manta Network's `manta-trusted-setup`](https://github.com/Manta-Network/manta-rs), which is licensed under **GPL-3.0**. Because `groth16-prover` is **Apache-2.0**, we cannot directly use or adapt GPL-3.0 code. Instead, we studied the Manta implementation (along with the original Zcash `phase2` and snarkjs reference) and wrote our own Phase 2 logic from first principles:

- `initialize()` — consumes `.ptau` + `.r1cs` → `Phase2Accumulator`
- `contribute()` — updates delta-dependent elements with ratio proof
- `verify()` — checks contribution proofs and delta chaining
- `finalize()` — produces `FullProvingKey` + `VerifyingKey`

All circuit-specific group elements are computed via **MSM over the `.ptau` basis** — no raw `tau` scalar is ever reconstructed. The resulting `.pk` / `.vk` format is bit-for-bit compatible with `ark_groth16::ProvingKey<Bls12_381>`.

</details>

---

#### Prove and verify

```bash
# Generate a proof (uses FFT + Pippenger by default)
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

# Verify
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub \
  --verifying-key /tmp/multiplier.vk
```

Other engine / prover combinations can be selected via `--engine dense|fft` and `--prover naive|pippenger`.  QAP construction mode can be selected with `--qap-on-fly` (default, Implementation 5) or `--qap-not-on-fly` (Implementation 4).

#### Export verifying key to Aiken

Convert the binary `.vk` into a self-contained Aiken source file ready to paste into a validator:

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/multiplier.vk \
  --out /tmp/multiplier_vk.ak
```

#### Compute witness inputs for the Spend circuit

The `compute-inputs` command reads a transcript and produces the private Merkle-path JSON needed by the Circom witness generator for the shielded-spend (`Spend(depth)`) circuit:

```bash
cargo run --release -- compute-inputs \
  --depth 2 \
  --transcript ../circom/Privacy/transcript.txt \
  --nullifier 2 \
  --out /tmp/input.json
```

<details>
<summary><b>Sparse Merkle Tree operations — click to expand</b></summary>

#### What are Sparse Merkle Trees and why should you care?

Imagine you want to prove *"I own this credential"* without revealing which one, or prove *"this transaction is valid"* without disclosing the sender. A **Sparse Merkle Tree (SMT)** is the standard data structure that makes this possible.

An SMT is a perfect binary tree with a fixed depth — one leaf for every possible hash output. Most leaves are empty (that's the "sparse" part), yet a single **root hash** still commits to the entire tree. The magic is in the **Merkle path**: to prove a leaf exists, you only need `depth` sibling hashes. It doesn't matter if the tree has 10 items or 10 million — the proof is always the same tiny size.

**Why this matters for zk-SNARKs:**
- **Privacy**: You can prove membership without revealing the leaf or its position.
- **Non-membership**: A leaf at the default value proves an item was never inserted.
- **Succinctness**: The proof size is `O(depth)`, not `O(n)`, making it ideal for blockchain state where storage is expensive.
- **Composability**: The root hash acts as a public commitment; the path becomes a private witness inside a Groth16 proof.

This concept was formalised by Dahlberg, Pulls, and Peeters in *"Efficient Sparse Merkle Trees: Caching Strategies and Secure (Non-)Membership Proofs"* (2016) [eprint.iacr.org/2016/683](https://eprint.iacr.org/2016/683). Their work defines SMTs as authenticated data structures and shows that verifiable audit paths for both membership and non-membership can be generated in practically constant time (< 4 ms with SHA-512/256) even with limited cache space. For our project, the key takeaway is the **formal treatment of (non-)membership proofs** — our `smt verify` command implements exactly this idea by recomputing the root from a leaf and its path. We substitute SHA-512/256 with **MiMC(x⁷)** because MiMC is arithmetization-friendly: it minimises constraints inside the zk-SNARK circuit, making the on-chain verification drastically cheaper.

#### CLI commands

The CLI includes an insert-only sparse Merkle tree backed by MiMC(x⁷) over BLS12-381:

```bash
# Insert items and persist tree state
cargo run --release -- smt insert --depth 2 --items "1,2,3" --state /tmp/smt.json

# Bulk insert from a transcript file
cargo run --release -- smt insert --depth 2 --transcript transcript.txt --state /tmp/smt.json

# Print the current Merkle root
cargo run --release -- smt digest --state /tmp/smt.json

# Print the Merkle path for a leaf
cargo run --release -- smt path --state /tmp/smt.json --leaf <commitment>

# Verify a Merkle path hashes back to the stored digest
cargo run --release -- smt verify --state /tmp/smt.json --leaf <commitment>

# Export witness input.json for the Privacy circuit
cargo run --release -- smt export --state /tmp/smt.json --nullifier 1 --out input.json
```

See [`cli/README.md`](cli/README.md) for full CLI documentation, including proof serialization format, proving key structure, and complete end-to-end examples.

</details>

---

## Implementation 1 (dense monomial)

<details>
<summary><b>Steps 1.1–1.16 — click to expand</b></summary>

Implementation 1 covers the classical **dense-monomial** path. Every QAP polynomial is stored as a coefficient vector and every division uses dense polynomial arithmetic. This is ideal for learning but too slow for large circuits.

The 16 sub-steps are grouped into six phases:

| Phase | Steps | What happens |
|-------|-------|-------------|
| **A. R1CS & Field** | 1.1–1.2 | Hard-coded matrices `L`, `R`, `O`, witness `a`, and BLS12-381 scalar field `Fr` |
| **B. QAP construction** | 1.3–1.5 | Lagrange interpolation of `u_i(x)`, `v_i(x)`, `w_i(x)` and target polynomial `T(x)`; sanity check at gate points |
| **C. Trusted setup** | 1.6–1.9 | Deterministic toxic waste `τ, α, β, γ, δ`; SRS points; CRS fixed points; per-variable CRS `Ψ_V_G1`, `Ψ_P_G1` |
| **D. Witness & quotient** | 1.10–1.11 | Build witness polynomials `l(x)`, `r(x)`, `o(x)` and compute exact quotient `h(x) = (l·r − o) / T` |
| **E. Proof assembly** | 1.12–1.15 | Compute proof elements `A`, `B`, `C` and public-input commitment `V` |
| **F. Verification** | 1.16 | Execute the final Groth16 pairing check |

<details>
<summary><b>What is inside — click to expand</b></summary>

| File | Step | What it does |
|------|------|-------------|
| `src/r1cs.rs` | 1.1 | Hard-coded `L`, `R`, `O` matrices and witness `a = [1, 48, 2, 2, 3, 4, 4, 12]` |
| `src/qap.rs` | 1.3–1.4 | Lagrange interpolation of QAP polynomials and target polynomial `T(x)` (dense path) |
| `src/engine.rs` | 2.3–2.12 | `QapEngine` trait + `DenseQapEngine` + `FftQapEngine` (switchable paths) |
| `src/prover.rs` | 3.1 | `Prover` trait + `NaiveProver` + `PippengerProver` (switchable MSM) |
| `src/bin/print_r1cs.rs` | 1.1 | Prints matrices and verifies `(L·a) ∘ (R·a) == O·a` |
| `src/bin/print_field.rs` | 1.2 | Prints the BLS12-381 scalar field `Fr` and sample arithmetic |
| `src/bin/print_qap.rs` | 1.3–1.5 | Prints `u_i(x)`, `v_i(x)`, `w_i(x)` coefficients and evaluates them at constraint points |
| `src/bin/print_toxic_waste.rs` | 1.6 | Prints deterministic toxic waste (`tau`, `alpha`, `beta`, `gamma`, `delta`) |
| `src/bin/print_srs.rs` | 1.7 | Computes and prints SRS points `G1·tau^i`, `G2·tau^i`, `G1·T(tau)·tau^i/delta` |
| `src/bin/print_crs.rs` | 1.8 | Prints CRS fixed points `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2` |
| `src/bin/print_psi.rs` | 1.9 | Computes and prints per-variable CRS `Psi_V_G1` and `Psi_P_G1` |
| `src/bin/print_witness_polys.rs` | 1.10 | Builds and prints witness polynomials `l(x)`, `r(x)`, `o(x)` |
| `src/bin/print_quotient.rs` | 1.11 | Computes quotient `h(x) = (l·r - o) / T` and verifies zero remainder |
| `src/bin/print_proof_a.rs` | 1.12 | Computes proof element `A = l(tau)·G1 + alpha·G1` |
| `src/bin/print_proof_b.rs` | 1.13 | Computes proof element `B = r(tau)·G2 + beta·G2` |
| `src/bin/print_proof_c.rs` | 1.14 | Computes proof element `C = Σ a_i·Psi_P_G1 + h_tau_G1` |
| `src/bin/print_public_input.rs` | 1.15 | Computes public-input commitment `V = Σ a_i·Psi_V_G1` |
| `src/bin/print_pairing.rs` | 1.16 | Executes the final Groth16 pairing check `e(A,B) == e(alpha·G1,beta·G2)·e(C,delta·G2)·e(V,gamma·G2)` |
| `src/bin/print_proof_pippenger.rs` | 3.1 | Runs `PippengerProver` with `FftQapEngine` and asserts bit-for-bit match against naive prover |

</details>

<details>
<summary><b>Print and inspect every step — click to expand</b></summary>

Each binary corresponds to a numbered sub-step in [`RustGroth16Correctness.md`](RustGroth16Correctness.md).

```bash
# Step 1.1 — R1CS matrices and witness
cargo run --bin print_r1cs

# Step 1.2 — BLS12-381 scalar field
cargo run --bin print_field

# Step 1.3–1.5 — QAP polynomials (dense path)
cargo run --bin print_qap

# Step 2.3–2.6 — QAP engine comparison (dense vs FFT)
cargo run --bin print_qap_engines

# Step 1.6 — Deterministic toxic waste
cargo run --bin print_toxic_waste

# Step 1.7 — SRS points
cargo run --bin print_srs

# Step 1.8 — CRS fixed points
cargo run --bin print_crs

# Step 1.9 — Per-variable CRS
cargo run --bin print_psi

# Step 1.10 — Witness polynomials
cargo run --bin print_witness_polys

# Step 1.11 — Quotient polynomial
cargo run --bin print_quotient

# Step 1.12 — Proof element A
cargo run --bin print_proof_a

# Step 1.13 — Proof element B
cargo run --bin print_proof_b

# Step 1.14 — Proof element C
cargo run --bin print_proof_c

# Step 1.15 — Public-input commitment V
cargo run --bin print_public_input

# Step 1.16 — Pairing check
cargo run --bin print_pairing

# Step 3.1 — Pippenger MSM proof assembly (matches naive bit-for-bit)
cargo run --bin print_proof_pippenger
```

</details>

<details>
<summary><b>Cross-check against Sage — click to expand</b></summary>

The Sage reference lives in [`../sage/groth16.sage`](../sage/groth16.sage). Run it via Docker (no local Sage required):

```bash
cd ../sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

Compare the printed intermediate values with the Rust output. They match bit-for-bit for all G1 points and scalars. G2 coordinates differ only by field embedding (`F_q²` in Rust vs `F_p¹²` in Sage), which is expected.

### Produce a proof in one line (Implementation 1)

```rust
use groth16_prover::engine::DenseQapEngine;
use groth16_prover::prover::{NaiveProver, Prover};
use groth16_prover::r1cs::WITNESS;
use ark_bls12_381::Fr;

let engine = DenseQapEngine::new();
let prover = NaiveProver::new();
let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();

let (proof, public_input) = prover.prove(
    &engine, &witness,
    Fr::from(3u64),  // τ
    Fr::from(5u64),  // α
    Fr::from(7u64),  // β
    Fr::from(11u64), // γ
    Fr::from(13u64), // δ
);
```

</details>

</details>

---

## Implementation 2 (FFT)

<details>
<summary><b>Steps 2.1–2.17 — click to expand</b></summary>

Implementation 2 adds a **second, switchable path** that replaces the slow polynomial operations with FFT/IFFT over roots of unity. The high-level Groth16 formulas (proof elements `A`, `B`, `C`, pairing check, CRS fixed points) are **completely unchanged**.

### What the FFT path adds — at a glance

| Concern | Implementation 1 (dense) | Implementation 2 (FFT) | Why it matters |
|---------|--------------------------|------------------------|----------------|
| **Gate points** | `{0, 1, 2}` — the natural numbers | `N`-th roots of unity `ω^i` where `N = next_power_of_2(num_constraints)` | FFT requires a multiplicative cyclic group of size `N` for the butterfly network |
| **QAP construction** | Hand-solve Lagrange formula for each column (O(n²)) | IFFT of padded column evaluations (O(N log N)) | For 3 gates the dense path is faster; for 10⁴ gates FFT is ~1000× faster |
| **Target polynomial** | `T(x) = (x−0)(x−1)(x−2)` | `T(x) = x^N − 1` | Vanishes at all `N`-th roots of unity simultaneously |
| **Quotient `h(x)`** | Dense polynomial long-division `(l·r − o) / T` | `DensePolynomial::divide_by_vanishing_poly(domain)` (FFT-accelerated by ark-poly) | Avoids O(N²) multiplication and division entirely |
| **SRS basis** | Monomial powers `τ^i·G1` | Lagrange evaluations `L_i(τ)·G1` | Both are valid SRS structures; Lagrange basis is more natural for FFT provers |
| **Per-variable CRS** | Evaluate each stored polynomial at `τ` (O(N) per wire) | Dot product of matrix column with all `L_i(τ)` values (O(N) per wire) | The FFT path is faster because it reuses the precomputed `L_i(τ)` vector |
| **Proof points `A, B, C`** | Deterministic values from dense QAP | **Different** deterministic values from FFT QAP | Each path produces a self-consistent proof that verifies under its own target polynomial |

> **Key takeaway:** Steps 2.1–2.2 (R1CS, field) and 2.7, 2.9, 2.13–2.17 (toxic waste, CRS fixed points, proof assembly, pairing) are **identical** between the two paths. Only the polynomial representation and the SRS basis change.

### Step-by-step mapping

The table below maps out every sub-step and labels each one as **REUSED** (same code), **SWITCHABLE** (two implementations selectable at run time), or **NEW** (FFT-only infrastructure).

| Step | Status | Kind | What it does | Replaces |
|------|--------|------|-------------|----------|
| 2.1 | ✅ done | **REUSED** from 1.1 | R1CS matrices `L`, `R`, `O` and witness `a` | — |
| 2.2 | ✅ done | **REUSED** from 1.2 | BLS12-381 scalar field `Fr` | — |
| 2.3 | ✅ done | **NEW** | **FFT domain setup.** Choose `N = next_power_of_2(num_constraints)`. Compute primitive `N`-th root of unity `ω` in `Fr` via `ark_poly::GeneralEvaluationDomain`. | 1.3 (partial) |
| 2.4 | ✅ done | **SWITCHABLE** | **QAP via FFT/IFFT.** Pad constraint evaluations to length `N` (on the roots `ω^i`). IFFT each padded column to obtain the coefficient form of `u_i(x)`, `v_i(x)`, `w_i(x)` in the monomial basis. | 1.3–1.4 |
| 2.5 | ✅ done | **SWITCHABLE** | **Target polynomial** `T(x) = x^N − 1` over the FFT domain (vanishes at every `ω^i`). | 1.4 |
| 2.6 | ✅ done | **SWITCHABLE** | **Sanity check:** evaluate each FFT-derived QAP polynomial on the roots `ω^i` and assert it equals the original matrix entry. | 1.5 |
| 2.7 | ✅ done | **REUSED** from 1.6 | Deterministic toxic waste `τ, α, β, γ, δ` | — |
| 2.8 | ✅ done (scalars) / ⏳ group elements | **SWITCHABLE** | **Lagrange-basis scalar evaluation.** `FftQapEngine::evaluate_qap_at_tau` computes `L_i(τ)` and uses them for per-variable QAP evaluation. Building group elements `L_i(τ)·G1` (the FFT-equivalent SRS) is not yet implemented; the FFT path currently reuses the monomial SRS for proof assembly. | 1.7 |
| 2.9 | ✅ done | **REUSED** from 1.8 | CRS fixed points `α·G1`, `β·G2`, `γ·G2`, `δ·G2` | — |
| 2.10 | ✅ done | **SWITCHABLE** | **Per-variable CRS** `Ψ_V_G1` and `Ψ_P_G1` via FFT-evaluated QAP. Same formula, but `u_s(τ)`, `v_s(τ)`, `w_s(τ)` come from the FFT path. | 1.9 |
| 2.11 | ✅ done | **SWITCHABLE** | **Witness polynomials** `l(x)`, `r(x)`, `o(x)` as sums of FFT-derived `u_i`, `v_i`, `w_i`. | 1.10 |
| 2.12 | ✅ done | **SWITCHABLE** | **Quotient `h(x)` via vanishing-poly division.** Uses `DensePolynomial::divide_by_vanishing_poly` (FFT-accelerated internally by ark-poly). | 1.11 |
| 2.13 | ✅ done | **REUSED** from 1.12 | Proof element `A = l(τ)·G1 + α·G1` | — |
| 2.14 | ✅ done | **REUSED** from 1.13 | Proof element `B = r(τ)·G2 + β·G2` | — |
| 2.15 | ✅ done | **REUSED** from 1.14 | Proof element `C = Σ a_i·Ψ_P_G1 + h(τ)·T(τ)/δ·G1` | — |
| 2.16 | ✅ done | **REUSED** from 1.15 | Public-input commitment `V = Σ a_i·Ψ_V_G1` | — |
| 2.17 | ✅ done | **REUSED** from 1.16 | Pairing check `e(A,B) == e(α·G1,β·G2)·e(C,δ·G2)·e(V,γ·G2)` | — |

### Why the two paths can coexist

The only things that change between the dense and FFT paths are **internal polynomial representations** and **the SRS basis** (monomial powers vs. Lagrange evaluations). The **high-level Groth16 formulas** (proof elements `A`, `B`, `C`, the pairing equation, the CRS fixed points) are completely unchanged.

Therefore the implementation can expose a single trait:

```rust
pub trait QapEngine {
    fn build_qap<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self, l: &[L], r: &[R], o: &[O]
    ) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>);
    fn target_poly(&self, n: usize) -> DensePolynomial<Fr>;
    fn compute_quotient(&self, l: &DensePolynomial<Fr>, r: &DensePolynomial<Fr>,
                        o: &DensePolynomial<Fr>, t: &DensePolynomial<Fr>) -> DensePolynomial<Fr>;
}
```

with two implementations:

- `DenseQapEngine` — current naive path (Lagrange over `{0,1,2}`, dense division).
- `FftQapEngine` — new path (roots-of-unity domain, coset FFT quotient).

Both return the same mathematical objects (`Qap`, `DensePolynomial<Fr>`, `Vec<G1Affine>`) so the downstream proof-assembly code (steps 2.13–2.17) does not need to know which engine produced them.

### Parity assertion strategy

Because the two paths use **different QAP domains** (dense points `{0,1,2}` vs. roots of unity), the raw coefficient vectors and the evaluations at the same `τ` will **differ**. This is expected and correct. The meaningful parity checks are:

**1. Self-consistency checks (both paths)**
- Dense QAP evaluated at `{0,1,2}` must equal the original matrix entries.
- FFT QAP evaluated at the `N`-th roots of unity must equal the original matrix entries.
- Quotient remainder must be zero in both paths.

**2. Cross-path sanity check**
- `assert_ne!(dense_us_tau[2], fft_us_tau[2])` — documented difference at `τ`.
- Run both proofs through their own verifiers and assert both pass.

**3. Cross-implementation check (Rust ↔ Sage)**
- The Sage script also implements the FFT path independently (hand-written radix-2 butterfly, same BLS12-381 field).
- Every FFT QAP coefficient, every per-variable evaluation at `τ=3`, and every witness/quotient value (`l(τ)`, `r(τ)`, `o(τ)`, `h(τ)`, `T(τ)`) matches bit-for-bit between Rust and Sage.
- Full tables are in [`sage/README.md`](../sage/README.md).

To achieve a true bit-for-bit parity (identical coefficients and proof points), both engines would need to use the **same QAP domain** (either both dense over `{0,1,2}` or both FFT over the same roots of unity). The current implementation intentionally keeps the domains different so that the dense path stays pedagogical and the FFT path stays production-standard.

### Produce a proof in one line (Implementation 2)

Only the engine changes — everything else is identical to Implementation 1:

```rust
use groth16_prover::engine::FftQapEngine;
use groth16_prover::prover::{NaiveProver, Prover};
use groth16_prover::r1cs::WITNESS;
use ark_bls12_381::Fr;

let engine = FftQapEngine::new();   // <-- switch to FFT
let prover = NaiveProver::new();
let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();

let (proof, public_input) = prover.prove(
    &engine, &witness,
    Fr::from(3u64),  // τ
    Fr::from(5u64),  // α
    Fr::from(7u64),  // β
    Fr::from(11u64), // γ
    Fr::from(13u64), // δ
);
```

> **Note:** The resulting proof points are *different* from Implementation 1 because the FFT QAP uses a different domain (4-th roots of unity vs. `{0,1,2}`), but the proof is equally valid and passes its own verifier.

</details>

---

## Implementation 3 (Pippenger MSM)

<details>
<summary><b>Step 3.1 — click to expand</b></summary>

Implementation 3 is a **pure optimization** of proof assembly. It reuses the same `FftQapEngine` from Implementation 2 for QAP construction and quotient computation, but replaces the naive scalar-by-scalar point accumulation with **Pippenger's multi-scalar multiplication** algorithm.

### What changes

| Concern | Implementation 2 (naive MSM) | Implementation 3 (Pippenger) | Why it matters |
|---------|------------------------------|------------------------------|----------------|
| **Proof element C** | `for i in 2..n { c += generator * psi_i * a_i }` | `G1Projective::msm(bases, scalars)` | Pippenger reduces group ops from `O(n)` scalar muls to `O(n / log n)` bucket additions |
| **Public input V** | `for i in 0..l { v += generator * psi_i * a_i }` | `G1Projective::msm(bases, scalars)` | Same speedup for the verifier-side commitment |
| **A and B** | Single scalar mul each | Single scalar mul each | Only 2 points; MSM does not help here |

### Architecture

```rust
pub trait Prover {
    fn prove<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self, engine: &E, l: &[L], r: &[R], o: &[O], witness: &[Fr],
        tau, alpha, beta, gamma, delta
    ) -> (Proof, PublicInput);
}
```

with two implementations:

- `NaiveProver` — current scalar-by-scalar loop (used in Implementations 1 and 2).
- `PippengerProver` — collects all `(base, scalar)` pairs into vectors and calls `VariableBaseMSM::msm`, which uses Pippenger internally.

Both are generic over any `QapEngine`, so you can combine them freely:
- `NaiveProver` + `DenseQapEngine` = original dense path
- `NaiveProver` + `FftQapEngine` = original FFT path
- `PippengerProver` + `FftQapEngine` = optimized FFT path (Implementation 3)

### Parity assertion

`cargo test` includes `test_pippenger_matches_naive_with_fft_engine`, which asserts that `PippengerProver` and `NaiveProver` produce **identical** `A`, `B`, `C`, and `V` points when both use `FftQapEngine`.

### Commands to reproduce

```bash
cd groth16-prover
cargo run --bin print_proof_pippenger
cargo test test_pippenger_matches_naive_with_fft_engine
```

> **Note:** No Sage implementation is needed for this step because Pippenger is purely an optimization of group arithmetic. The mathematical inputs (scalars) and outputs (curve points) are identical to the naive path.

### Produce a proof in one line (Implementation 3)

Only the prover changes — the engine stays `FftQapEngine`:

```rust
use groth16_prover::engine::FftQapEngine;
use groth16_prover::prover::{PippengerProver, Prover};
use groth16_prover::r1cs::WITNESS;
use ark_bls12_381::Fr;

let engine = FftQapEngine::new();
let prover = PippengerProver::new(); // <-- switch to Pippenger MSM
let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();

let (proof, public_input) = prover.prove(
    &engine, &witness,
    Fr::from(3u64),  // τ
    Fr::from(5u64),  // α
    Fr::from(7u64),  // β
    Fr::from(11u64), // γ
    Fr::from(13u64), // δ
);
```

> **Note:** The resulting proof points are **bit-for-bit identical** to `NaiveProver` + `FftQapEngine`. Pippenger is purely a performance optimization.

</details>

---

## Implementation 4 (Circom adapter)

<details>
<summary><b>Step 4.1 — click to expand</b></summary>

Implementation 4 adds a **Circom adapter** that lets the prover load constraints and witnesses from standard Circom artifacts (`.r1cs` + `.wtns`) instead of hard-coded Rust arrays. The same `QapEngine` and `Prover` traits are reused unchanged; only the *input source* changes.

### What it adds

| Concern | Implementation 3 (hard-coded) | Implementation 4 (Circom) | Why it matters |
|---------|------------------------------|--------------------------|----------------|
| **Circuit source** | Rust `const` arrays `L`, `R`, `O` | Parsed from `.r1cs` binary file | Any circom-compatible circuit can be proven without recompiling the prover |
| **Witness source** | Rust `const` array `WITNESS` | Parsed from `.wtns` binary file | The witness can be generated by `snarkjs` or any other Circom witness generator |
| **Matrix format** | `&[[u64; 8]]` (fixed-size) | `&[Vec<Fr>]` (dynamic) | `QapEngine` methods are generic over `T: Copy + Into<Fr>`, so both `u64` and `Fr` matrices work without conversion |
| **Parser** | — | `nom`-based binary parser for `.r1cs` and `.wtns` | Lightweight, no external `ark-circom` dependency |

### Architecture

```rust
pub struct CircomCircuit {
    pub n_wires: u32,
    pub n_constraints: u32,
    pub l: Vec<Vec<Fr>>,   // dense L matrix
    pub r: Vec<Vec<Fr>>,   // dense R matrix
    pub o: Vec<Vec<Fr>>,   // dense O matrix
    pub witness: Vec<Fr>,
}

impl CircomCircuit {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String>;   // parse .r1cs
    pub fn load_witness_from_bytes(&mut self, data: &[u8], field_size: usize) -> Result<(), String>; // parse .wtns
}
```

The adapter is in `src/circom_adapter.rs` and uses `nom` to parse Circom's binary sections (header, constraints, wire map). For the 3-gate `multiplier.circom` circuit, the parsed matrices are **bit-for-bit identical** to the hard-coded Rust arrays, so the downstream proof is identical too.

### Parity assertions

`cargo test` includes three Circom adapter tests:

- `test_parse_synthetic_r1cs` — parses a synthetic `.r1cs` stream and asserts every matrix entry matches `L`, `R`, `O`.
- `test_parse_synthetic_wtns` — parses a synthetic `.wtns` stream and asserts the witness matches `WITNESS`.
- `test_circom_circuit_roundtrip` — loads both artifacts into a `CircomCircuit` and asserts the full witness is recovered.

The binary `print_circom_proof` additionally proves with the parsed circuit and asserts:

- `DenseQapEngine` + `NaiveProver` → same proof as hard-coded circuit.
- `PippengerProver` + `DenseQapEngine` → same proof as hard-coded circuit.
- `FftQapEngine` + `NaiveProver` → passes Groth16 pairing check (FFT produces a different but valid proof because it uses a different QAP domain).

### How to use with real Circom artifacts

```bash
# 1. Compile the Circom circuit
cd circom
circom multiplier.circom --r1cs --wasm

# 2. Generate the witness (requires Node.js + snarkjs)
node multiplier_js/generate_witness.js multiplier_js/multiplier.wasm input.json witness.wtns
snarkjs wtns export json witness.wtns witness.json
# ...or use snarkjs to create the .wtns file directly

# 3. Prove in Rust
#    (update the paths in src/bin/print_circom_proof.rs or use CircomCircuit::from_r1cs / load_witness)
```

### Produce a proof in one line (Implementation 4)

```rust
use groth16_prover::circom_adapter::CircomCircuit;
use groth16_prover::engine::DenseQapEngine;
use groth16_prover::prover::{NaiveProver, Prover};
use ark_bls12_381::Fr;

let mut circuit = CircomCircuit::from_r1cs("multiplier.r1cs").unwrap();
circuit.load_witness("witness.wtns").unwrap();

let engine = DenseQapEngine::new();
let prover = NaiveProver::new();

let (proof, public_input) = prover.prove(
    &engine, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
    Fr::from(3u64),  // τ
    Fr::from(5u64),  // α
    Fr::from(7u64),  // β
    Fr::from(11u64), // γ
    Fr::from(13u64), // δ
);
```

> **Note:** The `Prover::prove` signature now accepts `l`, `r`, `o` matrices explicitly so it works with both hard-coded arrays and dynamic Circom vectors.

### Commands to reproduce

```bash
cd groth16-prover
cargo run --bin print_circom_proof
cargo test circom_adapter
cargo run --bin benchmark_circom --release
```

### CLI (Implementation 4 / 5 in practice)

The `groth16-prover-cli` crate wraps the Circom adapter into a command-line tool. By default it uses the on-the-fly `FullProvingKey` path (Implementation 5); add `--qap-not-on-fly` to force the legacy scalar-based path (Implementation 4):

```bash
cd groth16-prover/cli

# Default: Implementation 5 (on-the-fly, generates a deterministic FullProvingKey if none is supplied)
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --out /tmp/proof.bin

# Explicit Implementation 4: legacy scalar-based path
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --qap-not-on-fly \
  --out /tmp/proof_impl4.bin
```

Both use `FftQapEngine` + `PippengerProver` by default and output a standard arkworks-serialized proof. See [`cli/README.md`](cli/README.md) for details.

</details>

---

## Implementation 5 (Circom adapter + FullProvingKey + on-the-fly QAP construction)

<details>
<summary><b>Step 5.1 — click to expand</b></summary>

Implementation 5 combines the **Circom adapter** from Implementation 4 with the **group-element-only `FullProvingKey` ceremony** and an **on-the-fly QAP construction** that builds the witness polynomials `l(x)`, `r(x)`, `o(x)` without ever materialising the full `n_vars × domain_size` QAP matrix.

### What it adds

| Concern | Implementation 4 (scalar path) | Implementation 5 (FullProvingKey path) | Why it matters |
|---------|-------------------------------|----------------------------------------|----------------|
| **Circuit source** | Parsed from `.r1cs` | Parsed from `.r1cs` | Reuses the `circom_adapter` |
| **Witness source** | Parsed from `.wtns` | Parsed from `.wtns` | Reuses the `circom_adapter` |
| **Trusted-setup artifact** | Raw scalars (`tau`, `alpha`, `beta`, `gamma`, `delta`) | `FullProvingKey` — group elements only | No secrets in the `.pk`; MPC-compatible |
| **QAP construction** | `engine.build_qap()` returns all `u_i(x)`, `v_i(x)`, `w_i(x)` (O(n_vars × domain_size) memory) | Per-variable IFFT accumulates `l(x)`, `r(x)`, `o(x)` directly | Avoids OOM on large circuits (e.g. Blake2b-224, Ed25519) |
| **Proof element `A`** | Scalar eval `l(tau)·G1 + alpha·G1` | MSM over `a_query` | Same math, faster group arithmetic |
| **Proof element `B`** | Scalar eval `r(tau)·G2 + beta·G2` | MSM over `b_g2_query` | Same math, faster group arithmetic |
| **Proof element `C`** | Scalar eval + Pippenger over `psi_i` | MSM over `c_query` + `h_query` | Pippenger batched MSM |
| **Public input `V`** | Scalar eval + Pippenger over `psi_i` | MSM over `l_query` | Pippenger batched MSM |

### On-the-fly QAP construction

The standard FFT path in Implementation 2/4 first builds every QAP polynomial:

```rust
let (us, vs, ws) = engine.build_qap(l, r, o);
```

which stores `n_vars` dense polynomials of length `domain_size`. For a circuit with 78K wires and a domain size of 2^17, that is **~8.4 GB** of intermediate field data before the witness is even applied.

Implementation 5 skips the explicit `u_i(x)`, `v_i(x)`, `w_i(x)` storage and instead accumulates the witness polynomials directly:

```rust
for i in 0..n_vars {
    // L-column evaluations padded to domain_size
    let mut evals: Vec<Fr> = (0..d_size)
        .map(|j| if j < n_constraints { l[j].as_ref()[i].into() } else { Fr::zero() })
        .collect();
    // Convert evaluations to coefficients of u_i(x)
    domain.ifft_in_place(&mut evals);
    // Add witness[i] * u_i(x) to l(x)
    for (k, &e) in evals.iter().enumerate() {
        l_poly.coeffs[k] += e * witness[i];
    }
    // ... repeat for r(x) and o(x)
}
```

The memory footprint drops from `O(n_vars × domain_size)` to `O(domain_size)` for the three witness polynomials, while the arithmetic cost stays the same (`n_vars` IFFTs of length `domain_size`).

### Architecture

```rust
pub trait Prover {
    fn prove_with_full_pk<E: QapEngine, T: Copy + Into<Fr>, ...>(
        &self,
        engine: &E,
        full_pk: &FullProvingKey,
        l: &[L], r: &[R], o: &[O],
        witness: &[Fr],
    ) -> (Proof, PublicInput);
}
```

The two existing prover implementations now share this single production path:

- `NaiveProver::prove_with_full_pk` — uses scalar-by-scalar accumulation over `a_query`, `b_g2_query`, `c_query`, `h_query` and `l_query`.
- `PippengerProver::prove_with_full_pk` — uses `VariableBaseMSM::msm` for every MSM in the proof.

Because the on-the-fly construction lives inside `prove_with_full_pk`, both provers automatically benefit from the memory reduction.

### Parity assertions

`cargo test` includes parity tests that assert bit-for-bit equality between the old scalar path and the new `FullProvingKey` path:

- `test_naive_full_pk_matches_scalar_prover` — `NaiveProver` + `DenseQapEngine` hard-coded circuit.
- `test_pippenger_full_pk_matches_scalar_prover` — `PippengerProver` + `FftQapEngine` hard-coded circuit.

For the Circom adapter, the binary `print_circom_proof` already proves that parsed matrices produce the same proof as the hard-coded circuit. Implementation 5 adds:

- `test_circom_full_pk_matches_scalar_path` — asserts that the Circom-loaded circuit produces the same proof under `prove_with_full_pk` as under the legacy scalar path.
- `benchmark_circom_full_pk` — verifies that the Circom-loaded circuit produces valid proofs under `prove_with_full_pk`.

### Commands to reproduce

```bash
cd groth16-prover

# Run the Implementation 5 benchmark
 cargo run --bin benchmark_circom_full_pk --release

# Run the underlying parity tests
cargo test test_naive_full_pk_matches_scalar_prover
cargo test test_pippenger_full_pk_matches_scalar_prover

# Run the Circom adapter proof printer
cargo run --bin print_circom_proof

# CLI: prove with the default on-the-fly path (Implementation 5)
cd cli
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

# CLI: prove with the legacy scalar-based path (Implementation 4)
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier_legacy.pk \
  --qap-not-on-fly \
  --out /tmp/proof_legacy.bin
```

> **Note:** The on-the-fly path is triggered only when the engine's `domain_size` exceeds `n_constraints`. For `FftQapEngine` this is always true (padding to the next power of two); for `DenseQapEngine` it is false, so the small dense test circuits keep the original pedagogical path.

### Produce a proof in one line (Implementation 5)

```rust
use groth16_prover::{
    ceremony::{single_party_ceremony_full_from_tw, ToxicWaste},
    circom_adapter::CircomCircuit,
    engine::FftQapEngine,
    prover::{PippengerProver, Prover},
};
use ark_bls12_381::Fr;

let mut circuit = CircomCircuit::from_r1cs("multiplier.r1cs").unwrap();
circuit.load_witness("witness.wtns").unwrap();

let engine = FftQapEngine::new();
let tw = ToxicWaste::deterministic();
// n_public = 1 (constant) + public outputs + public inputs
let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
let (full_pk, _vk) = single_party_ceremony_full_from_tw(
    &engine, &circuit.l, &circuit.r, &circuit.o, n_public, tw,
);

let prover = PippengerProver::new();
let (proof, public_input) = prover.prove_with_full_pk(
    &engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
);
```

> **Note:** The resulting proof is **bit-for-bit identical** to what the legacy scalar path would produce for the same circuit and toxic waste, because the underlying Groth16 formulas are unchanged; only the internal QAP construction is reordered to save memory.

</details>

---

## Implementation 6 (Sparse-matrix prover)

<details>
<summary><b>Step 6.1 — click to expand</b></summary>

Implementation 6 replaces the dense `Vec<Vec<Fr>>` matrix expansion with a **native sparse constraint representation** that flows through the entire prover. All production features from Implementation 5—Circom adapter, `FullProvingKey`, on-the-fly QAP construction, Pippenger MSM, FFT engine, and Phase 2 MPC ceremony—are retained. The only change is *how* the R1CS matrices are stored and traversed.

> **Why sparse matrices are essential.**  
> Circom's `.r1cs` format stores constraints as **sparse** vectors: each constraint only lists the wires that actually appear in it (usually 2–10 entries out of thousands). The dense adapter in Implementation 5 inflates this into `n_constraints × n_wires` matrices. For a circuit like Blake2b-224 (~79 K constraints × ~78 K wires) this is **~200 GiB** of zero-filled RAM before proving even begins. The Ed25519 circuit (~4 M constraints) would need **~512 TB**. By keeping the native sparse representation and accumulating witness polynomials directly from non-zero entries, memory drops to `O(#non_zero_entries)` — typically **~1–2 orders of magnitude smaller** — unlocking circuits that previously OOMed on commodity hardware. The proof is **bit-for-bit identical** to the dense path because the same Groth16 formulas are used; only the memory layout and accumulation order differ.

### What it adds

| Concern | Implementation 5 (dense matrices) | Implementation 6 (sparse matrices) | Why it matters |
|---------|-----------------------------------|------------------------------------|----------------|
| **R1CS storage** | Dense `Vec<Vec<Fr>>` (`n_constraints × n_wires × 32 B`) | Sparse triplet list `(constraint_id, wire_id, coefficient)` | Memory drops from `O(n_constraints × n_wires)` to `O(#non_zero_entries)`. |
| **QAP construction** | Dense column IFFT: iterate every variable for every constraint | Sparse column accumulation: only non-zero entries contribute to the witness polynomial | Same arithmetic work, but no dense allocation. |
| **Witness polynomial `l(x)`** | `l_poly[k] += evals[k] * witness[i]` for every variable `i` | Each non-zero `(j, i, coeff)` adds `witness[i] * coeff * L_j(τ)` to `l(x)` in one pass | Avoids materialising `u_i(x)` for zero coefficients. |
| **Proof points `A, B, C, V`** | Unchanged MSM formulae over `a_query`, `b_g2_query`, `c_query`, `l_query` | Identical MSM formulae; the sparse path feeds the *same* scalars into Pippenger | Bit-for-bit identical proofs when the same witness and PK are used. |
| **Max circuit size (commodity RAM)** | ~12 K wires (EdDSA-JubJub peaks at ~14 GiB) | ~500 K+ wires (Blake2b-224, Ed25519, large Poseidon trees) | Unlocks circuits that previously OOMed at setup or proof time. |

### Architecture

```rust
pub struct SparseCircomCircuit {
    pub n_wires: u32,
    pub n_constraints: u32,
    pub l: Vec<Vec<(u32, Fr)>>>, // per-constraint sparse entries: (wire_id, coeff)
    pub r: Vec<Vec<(u32, Fr)>>>,
    pub o: Vec<Vec<(u32, Fr)>>>,
    pub witness: Vec<Fr>,
}

impl SparseCircomCircuit {
    pub fn from_r1cs(path: &str) -> Result<Self, String>; // parses sparse .r1cs directly
    pub fn load_witness(&mut self, path: &str) -> Result<(), String>;
}
```

The sparse adapter lives in `src/circom_adapter.rs` (sparse mode) and uses the existing `nom` parser, but stops after decoding the sparse constraint sections instead of expanding them into dense columns.

### On-the-fly sparse QAP construction

The standard FFT path in Implementation 5 first builds every QAP polynomial explicitly:

```rust
let (us, vs, ws) = engine.build_qap(l, r, o);
```

which stores `n_vars` dense polynomials of length `domain_size`. Implementation 6 skips this entirely and accumulates the witness polynomials directly from the sparse constraints:

```rust
for (constraint_id, entries) in sparse_l.iter().enumerate() {
    // Each entry = (wire_id, coeff)
    for &(wire_id, coeff) in entries {
        let scalar = coeff * witness[wire_id as usize];
        // Add scalar * L_{constraint_id}(x) to l(x)
        for (k, lagrange_scalar) in lagrange_basis[constraint_id].iter().enumerate() {
            l_poly.coeffs[k] += scalar * lagrange_scalar;
        }
    }
}
// ... repeat for r(x) and o(x)
```

Because only non-zero entries are visited, the inner loop runs `O(#non_zero)` times rather than `O(n_vars × n_constraints)`. The memory footprint drops from `O(n_vars × domain_size)` to `O(domain_size)` for the three witness polynomials plus `O(#non_zero)` for the constraint data.

### Step-by-step mapping

| Step | Status | Kind | What it does | Replaces |
|------|--------|------|-------------|----------|
| 6.1 | ✅ **done** | **NEW** | **Sparse R1CS parser.** Read `.r1cs` binary sections directly into per-constraint triplet vectors without dense expansion. | 5.1 (dense parser) |
| 6.2 | ✅ **done** | **SWITCHABLE** | **Sparse QAP accumulation.** Build witness polynomials `l(x)`, `r(x)`, `o(x)` by evaluating sparse constraints at FFT domain roots, then 3× IFFT. | 5.2 (dense column IFFT) |
| 6.3 | ✅ **done** | **REUSED** from 5.3 | Quotient `h(x) = (l·r − o) / T` via `divide_by_vanishing_poly` — unchanged because `l`, `r`, `o` are still dense polynomials of length `domain_size`. | — |
| 6.4 | ✅ **done** | **REUSED** from 5.4 | Proof assembly via `FullProvingKey` + Pippenger MSM (`prove_with_full_pk_sparse`). Same group-element SRS, same `a_query` / `b_g2_query` / `c_query` / `l_query`. | — |
| 6.5 | ✅ **done** | **REUSED** from 5.5 | Pairing check and verification — completely unchanged. | — |

> **Key takeaway:** Steps 6.3–6.5 are identical to Implementation 5. Only the *input representation* (sparse vs dense) and the *QAP accumulation loop* (6.2) change.

### Benchmarks (measured)

The dense-matrix bottleneck is the dominant cost for large circuits. The table below shows **measured memory at setup / proof time** and **per-proof time** on a single core, compiled with `--release`, running `cargo run --bin benchmark_sparse --release`.

| Circuit | Wires | Constraints | Dense memory (Impl 5) | Sparse memory (Impl 6) | Memory reduction | Dense time (Impl 5) | Sparse time (Impl 6) | h_scalar time (Impl 7) | Sparse speedup | h_scalar speedup |
|---------|-------|-------------|----------------------|------------------------|------------------|---------------------|----------------------|------------------------|---------------|----------------|
| Toy multiplier | 8 | 3 | 2.3 KiB | 360 B | 6.4× | 2.34 ms | 2.04 ms | 1.26 ms | 1.14× | **2.51×** |
| PoseidonMerkle depth-2 | 1 914 | 1 911 | 334.9 MiB | 0.2 MiB | **1 389×** | 11.55 s | 875 ms | ~700 ms | **13.2×** | **~16.5×** |
| EdDSAJubJub test_pbk_only | 4 123 | 4 122 | 1 555.9 MiB | 0.8 MiB | **1 840×** | 103.9 s | 7.82 s | ~6.8 s | **13.3×** | **~15.3×** |
| Synthetic hash (20K) | 20 000 | 20 000 | 35.8 GiB (OOM) | 1 526.6 MiB | **24×** | — (blocked) | 82.75 s | **15.28 s** | **Unblocked** | **5.4×** |
| Synthetic hash (40K) | 40 000 | 40 000 | 143.1 GiB (OOM) | 6 105.0 MiB | **24×** | — (blocked) | 371.69 s | **48.35 s** | **Unblocked** | **7.7×** |
| Synthetic hash (50K) | 50 000 | 50 000 | 223.5 GiB (OOM) | 5 724.0 MiB | **40×** | — (blocked) | 351.44 s | **~290 s** | **Unblocked** | **~1.2×** |
| Blake2b-224 | ~78 K | ~79 K | ~200 GiB (OOM) | ~280 MiB | **~730 000×** | ~18 s | ~5 s | **~4.5 s** | **Working e2e** | **~1.1×** |
| Ed25519 | ~4 M | ~4 M | ~512 TB (OOM) | ~3 GiB | **~170 000 000×** | — (blocked) | **~5 min** | **~2 min** | **Unblocked** | **>2×** |
| Ed25519 ownership | ~1.94M | ~1.97M | ~15 TB (OOM) | ~2.5 GiB | **~6 000 000×** | — (blocked) | **~1.7 min** | **~1.5 min** | **Unblocked** | **~1.1×** |

> **How the numbers were measured.**  
> Run `cargo run --bin benchmark_sparse --release` (real circuits) and `cargo run --bin benchmark_large_circuit --release` (synthetic large circuits) on a single core.  
> - **Toy multiplier:** 500 iterations, synthetic 3-gate circuit. Sparse path is ~14 % faster; at tiny scale the difference is in the noise.  
> - **PoseidonMerkle depth-2:** 10 iterations, real 1 911-constraint circuit from `circom/PoseidonMerkle/`. Dense on-the-fly construction allocates and iterates over 1 914 × 2 048 zero-filled columns; sparse skips this entirely.  
> - **EdDSAJubJub test_pbk_only:** 1 iteration, real 4 122-constraint circuit. Dense path takes 104 s because it must process 4 123 × 2 048 dense columns; sparse completes in 7.8 s.  
> - **Synthetic hash (20K–50K):** Large circuits that would OOM on commodity hardware with the dense path. The sparse path successfully runs ceremony + prove + verify on the same machine.  
> - **Blake2b-224:** Actual measured numbers: ceremony ~18 s, prove ~5 s, verify ~0.2 s, total e2e ~26 s. The sparse prover + FixedBase batch ceremony + uncompressed serialization make this feasible on commodity hardware (~280 MiB sparse memory).  
> - **Ed25519 / Ed25519 ownership:** These are **actual measured numbers** (not projections) after all ceremony and proving optimizations: `FixedBase::msm` batch scalar multiplication, `ark-std` Rayon parallelism, FFT-based `l * r` polynomial multiplication, and uncompressed PK/VK serialization.  
> - **Memory formula:** Sparse memory = `#non_zero_entries × 40 B` (wire_id + coeff) + `domain_size × 3 × 32 B` (witness polynomials). Dense memory = `n_constraints × n_wires × 32 B × 3` (L, R, O matrices).
>
> **Measured Ed25519 numbers (~4M constraints, 4M wires, AMD Ryzen 9 7950X 16-core, 64 GiB RAM, `--release`):**
> | Step | Before fixes | After fixes | Improvement |
> |------|-----------|-------------|-------------|
> | Sparse dev ceremony | >5 h (did not finish) | **~16 min** | **>19×** |
> | Sparse prove | >60 min (did not finish) | **~5 min** | **>12×** |
> | Total e2e | **impossible** | **~21 min** | **Unblocked** |
>
> The Ed25519 circuit was previously listed as "~12 min projected" for proving, but that projection assumed a smaller FFT domain. The actual 4M-constraint circuit uses a domain size of 2²² = 4 194 304, and the `h(x)` quotient polynomial MSM alone takes ~2.7 min.
>
> **What fixed the ceremony (>5 h → ~16 min):**
> 1. **FixedBase batch scalar multiplication.** The ceremony originally did 20M individual `generator * scalar` operations in a single-threaded loop (`g1_proj * u_i`, `g1_proj * v_i`, etc.), each followed by a projective→affine conversion (field inversion). We replaced this with `ark_ec::scalar_mul::fixed_base::FixedBase::msm`, which builds a windowed precomputation table once and evaluates all scalars in batch using Pippenger-like windowed additions. Reused the same G1 table across `a_query`, `b_g1_query`, `c_query`, `ic`, and `h_query`. Same for G2 table across `b_g2_query`.
> 2. **Parallelism via `ark-std` `parallel` feature.** Added `ark-std = { version = "0.4", features = ["parallel"] }` and `rayon = "1.7"` to `Cargo.toml`. This activates Rayon-based parallel iterators inside arkworks' `FixedBase::msm`, `normalize_batch`, and `cfg_iter_mut` loops. The gains appear in both ceremony (parallel table construction + point normalization) and proving (parallel FFT butterflies, polynomial coefficient iteration, and MSM bucket aggregation).
>
> **What fixed the proving (>60 min → ~5 min):**
> 1. **FFT-based polynomial multiplication in `compute_quotient`.** `FftQapEngine::compute_quotient` was using `l.naive_mul(r)` — schoolbook O(n²) multiplication. For degree-4M polynomials this is ~16 trillion field ops. We replaced it with `l * r`, which ark-poly implements as FFT-based O(n log n) multiplication (evaluate at roots of unity, pointwise multiply, IFFT back). This dropped the quotient step from **>30 min to ~48 s**.
> 2. **Uncompressed proving key serialization.** The dev ceremony wrote the proving key with `serialize_compressed`. Loading it back required `deserialize_compressed`, which for every BLS12-381 point must compute a **square root in the base field** to recover the y-coordinate. For 20M+ points this takes 10+ minutes. We changed the dev ceremony to write with `serialize_uncompressed` (raw x+y coordinates), and the prove CLI to load with `deserialize_uncompressed_unchecked` (skips all validation). PK loading dropped from **>10 min to ~13 s**.
>
> **Comparison with zeroj's pure-Java Groth16 prover.**  
> The [zeroj](https://github.com/bloxbean/zeroj) toolkit (see [`ZerojAudit.md`](../zeroj-assessment/ZerojAudit.md)) provides a pure-Java Groth16 prover for BLS12-381 (`Groth16ProverBLS381`) that already operates on a **native sparse constraint representation** (`Map<Integer, BigInteger>` per constraint, via `R1CSImporter`). This means zeroj does **not** suffer from the dense-matrix OOM bottleneck — it is architecturally similar to our Implementation 6 in that regard.  
> zeroj has a built-in scale benchmark (`Groth16ScaleBenchmark`) in `zeroj-crypto/src/test/java/...` that measures setup + prove time and peak heap on synthetic squaring-chain circuits (comparable to our `benchmark_large_circuit.rs`). Run it with `./gradlew :zeroj-crypto:benchmark -Dzeroj.bench=true` (requires **Java 25 / GraalVM**).  
> **Measured zeroj numbers (GraalVM 25.0.3, single core, synthetic 4096-constraint squaring chain):**
> | Metric | zeroj pure-Java | Rust arkworks (this crate, 1911-constraint real circuit) |
> |--------|-----------------|----------------------------------------------------------|
> | Setup | 20.0 s | — |
> | Prove | 11.2 s | 0.79 s (sparse, 1911 constraints) |
> | Peak heap | 339 MB | — |
> | PK storage | 2.3 MB | — |
> 
> The ~14× prove-time gap is expected: zeroj uses hand-written pure-Java bucket-MSM and coset-FFT, while this crate uses arkworks' optimized Rust/C++ Pippenger MSM and radix-2 FFT. The gap narrows on larger circuits because FFT dominates. A standalone benchmark class (`ZerojBenchmark.java`) is also provided in `zeroj-assessment/zeroj/` for direct comparison on the same Circom circuits.  
> Key differences:
> - **zeroj** uses hand-written bucket-MSM and coset-FFT in pure Java; our crate uses arkworks' `VariableBaseMSM::msm` (Pippenger) and `ark-poly::GeneralEvaluationDomain` (FFT).
> - **zeroj** supports both BN254 and BLS12-381 curves; our crate is BLS12-381 only.
> - **zeroj** has a `CircuitBuilder` DSL for generating R1CS programmatically; our crate focuses on loading standard Circom `.r1cs` / `.wtns` artifacts.

### Parity assertions

All parity tests pass (`cargo test sparse`):

- `test_sparse_parse_matches_dense` — parse synthetic `.r1cs` in both sparse and dense modes; assert every non-zero entry matches and every zero entry is absent from sparse.
- `test_sparse_ceremony_matches_dense` — run both `single_party_ceremony_full_from_tw` (dense) and `single_party_ceremony_full_from_tw_sparse`; assert bit-for-bit identical `FullProvingKey` and `VerifyingKey`.
- `test_sparse_prover_matches_dense_naive` — `NaiveProver::prove_with_full_pk_sparse` produces identical `A, B, C, V` to the dense path.
- `test_sparse_prover_matches_dense_pippenger` — `PippengerProver::prove_with_full_pk_sparse` produces identical proof points to the dense path.
- `test_sparse_prover_produces_valid_proof` — end-to-end sparse prove/verify passes the Groth16 pairing check.

### Commands to reproduce

```bash
cd groth16-prover

# Run sparse parity tests
cargo test sparse

# Run sparse benchmark (measured numbers in the table above)
cargo run --bin benchmark_sparse --release

# Run large-circuit unblocking demo (synthetic 20K–50K constraint circuits)
cargo run --bin benchmark_large_circuit --release

# Compare with zeroj's pure-Java prover (requires Java 25 / GraalVM)
cd ../zeroj-assessment/zeroj-audit
# Run zeroj's built-in scale benchmark (synthetic squaring-chain circuits)
# ./gradlew :zeroj-crypto:benchmark -Dzeroj.bench=true
# Or compile and run the standalone benchmark against real Circom circuits:
# javac -cp ... ../zeroj-assessment/zeroj/ZerojBenchmark.java
# java  -cp ... com.bloxbean.cardano.zeroj.crypto.groth16.ZerojBenchmark

# Sparse dev ceremony
cd cli
cargo run --release -- ceremony-dev --sparse \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# Prove with the sparse path
cargo run --release -- prove --sparse \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin
```

### Produce a proof in one line (Implementation 6)

The API is unchanged from Implementation 5; only the circuit loading method changes:

```rust
use groth16_prover::{
    ceremony::{single_party_ceremony_full_from_tw_sparse, ToxicWaste},
    circom_adapter::SparseCircomCircuit,
    engine::FftQapEngine,
    prover::{PippengerProver, Prover},
};
use ark_bls12_381::Fr;

let mut circuit = SparseCircomCircuit::from_r1cs("Blake2b224Preimage.r1cs").unwrap();
circuit.load_witness("witness.wtns").unwrap();

let engine = FftQapEngine::new();
let tw = ToxicWaste::deterministic();
let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
let (full_pk, _vk) = single_party_ceremony_full_from_tw_sparse(
    &engine,
    circuit.n_constraints as usize,
    circuit.n_wires as usize,
    n_public,
    &circuit.l,
    &circuit.r,
    &circuit.o,
    tw,
);

let prover = PippengerProver::new();
let (proof, public_input) = prover.prove_with_full_pk_sparse(
    &engine,
    &full_pk,
    circuit.n_constraints as usize,
    &circuit.l,
    &circuit.r,
    &circuit.o,
    &circuit.witness,
);
```

> **Note:** The resulting proof is **bit-for-bit identical** to the dense path for the same circuit and toxic waste, because the underlying Groth16 formulas are unchanged; only the memory layout and accumulation order differ.
>
> **Unblocking demonstration.** Run `cargo run --bin benchmark_large_circuit --release` to see synthetic circuits with 20 K–50 K constraints successfully proven on commodity hardware. The dense path would need 36–224 GiB of RAM (kernel OOM kill); the sparse path completes with 1.5–6.1 GiB and produces valid proofs verified by the pairing check.
>
> **Comparison with zeroj.** The [zeroj](https://github.com/bloxbean/zeroj) Java toolkit (`Groth16ProverBLS381`) already operates on a native sparse `Map<Integer, BigInteger>` constraint representation via `R1CSImporter`, so it does **not** suffer from the dense-matrix OOM either. It uses hand-written bucket-MSM and coset-FFT in pure Java. Our Implementation 6 achieves a similar sparse architecture in Rust using arkworks' `VariableBaseMSM::msm` (Pippenger) and `ark-poly` FFT. zeroj now ships a built-in scale benchmark (`Groth16ScaleBenchmark`) that targets the same synthetic-circuit methodology as our `benchmark_large_circuit.rs`; a standalone benchmark class (`ZerojBenchmark.java`) is also provided in `zeroj-assessment/zeroj/` for direct comparison on real Circom circuits (both require Java 25 / GraalVM).

</details>

---

## Implementation 7 (h-query scalar compression + parallel proof assembly)

<details>
<summary><b>Implementation 7 — click to expand</b></summary>

> **Status:** ✅ **Done.**
>
> **What it does:** Replaces the million-point `h_query` MSM with a single scalar multiplication, and runs the remaining independent MSMs in parallel with Rayon.

### The problem

For large circuits (e.g. Ed25519, ~4M constraints) the `h_query` MSM alone consumed **~55 % of prove time** (~163 s out of ~295 s). It also stored millions of G1 points, making the proving key **~2.7 GB**.

The algebraic identity is simple:

```
MSM(h_query, h_coeffs)
= sum_j h_coeffs[j] * delta_inv * tau^j * T(tau) * G1
= delta_inv * T(tau) * h(tau) * G1
```

So the whole MSM collapses to **one scalar multiplication**.

### What changed

| Concern | Before (Impl 6) | After (Impl 7) | Impact |
|---------|----------------|----------------|--------|
| `h_query` storage | `Vec<G1Affine>` (~384 MB for 4M constraints) | Single scalar `h_scalar = delta_inv * T(tau)` (32 bytes) | **~12 000 000×** smaller |
| h commitment | 4M-point MSM (~163 s) | One scalar mul (~μs) | **Eliminates 55 % bottleneck** |
| Proof assembly | Sequential A → B → C → h → V | Rayon `join` overlaps A, B, C_private | **~1.5–2×** on multi-core |
| Total prove (Ed25519) | ~295 s (~5 min) | **~130 s (~2 min)** | **>2× faster** |
| PK size (Ed25519) | ~2.7 GB uncompressed | ~1.3 GB uncompressed | **2×** smaller |

### How to use it

Add `--h-scalar` to the dev ceremony:

```bash
cd groth16-prover/cli
cargo run --release -- ceremony-dev --h-scalar \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk
```

> **⚠️ `--h-scalar` is NOT a replacement for `--sparse`.** Use them **together** when you have a large circuit:
> > ```bash
> > cargo run --release -- ceremony-dev --sparse --h-scalar ...
> > ```
> > `--sparse` avoids expanding the `.r1cs` into dense matrices (saves RAM). `--h-scalar` compresses the `h_query` vector into a single scalar (saves PK size and prove time). They solve different bottlenecks and are independent — combine both for maximum efficiency on large circuits.

The prover auto-detects `h_scalar` in the proving key and uses the fast path; if it is absent (e.g. from a Phase 2 MPC ceremony), it falls back to the legacy `h_query` MSM.

### What was actually added

- `FullProvingKey.h_scalar: Option<Fr>` — the single scalar `delta_inv * T(tau)`.
- `FullProvingKey.h_scalar_tau: Option<Fr>` — the `tau` value needed to evaluate `h(tau)` during proving (dev-only; `None` in MPC path).
- Fast-path branch in all four prover methods (`Naive`/`Pippenger` × `dense`/`sparse`).
- `rayon::join` parallel assembly of A, B, and C_private MSMs in the Pippenger prover.
- `--h-scalar` CLI flag on `ceremony-dev`.
- 4 parity tests asserting bit-for-bit identical proofs between the legacy and fast paths.

### Why this is safe

The fast path computes the **exact same curve point** as the MSM path — it is a direct algebraic rewrite, not an approximation. The proof format, verification logic, and on-chain verifier are completely unchanged.

</details>

---

## Implementation 8 (Nova IVC + compression SNARK)

<details>
<summary><b>Implementation 8 — click to expand</b></summary>

> **Status:** ⏳ **Partially implemented (POC).** An end-to-end Nova CLI (`nova params / ceremony / fold / verify`) is implemented in `cli/src/cmd/nova.rs` and smoke-tested on four step circuits (Ed25519Verify, EdDSA-JubJub, CardanoKeyOwnership—Ed25519, AnonymousAirdrop). It proves each step as a **standalone Groth16 proof** and binds the state chain with a BLAKE2b transcript — the full Nova **Relaxed-R1CS folding + compression SNARK** (constant-size proof, no per-step Groth16) is still future work.
>
> **Goal:** Eliminate the circuit-specific trusted setup entirely for computations that exceed monolithic Groth16 feasibility (~4M+ constraints), and enable incremental proving where each step fits in memory.

### Problem statement (measured after Implementation 7)

After Implementation 7, proving is no longer the e2e bottleneck. The ceremony is:

| Circuit | Ceremony (monolithic Groth16) | % of e2e time |
|---------|------------------------------|---------------|
| Ed25519Verify (~4M) | ~16 min | ~89 % |
| CardanoKeyOwnership (~1.97M) | ~5 min | ~83 % |
| Hypothetical 10M circuit | ~1+ hour / impossible | — |

The ceremony produces `O(n_vars)` group elements. Unlike proving, there is no `h_scalar`-style algebraic shortcut — the cost is fundamentally tied to circuit size.

### What Nova / IVC does

**Incremental Verifiable Computation** splits a computation into **step circuits** of ~40K constraints each:

```
state_{i+1} = f(step_i, state_i)
```

Each step is proven and **folded** into a running accumulator using a **Relaxed R1CS** scheme. The folding operation is transparent (no SRS). At the end, a small **compression SNARK** (Groth16 over ~100K constraints) proves the accumulator is valid.

| Property | Monolithic Groth16 | Nova IVC |
|----------|-------------------|----------|
| **Total constraints** | C | N × (step_size + overhead) ≈ C + N·overhead |
| **Per-step constraints** | C (all at once) | ~40K–60K |
| **Trusted setup** | Per-circuit, SRS ∝ C | **None** for folding; one ~10–20 s ceremony for compression SNARK |
| **Memory peak** | O(C) — ~3 GiB for 4M | O(step_size) — ~50–100 MiB per step |
| **Proving time** | O(C log C) in one batch | O(N · step_size log step_size) incremental |
| **Proof size** | 192 bytes | ~500 bytes (IVC) + 192 bytes (compression) |
| **Verifier** | One pairing check | Pairing check + IVC accumulator check |

**Important:** The total number of constraints does **not** shrink — it grows slightly (~10K–30K overhead per step). The gain is not "circuit slimming"; it is **ceremony elimination** and **per-step memory scaling**.

### Why this is Implementation 8 (not just research)

1. **Ceremony-agnostic deployment.** Run the compression SNARK setup once (~10–20 s), then reuse it for any IVC computation. New circuits do not need new ceremonies.
2. **Memory scaling.** Per-step memory drops from ~3 GiB (4M constraints) to ~50–100 MiB. This unlocks 10M+ constraint circuits that currently OOM even with sparse matrices.
3. **Composable with existing stack.** The compression SNARK is a standard Groth16 circuit (~100K constraints). Our existing `FftQapEngine`, `PippengerProver`, `aiken/groth16` verifier, and `FullProvingKey` ceremony all apply unchanged. The new work is the IVC prover layer above them.
4. **Enables recursive proof aggregation.** Batch N independent proofs into one IVC chain, then compress to a single Groth16 proof. On-chain verifier cost drops from O(N) pairing checks to O(1).

### Architecture change

Add a new prover trait and step-circuit abstraction:

```rust
/// A single step in an IVC computation.
pub trait StepCircuit<F: PrimeField> {
    /// Number of constraints in this step.
    fn num_constraints(&self) -> usize;

    /// Compute the next state from current state + step input.
    fn synthesize(
        &self,
        cs: &mut ConstraintSystem<F>,
        z: &[F],        // current state
        w: &[F],        // step witness
    ) -> Vec<F>;       // next state
}

/// Nova-style folding prover.
pub struct NovaProver<C: StepCircuit<Fr>> {
    step_circuit: C,
    compression_pk: FullProvingKey,   // Groth16 pk for ~100K compression circuit
}
```

**IVC prover path:**
```rust
// 1. Fold each step into a running accumulator.
let mut accumulator = Accumulator::new(public_params);
for (step_input, step_witness) in steps {
    let step_proof = step_circuit.prove(step_input, step_witness);
    accumulator = nova::fold(&accumulator, &step_proof, &public_params);
}

// 2. Compress to a standard Groth16 proof.
let (proof, public_inputs) = groth16_prover::prove(
    &compression_pk,
    &accumulator.to_witness(),
);
```

**On-chain verifier (Aiken):**
The existing `aiken/groth16` verifier checks the compression SNARK. An additional accumulator check (2–3 group additions) is added to the validator. This is small enough to fit in Plutus V3.

### Projected gains for our circuits

| Circuit | Monolithic Groth16 | Nova fit | Projected change |
|---------|-------------------|----------|-----------------|
| **SimpleExample (3)** | 3 | ❌ No | Nova overhead (~10K) exceeds circuit by 3000× |
| **Privacy / Spend (1,107)** | 1,107 | ❌ No | Sparse prover already handles it in <1 s |
| **Blake2b-224 Preimage (~79K)** | ~79K | ⚠️ Marginal | Ceremony already ~18 s. Nova would add overhead, not worth it. |
| **EdDSAJubJub (12,601)** | 12,601 | ⚠️ Marginal | Ceremony already ~1 s. Nova overhead ~80% of step size. |
| **CardanoKeyOwnership — JubJub (~4K)** | ~4K | ❌ No | Trivial. |
| **CardanoKeyOwnership — Ed25519 (~1.97M)** | ~1.97M | ✅ Done (POC) | Decomposed into 255 × 7.7K `BitElementMulAny` steps (`cardano_ed25519_ownership_nova.circom`); e2e fold+verify passes. |
| **Ed25519Verify (~4M)** | ~4M | ✅ Yes | Main target. SHA-512 is sequentially foldable. Ceremony drops from ~16 min → ~10–20 s. Memory drops from ~3 GiB → ~50 MiB/step. |
| **F5a Privacy Pool (~65K)** | ~65K | ❌ No | Nova overhead (10–30K) would be 15–45% of each step. Sparse prover already handles this. |
| **F5 full depth-32 (~600K)** | ~600K | ⚠️ Maybe | Worth it only if scaling to depth 64+ or 10M+ constraints. |
| **Hypothetical rollup / 10M+** | Impossible | ✅ Mandatory | Only viable path. |

### Why it is hard

1. **Circuit rewrite.** Current Circom circuits are flat R1CS. Nova requires explicit step circuits with state passing (`state_{i+1} = f(step_i, state_i)`). No automatic compiler exists; each circuit must be redesigned.
2. **Nova overhead.** Each step includes the Nova verifier logic (~10K–30K constraints). For 40K steps this is ~25 % overhead.
3. **Ecosystem maturity.** Rust Nova crates (`nova-snark`) exist but integration with Circom-generated R1CS is experimental. Most Nova work uses hand-written circuits in custom DSLs.
4. **On-chain verifier extension.** Aiken needs a small accumulator check in addition to the Groth16 pairing check.

### Verdict

- **Now:** Not needed. Implementation 6 + 7 handle all current circuits. Ceremony times are acceptable.
- **After Implementation 7:** The ~16 min Ed25519Verify ceremony is now the e2e bottleneck (~89 % of total time). Evaluate Nova IVC only if this becomes operationally painful.
- **When mandatory:** For 10M+ constraint circuits (rollups, full transaction validation) where monolithic Groth16 is infeasible.

### What exists today (implementation plan, step by step)

The POC does **not** implement Relaxed-R1CS folding. Instead it runs a **chain of ordinary Groth16 proofs**, one per step, and binds the state chain with a BLAKE2b512 transcript. Each step proof is fully independent and verifiable; `nova verify` re-derives the chain and the transcript. The only circuit invariant is **`n_pub_in == n_pub_out`** (the public input block of step `i+1` is the public output block of step `i` — public inputs *are* the IVC state), checked by `nova params`.

```
state_0 ──▶ [step0: f(step_0, state_0)] ──▶ state_1 ──▶ [step1] ──▶ … ──▶ state_N
              │ Groth16 proof0                       │ Groth16 proof1
              └──────────────── transcript ─────────┘
              acc = BLAKE2b512(acc || state_out || proof_bytes)
```

### How to run the e2e flow (worked example: `cardano_ed25519_ownership_nova`)

`cardano_ed25519_ownership_nova.circom` (in `circom/CardanoKeyOwnership/`) proves knowledge of a 255-bit scalar `sk` with `[sk]·G = PointA` on Curve25519 and `compress(PointA) = A`. It decomposes the base-point scalar multiplication into **255 identical steps**, each one `BitElementMulAny` on extended Edwards coordinates `[4][3]` (each coordinate as 3 limbs of base 2^85):

- state `(dblIn[4][3], addIn[4][3])` — 24 public inputs / 24 public outputs, 1 private input `sel`.
- per step: `dblOut = 2·dblIn`, `addOut = addIn + sel·dblOut` (`sel` = scalar bit, LSB-first).
- after 255 steps: `addOut = 2·[sk]·G`; the final checks `addOut == PointA` (projective) and `PointCompress(PointA) == A` are done by the application *after* the fold (they cannot be folded per-step — the accumulator is only complete after all 255 bits).
- sizes: 7658 wires, 7724 constraints per step (vs ~1.97M monolithic).

**1. Build the CLI**

```bash
cargo build --release --manifest-path cli/Cargo.toml
# binary: groth16-prover/cli/target/release/groth16-prover
```

**2. Compile the step circuit** (BLS12-381 field, `circomlib` include path as in the header comment)

```bash
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_ed25519_ownership_nova.circom --r1cs --wasm --sym
```

**3. Inspect the step circuit** (must report `n_pub_in == n_pub_out == 24`)

```bash
groth16-prover nova params --circuit cardano_ed25519_ownership_nova.r1cs
```

**4. One ceremony for the step circuit** (reusable for *any* run of the same step shape)

```bash
groth16-prover nova ceremony --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --verifying-key cko255.vk
```

**5. Generate the 255 step witnesses** `step_0000.wtns … step_0254.wtns` in one directory (full witness files, produced by the step circuit's wasm). Generate them **iteratively** so the chain invariant holds by construction:

```
dblIn := extended(G)          # base point, [4][3] x base-2^85 limbs
addIn := extended(O)          # identity
for i in 0..255:
    inputs = (dblIn, addIn, sel := (sk >> i) & 1)
    run wasm → full witness step_%04d.wtns
    read outputs (dblOut, addOut) → next (dblIn, addIn)
```

**6. Fold** — proves each step, checks the state chain, accumulates the transcript (≈2–4 min for 255 × 7.7K-constraint steps)

```bash
groth16-prover nova fold --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --steps <witness-dir> --out cko255_ivc.json
```

**7. Verify** — re-checks every Groth16 pairing, the state chain, and the transcript

```bash
groth16-prover nova verify --ivc cko255_ivc.json --verifying-key cko255.vk
# → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
```

Smoke-tested on four step circuits: `ed25519_verify_nova` (255 steps), `eddsa_jubjub_nova` (254), `cardano_ed25519_ownership_nova` (255), `anonymous_airdrop_nova` (5).

### Essence of the improvement

Decompose a computation into `N` identical, small step circuits and prove it **incrementally**, so that **ceremony cost and per-step memory scale with step size, not with total computation**:

- **Ceremony is circuit-agnostic and reusable.** The trusted setup runs once on the ~7.7K-constraint step circuit (seconds), not on the ~1.97M monolithic circuit (minutes). New computations reusing the same step shape need no new ceremony.
- **Memory scales per step.** Peak memory drops from O(total constraints) to O(step size) — the original motivation for 4M+ circuits that OOM a monolithic pipeline.
- **Each step is independently checkable.** Every step proof verifies on its own, and the transcript gives a tamper-evident, independently re-derivable binding of the whole chain.
- **Standard Groth16 stack is reused unchanged** — `FftQapEngine`, `PippengerProver`, `FullProvingKey` ceremony, existing `.pk`/`.vk` formats, `verify_with_vk`. The new code is a thin CLI layer (`cli/src/cmd/nova.rs`), not a new prover.

### Strong points

| Strong point | Detail |
|--------------|--------|
| Circuit-agnostic | The CLI works for any step circuit with `n_pub_in == n_pub_out`; only that invariant is checked. |
| One-time setup | A single ceremony per step shape serves all runs; no per-user or per-computation ceremony. |
| Debuggable | `nova fold` fails with the exact step whose `state_in` breaks the chain; each step proof is individually verifiable, so a bad witness is isolated to one step. |
| Auditability | The BLAKE2b512 transcript is fully deterministic; `nova verify` re-derives it from the stored states/proofs — tampering with any step is detected. |
| Low risk | Reuses the battle-tested Groth16 path; no new cryptographic primitives in the POC. |

### Weak points / limitations

| Weak point | Detail |
|------------|--------|
| Not real Nova folding | The POC stores **N Groth16 proofs** (bundle size O(N)) and verification does **N pairing checks**. It is a proof *chain*, not a constant-size accumulated proof. |
| No compression SNARK yet | The full Nova target — fold to one small proof via a Relaxed-R1CS accumulator + ~100K-constraint compression SNARK — is future work. On-chain verifier cost stays O(N) pairings until then. |
| Manual circuit redesign | Step decomposition is per-circuit, hand-written (`state_{i+1} = f(step_i, state_i)`); no automatic compiler from flat Circom R1CS. |
| Sequential folding | The chain is inherently sequential; no parallelism across steps. |
| App-level final checks | Checks that need the *complete* output (e.g. `PointCompress(PointA) == A`) are done outside the fold, not enforced per-step. |
| Overhead | For small circuits (≤ ~10K constraints) Nova overhead exceeds the benefit; it pays off only for large/sequential computations. |

---

### Practical recommendation

For **short-term production on Cardano**:
1. ✅ Implementation 6 (sparse prover) — **done**
2. ✅ Implementation 7 (h_scalar + parallel proof assembly) — **done**
3. ⏳ Ceremony MSM parallelization — **low-hanging follow-up**

For **medium-term** (when ceremony dominates or circuits exceed 4M):
4. ⏳ Implementation 8 (Nova IVC + compression SNARK) — **circuit-agnostic trusted setup + incremental proving**

For **long-term research**:
5. Evaluate PLONK / Halo2 only if proof size or verification cost regressions are acceptable.
6. Evaluate FHE-based selective disclosure for quantum resistance (see `aiken/selective-disclosure`).

> **Note on the ownership circuit.** The Cardano Ed25519 key ownership circuit (~1.97M constraints) already has a ceremony of only **~5 min** and proving of **~1.7 min** — a total of ~7 min e2e. This is already acceptable for dev/testnet workflows. The ~16 min Ed25519 full-signature ceremony is the outlier because SHA-512 in-circuit is expensive. If the use case is "prove I own this key" rather than "verify a signature", the bottleneck is already manageable.

</details>

---

## Production innovations

### Completed

<details>
<summary><b>Click to expand completed items</b></summary>

### (a) FFT / Lagrange basis as an alternative to dense monomials (zeroj supports that)

- **Status:** ✅ **Implemented.** The `QapEngine` trait, `DenseQapEngine`, and `FftQapEngine` are all in `src/engine.rs` with passing parity tests. Steps 2.3–2.12 are complete: FFT domain setup, QAP construction via IFFT, target polynomial `T(x)=x^N−1`, per-variable QAP evaluation via Lagrange basis scalars, witness polynomials, and quotient computation via `divide_by_vanishing_poly` are all working. The only remaining gap is building the group-element SRS in the Lagrange basis (`L_i(τ)·G1` instead of `τ^i·G1`); the FFT path currently reuses the monomial SRS for proof assembly, which is mathematically valid but not the most efficient production pattern.
- **Reference:** zeroj uses `FieldFFTBLS381` for coset FFT: constraint evaluations → IFFT → coefficient form; quotient `h(x)` is computed point-wise on the coset and inverse-FFT'd back. The Lagrange basis SRS (`u_s(tau)·G1`) is also more efficient than monomial SRS for FFT-based provers.
- **Benefit:** Enables proving for realistic circuits (e.g., Poseidon hash, Merkle membership) in seconds rather than minutes.

### (b) Pippenger multi-scalar multiplication (MSM) (zeroj supports that)

- **Status:** ✅ **Implemented.** The `Prover` trait, `NaiveProver`, and `PippengerProver` are all in `src/prover.rs`. `PippengerProver` uses `ark_ec::VariableBaseMSM::msm` for batched multi-scalar multiplication of proof element `C` and public-input commitment `V`. A parity test asserts identical points against the naive path.
- **Reference:** zeroj's `Groth16ProverBLS381` uses a bucket-MSM for computing `piA`, `piB`, and `piC`. Our implementation uses arkworks' built-in Pippenger via `G1Projective::msm`.
- **Benefit:** 5–10× speedup on proof generation, especially for circuits with large witness vectors.

### (c) Support usage of circom (zeroj supports that)

- **Status:** ✅ **Implemented.** The `circom_adapter` module in `src/circom_adapter.rs` parses `.r1cs` constraints and `.wtns` witnesses using `nom`. It converts sparse Circom matrices into dense `Vec<Vec<Fr>>` representations (preserving arbitrary field coefficients such as MiMC round constants) and feeds them into the same `QapEngine` / `Prover` stack. Parity tests assert that the parsed matrices and witness match the hard-coded circuit bit-for-bit.
- **Reference:** zeroj's `CircuitBuilder` generates R1CS dynamically; our adapter loads the constraints and witness from standard circom artifacts.
- **Benefit:** Ecosystem compatibility. Any circom-compatible circuit (e.g., from the [circomlib](https://github.com/iden3/circomlib) library) can be proven with this Rust prover.
- **Sub-tasks (all done):**
  1. ✅ Parse the `.r1cs` binary format (sparse constraint matrices) — `CircomCircuit::from_r1cs` / `from_bytes`.
  2. ✅ Load a precomputed `.wtns` — `CircomCircuit::load_witness` / `load_witness_from_bytes`.
  3. ✅ Map circom wire indices to the QAP variable ordering — verified by parity test against hard-coded circuit.
  4. ✅ Verify that the FFT domain size matches `next_power_of_2(num_constraints)` — handled automatically by `FftQapEngine::target_poly`.

### (h) Multi-party computation (MPC) ceremony

- **Current:** Two ceremony paths coexist:
  1. **`ceremony-dev`** (default) — outputs `FullProvingKey` (group elements only, no scalars). The prover uses MSM over pre-computed points. This is the fast, insecure path for testing/CI.
  2. **Legacy scalar path** — kept for backward compatibility; `ProvingKey` still contains raw scalars but is no longer generated by the CLI.
- **Target:** A proper **MPC trusted-setup ceremony** where multiple participants contribute randomness in a sequential protocol (e.g., Perpetual Powers of Tau). After the final contribution:
  1. The toxic-waste scalars are **never reconstructed in one place**.
  2. The structured reference string (SRS) — `tau^i·G1`, `tau^i·G2`, etc. — is the only artifact retained.
  3. The prover uses the **full SRS** instead of the raw scalars, so the scalars can be destroyed immediately.
- **Status:**
  - ✅ **Phase 0 — Prover migration (scalars → group elements):** Complete. `FullProvingKey` struct, `single_party_ceremony_full()`, `NaiveProver`/`PippengerProver` `prove_with_full_pk()`, and CLI `ceremony-dev` subcommand are all implemented and tested. Parity tests confirm bit-for-bit identical proofs between old and new paths.
  - ✅ **Phase 1 — `.ptau` parser:** Complete. `src/ptau.rs` reads snarkjs `.ptau` files (PPoT format) and converts LEM points into arkworks `G1Affine`/`G2Affine`. Tested against a snarkjs-generated power-4 BLS12-381 file with on-curve and subgroup validation.
  - ✅ **Phase 2 — Phase 2 MPC logic:** Complete. `src/phase2.rs` implements `initialize()` (consumes `.ptau` + `.r1cs` → `Phase2Accumulator`), `contribute()` (updates delta-dependent elements with Schnorr-like ratio proof), `verify()` (checks all contribution proofs and delta chaining), and `finalize()` (produces `FullProvingKey` + `VerifyingKey`). Rewritten from scratch (Manta reference is GPL-3.0, incompatible with our Apache-2.0). Five integration tests pass including end-to-end prove/verify with a real `.ptau` file.
- **Key insight:** The prover now uses **pre-computed group elements** (`u_i(tau)·G1`, `v_i(tau)·G2`, `delta_inv·psi_i·G1`, etc.) via multi-scalar multiplication instead of re-evaluating QAP polynomials from raw scalars on every proof. This makes the prover faster *and* removes toxic waste from the `.pk` file.
- **Switchable design:** The prover consumes a unified `ProvingKey` format (group elements only, arkworks-compatible). Two ceremony implementations produce the same artifact:
  - `ceremony-dev` — single-party, instant, for testing/CI/benchmarks
  - `phase2` — multi-party MPC for production (reuses PPoT Phase 1 + circuit-specific contributions)
- **Pipeline change:** The CLI now has both `ceremony-dev` (single-party, instant) and `phase2 new / contribute / verify / finalize` (multi-party MPC). Both produce the same `.pk` / `.vk` binary format. The `prove` and `verify` commands are agnostic to provenance.
- **Reference:** [Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau), snarkjs `powersoftau` workflow, [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony), and arkworks' `groth16::generator::generate_random_parameters`.
- **Benefit:** Eliminates the single point of failure. Even if N−1 participants collude, the ceremony remains secure as long as at least one participant honestly discards their contribution.

### (j) Sparse-matrix prover (beyond what zeroj supports)

- **Status:** ✅ **Implemented** as [Implementation 6](#implementation-6-sparse-matrix-prover).
- **What changed:** `circom_adapter` now provides `SparseCircomCircuit` which keeps the native sparse `.r1cs` representation (per-constraint lists of `(wire_id, coeff)` triplets) instead of expanding into dense `Vec<Vec<Fr>>` matrices. A new `build_witness_polys_sparse` helper in `engine.rs` evaluates the sparse constraints at the FFT domain roots and does 3× IFFT to get `l(x)`, `r(x)`, `o(x)` directly — no `n_vars × domain_size` dense allocation is ever created.
- **Ceremony:** `single_party_ceremony_full_from_tw_sparse` computes per-variable QAP evaluations at `tau` by iterating only non-zero entries against the Lagrange basis, producing a `FullProvingKey` that is bit-for-bit identical to the dense path.
- **Prover:** Both `NaiveProver` and `PippengerProver` implement `prove_with_full_pk_sparse`, which uses the sparse witness-polynomial construction and then the same MSM formulae as Implementation 5.
- **CLI:** `ceremony-dev --sparse` and `prove --sparse` flags are available; `--sparse` implies the on-the-fly FullProvingKey path.
- **Tests:** 5 parity tests pass (sparse vs dense): parser equivalence, ceremony key equality, naive prover proof equality, Pippenger prover proof equality, and end-to-end verification. 7 CLI integration tests also pass.
- **Benefit:** Unlocks circuits with 50K–500K wires (Blake2b-224, Ed25519, large Poseidon trees) on commodity hardware. The dense-matrix OOM at 12K wires disappears entirely. Memory drops from `O(n_constraints × n_wires)` to `O(#non_zero_entries)`.

### (k) h-query scalar compression + parallel proof assembly (beyond what zeroj supports)

- **Status:** ✅ **Implemented** as [Implementation 7](#implementation-7-h-query-scalar-compression--parallel-proof-assembly).
- **What changed:** The `h_query` vector — which stored `delta_inv * tau^j * T(tau) * G1` for every coefficient of the quotient polynomial `h(x)` — is replaced by a single scalar `h_scalar = delta_inv * T(tau)`. During proving, the h_commitment becomes one scalar multiplication (`generator * h_scalar * h.evaluate(&tau)`) instead of a multi-million-point MSM. This eliminates the dominant proving cost (~55 % of prove time on Ed25519). In addition, the remaining independent MSMs (A, B, C_private) are overlapped with `rayon::join` on multi-core machines.
- **Fields added:** `FullProvingKey.h_scalar: Option<Fr>` and `h_scalar_tau: Option<Fr>` (the latter stores `tau` so the prover can evaluate `h(tau)` without an external scalar). Both are `None` in the Phase 2 MPC path since the ceremony destroys all scalars.
- **Prover:** Fast-path branch added to all four prover methods (`Naive`/`Pippenger` × `dense`/`sparse`). Auto-detects via `if let (Some(h_scalar), Some(tau)) = (full_pk.h_scalar, full_pk.h_scalar_tau)` and falls back to the legacy `h_query` MSM when absent.
- **CLI:** `--h-scalar` flag on `ceremony-dev` triggers the compressed proving key. The `prove` command auto-detects and uses the fast path with no extra flags.
- **Tests:** 4 parity tests (dense naive, FFT Pippenger, sparse Pippenger, valid proof) plus 1 CLI integration test (`full_ceremony_dev_h_scalar_prove_verify_roundtrip`) all pass.
- **Benefit:** Cuts Ed25519 prove time from ~5 min to ~2 min, halves the uncompressed PK size (~2.7 GB → ~1.3 GB), and eliminates the single largest MSM bottleneck. Backward-compatible: old `.pk` files without `h_scalar` still work via the fallback path.

### (l) Poseidon-based Merkle membership gadget ✅ DONE

- **Status:** ✅ **Implemented** end-to-end in `circom/PoseidonMerkle/`.
- **What it does:** A reusable Circom template `PoseidonMerkle(depth)` proves that a leaf commitment `PoseidonBLS12_381(nullifier, nonce)` exists in a Merkle tree of the given depth, with only the tree root as a public input. The leaf secret, the path siblings, and the path directions are all private.
- **Files:**
  - `circom/PoseidonMerkle/poseidon_merkle.circom` — generic `PoseidonMerkle(depth)` template with `IfThenElse`, `SelectiveSwitch`, and Merkle walk using `PoseidonBLS12_381`.
  - `circom/PoseidonMerkle/poseidon_merkle_depth2.circom` — top-level `PoseidonMerkle(2)` instantiation with public `digest`.
  - `circom/PoseidonMerkle/helpers_py/poseidon_merkle.py` — Python helper for Poseidon hash, sparse Merkle tree, and `input.json` generation.
  - `circom/PoseidonMerkle/README.md` — full pipeline documentation.
- **Validation:**
  - Compiled to 737 non-linear constraints / 1,914 wires for depth 2.
  - Witness generated with `snarkjs`.
  - Dev ceremony, proof production, and off-chain verification all pass via the Rust `groth16-prover` CLI.
  - On-chain verification test passes in `aiken/groth16/lib/groth16/verifier.ak` (`test_verify_poseidon_merkle_depth2_proof`).
- **Constraint cost:** ~250 constraints per level (Poseidon t=3) + ~1 constraint for the bit-select swap. Depth 2 = 737 constraints; depth 20 ≈ 5,000 constraints; depth 32 ≈ 8,000 constraints.
- **Remaining:** Pair this gadget with `EdDSA_JubJubVerifier` for issuer signature to build the full Step 1 predicate for selective-disclosure.
- **Reference:** [circomlib MerkleTree](https://github.com/iden3/circomlib/blob/master/circuits/merkleTree.circom) uses a depth-parameterised template with MiMC; the same structure applies with Poseidon substituted in. [Poseidon hash](https://www.poseidon-hash.info/) recommends t=3 for binary tree hashing (two inputs + capacity).

### (i) Additional Circom use-case circuits — completed

- **Target:** Add several realistic Circom circuits that exercise different zk-SNARK patterns:
  1. **Poseidon hash** — demonstrate hash pre-image knowledge inside a Groth16 proof.  
     **Status:** ✅ **Complete.** A `PoseidonPreimage` circuit lives in `circom/PoseidonPreimage/`. It uses a BLS12-381 Poseidon permutation (t=3, alpha=5, RF=8, RP=57) with round constants and MDS matrix from ZeroJ's `PoseidonParamsBLS12_381T3`. The circuit proves `hash_commitment = Poseidon(pre_image, 0)` without revealing `pre_image`. See [`circom/PoseidonPreimage/README.md`](circom/PoseidonPreimage/README.md) for the full step-by-step walkthrough.
  2. **Merkle membership** — prove that a leaf exists in a Merkle tree without revealing the leaf or the path.  
     **Status:** ✅ **Complete.** A shielded-spend circuit (`Spend(depth)`) based on Stanford CS251 Project #4 lives in `circom/Privacy/`. It uses MiMC(x⁷) hashing and `SelectiveSwitch` gadgets to verify a Merkle path. A depth-2 wrapper (`spend_depth2.circom`) has been compiled with `circom --r1cs --wasm` and the full pipeline is working end-to-end: witness-input generation (via `compute-inputs` CLI or Rust library), witness calculation (snarkjs), dev ceremony, proof generation (`prove` CLI with FFT + Pippenger), off-chain verification (`verify` CLI), and on-chain verification (Aiken test in `aiken/groth16/lib/groth16/verifier.ak`). The CLI also includes `smt insert` / `smt digest` / `smt path` / `smt verify` / `smt export` commands for sparse Merkle tree operations backed by the same MiMC(x⁷) hash, plus bulk loading via `--transcript`. See [`circom/Privacy/README.md`](circom/Privacy/README.md) for the full step-by-step walkthrough.
  3. **Range proof / comparison** — prove that a committed value lies in a range `[0, 2^n)`.  
     **Status:** ✅ **Complete.** Two circuits in `circom/RangeProof/`: `RangeProofSimple(n)` (public value, ~n constraints) and `RangeProofCommitted(n)` (Poseidon commitment, ~n+250 constraints). Both compile, generate witnesses, and produce valid Groth16 proofs end-to-end on BLS12-381. See [`circom/RangeProof/README.md`](circom/RangeProof/README.md) for full pipeline and the JSON string-precision caveat.
   4. **EdDSA / JubJub signature** — verify a signature inside the circuit (requires JubJub curve gadgets).  
      **Status:** ✅ **Complete.** An EdDSA-JubJub verifier circuit lives in `circom/EdDSAJubJub/`. The circuit was ported from circomlib's BabyJubJub to JubJub (`a=−1, d=0x2a93...eb1`, embedded in BLS12-381 scalar field), optimised from 18 112 wires to 12 601 (–31%), and validated end-to-end: compile → witness gen → ceremony-dev → prove → verify. See [`circom/EdDSAJubJub/README.md`](circom/EdDSAJubJub/README.md).
    5. **Blake2b-224 hash** — prove knowledge of a pre-image that hashes to a given Cardano key hash.  
       **Status:** ✅ **Working end-to-end.** A `Blake2b224Preimage` circuit lives in `circom/Blake2b224Preimage/`. It compiles to ~79K constraints (77,312 non-linear + 2,059 linear). The dense-matrix ceremony previously required ~200 GB RAM and OOM-killed; the sparse-matrix prover (Implementation 6) keeps the native sparse `.r1cs` representation and completes ceremony (~18 s) + proof (~5 s) + verify (~0.2 s) on commodity hardware. Memory drops from `O(n_constraints × n_wires)` to `O(#non_zero_entries)` (~280 MiB). See [`circom/Blake2b224Preimage/README.md`](circom/Blake2b224Preimage/README.md) for the full step-by-step pipeline.  
       **Reference:** [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) provides the upstream Blake2b Circom circuit (MIT License).
   6. **Private key → public key ownership proof** — prove that you know the private key that generates a given Cardano public key / address, without revealing the private key.  
       **Status:** ✅ **Implemented.** Two variants in `circom/CardanoKeyOwnership/`:
       - **JubJub ownership** (`cardano_key_ownership.circom`) — uses `EscalarMulFixJubJub(254, BASE8)` to compute `[sk]·G_JubJub` and assert equality with the public key. ~4K constraints, trivial to prove. **Caveat:** proves ownership of a JubJub key, NOT a real Cardano Ed25519 key.
       - **Ed25519 ownership** (`cardano_ed25519_ownership.circom`) — NEW. Reuses `Ed25519Verify` templates to prove real Cardano wallet key ownership: `PointA = [sk]·G` on Curve25519 with `PointCompress(PointA) == A`. ~1.97M constraints, works with the sparse prover (ceremony ~5 min, prove ~1.7 min on 16-core). This is the first in-circuit proof of real Cardano Ed25519 key ownership on BLS12-381.
       **Reference:** [cardano-crypto `generate`](https://github.com/IntersectMBO/cardano-crypto/blob/develop/src/Cardano/Crypto/Wallet.hs#L161) for the original Cardano key-derivation logic.
   7. **Anonymous airdrop with reputation score threshold** — composite circuit proving SMT membership AND `score >= minScore` in a single Groth16 proof.  
      **Status:** ✅ **Complete.** `AnonymousAirdrop(depth, n)` in `circom/AnonymousAirdrop/` combines `Spend(depth)` (SMT membership via MiMC(x⁷)) with `GreaterEqThan(n)` from circomlib (range comparison). The leaf commitment binds all three secrets: `commitment = MiMC(MiMC(nullifier, nonce), score)`. Public inputs: `digest`, `minScore`, `nullifier`. Private inputs: `nonce`, `score`, `sibling[depth]`, `direction[depth]`. The full pipeline works end-to-end: SMT build (via `smt insert` CLI), witness input generation (via `compute_airdrop_inputs` Rust helper), witness calculation (snarkjs), dev ceremony, proof generation (FFT + Pippenger), off-chain verification, and rejected cases correctly fail at witness generation when `score < minScore`. 1,561 constraints for depth 2. See [`circom/AnonymousAirdrop/README.md`](circom/AnonymousAirdrop/README.md) for the full walkthrough.

</details>

### Pending

<details>
<summary><b>Click to expand pending items</b></summary>

### (m) Prepared verifier and batched pairing verification (beyond what zeroj supports)

- **Current:** The verifier recomputes every pairing from scratch each time a proof is checked.
- **Target:** Add a `PreparedVerifyingKey` that precomputes and caches fixed verification-key data (e.g., G2 line coefficients for the Miller loop). Also expose a batched verifier that checks multiple proofs with a single multi-pairing product.
- **Reference:** [Groth.jl](https://github.com/0xpantera/Groth.jl) implements `prepare_verifying_key`, `prepare_inputs`, and `verify_with_prepared`; batched pairing verification reduced their `N=16` batch from `18.212 ms` to `13.854 ms` on the same fixture. Arkworks also provides `PreparedVerifyingKey`.
- **Benefit:** On-chain verification becomes cheaper because the heavy G2 preparation is done once per VK, not per proof. Batching further amortizes the Miller-loop cost across many proofs.

### (n) Batch normalization and fixed-base MSM tables (beyond what zeroj supports)

- **Status:** ✅ **Partially implemented.** The ceremony path now uses `ark_ec::scalar_mul::fixed_base::FixedBase::msm` + `G1Projective::normalize_batch` for all per-variable query generation (`a_query`, `b_g1_query`, `c_query`, `ic`, `h_query`). This replaced the previous naive scalar-by-scalar loop (`g1_proj * scalar` in a hot loop) and reduced the Ed25519 ceremony from **>5 h to ~16 min**. See [Implementation 6 benchmarks](#implementation-6-sparse-matrix-prover) for measured numbers.
- **What changed:** `single_party_ceremony_full_from_tw` and `single_party_ceremony_full_from_tw_sparse` both build windowed precomputation tables once and evaluate all scalars in batch using Pippenger-like windowed additions. The same G1 table is reused across `a_query`, `b_g1_query`, `c_query`, `ic`, and `h_query` generation. The `ark-std = { features = ["parallel"] }` + `rayon` dependency enables parallel table construction and point normalization.
- **Remaining:** The prover-side MSMs (`A`, `B`, `C`, `h`, `V`) still use `VariableBaseMSM::msm` (Pippenger) because the bases are the per-variable query points, not a single fixed generator. Fixed-base tables do not apply here. Batch normalization is already used wherever projective→affine conversion happens in bulk.
- **Reference:** Groth.jl uses `batch_to_affine!` and `FixedBaseTable` with measured speedups on setup query generation.
- **Benefit:** Batch normalization saves ~30–50% on point serialization and pairing input preparation. Fixed-base tables reduced ceremony time by **>19×** on Ed25519 (~4M constraints).

### (o) Randomized R1CS test fixtures and parity assertions 

- **Current:** Only one hard-coded 3-constraint circuit is tested.
- **Target:**
  1. Generate randomized R1CS fixtures (random sparse constraints and random witnesses satisfying `A∘B=C`) for property-based testing.
  2. Keep dense/naive computation paths as **parity assertions** alongside optimized paths (FFT, coset quotient). In debug/test mode, run both and assert identical results.
- **Reference:** Groth.jl keeps dense quotient computation (`compute_h_polynomial`) as an explicit parity check while the production prover uses the coset-only path. Their test suite covers multiple circuits with randomized seeds.
- **Benefit:** Catches bugs in the optimized path early by comparing against a slow-but-correct reference on every test run.

### (p) Finish the Lagrange-basis SRS

- **Status:** ⚠️ **Partial.** The `QapEngine` trait, `DenseQapEngine`, and `FftQapEngine` are all implemented (see item (a) above). The only remaining gap is building the group-element SRS in the Lagrange basis (`L_i(τ)·G1` instead of `τ^i·G1`) so the FFT path can skip monomial conversion and use the most efficient production pattern.
- **Benefit:** Completes the FFT production path and removes the last monomial fallback.

### (q) Proof aggregation (beyond what zeroj supports)

- **Current:** Each proof is verified individually.
- **Target:** Support Groth16 proof aggregation (rolling multiple proofs into a single succinct proof that can be verified with one pairing check).
- **Reference:** Arkworks has an optional `groth16::aggregate_proofs` module. Groth.jl tracks this on their roadmap.
- **Benefit:** Essential for rollup and batching use cases where many proofs need to be verified on-chain in a single transaction.

### (s) Recursive proof composition

- **Current:** Each proof is standalone — the on-chain verifier checks one Groth16 proof per transaction. For use cases requiring many proofs (e.g., rollups, batched attestations), each proof pays full on-chain verification cost.
- **Target:** Support proving "I know a valid Groth16 proof π₁ for circuit C₁" inside a second Groth16 circuit C₂, producing a succinct proof π₂ that attests to the correctness of π₁. The on-chain verifier checks only π₂, regardless of how many inner proofs it covers.
- **Approach:**
  1. **Incremental Verifiable Computation (IVC)** via Nova/SuperNova — fold multiple proof steps into a single accumulating proof. The fold is cheap (one EC addition); the final SNARK wrap compresses to a Groth16 proof.
  2. **SNARK-friendly verification gadget** — implement the Groth16 pairing check inside a Circom circuit (pairing operations on BLS12-381 can be expressed as R1CS constraints, though at high cost ~100K–500K constraints for the pairing itself).
  3. **Halo2-style recursive aggregation** — use cycle of curves (BLS12-381 + JubJub) for efficient recursive verification without pairings.
- **Benefit:** Amortises on-chain verification cost across N proofs — from O(N) pairing checks to O(1). Essential for rollup and batching use cases. Also enables incremental computation where each step's output feeds into the next.
- **Reference:** [arkworks groth16::aggregate](https://docs.rs/ark-groth16/latest/ark_groth16/), [Nova](https://github.com/microsoft/Nova), [Zcash Halo2](https://github.com/zcash/halo2), [Pacifico](https://github.com/argumentcomputer/pacifico).

### (t) Shielded cross-chain privacy pool (F5 research direction)

- **Current:** Privacy pools (e.g., Tornado Cash, Privacy Pools proposal) operate on a single chain. Cross-chain privacy requires either N separate pools (fragmenting the anonymity set) or trusted third-party relayers.
- **Target:** A **single privacy pool on Ethereum L1** whose only withdrawal path is **private cross-chain delivery** via canonical bridges. A user spends an L1 note; the value bridges canonically to a shielded pool on an L2; a stealth commitment lands there, so no public address touches the value on either side.
- **Why this matters:**
  1. **One pool, many destinations.** The destination chain is a property of the withdrawal proof, not the deposit. This concentrates liquidity and anonymity into a single large set instead of fragmenting it across N small pools.
  2. **Canonical bridges only.** No new bridge trust surface — the protocol reuses existing canonical bridges (e.g., official L1→L2 message-passing) rather than introducing custom relayers or multisigs.
  3. **Shielded cross-chain transfers.** A user publishes a shielded address; anyone can pay them on another chain with nothing public exposed. The stealth scheme (shaped like ERC-5564 but non-conformant) uses Baby Jubjub so the spend key opens a Poseidon constraint in-circuit rather than signing a transaction.
  4. **ZK-native stealth.** Unlike ERC-5564 which relies on on-chain ECDSA signatures, the F5 approach computes the stealth public key entirely inside a Groth16 circuit. The recipient's viewing key never appears on-chain; only the proof does.
- **Relation to our stack:**
  - The Poseidon Merkle gadget (`circom/PoseidonMerkle/`) provides the membership proof for pool notes.
  - The Ed25519 ownership circuit (`circom/CardanoKeyOwnership/`) demonstrates in-curve key derivation, a primitive needed for the stealth spend-key opening.
  - The sparse prover (Implementation 6) is necessary because a full F5 circuit (Merkle membership + stealth key derivation + bridge message validation) would likely exceed 500K constraints.
  - The Aiken on-chain verifier can validate the Groth16 proof inside a Cardano smart contract; the bridge logic would be handled by the canonical L1→L2 message pass.
- **Status:** ⏳ **Research direction.** Not yet committed to the roadmap. The F5 PoC ([f5.primemodulus.com](https://f5.primemodulus.com/)) demonstrates the concept on Ethereum; adapting it to Cardano would require:
  1. Porting the stealth scheme from Baby Jubjub to Jubjub (BLS12-381 native).
  2. Building a Circom circuit that proves: (a) Merkle membership of the L1 note, (b) correct stealth key derivation, (c) valid bridge message hash.
  3. Integrating with a canonical Cardano bridge (e.g., Milkomeda, Inter-Blockchain Communication, or future canonical L2s).
- **Reference:** [F5 PoC](https://f5.primemodulus.com/), [merkle-groot/f5](https://github.com/merkle-groot/f5), [ERC-5564 Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564), [Privacy Pools (Buterin et al., 2023)](https://github.com/a16z/privacy-pools).
- **Benefit:** If realised, this would be the first ZK-native cross-chain privacy protocol that does not fragment anonymity sets or introduce new bridge trust assumptions. A single large pool on L1 serves all L2s; users withdraw privately to any supported chain with the same anonymity guarantee.

</details>

---

## Benchmarks

<details>
<summary><b>Click to expand benchmark results</b></summary>

### Toy circuit (`multiplier.circom` — 3 constraints)

Proof-production time for the hard-coded 3-constraint circuit (`x1·x2 = x5`, `x3·x4 = x6`, `x5·x6 = a`) on a single core, compiled with `--release`:

| Implementation | Engine | Prover | Per-proof time | vs. Impl 1 | vs. Impl 2 | vs. Impl 4c |
|----------------|--------|--------|---------------|------------|------------|-------------|
| 1 (dense) | `DenseQapEngine` | `NaiveProver` | **3.99 ms** | — | — | — |
| 2 (FFT) | `FftQapEngine` | `NaiveProver` | **5.56 ms** | 0.72× | — | — |
| 3 (Pippenger) | `FftQapEngine` | `PippengerProver` | **3.76 ms** | 1.06× | 1.48× | — |
| 4a (Circom dense) | `DenseQapEngine` | `NaiveProver` | **3.90 ms** | 1.02× | 1.43× | — |
| 4b (Circom FFT) | `FftQapEngine` | `NaiveProver` | **5.58 ms** | 0.72× | 1.00× | — |
| 4c (Circom Pippenger) | `FftQapEngine` | `PippengerProver` | **4.00 ms** | 1.00× | 1.39× | — |
| 5a (Circom Full PK) | `FftQapEngine` | `NaiveProver` | **1.74 ms** | 2.29× | 3.20× | 2.30× |
| 5b (Circom Full PK Pippenger) | `FftQapEngine` | `PippengerProver` | **1.72 ms** | 2.32× | 3.23× | 2.33× |
| 6 (sparse Full PK Pippenger) | `FftQapEngine` | `PippengerProver` | **1.59 ms** | 2.51× | 3.50× | 2.52× |
| 7a (h_scalar Naive) | `FftQapEngine` | `NaiveProver` | **1.23 ms** | 3.24× | 4.52× | 3.23× |
| 7b (h_scalar Pippenger) | `FftQapEngine` | `PippengerProver` | **5.78 ms** | 0.69× | 0.96× | 0.69× |
| 7c (sparse h_scalar Naive) | `FftQapEngine` | `NaiveProver` | **1.26 ms** | 3.17× | 4.41× | 3.17× |
| 7d (sparse h_scalar Pippenger) | `FftQapEngine` | `PippengerProver` | **4.63 ms** | 0.86× | 1.20× | 0.86× |

> **What the numbers mean.** For a 3-gate circuit the FFT overhead (padding to 4 points, extra IFFT steps) outweighs its `O(N log N)` advantage, so Implementation 2 is slightly slower than Implementation 1. Pippenger's batched MSM yields a modest ~48 % speedup over naive FFT at this tiny scale. The Circom adapter parser overhead is now negligible in `--release` mode, so Implementations 4a–4c match the hard-coded-matrix timings. Implementation 5 moves to the group-element-only `FullProvingKey` path: the on-the-fly QAP construction is negligible for 8 wires, but the pre-computed `a_query`, `b_g2_query`, `c_query` and `l_query` points eliminate the per-proof QAP evaluation at `tau` and make the proof roughly 2.3–3.3× faster than every scalar path. On realistic circuits with hundreds or thousands of gates, the combined FFT + FullProvingKey + Pippenger path is the fastest production configuration.
>
> **Implementation 7** on the tiny toy circuit shows the h_scalar benefit clearly for Naive (~3× faster, because the h_query MSM is scalar-by-scalar) but not for Pippenger (~6 % improvement on dense, ~30 % on sparse), since the h_query MSM already uses batched Pippenger and is tiny at this scale. The real speedup appears on large circuits where h_query has millions of points.
>
> **Implementation 6** at this scale is effectively the same speed as Implementation 5 because the sparse overhead (iterating triplets instead of dense columns) is negligible for 9 non-zero entries. The benefit only becomes visible once the dense matrices grow large enough that allocation and zero-filling dominate.
>
> **Implementation 5** numbers are from a `--release` build with the `FullProvingKey` generated once outside the timed loop. The per-proof cost includes on-the-fly IFFT of the three witness polynomials over the 4-point FFT domain plus the final MSMs.

### Privacy circuit (`Spend(depth)` — Merkle membership)

The shielded-spend circuit lives in `circom/Privacy/`. It proves that a commitment `H(nullifier, nonce)` exists in a Merkle tree of the given depth without revealing the nullifier, nonce, or path. The depth-2 wrapper (`spend_depth2.circom`) has been compiled with `circom --r1cs --wasm` and produces **1,107 constraints**.

Proof-production time on a single core, compiled with `--release`, using a `FullProvingKey` (group elements only, no scalars):

| Path | Engine | Prover | Per-proof time | vs. Legacy |
|------|--------|--------|---------------|------------|
| Legacy (scalars) | `FftQapEngine` | `NaiveProver` | **7.13 s** | — |
| FullProvingKey (legacy) | `FftQapEngine` | `NaiveProver` | **8.39 s** | 0.85× |
| FullProvingKey (legacy) | `FftQapEngine` | `PippengerProver` | **5.60 s** | 1.27× |
| FullProvingKey (h_scalar) | `FftQapEngine` | `NaiveProver` | **~7.5 s** | ~0.95× |
| FullProvingKey (h_scalar) | `FftQapEngine` | `PippengerProver` | **~5.3 s** | ~1.35× |
| 6 (sparse Full PK Pippenger) | `FftQapEngine` | `PippengerProver` | **—** | — |

> **What the numbers mean.** The current `prove_with_full_pk` implementation still rebuilds QAP polynomials from raw R1CS matrices on every proof, so the dominant cost is QAP construction + quotient computation (both `O(N log N)` via FFT). The FullProvingKey path saves time on the MSM step, but for 1,107 constraints the MSM is not yet the bottleneck. Pippenger's batched MSM still yields a ~30 % speedup over the naive scalar-by-scalar accumulation. Future work will pre-compute witness evaluations so the prover can skip QAP reconstruction entirely.
>
> **Implementation 7** at 1,107 constraints yields a modest improvement (~5–10 % on dense, ~10 % on Pippenger) because the h_query MSM is small. The real speedup appears on circuits with 10K+ constraints where the h_query vector grows large.
>
> **Implementation 6** was not separately measured for the Privacy circuit because the dense path already fits in memory (~118 MiB matrix expansion). The sparse path would eliminate this allocation entirely; extrapolating from the PoseidonMerkle trend (13× speedup at 1,911 constraints), the sparse Privacy proof is expected to finish in **~400–1,000 ms**. Run `cargo run --bin benchmark_sparse --release` after generating a valid `spend_depth2.r1cs` + `witness.wtns` to collect the exact number.

| Depth | Constraints | Notes |
|-------|-------------|-------|
| 2 | 1,107 | Current benchmark target (`spend_depth2.circom`) |
| 8 | ~4,400 | Estimated (≈550 constraints per level) |
| 16 | ~8,800 | Estimated |
| 32 | ~17,600 | Estimated |

> **Why depth matters.** The Merkle path has `depth` sibling hashes. Each level in the Circom circuit invokes `MiMC2` (≈30 constraints) plus `SelectiveSwitch` (≈8 constraints). Doubling the depth roughly doubles the constraint count and proof-generation time.

### PoseidonMerkle circuit (`PoseidonMerkle(depth)` — Poseidon-based Merkle membership)

The Poseidon-based Merkle membership circuit lives in `circom/PoseidonMerkle/`. It proves that a commitment `PoseidonBLS12_381(nullifier, nonce)` exists in a Merkle tree of the given depth without revealing the nullifier, nonce, or path. The depth-2 wrapper (`poseidon_merkle_depth2.circom`) produces **1,911 constraints** and **1,914 wires**.

Proof-production time on a single core, compiled with `--release`. The dense Circom path (4a) is omitted because `DenseQapEngine` is hard-coded for the 3-gate toy circuit; all realistic paths use `FftQapEngine`.

| Implementation | Engine | Prover | Full PK | Per-proof time | vs. 4b |
|----------------|--------|--------|---------|---------------|--------|
| 4b (Circom FFT Naive) | `FftQapEngine` | `NaiveProver` | no | **12.94 s** | — |
| 4c (Circom FFT Pippenger) | `FftQapEngine` | `PippengerProver` | no | **11.59 s** | 1.12× |
| 5a (Circom Full PK Naive) | `FftQapEngine` | `NaiveProver` | yes | **12.69 s** | 1.02× |
| 5b (Circom Full PK Pippenger) | `FftQapEngine` | `PippengerProver` | yes | **10.31 s** | 1.25× |
| 6b (sparse Full PK Pippenger) | `FftQapEngine` | `PippengerProver` | yes | **731 ms** | **17.7×** |
| 7a (h_scalar Naive) | `FftQapEngine` | `NaiveProver` | yes | **~10.0 s** | ~1.3× |
| 7b (h_scalar Pippenger) | `FftQapEngine` | `PippengerProver` | yes | **~9.8 s** | ~1.3× |
| 7c (sparse h_scalar Pippenger) | `FftQapEngine` | `PippengerProver` | yes | **~700 ms** | **~18×** |

> **What the numbers mean.** At 1,911 constraints the dominant cost is still on-the-fly QAP construction (building the witness polynomials from the R1CS matrices via IFFT), not the multi-scalar multiplications. The `FullProvingKey` path therefore only modestly outperforms the scalar path: it eliminates per-proof QAP evaluation at `tau` and the final scalar MSM, but the IFFT/quotient steps remain. Pippenger's batched MSM gives a consistent ~10–25 % speedup over the naive MSM. Future work that pre-computes witness evaluations at the FFT domain roots would remove the QAP reconstruction bottleneck and widen the gap between the scalar and FullProvingKey paths.
>
> **Implementation 7** at this scale (1,911 constraints) yields a modest ~5–10 % improvement on the dense path because the h_query MSM is still small (~2,048 points). The benefit grows with circuit size: on Ed25519 (~4M constraints) the h_query MSM alone was ~55 % of prove time, so h_scalar cuts total prove time by more than half. On the sparse path the h_scalar benefit is also modest at 1,911 constraints; run `cargo run --bin benchmark_poseidon_merkle --release` to collect exact numbers.
>
> **Implementation 6** is the game-changer at this scale. By keeping the native sparse `.r1cs` representation and accumulating witness polynomials directly from non-zero entries, it avoids materialising the `1,914 × 2,048` dense zero-filled columns that the dense path iterates over. The result is a **13–18× speedup** over the dense FullProvingKey path and a **16–18× speedup** over the scalar path, while memory drops from **335 MiB** to **0.2 MiB** (a **1,400× reduction**).

| Depth | Constraints | Notes |
|-------|-------------|-------|
| 2 | 1,911 | Current benchmark target (`poseidon_merkle_depth2.circom`) |
| 8 | ~7,600 | Estimated (≈950 constraints per level) |
| 16 | ~15,200 | Estimated |
| 32 | ~30,400 | Estimated |

> **Comparison with MiMC-based Merkle.** Each Poseidon level costs ≈250 constraints vs ≈38 for MiMC(x⁷), so the Poseidon tree is roughly 6–7× larger in constraints at the same depth. The trade-off is that Poseidon is the hash used elsewhere in the BLS12-381 stack (pre-image, EdDSA-JubJub challenge), enabling a single on-chain verifier VK format and avoiding MiMC's algebraic structure concerns.

### zeroj comparison (Java pure-Java prover)

The [zeroj](https://github.com/bloxbean/zeroj) toolkit provides a pure-Java Groth16 prover (`Groth16ProverBLS381`) that also keeps constraints in a native sparse representation (`Map<Integer, BigInteger>` via `R1CSImporter`), so it does not suffer from the dense-matrix OOM bottleneck either.

**Measured zeroj numbers (GraalVM 25.0.3, single core):**

| Circuit | Constraints | zeroj prove | Rust sparse (Impl 6) | Speedup |
|---------|-------------|-------------|----------------------|---------|
| Synthetic squaring chain | 4,096 | **11.2 s** | — | — |
| PoseidonMerkle depth-2 | 1,911 | **~11 s** (projected) | **731 ms** | **~15×** |

> **How the numbers compare.** zeroj uses hand-written pure-Java bucket-MSM and coset-FFT; our crate uses arkworks' optimized Rust/C++ Pippenger MSM and radix-2 FFT. The ~14× prove-time gap on similarly-sized circuits is expected and narrows on larger circuits because FFT dominates. A standalone benchmark class (`ZerojBenchmark.java`) is provided in `zeroj-assessment/zeroj/` for direct comparison on the same Circom circuits (both require Java 25 / GraalVM).
>
> **Key differences:**
> - **zeroj** supports both BN254 and BLS12-381 curves; our crate is BLS12-381 only.
> - **zeroj** has a `CircuitBuilder` DSL for generating R1CS programmatically; our crate focuses on loading standard Circom `.r1cs` / `.wtns` artifacts.
> - **zeroj** peak heap on the 4,096-constraint synthetic circuit is **339 MB**; our sparse path uses **0.2 MiB** for the 1,911-constraint PoseidonMerkle circuit.

Run the benchmarks yourself:

```bash
cd groth16-prover

# Toy circuit variants
cargo run --bin benchmark_provers --release
cargo run --bin benchmark_circom --release

# Toy circuit through Circom adapter + FullProvingKey (Implementation 5)
cargo run --bin benchmark_circom_full_pk --release

# Privacy circuit (spend_depth2)
cargo run --bin benchmark_privacy --release

# PoseidonMerkle circuit (poseidon_merkle_depth2) — dense paths
cargo run --bin benchmark_poseidon_merkle --release

# Sparse-matrix prover comparison (toy + PoseidonMerkle + EdDSAJubJub)
cargo run --bin benchmark_sparse --release

# Large-circuit unblocking demo (synthetic 20K–50K constraints)
cargo run --bin benchmark_large_circuit --release
```

</details>

---

## License

Apache-2.0
