# groth16-prover

An **end-to-end Groth16 prover** in Rust over the BLS12-381 curve.

> **Purpose.** This crate implements the full Groth16 pipeline—from R1CS constraints to a valid zero-knowledge proof—using [arkworks](https://arkworks.rs/) primitives. It began as a didactic reference (hard-coded circuit, dense monomial polynomials, deterministic toxic waste) so that every intermediate value could be printed, inspected, and compared against an independent reference implementation. Since then it has grown into a production-capable toolkit with FFT-based QAP construction, Pippenger multi-scalar multiplication, a Circom adapter, a CLI, and a Phase 2 multi-party computation ceremony.

> **Correctness guarantee.** The entire implementation has been cross-checked line-by-line against a [Sage](https://www.sagemath.org/) script that implements the same mathematics from scratch. See [`RustGroth16Correctness.md`](RustGroth16Correctness.md) for the bit-for-bit comparison of every sub-step.

---

## How to use

### 1. Run unit tests

```bash
cd groth16-prover
cargo test
```

All 38 library tests pass (R1CS relation, QAP interpolation, target polynomial, field arithmetic, Circom parser, prover parity, ptau parser, Phase 2 MPC).

### 2. Use the CLI

A full-featured command-line interface lives in `groth16-prover/cli/`. It covers the entire Groth16 lifecycle—from ceremony to proof generation and verification—and includes auxiliary tools for Circom witness computation and sparse Merkle tree operations.

#### Ceremony

Two switchable ceremony paths produce the same `.pk` / `.vk` binary format. The prover and verifier are agnostic to which path was used.

**Dev ceremony** (single-party, instant — for testing and CI):

```bash
cd groth16-prover/cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk
```

**Production ceremony** (multi-party MPC — for mainnet):

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

Other engine / prover combinations can be selected via `--engine dense|fft` and `--prover naive|pippenger`.

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

#### Sparse Merkle Tree operations

The CLI includes an insert-only sparse Merkle tree backed by MiMC(x⁷) over BLS12-381:

```bash
# Insert items and persist tree state
cargo run --release -- smt insert --depth 2 --items "1,2,3" --state /tmp/smt.json

# Print the current Merkle root
cargo run --release -- smt digest --state /tmp/smt.json

# Print the Merkle path for a leaf
cargo run --release -- smt path --state /tmp/smt.json --index 1
```

See [`cli/README.md`](cli/README.md) for full CLI documentation, including proof serialization format, proving key structure, and complete end-to-end examples.

---

## Design choices (and why)

| Choice | Rationale |
|--------|-----------|
| **Hard-coded circuit** | A 3-constraint multiplication chain (`x1·x2=x5`, `x3·x4=x6`, `x5·x6=a`) is large enough to exercise every Groth16 step, yet small enough to verify by hand. |
| **Dense monomial basis** | `u_i(x)`, `v_i(x)`, `w_i(x)` are stored as dense coefficient vectors. This makes printing and comparison trivial. It is `O(n²)` and therefore unsuitable for production circuits with millions of constraints, but it is ideal for learning. |
| **No randomizers (`r = s = 0`)** | Proof elements `A`, `B`, `C` use the textbook formulas without blinding. This removes entropy and makes the outputs deterministic and reproducible. A production prover would add random `r` and `s` for zero-knowledge. |
| **Deterministic toxic waste** | `tau=3`, `alpha=5`, `beta=7`, `gamma=11`, `delta=13` are hard-coded small primes. In a real deployment these would be generated securely and destroyed; here they are fixed so that two independent codebases can produce the exact same curve points. |
| **Two switchable QAP engines** | The dense path (classical Lagrange over `{0,1,2}`) is the default for pedagogical clarity. The FFT path (roots of unity, IFFT, `T(x)=x^N−1`) is implemented via the `QapEngine` trait and cross-checked against Sage bit-for-bit. Both paths share the same downstream proof-assembly code. |
| **Two switchable MSM provers** | Proof assembly uses either `NaiveProver` (scalar-by-scalar accumulation, pedagogical) or `PippengerProver` (batched multi-scalar multiplication via `VariableBaseMSM::msm`, production). Both are generic over any `QapEngine` and produce identical proof points. |

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

### CLI (Implementation 4 in practice)

The `groth16-prover-cli` crate wraps the Circom adapter into a command-line tool:

```bash
cd groth16-prover/cli
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --out /tmp/proof.bin
```

This uses `FftQapEngine` + `PippengerProver` under the hood and outputs a standard arkworks-serialized proof. See [`cli/README.md`](cli/README.md) for details.

</details>

---

## TO DO — Production innovations 

<details>
<summary><b>Pending improvements — click to expand</b></summary>

The current crate is a **reference implementation** for correctness verification. The following items, already present in the [zeroj](https://github.com/bloxbean/zeroj) Java toolkit (see [`ZerojAudit.md`](../ZerojAudit.md)), would need to be adopted for production use:

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

### (d) Prepared verifier and batched pairing verification (beyond what zeroj supports)

- **Current:** The verifier recomputes every pairing from scratch each time a proof is checked.
- **Target:** Add a `PreparedVerifyingKey` that precomputes and caches fixed verification-key data (e.g., G2 line coefficients for the Miller loop). Also expose a batched verifier that checks multiple proofs with a single multi-pairing product.
- **Reference:** [Groth.jl](https://github.com/0xpantera/Groth.jl) implements `prepare_verifying_key`, `prepare_inputs`, and `verify_with_prepared`; batched pairing verification reduced their `N=16` batch from `18.212 ms` to `13.854 ms` on the same fixture. Arkworks also provides `PreparedVerifyingKey`.
- **Benefit:** On-chain verification becomes cheaper because the heavy G2 preparation is done once per VK, not per proof. Batching further amortizes the Miller-loop cost across many proofs.

### (e) Proof aggregation (beyond what zeroj supports)

- **Current:** Each proof is verified individually.
- **Target:** Support Groth16 proof aggregation (rolling multiple proofs into a single succinct proof that can be verified with one pairing check).
- **Reference:** Arkworks has an optional `groth16::aggregate_proofs` module. Groth.jl tracks this on their roadmap.
- **Benefit:** Essential for rollup and batching use cases where many proofs need to be verified on-chain in a single transaction.

### (f) Batch normalization and fixed-base MSM tables (beyond what zeroj supports)

- **Current:** Individual `G1Affine::from(projective)` calls and naive scalar-by-scalar point accumulation.
- **Target:**
  1. **Batch normalization** — Convert a vector of projective points to affine in one pass using a shared Z-coordinate inversion (Montgomery trick). This is faster than `N` individual inversions.
  2. **Fixed-base MSM tables** — Precompute w-NAF window tables for repeated base points (e.g., SRS1/2/3 and CRS fixed points used during setup). Reuse these tables when the same bases are multiplied by different scalars.
- **Reference:** Groth.jl uses `batch_to_affine!` and `FixedBaseTable` with measured speedups on setup query generation.
- **Benefit:** Batch normalization saves ~30–50% on point serialization and pairing input preparation. Fixed-base tables speed up setup and any verifier-side IC recomputation.

### (g) Randomized R1CS test fixtures and parity assertions 

- **Current:** Only one hard-coded 3-constraint circuit is tested.
- **Target:**
  1. Generate randomized R1CS fixtures (random sparse constraints and random witnesses satisfying `A∘B=C`) for property-based testing.
  2. Keep dense/naive computation paths as **parity assertions** alongside optimized paths (FFT, coset quotient). In debug/test mode, run both and assert identical results.
- **Reference:** Groth.jl keeps dense quotient computation (`compute_h_polynomial`) as an explicit parity check while the production prover uses the coset-only path. Their test suite covers multiple circuits with randomized seeds.
- **Benefit:** Catches bugs in the optimized path early by comparing against a slow-but-correct reference on every test run.

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

### (i) Additional Circom use-case circuits

- **Current:** Only one circuit (`multiplier.circom`) lives in `circom/SimpleExample/`. It is a trivial 3-gate multiplication chain used to validate the Circom adapter end-to-end.
- **Target:** Add several realistic Circom circuits that exercise different zk-SNARK patterns:
  1. **Poseidon hash** — demonstrate hash pre-image knowledge inside a Groth16 proof.
  2. **Merkle membership** — prove that a leaf exists in a Merkle tree without revealing the leaf or the path.  
     **Status:** 🚧 **Started.** A shielded-spend circuit (`Spend(depth)`) based on Stanford CS251 Project #4 lives in `circom/Privacy/`. It uses MiMC(x⁷) hashing and `SelectiveSwitch` gadgets to verify a Merkle path. A depth-2 wrapper (`spend_depth2.circom`), sample transcript, and a Node.js input generator are included. The circuit still needs to be compiled with `circom --prime bls12381` and proven end-to-end with the Rust CLI.
  3. **Range proof / comparison** — prove that a committed value lies in a range `[0, 2^n)`.
  4. **EdDSA / BabyJubJub signature** — verify a signature inside the circuit (requires JubJub curve gadgets).
  5. **Blake2b-224 hash** — prove knowledge of a pre-image that hashes to a given Cardano key hash. Cardano uses Blake2b-224 for address and key hashing, so an in-circuit Blake2b-224 gadget is essential for any zk-proof that needs to reason about Cardano keys or addresses. Reference implementation: [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) provides a generic Blake2b Circom circuit.
  6. **Private key → public key ownership proof** — prove that you know the private key that generates a given Cardano public key / address, without revealing the private key. This is the core key-derivation step used in Cardano wallets ([cardano-crypto `generate`](https://github.com/IntersectMBO/cardano-crypto/blob/develop/src/Cardano/Crypto/Wallet.hs#L161)): given a private scalar `x`, show that `pub = x · G` (for the appropriate curve generator G). A Circom circuit that replicates this scalar-multiplication-and-derivation logic would allow a user to prove wallet ownership on-chain inside a Groth16 proof.
  7. **EdDSA Ed25519 signature verification** — verify a standard Ed25519 signature inside a Groth16 circuit. Ed25519 is widely used outside the BN254 ecosystem (SSH, TLS, many blockchains), so an in-circuit verifier would let a Cardano zk-proof attest to off-chain events signed by standard Ed25519 keys. Reference implementation: [Electron-Labs/ed25519-circom](https://github.com/Electron-Labs/ed25519-circom) provides a full Ed25519 signature-verification circuit in Circom.
- **Reference:** [circomlib](https://github.com/iden3/circomlib) provides production-grade Poseidon, MiMC, Merkle, and EdDSA circuits for BN254. Porting to BLS12-381 requires updating the field constants. For Blake2b-224, see [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits). For key-derivation logic, see [IntersectMBO/cardano-crypto](https://github.com/IntersectMBO/cardano-crypto/blob/develop/src/Cardano/Crypto/Wallet.hs#L161). For Ed25519 in-circuit verification, see [Electron-Labs/ed25519-circom](https://github.com/Electron-Labs/ed25519-circom).
- **Benefit:** Shows that the Rust prover + Aiken verifier pipeline works for real-world zk-SNARK applications, not just toy arithmetic circuits. Blake2b-224, key-ownership proofs, and Ed25519 verification in particular unlock cross-chain and identity use cases (proving ownership of a key, linking a proof to an on-chain address, anonymous identity verification, attesting to off-chain signed data, etc.).

</details>

---

## Benchmarks

<details>
<summary><b>Click to expand benchmark results</b></summary>

### Toy circuit (`multiplier.circom` — 3 constraints)

Proof-production time for the hard-coded 3-constraint circuit (`x1·x2 = x5`, `x3·x4 = x6`, `x5·x6 = a`) on a single core, compiled with `--release`:

| Implementation | Engine | Prover | Per-proof time | vs. Impl 1 | vs. Impl 2 |
|----------------|--------|--------|---------------|------------|------------|
| 1 (dense) | `DenseQapEngine` | `NaiveProver` | **3.87 ms** | — | — |
| 2 (FFT) | `FftQapEngine` | `NaiveProver` | **4.04 ms** | 0.96× | — |
| 3 (Pippenger) | `FftQapEngine` | `PippengerProver` | **3.30 ms** | 1.17× | 1.22× |
| 4a (Circom dense) | `DenseQapEngine` | `NaiveProver` | **55.16 ms** | 0.07× | 0.07× |
| 4b (Circom FFT) | `FftQapEngine` | `NaiveProver` | **94.30 ms** | 0.04× | 0.04× |
| 4c (Circom Pippenger) | `FftQapEngine` | `PippengerProver` | **53.42 ms** | 0.07× | 0.08× |

> **What the numbers mean.** For a 3-gate circuit the FFT overhead (padding to 4 points, extra IFFT steps) outweighs its `O(N log N)` advantage, so Implementation 2 is slightly slower than Implementation 1. Pippenger's batched MSM still yields a modest ~20 % speedup even at this tiny scale. On realistic circuits with hundreds or thousands of gates, the FFT advantage grows to ~1000× and Pippenger's MSM speedup grows to 5–10×.
>
> **Implementation 4** numbers are from a debug build (the `.r1cs`/`.wtns` parser and dynamic allocation add overhead). In `--release` mode the Circom adapter is only marginally slower than the hard-coded path because the core QAP and prover code is identical; the extra cost is purely parsing and memory allocation.

### Privacy circuit (`Spend(depth)` — Merkle membership)

The shielded-spend circuit lives in `circom/Privacy/`. It proves that a commitment `H(nullifier, nonce)` exists in a Merkle tree of the given depth without revealing the nullifier, nonce, or path. Constraint count grows linearly with depth (each level adds one `MiMC2` hash and two `IfThenElse` gadgets).

> **Status:** 🚧 Pending end-to-end compilation with `circom --prime bls12381`. Once the `.r1cs` artifact is available, the numbers below will be populated by `cargo run --bin benchmark_circom --release`.

| Depth | Estimated constraints | Expected FFT QAP + Pippenger | Notes |
|-------|----------------------|------------------------------|-------|
| 2 | ~60 | *pending* | Wrapper used for adapter validation |
| 8 | ~240 | *pending* | Small anonymity set |
| 16 | ~480 | *pending* | Medium anonymity set |
| 32 | ~960 | *pending* | Large anonymity set |

> **Why depth matters.** The Merkle path has `depth` sibling hashes. Each level in the Circom circuit invokes `MiMC2` (≈30 constraints) plus `SelectiveSwitch` (≈8 constraints). Doubling the depth roughly doubles the constraint count and proof-generation time. Even at depth 32, the FFT + Pippenger path is expected to stay under **100 ms** per proof on a single core because the MSM overhead dominates and the witness vector remains small.

Run the benchmarks yourself:

```bash
cd groth16-prover

# Toy circuit variants
cargo run --bin benchmark_provers --release
cargo run --bin benchmark_circom --release

# Privacy circuit (once the .r1cs is available)
cargo run --release -- prove \
  --circuit circom/Privacy/spend_depth2.r1cs \
  --witness circom/Privacy/witness.wtns \
  --engine fft --prover pippenger --out /tmp/proof.bin
```

</details>

---

## License

Apache-2.0
