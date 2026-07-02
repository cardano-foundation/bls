# Groth16 in Aiken using BLS12-381

## Goal

Implement a minimal Groth16 proof system on Cardano where:

- **Off-chain** tools handle the trusted setup and proof generation.
- **On-chain** Aiken validator performs the final pairing check.

We first solve a *concrete* R1CS circuit (taken from the reference notebook) end-to-end, and then sketch how to generalize to arbitrary circuits.

---

## Reference Circuit

From `Coh22HW10.ipynb`:

```
x1 * x2 == x5
x3 * x4 == x6
x5 * x6 == a
```

Concrete witness: `a = [1, 48, 2, 2, 3, 4, 4, 12]`.

R1CS matrices `L`, `R`, `O` (3 constraints × 8 variables) are defined in the notebook.

> **Note:** The reference notebook uses `bn128` for illustration. We will translate all curve operations to **BLS12-381**, which is natively supported by Cardano / Aiken builtins.

---

## Architecture

| Phase | Where | What |
|-------|-------|------|
| Trusted Setup | Off-chain (Rust + arkworks) | Generate SRS, evaluation points, and verification/proving keys. |
| Proving | Off-chain (Rust + arkworks) | Build witness, interpolate polynomials, compute `h(x)`, and assemble proof `(A, B, C)`. |
| Verification | On-chain (Aiken) | Recompute public-input commitment `V` and run the pairing check. |

---

## Why the Prover Must Stay Off-Chain

Aiken is designed for **on-chain validators** (the verifier side), not for heavy off-chain computation. A Groth16 prover requires operations that are impractical inside a Cardano script:

| Prover Step | What it requires | On-chain reality |
|-------------|----------------|------------------|
| **Polynomial interpolation** | FFTs over large vectors (O(n log n)) | No FFT primitives; naive O(n²) Lagrange exceeds execution units. |
| **Polynomial multiplication** `l(x)·r(x)` | FFT-based convolution or O(n²) coefficient multiplication | Too expensive for validator budgets. |
| **Quotient** `h(x) = (l·r - o) / T` | Polynomial long division or FFT | Not available in Aiken's standard library. |
| **Multi-scalar multiplication (MSM)** `∑ cᵢ · G₁` | Large MSM in `G₁` and `G₂` — the bulk of proving time | Aiken has scalar multiplication, but thousands of them in a single script exceed memory/CPU limits. |
| **Random toxic waste** `τ, α, β, δ` | Secure random sampling and secure deletion | Cannot generate or discard secrets securely inside an on-chain script. |

Even for a toy circuit with 3 constraints, the prover performs polynomial arithmetic of degree ~6 and MSMs of length ~6. While that might technically "fit" in a literal sense, Aiken lacks polynomial rings, FFTs, and MSM batching. Implementing all of that from scratch in a language optimized for tiny deterministic scripts is neither practical nor aligned with Cardano's execution model.

### What Aiken *is* perfect for

Aiken's `bls12_381` module (`G1Element`, `G2Element`, `ml_result`, pairing) is ideal for the **Groth16 verifier**:

```aiken
let lhs = bls12_381.pairing(a, b)
let rhs = bls12_381.pairing(alpha_g1, beta_g2)
  |> bls12_381.ml_result_mul( bls12_381.pairing(c, delta_g2) )
  |> bls12_381.ml_result_mul( bls12_381.pairing(v, gamma_g2) )

lhs == rhs
```

The verifier only needs:
- 3 pairings
- 2 `G1` scalar multiplications (for `V` and `C` if they aren't precomputed)
- A few point additions

That's exactly what Aiken / Plutus V2 is built for.

### Recommended architecture

| Component | Where it runs | Technology |
|-----------|---------------|------------|
| **Trusted setup / SRS generation** | Off-chain, air-gapped | Rust / arkworks / snarkjs |
| **Prover** | Off-chain, user's machine | Rust / arkworks (this crate) |
| **Verifier** | On-chain, Cardano validator | Aiken / Plutus |

If the goal is a Cardano-native ZK verifier, keep the prover in Rust and write the verifier in Aiken. That is the standard and sensible path.

---

## Sage Reference Implementation

Before building the production Rust tooling, we maintain a **pure-Sage prototype** at `../sage/groth16.sage` that mirrors the concrete example end-to-end. It serves as:

- A **readable reference** for the mathematics (polynomial interpolation, SRS construction, pairing check).
- A **sanity-check** for expected proof/verification key values that the Rust implementation must reproduce.
- A **comparison baseline** for BLS12-381 point and pairing arithmetic (the Sage script uses a pure-Sage curve definition, while arkworks uses its own optimized implementation).

### What `../sage/groth16.sage` contains

| Section | Description |
|---------|-------------|
| **1. R1CS** | Hard-codes the `L`, `R`, `O` matrices and witness `a = [1, 48, 2, 2, 3, 4, 4, 12]`, then verifies `(L·a) ∘ (R·a) = O·a`. |
| **2. Finite field & polynomials** | Builds `GF(q)` (BLS12-381 scalar field) and interpolates each column of `L/R/O` to obtain `u_i(x)`, `v_i(x)`, `w_i(x)`. Also constructs the target polynomial `T(x) = (x-0)(x-1)(x-2)`. |
| **3. Trusted Setup** | Draws random `tau, alpha, beta, gamma, delta`, computes the SRS (`G1·tau^i`, `G2·tau^i`, `G1·T(tau)·tau^i/delta`), and derives the CRS points `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2`, plus the `Psi_V_G1` (public) and `Psi_P_G1` (private) vectors. |
| **4. Prover** | Computes `l(x)`, `r(x)`, `o(x)`, the quotient `h(x) = (l·r - o)/T`, then evaluates everything in the exponent to produce the proof `(A, B, C)`. |
| **5. Verifier** | Recomputes the public-input commitment `V` and runs the Groth16 pairing equation using the pure-Sage `atePairing` from `bls13-381.sage`. |

### Dependencies

- **SageMath** (tested with Sage ≥ 9.x)
- `../sage/bls13-381.sage` — loaded at the top of `groth16.sage`; defines the BLS12-381 curve parameters, generators `g1`, `g2`, subgroup order `q`, and the `atePairing` function.

### Running it

```bash
cd ../sage
sage groth16.sage
```

Expected output:
```
R1CS relation verified.
Trusted setup complete.
l(x) = ...
r(x) = ...
o(x) = ...
h(x) = ...
Proof generated.
Pairing check PASSED.  The proof is valid.
```

### Relationship to the Rust / Aiken pipeline

| Concern | Sage script | Production stack |
|---------|-------------|------------------|
| Curve & pairings | Pure Sage (`bls13-381.sage`) | `ark-bls12-381` |
| Polynomials | Sage `PolynomialRing` | `ark-poly` |
| Field arithmetic | Sage `GF(q)` | `ark-ff` / `ark-bls12_381::Fr` |
| Serialization | None (in-memory only) | `ark-serialize` (compressed) |
| On-chain verification | N/A | Aiken BLS12-381 builtins |

> **Note:** The Sage script does not output serialized keys or proofs. Its purpose is to validate the algorithmic steps and produce known-good intermediate values (e.g., polynomial coefficients, SRS points) that can be cross-checked against the Rust implementation during development.

---

## Step 1: Concrete Example Circuit (Decomposed)

Step 1 is broken into **16 granular sub-steps**. Each sub-step has three tracks:

| Track | Purpose |
|-------|---------|
| **Rust / arkworks** | Production implementation |
| **Sage** | Mathematical sanity check and known-good intermediate values |
| **Julia (Groth.jl)** | Optional cross-check against an independent from-scratch implementation |

> **Cross-checking workflow:** For each sub-step, implement it in Rust first, then print the intermediate result (e.g. polynomial coefficients, curve point coordinates). Reproduce the *same* computation in Sage (and optionally Julia) and assert the outputs match. Only proceed to the next sub-step once the current one is verified.

---

### 1.1 R1CS: Matrices and Witness

**Goal:** Hard-code the circuit's `L`, `R`, `O` matrices and witness vector `a`, then verify `(L·a) ∘ (R·a) = O·a`.

| Track | Action |
|-------|--------|
| Rust | Define `[[u64; 8]; 3]` arrays (or `ark_ff::Fr` matrices) for `L`, `R`, `O`. Build witness `a` as a `Vec<Fr>`. Verify element-wise. |
| Sage | Already implemented in `../sage/groth16.sage` (Section 1). Prints `R1CS relation verified.` |
| Julia | Use `GrothProofs.create_r1cs_example_multiplication()` or build manually; verify with `is_satisfied()`. |

**Output to cross-check:** The three matrices and witness vector values.

---

### 1.2 Finite Field: BLS12-381 Scalar Field `Fr`

**Goal:** Ensure Rust, Sage, and Julia all agree on the scalar field modulus and basic arithmetic.

| Track | Action |
|-------|--------|
| Rust | Use `ark_bls12_381::Fr`. Verify that `Fr::MODULUS` equals the BLS12-381 subgroup order `q`. |
| Sage | `Fq = GF(q)` from `bls13-381.sage`. Print `q`. |
| Julia | `GrothCurves.BN254_ORDER_R` is BN254's `r`, so skip exact match; instead verify that a few sample operations (add, mul, inv) yield the same results when ported to the same modulus. |

**Output to cross-check:** Field modulus `q`, and sample operations `a + b`, `a * b`, `a^-1` for random `a, b`.

---

### 1.3 Polynomial Interpolation: `u_i(x)`, `v_i(x)`, `w_i(x)`

**Goal:** Interpolate each column of `L`, `R`, `O` into polynomials over `Fr`.

| Track | Action |
|-------|--------|
| Rust | Use `ark_poly` (e.g. `DensePolynomial` or interpolation via Vandermonde / Lagrange). For 3 constraints, a manual Lagrange interpolation is fine. |
| Sage | `PR.lagrange_polynomial(zip(xs, col))` in `groth16.sage` (Section 2). |
| Julia | `r1cs_to_qap()` in `GrothProofs.QAP` handles FFT-based interpolation. For 3 points, dense interpolation also works. |

**Output to cross-check:** For each `i = 0..7`, the coefficient vectors of `u_i(x)`, `v_i(x)`, `w_i(x)`.

---

### 1.4 Target Polynomial `T(x)`

**Goal:** Construct `T(x) = (x - 0)(x - 1)(x - 2)`.

| Track | Action |
|-------|--------|
| Rust | Multiply linear factors in `ark_poly`. |
| Sage | `T = prod(x - xi for xi in xs)` in `groth16.sage`. |
| Julia | `qap.t` in Groth.jl (though their default uses roots of unity; for 3 points we construct manually). |

**Output to cross-check:** Coefficients of `T(x)`: `[-0, 2, -3, 1]` or equivalent.

---

### 1.5 QAP Verification: Evaluate `u_i`, `v_i`, `w_i` at Constraint Points

**Goal:** Sanity-check that the interpolated polynomials actually reproduce the original R1CS columns at `x = 0, 1, 2`.

| Track | Action |
|-------|--------|
| Rust | Evaluate each `u_i(x)` at `x = 0, 1, 2` using `ark_poly` evaluation; assert equals `L[:, i]`. Repeat for `v_i`/`R` and `w_i`/`O`. |
| Sage | Implicit in the interpolation; add explicit assertions: `all(us[i](xs[j]) == L[j][i] for ...)`. |
| Julia | Similar assertions in `GrothProofs.QAP` tests or manual checks. |

**Output to cross-check:** A boolean `true` / assertion pass for all 24 evaluations.

---

### 1.6 Trusted Setup: Toxic Waste Generation

**Goal:** Sample random `tau, alpha, beta, gamma, delta` in `Fr`.

| Track | Action |
|-------|--------|
| Rust | Use `ark_ff::UniformRand` with a deterministic RNG (e.g. `test_rng()` from `ark_std`) so values are reproducible across runs. |
| Sage | `random.randint(1, q-1)` in `groth16.sage`. Print and hard-code the same values for cross-checking. |
| Julia | `_rand_field_nonzero()` in `GrothProofs.Groth16`. |

**Output to cross-check:** The five scalar values `tau, alpha, beta, gamma, delta`.

---

### 1.7 Trusted Setup: SRS Generation

**Goal:** Compute `G1·tau^i`, `G2·tau^i`, and `G1·T(tau)·tau^i/delta`.

| Track | Action |
|-------|--------|
| Rust | Use `ark_ec::Group::mul` or `mul_bigint` on `ark_bls12_381::G1Projective` / `G2Projective`. |
| Sage | `SRS1 = [ZZ(tau^i) * g1 ...]` in `groth16.sage` (Section 3). |
| Julia | Query generation in `setup_full()` (though their structure uses `A_query_g1`, `B_query_g2`, etc.). |

**Output to cross-check:** Coordinates (affine or projective) of `SRS1[0..2]`, `SRS2[0..2]`, `SRS3[0..1]`.

---

### 1.8 Trusted Setup: CRS Fixed Points

**Goal:** Compute `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2`.

| Track | Action |
|-------|--------|
| Rust | Scalar multiplication on generators. |
| Sage | `alphaG1 = ZZ(alpha) * g1`, etc. in `groth16.sage`. |
| Julia | `scalar_mul(g1, α)`, `g2_subgroup_scalar_mul(g2, β)`, etc. in `setup_full()`. |

**Output to cross-check:** Affine coordinates of the four fixed CRS points.

---

### 1.9 Trusted Setup: `Psi_V_G1` and `Psi_P_G1`

**Goal:** Compute the per-variable CRS points:
- `Psi_V_G1[i] = (beta·u_i(tau) + alpha·v_i(tau) + w_i(tau)) / gamma * G1` for public inputs
- `Psi_P_G1[i] = (beta·u_i(tau) + alpha·v_i(tau) + w_i(tau)) / delta * G1` for private inputs

| Track | Action |
|-------|--------|
| Rust | Scalar mul + point add on G1, then divide scalar by `gamma` or `delta`. |
| Sage | Loop in `groth16.sage` (Section 3). |
| Julia | `IC` (public) and `L_query_g1` (private) in `setup_full()`. |

**Output to cross-check:** Coordinates of `Psi_V_G1[0..1]` and `Psi_P_G1[0..5]`.

---

### 1.10 Prover: Witness Polynomials `l(x)`, `r(x)`, `o(x)`

**Goal:** Compute `l(x) = Σ a_i·u_i(x)`, `r(x) = Σ a_i·v_i(x)`, `o(x) = Σ a_i·w_i(x)`.

| Track | Action |
|-------|--------|
| Rust | Linear combination of `DensePolynomial`s with `Fr` coefficients. |
| Sage | `l = sum(a_Fq[i] * us[i] for i in ...)` in `groth16.sage` (Section 4). |
| Julia | `combined_qap_polynomials()` in `GrothProofs.QAP`. |

**Output to cross-check:** Coefficient vectors of `l(x)`, `r(x)`, `o(x)`.

---

### 1.11 Prover: Quotient Polynomial `h(x)`

**Goal:** Compute `h(x) = (l(x)·r(x) - o(x)) / T(x)` and assert exact division.

| Track | Action |
|-------|--------|
| Rust | Multiply `l` and `r` in `ark_poly`, subtract `o`, then divide by `T` (dense division for now; coset FFT comes in Step 2). |
| Sage | `h = (l*r - o) // T` in `groth16.sage` (Section 4). |
| Julia | `compute_h_polynomial_dense()` or `compute_h_polynomial_coset()` in `GrothProofs.QAP`. |

**Output to cross-check:** Coefficients of `h(x)`, plus confirmation that remainder is zero.

---

### 1.12 Prover: Proof Element `A`

**Goal:** Compute `A = l(tau)·G1 + alpha·G1`.

| Track | Action |
|-------|--------|
| Rust | Evaluate `l` at `tau` (Horner or direct `ark_poly` evaluation), scalar-mul `G1`, add `alphaG1`. |
| Sage | `l_tau_G1 = eval_in_exponent(l.coeffs, SRS1)` then `A = l_tau_G1 + alphaG1`. |
| Julia | `A1_g1 = pk.alpha_g1 + A_acc_g1` then `A = A1_g1 + scalar_mul(pk.delta_g1, r)` (with randomizer `r`). For our first test, set `r = 0`. |

**Output to cross-check:** Affine coordinates of `A`.

---

### 1.13 Prover: Proof Element `B`

**Goal:** Compute `B = r(tau)·G2 + beta·G2`.

| Track | Action |
|-------|--------|
| Rust | Evaluate `r` at `tau`, scalar-mul `G2`, add `betaG2`. |
| Sage | `r_tau_G2 = eval_in_exponent(r.coeffs, SRS2)` then `B = r_tau_G2 + betaG2`. |
| Julia | `B = pk.beta_g2 + B_acc_g2 + g2_subgroup_scalar_mul(pk.delta_g2, s)` (set `s = 0` for first test). |

**Output to cross-check:** Affine coordinates of `B`.

---

### 1.14 Prover: Proof Element `C`

**Goal:** Compute `C = Σ_{i≥2} a_i·Psi_P_G1[i-2] + h(tau)·T(tau)/delta·G1`.

| Track | Action |
|-------|--------|
| Rust | MSM over `Psi_P_G1` with private witness scalars, plus `eval_in_exponent` for `h` using `SRS3`. |
| Sage | `Psi_with_a + h_tau_G1` in `groth16.sage` (Section 4). |
| Julia | `HL + scalar_mul(B1_g1, r) + scalar_mul(A1_g1, s) + rs_delta` (set `r = s = 0` for first test). |

**Output to cross-check:** Affine coordinates of `C`.

---

### 1.15 Verifier: Public Input Commitment `V`

**Goal:** Recompute `V = a_0·Psi_V_G1[0] + a_1·Psi_V_G1[1]`.

| Track | Action |
|-------|--------|
| Rust | MSM over `Psi_V_G1` with public inputs `[1, 48]`. |
| Sage | `V = sum(ZZ(a_vec[i]) * Psi_V_G1[i] for i in 0..1)` in `groth16.sage` (Section 5). |
| Julia | `vk_x = vk.IC[1] + Σ input[i] * vk.IC[i+1]` in `verify_full()`. |

**Output to cross-check:** Affine coordinates of `V`.

---

### 1.16 Verifier: Pairing Check

**Goal:** Verify `e(A, B) == e(alpha·G1, beta·G2) · e(V, gamma·G2) · e(C, delta·G2)`.

| Track | Action |
|-------|--------|
| Rust | Use `ark_ec::pairing::Pairing` to compute the four pairings and compare `GT` elements. |
| Sage | `atePairing(A, B) == atePairing(alphaG1, betaG2) * ...` in `groth16.sage` (Section 5). |
| Julia | `pairing(engine, proof.A, proof.B) == pairing(engine, vk.alpha_g1, vk.beta_g2) * ...` in `verify_full()`. |

**Output to cross-check:** Boolean `true` / assertion pass.

---

### Step 1 End-to-End Deliverable

Once all 16 sub-steps are individually verified and cross-checked, the final deliverables are:

1. **Rust crate** (`groth16-prover/`) that can:
   - Load the hard-coded circuit.
   - Run trusted setup (deterministic for tests).
   - Generate a proof `(A, B, C)`.
   - Verify the proof locally using `ark-bls12-381` pairings.
2. **Sage script** (`../sage/groth16.sage`) updated with explicit intermediate-value printouts for every sub-step.
3. **Julia notebook** (optional, `../julia/groth16.jl`) reproducing the same concrete example with Groth.jl for independent validation.
4. **Aiken validator** (`validators/groth16.ak`) hard-coded with the verification key and pairing check for the concrete circuit.

---

## Step 2: Sketch Plan for General Circuits

Once the concrete example is fully working, the next phase is to make the system generic.

### 2.1 Circuit Compiler (Off-chain)

- Accept an arbitrary arithmetic circuit (e.g., from Circom, Arkworks, or a custom DSL).
- Flatten to **R1CS** (`L`, `R`, `O` matrices).
- Generate a full **witness vector** from public + private inputs.

### 2.2 General Trusted Setup (Off-chain)

- Given `m` constraints and `n` variables:
  - SRS sizes scale with degree `m`.
  - `T(x) = ∏_{i=0}^{m-1} (x - i)`.
- Produce a structured reference string for both G1 and G2.
- Output a **verification key** and **proving key** that can be serialized and reused.

### 2.3 General Prover (Off-chain)

- Automate:
  1. Witness generation.
  2. Polynomial interpolation (`u_i`, `v_i`, `w_i`).
  3. Construction of `l(x)`, `r(x)`, `o(x)`.
  4. Polynomial division to obtain `h(x)`.
  5. Evaluation at `tau` using the SRS to build `A`, `B`, `C`.
- Support dynamic-length public / private input splits.

### 2.4 General Verifier in Aiken

- Make the validator **parameterized** by a verification key (stored as constants or passed as configuration).
- Accept:
  - A proof `(A, B, C)`.
  - A list of public inputs of arbitrary length.
- Compute `V` as an **on-chain multi-scalar multiplication (MSM)** over the public inputs and `Psi_V_G1` points.
- Run the same pairing equation:
  ```
  e(B, A) == e(beta*G2, alpha*G1) * e(delta*G2, C) * e(gamma*G2, V)
  ```
- Because Aiken BLS12-381 builtins support MSM and pairings, the check remains constant-time in the number of pairings regardless of public-input size.

### 2.5 Tooling & Integration

- Build a CLI / Rust crate that:
  1. Reads an R1CS file + witness.
  2. Runs the trusted setup (or loads a saved SRS).
  3. Generates a BLS12-381 proof.
  4. Serializes the proof and public inputs into a Cardano transaction datum.
- Provide Aiken helper functions for G1/G2 point arithmetic and MSM to keep the validator code clean.

---

## Milestones / TODO

### Step 1: Concrete Circuit (Granular)

Each sub-step must be implemented in Rust, verified in Sage, and optionally cross-checked in Julia before marking complete.

**Setup & R1CS**
- [ ] **1.1** R1CS matrices `L`, `R`, `O` and witness `a = [1, 48, 2, 2, 3, 4, 4, 12]`; verify `(L·a) ∘ (R·a) = O·a`.
- [x] **1.2** BLS12-381 scalar field `Fr`: confirm modulus and sample arithmetic across Rust / Sage / Julia.
- [x] **1.3** Polynomial interpolation: compute `u_i(x)`, `v_i(x)`, `w_i(x)` for all 8 variables.
- [ ] **1.4** Target polynomial `T(x) = (x-0)(x-1)(x-2)`.
- [ ] **1.5** QAP verification: assert `u_i(j) = L[j][i]`, `v_i(j) = R[j][i]`, `w_i(j) = O[j][i]` for `j = 0,1,2`.

**Trusted Setup**
- [ ] **1.6** Toxic waste: sample and print `tau, alpha, beta, gamma, delta` (deterministic for tests).
- [ ] **1.7** SRS: `G1·tau^i`, `G2·tau^i`, `G1·T(tau)·tau^i/delta`.
- [ ] **1.8** CRS fixed points: `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2`.
- [ ] **1.9** Per-variable CRS: `Psi_V_G1` (public) and `Psi_P_G1` (private).

**Proving**
- [ ] **1.10** Witness polynomials `l(x)`, `r(x)`, `o(x)`.
- [ ] **1.11** Quotient polynomial `h(x) = (l·r - o) / T` with zero-remainder assertion.
- [ ] **1.12** Proof element `A = l(tau)·G1 + alpha·G1`.
- [ ] **1.13** Proof element `B = r(tau)·G2 + beta·G2`.
- [ ] **1.14** Proof element `C = Σ a_i·Psi_P_G1 + h(tau)·T(tau)/delta·G1`.

**Verification**
- [ ] **1.15** Public-input commitment `V = a_0·Psi_V_G1[0] + a_1·Psi_V_G1[1]`.
- [ ] **1.16** Pairing check: `e(A,B) == e(alpha·G1, beta·G2) · e(V, gamma·G2) · e(C, delta·G2)`.

**Integration**
- [ ] **1.17** Aiken on-chain validator: hard-code verification key, recompute `V`, run pairing check via BLS12-381 builtins.
- [ ] **1.18** End-to-end: Rust generates proof + serialized VK, Aiken validator accepts it in `aiken test`.

### Step 2: General Circuits

- [ ] **2.1** Circuit compiler: accept arbitrary R1CS matrices and witnesses using `ark-relations` / `ark-r1cs-std`.
- [ ] **2.2** General trusted setup: SRS scaling with constraint count, reusable proving/verification keys.
- [ ] **2.3** General prover: coset FFT quotient, dynamic public/private input split.
- [ ] **2.4** General Aiken verifier: parameterized VK, dynamic-length public inputs, on-chain MSM.
- [ ] **2.5** CLI tooling: Rust crate going from R1CS + witness → proof → Cardano-ready transaction datum.

---

## Dependencies (Tentative)

- **Off-chain**: Rust with [`arkworks`](https://arkworks.rs/) ecosystem (`ark-bls12-381`, `ark-groth16`, `ark-poly`, `ark-ec`, `ark-ff`) for finite-field arithmetic, polynomial operations, elliptic-curve pairings, and serialization. Python may be used for prototyping with `py_ecc`, but the production tooling will be Rust-based.
- **On-chain**: [Aiken](https://aiken-lang.org) with built-in BLS12-381 primitives.

### Why arkworks?

`arkworks` provides a mature, modular Rust framework for zkSNARKs. For this project it gives us:

- **Native BLS12-381 support** via `ark-bls12-381`, matching Cardano's curve.
- **R1CS integration**: `ark-snark` and `ark-relations` traits for circuit definitions and witness generation.
- **Polynomial arithmetic**: `ark-poly` supports interpolation, evaluation, and division over finite fields—exactly what we need for `u_i(x)`, `v_i(x)`, `w_i(x)` and the quotient `h(x)`.
- **Curve operations & pairings**: `ark-ec` and `ark-pairing` provide type-safe G1/G2 arithmetic and Miller-loop / final-exponentiation APIs.
- **Serialization**: `ark-serialize` offers canonical compressed formats we can standardize on for passing points into Aiken datums/redeemers.

---

## Notes

- Keep the first implementation minimal: hard-code the concrete circuit, witness, and verification key in Aiken to prove the pairing logic works.
- Only after the concrete circuit verifies on-chain should we abstract to generic matrices and inputs.
- BLS12-381 builtins in Aiken operate on compressed / uncompressed points; make sure the serialization format between off-chain prover and on-chain verifier is agreed upon.
