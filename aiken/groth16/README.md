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

## Step 1: Concrete Example Circuit

### 1.1 Off-chain Trusted Setup (using arkworks)

We will implement this in Rust with `arkworks` crates (`ark-bls12-381`, `ark-poly`, `ark-ff`, `ark-ec`).

1. **Select toxic waste** over the BLS12-381 scalar field (`ark_bls12_381::Fr`):
   `tau, alpha, beta, gamma, delta`.
2. **Interpolate** each column of `L`, `R`, `O` to obtain polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` over `Fr` using `ark-poly` interpolation APIs.
3. **Target polynomial**: `T(x) = (x - 0)(x - 1)(x - 2)` via `ark-poly`.
4. **Generate SRS**:
   - `SRS1 = [G1 * tau^i]` for `i = 0..2`
   - `SRS2 = [G2 * tau^i]` for `i = 0..2`
   - `SRS3 = [G1 * T(tau) * tau^i / delta]` for `i = 0..1`
   - Use `ark-ec` scalar multiplication on `ark_bls12_381::G1Projective` / `G2Projective`.
5. **Compute CRS points**:
   - `alpha*G1`, `beta*G2`, `gamma*G2`, `delta*G2`
   - `Psi_V_G1` (first 2 variables, public, divided by `gamma`)
   - `Psi_P_G1` (remaining variables, private, divided by `delta`)
6. **Export keys** (using `ark-serialize` in canonical compressed format):
   - *Verification Key* → passed to the on-chain validator.
   - *Proving Key* → kept off-chain for proof generation.

### 1.2 Off-chain Prover (using arkworks)

1. **Witness**: `a = [1, 48, 2, 2, 3, 4, 4, 12]` mapped into `ark_bls12_381::Fr` scalars.
2. **Polynomials** (using `ark-poly`):
   - `l(x) = Σ a_i * u_i(x)`
   - `r(x) = Σ a_i * v_i(x)`
   - `o(x) = Σ a_i * w_i(x)`
3. **Quotient polynomial**:
   - `h(x) = (l(x) * r(x) - o(x)) / T(x)`
   - Assert remainder is zero.
4. **Evaluate at `tau` using SRS** (with `ark-ec` MSM / scalar mul):
   - `A = l(tau)*G1 + alpha*G1`
   - `B = r(tau)*G2 + beta*G2`
   - `C = Σ_{i≥2} a_i * Psi_P_G1[i-2] + h(tau)*T(tau)/delta * G1`
5. **Output**: Proof `(A, B, C)` and public inputs `[1, 48]` serialized via `ark-serialize`.

### 1.3 On-chain Verifier (Aiken)

1. **Receive** via redeemer / datum:
   - Proof: `A` (G1), `B` (G2), `C` (G1)
   - Public inputs: `a_0 = 1`, `a_1 = 48`
2. **Recompute `V`** (public-input commitment in G1):
   - `V = a_0 * Psi_V_G1[0] + a_1 * Psi_V_G1[1]`
   - Done via Aiken BLS12-381 scalar multiplication and point addition builtins.
3. **Pairing check**:
   ```
   e(B, A) == e(beta*G2, alpha*G1) * e(delta*G2, C) * e(gamma*G2, V)
   ```
   - Use Aiken’s `bls12_381_final_verify` and related builtins.
4. **Outcome**: If the pairing equation holds, the validator succeeds.

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

- [ ] **Step 1a**: Implement off-chain trusted setup & prover for the concrete example in Rust with `arkworks` (or prototype in Python with `py_ecc`).
- [ ] **Step 1b**: Write Aiken validator that verifies the concrete proof using on-chain pairings.
- [ ] **Step 1c**: End-to-end test: generate proof off-chain, feed it into `aiken test` or a local integration test, and confirm it passes.
- [ ] **Step 2a**: Generalize the off-chain prover to accept arbitrary R1CS matrices and witnesses using `ark-relations` / `ark-r1cs-std`.
- [ ] **Step 2b**: Generalize the Aiken verifier to accept dynamic-length public inputs and a parameterized verification key.
- [ ] **Step 2c**: Add CLI tooling (Rust crate using `arkworks`) to go from R1CS + witness → proof → Cardano-ready transaction.

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
