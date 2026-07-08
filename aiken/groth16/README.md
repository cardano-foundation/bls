# Groth16 in Aiken using BLS12-381

## Goal

Implement a minimal Groth16 proof system on Cardano where:

- **Off-chain** tools handle the trusted setup and proof generation.
- **On-chain** Aiken validator performs the final pairing check.

We first solved a *concrete* 3-constraint R1CS circuit end-to-end, and now sketch how to generalize to arbitrary circuits.

---

## Reference Circuit

```
x1 * x2 == x5
x3 * x4 == x6
x5 * x6 == a
```

Concrete witness: `a = [1, 48, 2, 2, 3, 4, 4, 12]`.

R1CS matrices `L`, `R`, `O` (3 constraints × 8 variables) are defined in the reference notebook.

> **Note:** The reference notebook uses `bn128` for illustration. We translated all curve operations to **BLS12-381**, which is natively supported by Cardano / Aiken builtins.

---

## Architecture

| Phase | Where | What | Technology |
|-------|-------|------|------------|
| Circuit definition | Off-chain | Flatten arithmetic circuit to R1CS matrices | circom / ark-relations |
| Trusted setup | Off-chain, air-gapped | Generate SRS, proving key, verification key | Rust / arkworks / snarkjs |
| Proving | Off-chain, user's machine | Build witness, interpolate, compute `h(x)`, assemble `(A, B, C)` | Rust / arkworks |
| Verification | On-chain, Cardano validator | Recompute `V` and run the pairing check | Aiken / Plutus V3 |

The prover must stay **off-chain** because it requires FFTs over large vectors, polynomial multiplication/division, and heavy MSM — all of which exceed Cardano script budgets. Aiken is designed for validators (the verifier side), not for heavy computation.

The Aiken `bls12_381` module (`G1Element`, `G2Element`, `ml_result`, pairing) is ideal for the verifier because it only needs 3–4 pairings, a few scalar multiplications, and point additions.

```aiken
let lhs = bls12_381.pairing(a, b)
let rhs = bls12_381.pairing(alpha_g1, beta_g2)
  |> bls12_381.ml_result_mul( bls12_381.pairing(c, delta_g2) )
  |> bls12_381.ml_result_mul( bls12_381.pairing(v, gamma_g2) )

lhs == rhs
```

---

## Cross-Check & Correctness

All intermediate values in the Groth16 pipeline — from R1CS matrices through polynomial coefficients, SRS/CRS points, witness polynomials, proof elements, and the final pairing — have been cross-checked between three independent codebases:

| Codebase | Language | Curve | Role | Documentation |
|----------|----------|-------|------|---------------|
| **Rust / arkworks** | Rust | BLS12-381 | Production prover + verifier | [`groth16-prover/README.md`](../../groth16-prover/README.md) |
| **Sage** | Python/Sage | BLS12-381 | Mathematical reference from scratch | [`RustGroth16Correctness.md`](../../RustGroth16Correctness.md) |
| **zeroj** | Java | BLS12-381 | Production Groth16 for Cardano | [`ZeroJAudit.md`](../../ZeroJAudit.md) |

### What was verified

- **Steps 1.1–1.5:** R1CS matrices, scalar field, QAP interpolation, target polynomial, sanity checks at constraint points — ✅ match bit-for-bit.
- **Steps 1.6–1.9:** Deterministic toxic waste, SRS (`G1·tau^i`, `G2·tau^i`), CRS fixed points, per-variable `Psi_V_G1` / `Psi_P_G1` — ✅ scalars match exactly; G1 coordinates match bit-for-bit.
- **Steps 1.10–1.11:** Witness polynomials `l(x)`, `r(x)`, `o(x)` and quotient `h(x)` — ✅ coefficients match exactly; zero remainder confirmed.
- **Steps 1.12–1.15:** Proof elements `A`, `B`, `C` and public-input commitment `V` — ✅ all intermediate scalars and G1 coordinates match.
- **Step 1.16:** Pairing check — ✅ Rust/arkworks pairing passes; Sage has a G2 embedding limitation but all inputs were verified independently.

> See [`RustGroth16Correctness.md`](../../RustGroth16Correctness.md) for the full step-by-step comparison table, printed intermediate values, and reproduction commands.

### Sage reference script

A pure-Sage prototype lives at [`../../sage/groth16.sage`](../../sage/groth16.sage). It mirrors the concrete example end-to-end and serves as a readable mathematical reference. Run it via Docker (no local Sage required):

```bash
cd ../../sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

Expected output includes `R1CS relation verified.`, `Trusted setup complete.`, `Proof generated.`, and confirmation that all intermediate assertions pass.

### zeroj as a third reference

[zeroj](https://github.com/bloxbean/zeroj) is a production-grade Java toolkit for Groth16 on Cardano. It already has a **working on-chain verifier** compiled from Java to UPLC (JULC). We audited it against our Rust/Sage stack and injected deterministic toxic-waste overloads so that a bit-for-bit cross-check is possible. See [`ZeroJAudit.md`](../../ZeroJAudit.md) for the detailed architectural comparison.

Key zeroj features relevant to this project:
- **Coset FFT** (`FieldFFTBLS381`) for `O(N log N)` polynomial arithmetic.
- **Pippenger MSM** for fast proof assembly.
- **JULC on-chain verifier** (`Groth16BLS12381Verifier`) that runs inside a Plutus V3 validator.
- **Circom-compatible circuit builder** (`CircuitBuilder`) for dynamic R1CS generation.

---

## Step 1: Concrete Example (Completed)

The concrete 3-constraint circuit has been implemented and verified end-to-end. The Rust crate [`groth16-prover`](../../groth16-prover/) contains 16 numbered binaries (`print_r1cs` through `print_pairing`) that reproduce every sub-step. See that crate's README for:
- How to run each binary.
- How to compare outputs against Sage.
- Design choices (dense monomials, no randomizers, deterministic toxic waste).
- A **TO DO** section listing production innovations needed next (FFT, Pippenger MSM, circom support, prepared verifier, proof aggregation, batch normalization, randomized test fixtures).

---

## Step 2: Sketch Plan for General Circuits

Once the concrete example is fully working, the next phase is to make the system generic.

### 2.1 Circuit Compiler (Off-chain)

- Accept an arbitrary arithmetic circuit (e.g., from Circom, Arkworks, or a custom DSL).
- Flatten to **R1CS** (`L`, `R`, `O` matrices).
- Generate a full **witness vector** from public + private inputs.

> Reference: zeroj's `CircuitBuilder` and the circom adapter described in [`ZeroJAudit.md`](../../ZeroJAudit.md) §2.1.

### 2.2 General Trusted Setup (Off-chain)

- Given `m` constraints and `n` variables:
  - SRS sizes scale with degree `m`.
  - `T(x) = ∏_{i=0}^{m-1} (x - i)`.
- Produce a structured reference string for both G1 and G2.
- Output a **verification key** and **proving key** that can be serialized and reused.

> Reference: zeroj's `Groth16SetupBLS381` (single-party dev/test setup) and snarkjs MPC ceremony for production.

### 2.3 General Prover (Off-chain)

- Automate:
  1. Witness generation.
  2. Polynomial interpolation (`u_i`, `v_i`, `w_i`) via FFT over roots of unity.
  3. Construction of `l(x)`, `r(x)`, `o(x)`.
  4. Coset-quotient computation of `h(x)`.
  5. Pippenger MSM to build `A`, `B`, `C` from the SRS.
- Support dynamic-length public / private input splits.

> Reference: zeroj's `Groth16ProverBLS381` uses coset FFT, Pippenger MSM, and optional randomizers `r`/`s` for zero-knowledge. See [`ZeroJAudit.md`](../../ZeroJAudit.md) §2.3, §2.11–2.14.

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

> Reference: zeroj's JULC on-chain verifier (`Groth16BLS12381Lib.verify`) already does this on Cardano's test VM. See [`ZeroJAudit.md`](../../ZeroJAudit.md) §2.16.

### 2.5 Tooling & Integration

- Build a CLI / Rust crate that:
  1. Reads an R1CS file + witness.
  2. Runs the trusted setup (or loads a saved SRS).
  3. Generates a BLS12-381 proof.
  4. Serializes the proof and public inputs into a Cardano transaction datum.
- Provide Aiken helper functions for G1/G2 point arithmetic and MSM to keep the validator code clean.

---

## Milestones / TODO

### Step 1: Concrete Circuit (Completed ✅)

All 16 sub-steps have been implemented in Rust, verified in Sage, and compared against zeroj where applicable. See [`RustGroth16Correctness.md`](../../RustGroth16Correctness.md) for the complete verification table.

Remaining integration items:
- [ ] **Aiken on-chain validator:** hard-code verification key, recompute `V`, run pairing check via BLS12-381 builtins.
- [ ] **End-to-end test:** Rust generates proof + serialized VK, Aiken validator accepts it in `aiken test`.

### Step 2: General Circuits

- [ ] **Circuit compiler:** accept arbitrary R1CS matrices and witnesses using `ark-relations` / `ark-r1cs-std`, or a circom adapter.
- [ ] **General trusted setup:** SRS scaling with constraint count, reusable proving/verification keys.
- [ ] **General prover:** coset FFT quotient, Pippenger MSM, dynamic public/private input split.
- [ ] **General Aiken verifier:** parameterized VK, dynamic-length public inputs, on-chain MSM.
- [ ] **CLI tooling:** Rust crate going from R1CS + witness → proof → Cardano-ready transaction datum.

### Production innovations (from zeroj & arkworks)

For a detailed breakdown of the production features still needed, see [`groth16-prover/README.md`](../../groth16-prover/README.md) §**TO DO — Production innovations**. The items are:

1. FFT / Lagrange basis as an alternative to dense monomials.
2. Pippenger multi-scalar multiplication (MSM).
3. Support usage of circom.
4. Prepared verifier and batched pairing verification.
5. Proof aggregation.
6. Batch normalization and fixed-base MSM tables.
7. Randomized R1CS test fixtures and parity assertions.

---

## Dependencies

- **Off-chain**: Rust with [`arkworks`](https://arkworks.rs/) ecosystem (`ark-bls12-381`, `ark-groth16`, `ark-poly`, `ark-ec`, `ark-ff`) for finite-field arithmetic, polynomial operations, elliptic-curve pairings, and serialization.
- **On-chain**: [Aiken](https://aiken-lang.org) with built-in BLS12-381 primitives.

### Why arkworks?

`arkworks` provides a mature, modular Rust framework for zkSNARKs. For this project it gives us:

- **Native BLS12-381 support** via `ark-bls12-381`, matching Cardano's curve.
- **R1CS integration**: `ark-snark` and `ark-relations` traits for circuit definitions and witness generation.
- **Polynomial arithmetic**: `ark-poly` supports interpolation, evaluation, and division over finite fields.
- **Curve operations & pairings**: `ark-ec` and `ark-pairing` provide type-safe G1/G2 arithmetic and Miller-loop / final-exponentiation APIs.
- **Serialization**: `ark-serialize` offers canonical compressed formats we can standardize on for passing points into Aiken datums/redeemers.

---

## Notes

- Keep the first on-chain implementation minimal: hard-code the concrete circuit, witness, and verification key in Aiken to prove the pairing logic works.
- Only after the concrete circuit verifies on-chain should we abstract to generic matrices and inputs.
- BLS12-381 builtins in Aiken operate on compressed / uncompressed points; make sure the serialization format between off-chain prover and on-chain verifier is agreed upon.
- For serialization, zeroj uses BLST compressed format (48 bytes for G1, 96 bytes for G2). Consider aligning with that for ecosystem compatibility.
