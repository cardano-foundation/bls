# groth16-prover

A **didactic, end-to-end Groth16 prover** in Rust over the BLS12-381 curve.

> **Purpose.** This crate demonstrates the full Groth16 pipeline—from hard-coded R1CS matrices to a valid zero-knowledge proof—using [arkworks](https://arkworks.rs/) primitives. It is intentionally simplistic (hard-coded circuit, dense monomial polynomials, no randomizers) so that every intermediate value can be printed, inspected, and compared against an independent reference implementation.

> **Correctness guarantee.** The entire implementation has been cross-checked line-by-line against a [Sage](https://www.sagemath.org/) script that implements the same mathematics from scratch. See [`RustGroth16Correctness.md`](../RustGroth16Correctness.md) for the bit-for-bit comparison of every sub-step.

---

## What is inside

| File | Step | What it does |
|------|------|-------------|
| `src/r1cs.rs` | 1.1 | Hard-coded `L`, `R`, `O` matrices and witness `a = [1, 48, 2, 2, 3, 4, 4, 12]` |
| `src/qap.rs` | 1.3–1.4 | Lagrange interpolation of QAP polynomials and target polynomial `T(x)` |
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

---

## How to use

### 1. Run unit tests

```bash
cd groth16-prover
cargo test
```

All 7 library tests pass (R1CS relation, QAP interpolation, target polynomial, field arithmetic).

### 2. Print and inspect every step

Each binary corresponds to a numbered sub-step in [`RustGroth16Correctness.md`](../RustGroth16Correctness.md).

```bash
# Step 1.1 — R1CS matrices and witness
cargo run --bin print_r1cs

# Step 1.2 — BLS12-381 scalar field
cargo run --bin print_field

# Step 1.3–1.5 — QAP polynomials
cargo run --bin print_qap

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
```

### 3. Cross-check against Sage

The Sage reference lives in [`../sage/groth16.sage`](../sage/groth16.sage). Run it via Docker (no local Sage required):

```bash
cd ../sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

Compare the printed intermediate values with the Rust output. They match bit-for-bit for all G1 points and scalars. G2 coordinates differ only by field embedding (`F_q²` in Rust vs `F_p¹²` in Sage), which is expected.

---

## Design choices (and why)

| Choice | Rationale |
|--------|-----------|
| **Hard-coded circuit** | A 3-constraint multiplication chain (`x1·x2=x5`, `x3·x4=x6`, `x5·x6=a`) is large enough to exercise every Groth16 step, yet small enough to verify by hand. |
| **Dense monomial basis** | `u_i(x)`, `v_i(x)`, `w_i(x)` are stored as dense coefficient vectors. This makes printing and comparison trivial. It is `O(n²)` and therefore unsuitable for production circuits with millions of constraints, but it is ideal for learning. |
| **No randomizers (`r = s = 0`)** | Proof elements `A`, `B`, `C` use the textbook formulas without blinding. This removes entropy and makes the outputs deterministic and reproducible. A production prover would add random `r` and `s` for zero-knowledge. |
| **Deterministic toxic waste** | `tau=3`, `alpha=5`, `beta=7`, `gamma=11`, `delta=13` are hard-coded small primes. In a real deployment these would be generated securely and destroyed; here they are fixed so that two independent codebases can produce the exact same curve points. |
| **No FFT** | Polynomial interpolation uses the classical Lagrange formula rather than FFT over roots of unity. Again, this is pedagogical: you can read the coefficient formula and verify it with pen and paper. |

---

## TO DO — Production innovations (from zeroj)

The current crate is a **reference implementation** for correctness verification. The following items, already present in the [zeroj](https://github.com/bloxbean/zeroj) Java toolkit (see [`ZerojAudit.md`](../ZerojAudit.md)), would need to be adopted for production use:

### (a) FFT / Lagrange basis as an alternative to dense monomials

- **Current:** QAP polynomials are built via dense Lagrange interpolation (`O(n²)` per column) and stored as coefficient vectors.
- **Target:** Support FFT-based polynomial arithmetic over roots of unity (`O(N log N)`). This is the industry standard for circuits with thousands or millions of constraints.
- **Reference:** zeroj uses `FieldFFTBLS381` for coset FFT: constraint evaluations → IFFT → coefficient form; quotient `h(x)` is computed point-wise on the coset and inverse-FFT'd back. The Lagrange basis SRS (`u_s(tau)·G1`) is also more efficient than monomial SRS for FFT-based provers.
- **Benefit:** Enables proving for realistic circuits (e.g., Poseidon hash, Merkle membership) in seconds rather than minutes.

### (b) Pippenger multi-scalar multiplication (MSM)

- **Current:** Point accumulations (`Σ a_i · Psi_P_G1`, SRS evaluations, proof assembly) use naive scalar-by-scalar multiplication and addition.
- **Target:** Implement [Pippenger's algorithm](https://zcash.github.io/halo2/background/pippenger.html) for multi-scalar multiplication. This reduces the number of group operations from `O(n)` scalar muls to roughly `O(n / log n)` bucket additions.
- **Reference:** zeroj's `Groth16ProverBLS381` uses a bucket-MSM for computing `piA`, `piB`, and `piC`.
- **Benefit:** 5–10× speedup on proof generation, especially for circuits with large witness vectors.

### (c) Support usage of circom

- **Current:** The circuit is hard-coded as Rust `const` arrays. Adding a new constraint requires editing source code.
- **Target:** Accept R1CS output from [circom](https://docs.circom.io/) (`.r1cs` + `.wasm` + `.wtns`).
- **Reference:** zeroj's `CircuitBuilder` generates R1CS dynamically; a circom adapter would load the constraints and witness from the standard circom artifacts.
- **Benefit:** Ecosystem compatibility. Any circom-compatible circuit (e.g., from the [circomlib](https://github.com/iden3/circomlib) library) can be proven with this Rust prover after the adapter is implemented.
- **Sub-tasks:**
  1. Parse the `.r1cs` binary format (sparse constraint matrices).
  2. Execute the `.wasm` witness generator (or load a precomputed `.wtns`).
  3. Map circom wire indices to the QAP variable ordering used by the prover.
  4. Verify that the FFT domain size matches `next_power_of_2(num_constraints)`.

### (d) Prepared verifier and batched pairing verification

- **Current:** The verifier recomputes every pairing from scratch each time a proof is checked.
- **Target:** Add a `PreparedVerifyingKey` that precomputes and caches fixed verification-key data (e.g., G2 line coefficients for the Miller loop). Also expose a batched verifier that checks multiple proofs with a single multi-pairing product.
- **Reference:** [Groth.jl](https://github.com/0xpantera/Groth.jl) implements `prepare_verifying_key`, `prepare_inputs`, and `verify_with_prepared`; batched pairing verification reduced their `N=16` batch from `18.212 ms` to `13.854 ms` on the same fixture. Arkworks also provides `PreparedVerifyingKey`.
- **Benefit:** On-chain verification becomes cheaper because the heavy G2 preparation is done once per VK, not per proof. Batching further amortizes the Miller-loop cost across many proofs.

### (e) Proof aggregation

- **Current:** Each proof is verified individually.
- **Target:** Support Groth16 proof aggregation (rolling multiple proofs into a single succinct proof that can be verified with one pairing check).
- **Reference:** Arkworks has an optional `groth16::aggregate_proofs` module. Groth.jl tracks this on their roadmap.
- **Benefit:** Essential for rollup and batching use cases where many proofs need to be verified on-chain in a single transaction.

### (f) Batch normalization and fixed-base MSM tables

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

---

## License

Apache-2.0
