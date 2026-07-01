# Correctness: Sage vs Rust Cross-Check

This document tracks the cross-checking of our Groth16 implementation between two independent codebases:

- **Rust / arkworks** — production implementation in `groth16-prover/`
- **Sage** — mathematical reference in `sage/groth16.sage`

Both use the **BLS12-381** curve (same subgroup order, same generators, same pairing). The Sage script implements curve arithmetic from scratch; the Rust crate uses `ark-bls12-381`. Agreement between the two gives high confidence that neither has a curve-specific bug.

---

## Methodology

For every sub-step in [README.md](README.md):

1. Implement the sub-step in Rust.
2. Print all intermediate values (polynomial coefficients, field elements, curve point coordinates).
3. Run the Sage script with deterministic inputs and print the same values.
4. Assert equality. If there is any mismatch, debug both sides before advancing.

> **Determinism:** Random values (toxic waste) are sampled from a fixed RNG seed in Rust and hard-coded in Sage so outputs are reproducible across runs.

---

## Sub-step Status

| Sub-step | Description | Status | Notes |
|----------|-------------|--------|-------|
| 1.1 | R1CS matrices `L`, `R`, `O` and witness `a` | ✅ **VERIFIED** | Identical hard-coded values; element-wise products match. |
| 1.2 | BLS12-381 scalar field `Fr` modulus | ⏳ pending | Will compare `q` and sample arithmetic. |
| 1.3 | Polynomial interpolation `u_i`, `v_i`, `w_i` | ⏳ pending | Will compare coefficient vectors. |
| 1.4 | Target polynomial `T(x)` | ⏳ pending | Will compare coefficients. |
| 1.5 | QAP verification at constraint points | ⏳ pending | Will assert `u_i(j) == L[j][i]`. |
| 1.6 | Toxic waste `tau, alpha, beta, gamma, delta` | ⏳ pending | Will use fixed deterministic values. |
| 1.7 | SRS: `G1·tau^i`, `G2·tau^i`, `G1·T(tau)·tau^i/delta` | ⏳ pending | Will compare point coordinates. |
| 1.8 | CRS fixed points `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2` | ⏳ pending | Will compare point coordinates. |
| 1.9 | Per-variable CRS `Psi_V_G1`, `Psi_P_G1` | ⏳ pending | Will compare point coordinates. |
| 1.10 | Witness polynomials `l(x)`, `r(x)`, `o(x)` | ⏳ pending | Will compare coefficients. |
| 1.11 | Quotient polynomial `h(x)` | ⏳ pending | Will compare coefficients + zero remainder. |
| 1.12 | Proof element `A` | ⏳ pending | Will compare point coordinates. |
| 1.13 | Proof element `B` | ⏳ pending | Will compare point coordinates. |
| 1.14 | Proof element `C` | ⏳ pending | Will compare point coordinates. |
| 1.15 | Public-input commitment `V` | ⏳ pending | Will compare point coordinates. |
| 1.16 | Pairing check | ⏳ pending | Will assert `lhs == rhs` in both. |

---

## Step 1.1 — Detailed Verification

### Hard-coded values (identical in both implementations)

**Witness:** `a = [1, 48, 2, 2, 3, 4, 4, 12]`

**L matrix:**
```
[0, 0, 1, 0, 0, 0, 0, 0]
[0, 0, 0, 0, 1, 0, 0, 0]
[0, 0, 0, 0, 0, 0, 1, 0]
```

**R matrix:**
```
[0, 0, 0, 1, 0, 0, 0, 0]
[0, 0, 0, 0, 0, 1, 0, 0]
[0, 0, 0, 0, 0, 0, 0, 1]
```

**O matrix:**
```
[0, 0, 0, 0, 0, 0, 1, 0]
[0, 0, 0, 0, 0, 0, 0, 1]
[0, 1, 0, 0, 0, 0, 0, 0]
```

### Computed intermediates

Running either implementation produces the same constraint evaluations:

| Constraint | `L·a` | `R·a` | `(L·a)·(R·a)` | `O·a` |
|------------|-------|-------|---------------|-------|
| 0 (x1·x2 = x5) | 2 | 2 | 4 | 4 |
| 1 (x3·x4 = x6) | 3 | 4 | 12 | 12 |
| 2 (x5·x6 = a) | 4 | 12 | 48 | 48 |

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_r1cs
cargo test
```

**Sage:**
```bash
cd sage
sage groth16.sage
```

Both print the matrices and the element-wise products shown above. The assertion `(L·a) ∘ (R·a) == O·a` passes in both.

---

## How to Read This Document

- ✅ **VERIFIED** — Both implementations have been run, outputs compared, and found equal.
- ⏳ **pending** — Not yet started or awaiting cross-check.
- ❌ **MISMATCH** — A discrepancy was found and is being investigated (none so far).

As we progress through Step 1, each sub-step will be added to the table above with its verification status and any notes about edge cases or implementation differences.
