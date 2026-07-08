# Sage Reference for Groth16 over BLS12-381

This directory contains a **pure Sage** reference implementation of the same 3-constraint Groth16 circuit used by the Rust `groth16-prover` crate and the zeroj Java toolkit.

> **Purpose.** The Sage script implements every algebraic step from first principles (polynomial interpolation, dense division, elliptic-curve scalar multiplication, ate pairing) without relying on any zk-SNARK library. It is the **mathematical ground truth** against which the Rust and Java implementations are compared.

---

## Files

| File | What it does |
|------|-------------|
| `bls13-381.sage` | BLS12-381 curve parameters, generators, and `atePairing` helper |
| `groth16.sage` | Complete dense-monomial Groth16 pipeline (Steps 1.1–1.16) |

---

## Running the script

With a local Sage installation:

```bash
cd sage
sage groth16.sage
```

Or via Docker (no local Sage required):

```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## What is inside `groth16.sage`

The script mirrors the numbered sub-steps in [`../groth16-prover/RustGroth16Correctness.md`](../groth16-prover/RustGroth16Correctness.md):

| Step | What it prints |
|------|---------------|
| 1.1 | R1CS matrices `L`, `R`, `O` and witness `a = [1, 48, 2, 2, 3, 4, 4, 12]` |
| 1.2 | BLS12-381 scalar field `Fq` modulus and sample arithmetic |
| 1.3 | QAP polynomial coefficients `u_i(x)`, `v_i(x)`, `w_i(x)` via Lagrange interpolation |
| 1.4 | Target polynomial `T(x) = (x−0)(x−1)(x−2)` |
| 1.5 | Sanity check: QAP polynomials evaluated at `{0,1,2}` match matrix entries |
| 1.6 | Deterministic toxic waste `τ=3, α=5, β=7, γ=11, δ=13` |
| 1.7 | SRS points `G1·τ^i`, `G2·τ^i`, `G1·T(τ)·τ^i/δ` |
| 1.8 | CRS fixed points `α·G1`, `β·G2`, `γ·G2`, `δ·G2` |
| 1.9 | Per-variable CRS `Ψ_V_G1` (public) and `Ψ_P_G1` (private) |
| 1.10 | Witness polynomials `l(x)`, `r(x)`, `o(x)` |
| 1.11 | Quotient `h(x) = (l·r − o) / T` with zero-remainder verification |
| 1.12 | Proof element `A = l(τ)·G1 + α·G1` |
| 1.13 | Proof element `B = r(τ)·G2 + β·G2` |
| 1.14 | Proof element `C = Σ a_i·Ψ_P_G1 + h(τ)·T(τ)/δ·G1` |
| 1.15 | Public-input commitment `V = Σ a_i·Ψ_V_G1` |
| 1.16 | Pairing equation (attempted; may fail due to G2 embedding limitations, but all inputs are verified) |

Every step asserts its own correctness and prints the exact values that the Rust binaries (`print_r1cs`, `print_qap`, `print_crs`, …) print. G1 scalars and coordinates match bit-for-bit. G2 coordinates differ by field embedding (`F_q²` in Rust/arkworks vs `F_p¹²` in Sage), which is expected.

---

## Step 2 — FFT / Lagrange basis path (implemented)

`groth16.sage` now contains **both** the dense-monomial path and the FFT/roots-of-unity path. After running Step 1.16, the script continues with Steps 2.3–2.12 to build the same QAP via FFT, compute the quotient, and compare the two paths side-by-side.

### What Step 2 adds — at a glance

| Concern | Step 1 (dense) | Step 2 (FFT) | Why it matters |
|---------|---------------|--------------|----------------|
| **Gate points** | `{0, 1, 2}` | `N`-th roots of unity `ω^i` where `N = next_power_of_2(num_constraints)` | FFT requires a cyclic group for the butterfly network |
| **QAP construction** | `PR.lagrange_polynomial(points)` for each column (O(n²)) | IFFT of padded column evaluations (O(N log N)) | For 3 gates the dense path is faster; for 10⁴ gates FFT is ~1000× faster |
| **Target polynomial** | `T(x) = prod(x − xi)` for `xi` in `{0,1,2}` | `T(x) = x^N − 1` | Vanishes at all `N`-th roots simultaneously |
| **Quotient `h(x)`** | Dense polynomial long-division `p // T` | Dense division still works for small N; coset FFT for large N | Sage's `p // T` is the textbook definition; the FFT path uses the same for our 3-gate demo |
| **SRS basis** | Monomial powers `τ^i·G1` | Lagrange evaluations `L_i(τ)·G1` | Both are valid; Lagrange basis is natural for FFT provers |
| **Per-variable CRS** | Evaluate each stored polynomial at `τ` | Dot product of matrix column with precomputed `L_i(τ)` vector | Reuses one `L_i(τ)` computation for all wires |
| **Proof points** | Deterministic values from dense QAP | **Different** deterministic values from FFT QAP | Self-consistent within each path |

> **Key takeaway:** The high-level Groth16 formulas (`A = l(τ)·G1 + α·G1`, `B = r(τ)·G2 + β·G2`, pairing check, CRS fixed points) are **identical** between the two paths. Only the polynomial representation and the SRS basis change.

### Step-by-step mapping

| Step | Status | Kind | What it does | Replaces |
|------|--------|------|-------------|----------|
| 2.1 | ✅ done | **REUSED** from 1.1 | R1CS matrices `L`, `R`, `O` and witness `a` | — |
| 2.2 | ✅ done | **REUSED** from 1.2 | BLS12-381 scalar field `Fq` | — |
| 2.3 | ✅ done | **NEW** | **FFT domain setup.** `N = next_power_of_2(3) = 4`. Compute primitive 4-th root of unity `ω` in `Fq` via `Fq.zeta(4)`. | 1.3 (partial) |
| 2.4 | ✅ done | **SWITCHABLE** | **QAP via FFT/IFFT.** Pad each matrix column to length 4. Use a custom radix-2 butterfly `ifft_iterative` to turn evaluations on `ω^i` into monomial coefficients. | 1.3–1.4 |
| 2.5 | ✅ done | **SWITCHABLE** | **Target polynomial** `T(x) = x^4 − 1`. | 1.4 |
| 2.6 | ✅ done | **SWITCHABLE** | **Sanity check:** evaluate each FFT-derived QAP polynomial on `1, ω, ω², ω³` and assert it equals the original matrix entry. | 1.5 |
| 2.7 | ✅ done | **REUSED** from 1.6 | Deterministic toxic waste `τ, α, β, γ, δ` | — |
| 2.8 | ⏳ not in Sage | **SWITCHABLE** | **Lagrange-basis SRS.** Compute `L_i(τ)` for `i = 0..3`, then build `L_i(τ)·G1`. Implemented in Rust `FftQapEngine`; Sage reuses monomial SRS for proof assembly. | 1.7 |
| 2.9 | ✅ done | **REUSED** from 1.8 | CRS fixed points `α·G1`, `β·G2`, `γ·G2`, `δ·G2` | — |
| 2.10 | ✅ done | **SWITCHABLE** | **Per-variable QAP at τ** via Lagrange basis dot product. `u_s(τ)`, `v_s(τ)`, `w_s(τ)` computed with `evaluate_qap_at_tau_fft`. | 1.9 |
| 2.11 | ✅ done | **SWITCHABLE** | **Witness polynomials** `l(x)`, `r(x)`, `o(x)` as sums of FFT-derived `u_i`, `v_i`, `w_i`. | 1.10 |
| 2.12 | ✅ done | **SWITCHABLE** | **Quotient `h(x)`** via dense division `p // T_fft`. For large N, coset FFT would be used instead. | 1.11 |
| 2.13 | ⏳ reuse dense | **REUSED** from 1.12 | Proof element `A = l(τ)·G1 + α·G1`. Sage uses dense `l(τ)` for the printed proof; FFT `l_fft(τ)` is printed for comparison only. | — |
| 2.14 | ⏳ reuse dense | **REUSED** from 1.13 | Proof element `B = r(τ)·G2 + β·G2`. Same note as above. | — |
| 2.15 | ⏳ reuse dense | **REUSED** from 1.14 | Proof element `C = Σ a_i·Ψ_P_G1 + h(τ)·T(τ)/δ·G1`. Same note as above. | — |
| 2.16 | ⏳ reuse dense | **REUSED** from 1.15 | Public-input commitment `V = Σ a_i·Ψ_V_G1`. Same note as above. | — |
| 2.17 | ⏳ reuse dense | **REUSED** from 1.16 | Pairing check. Same note as above. | — |

### Why both paths are in Sage

The Sage script is the **mathematical ground truth**. Adding the FFT path serves two purposes:

1. **Pedagogical completeness:** You can see the exact same QAP built two different ways — by hand-solved Lagrange and by IFFT — and verify they agree at their respective domains.
2. **Cross-implementation verification:** The Sage FFT output can be compared against the Rust `FftQapEngine` output. Both use the same BLS12-381 field and the same 4-th roots of unity, so the coefficients and evaluations must match bit-for-bit.

The FFT section in `groth16.sage` is only ~150 lines (Cooley-Tukey butterfly, IFFT wrapper, QAP builder, Lagrange basis evaluation). It does not replace the dense path; it runs **after** it and prints a side-by-side comparison.

### Cross-checking the two paths

Run the script and look at the "Parity Summary" section at the end:

```bash
cd sage
sage groth16.sage
```

You will see:

- **Dense path (Steps 1.x):** QAP evaluated at `{0,1,2}` matches the matrix. Quotient remainder is zero. Proof points are printed.
- **FFT path (Steps 2.x):** QAP evaluated at the 4-th roots of unity matches the matrix. Quotient remainder is zero. Polynomial coefficients differ from the dense path.
- **Cross-path sanity:** `u_2(τ)` differs between dense (`1`) and FFT (`10`). This is **expected and correct** — the two paths use different QAP domains.

To see the same comparison in Rust:

```bash
cd ../groth16-prover
cargo run --bin print_qap_engines
```

---

## License

Apache-2.0
