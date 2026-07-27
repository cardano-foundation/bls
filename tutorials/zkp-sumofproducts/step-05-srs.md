# Step 1.7: Structured Reference String (SRS)

**What this step does.** The SRS is the set of elliptic-curve points that the prover needs to build a proof. It is computed during the trusted setup by multiplying the curve generators `G1` and `G2` by powers of the secret scalar `τ`. Because the raw scalar `τ` is never stored — only its "shadows" on the curve — the prover can evaluate polynomials at `τ` without knowing `τ` itself.

## Paper and pencil

The SRS has three parts:

1. **SRS1** — `τ^i · G1` for `i = 0, 1, 2, ..., N-1`
   Used to compute `l(τ)·G1` and other left-side terms.

2. **SRS2** — `τ^i · G2` for `i = 0, 1, 2, ..., N-1`
   Used to compute `r(τ)·G2` and other right-side terms.

3. **SRS3** — `T(τ)·τ^i / δ · G1` for `i = 0, 1, 2, ..., N-2`
   Used to compute the quotient term `h(τ)·T(τ)/δ·G1` in proof element `C`.

### Degree bounds for SumOfProducts

The QAP polynomials are degree 3 (Lagrange basis for 4 points). The witness polynomials `l(x)`, `r(x)`, `o(x)` are at most degree 3. Their product `l(x)·r(x)` is at most degree 6. The target polynomial `T(x)` is degree 4. Therefore the quotient `h(x)` is at most degree 2.

For SRS1 and SRS2 we need powers up to `τ^3` (degree of the QAP polynomials). For SRS3 we need powers up to `τ^2` (degree of the quotient).

In our implementation, `N = 4` (number of constraints), so:

- SRS1: `τ^0·G1, τ^1·G1, τ^2·G1, τ^3·G1`
- SRS2: `τ^0·G2, τ^1·G2, τ^2·G2, τ^3·G2`
- SRS3: `T(τ)·τ^0/δ·G1, T(τ)·τ^1/δ·G1, T(τ)·τ^2/δ·G1`

### Computing T(τ)

```
T(x) = x⁴ − 6x³ + 11x² − 6x
T(3) = 81 − 162 + 99 − 18 = 0
```

Wait — that gives `T(3) = 0`! This happens because `3` is one of the constraint points. Let me recalculate:

```
T(x) = x(x−1)(x−2)(x−3)
T(3) = 3 · 2 · 1 · 0 = 0
```

This means `τ = 3` is a root of `T(x)`, which would make `T(τ)/δ = 0` and collapse SRS3. In the original tutorial for the 3-gate multiplier, `T(x) = (x−0)(x−1)(x−2) = x³ − 3x² + 2x`, and `τ = 3` was not a root (`T(3) = 6`).

**For SumOfProducts with 4 constraint points `{0, 1, 2, 3}` and `τ = 3`, the target polynomial evaluates to zero.** This means the pedagogical choice of `τ = 3` does not work for the 4-constraint circuit. In practice, `τ` is a random 253-bit number and this collision is astronomically unlikely.

For the tutorial walkthrough, we can either:
1. Use a different `τ` (e.g., `τ = 4`) so that `T(τ) ≠ 0`
2. Keep `τ = 3` and note that the SRS3 term vanishes (which is actually valid — it just means the quotient term contributes nothing in this special case)

We use **`τ = 4`** for the SumOfProducts walkthrough so that all steps produce non-trivial outputs.

### Revised parameters

| Parameter | Value | Role |
|-----------|-------|------|
| `τ` (tau)   | 4   | Secret evaluation point |
| `α` (alpha) | 5   | Mixed term for proof element C |
| `β` (beta)  | 7   | Mixed term for proof elements B and C |
| `γ` (gamma) | 11  | Denominator for public-input CRS elements |
| `δ` (delta) | 13  | Denominator for private-input CRS elements |

### Computing SRS points

**T(τ) with τ = 4:**

```
T(4) = 4 · 3 · 2 · 1 = 24
```

**SRS1:** `τ^i · G1`

| i | scalar `τ^i` | Point |
|---|-------------|-------|
| 0 | 1 | `1 · G1` |
| 1 | 4 | `4 · G1` |
| 2 | 16 | `16 · G1` |
| 3 | 64 | `64 · G1` |

**SRS2:** `τ^i · G2`

| i | scalar `τ^i` | Point |
|---|-------------|-------|
| 0 | 1 | `1 · G2` |
| 1 | 4 | `4 · G2` |
| 2 | 16 | `16 · G2` |
| 3 | 64 | `64 · G2` |

**SRS3:** `T(τ)·τ^i / δ · G1` with `T(τ) = 24`, `δ = 13`

Base scalar: `24/13 = 24 · 13^(−1) mod q`

| i | scalar `24·τ^i/13` | Point |
|---|---------------------|-------|
| 0 | `24/13` | `(24/13) · G1` |
| 1 | `96/13` | `(96/13) · G1` |
| 2 | `384/13` | `(384/13) · G1` |

## Summary

The SRS provides the "power table" that lets the prover evaluate polynomials at `τ` without knowing `τ`. With `τ = 4` and 4 constraint points, we get non-trivial SRS points that feed directly into the proof construction in later steps.
