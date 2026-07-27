# Step 1.6: Toxic waste

See the [main tutorial](../zkp-from-first-principles.md#step-16-toxic-waste) for a detailed explanation of toxic waste and why the scalars must be secret and random.

**Important difference for SumOfProducts.** The main tutorial uses `τ = 3` for the 3-gate multiplier circuit. For the 4-gate SumOfProducts circuit, `τ = 3` is a root of `T(x) = x(x−1)(x−2)(x−3)`, which would make `T(τ) = 0` and collapse the SRS. Therefore the SumOfProducts walkthrough uses `τ = 4` instead.

| Parameter | Value | Role |
|-----------|-------|------|
| `τ` (tau)   | 4   | Secret evaluation point |
| `α` (alpha) | 5   | Mixed term for proof element C |
| `β` (beta)  | 7   | Mixed term for proof elements B and C |
| `γ` (gamma) | 11  | Denominator for public-input CRS elements |
| `δ` (delta) | 13  | Denominator for private-input CRS elements |

The other four scalars (`α, β, γ, δ`) are the same as in the multiplier tutorial. Only `τ` changes because of the different constraint point set.
