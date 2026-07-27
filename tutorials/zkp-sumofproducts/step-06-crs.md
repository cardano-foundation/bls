# Step 1.8: CRS fixed points

See the [main tutorial](../zkp-from-first-principles.md#step-18-crs-fixed-points) for a detailed explanation of the CRS fixed points.

The four fixed points are circuit-independent — they depend only on the toxic waste scalars `α, β, γ, δ`, not on the circuit structure:

| Point | Formula | Group |
|-------|---------|-------|
| `α·G1` | `5 · G1` | G1 |
| `β·G2` | `7 · G2` | G2 |
| `γ·G2` | `11 · G2` | G2 |
| `δ·G2` | `13 · G2` | G2 |

These are identical to the multiplier tutorial since the toxic waste values are the same.
