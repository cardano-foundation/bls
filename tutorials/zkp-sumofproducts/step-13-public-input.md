# Step 1.15: Public-input commitment V

**What this step does.** The verifier does not know the private witness values, but it does know the public inputs (the constant `1` and the output `out = 100`). It recomputes a commitment `V` by taking a linear combination of the public-input CRS points `Psi_V_G1` weighted by the public input values.

## Paper and pencil

Public wires: `a_0 = 1` (constant), `a_1 = 100` (output).

From [Step 1.9](step-07-psi.md):

| Variable | Wire | Witness `a_i` | `psi_scalar` (÷ γ) |
|----------|------|---------------|---------------------|
| 0 | `1` (const) | 1 | `0/γ = 0` |
| 1 | `out` | 100 | `4/11` |

```
V = 1·0 + 100·(4/11)
  = 400/11
```

In Fr this is `400 · 11^(−1) mod q`.

## Verification

```
11 · V_scalar ≡ 400 (mod q)  ✓
```

The public-input commitment is `(400/11) · G1`.
