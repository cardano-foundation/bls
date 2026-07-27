# Step 1.14: Proof element C

**What this step does.** Proof element `C` is the most complex. It has two parts:
1. A linear combination of the per-variable CRS points `Psi_P_G1`, weighted by the witness values.
2. The quotient term `h(τ)·T(τ)/δ · G1`.

Part 1 commits the prover to the private witness values; part 2 encodes the fact that the constraints are satisfied.

## Paper and pencil

### Part 1 — private wire contributions

Private wires are variables 2–13 (inputs `a` through `h`, intermediates `t1` through `t4`).

From [Step 1.9](step-07-psi.md), the per-variable scalars are:

| Variable | Wire | Witness `a_i` | `psi_scalar` |
|----------|------|---------------|-------------|
| 2 | `a` | 1 | `−7/13` |
| 3 | `b` | 2 | `−5/13` |
| 4 | `c` | 3 | `28/13` |
| 5 | `d` | 4 | `20/13` |
| 6 | `e` | 5 | `−42/13` |
| 7 | `f` | 6 | `−30/13` |
| 8 | `g` | 7 | `28/13` |
| 9 | `h` | 8 | `20/13` |
| 10 | `t1` | 2 | `−1/13` |
| 11 | `t2` | 12 | `4/13` |
| 12 | `t3` | 30 | `−6/13` |
| 13 | `t4` | 56 | `4/13` |

The sum of `a_i · psi_scalar_i`:

```
= (1·(−7) + 2·(−5) + 3·28 + 4·20 + 5·(−42) + 6·(−30) + 7·28 + 8·20 + 2·(−1) + 12·4 + 30·(−6) + 56·4) / 13
= (−7 − 10 + 84 + 80 − 210 − 180 + 196 + 160 − 2 + 48 − 180 + 224) / 13
= 283 / 13
```

### Part 2 — quotient term

Since `h(x) = 0` (see [Step 1.11](step-09-quotient.md)):

```
h(τ)·T(τ)/δ = 0 · 24 / 13 = 0
```

### Total scalar for C

```
C_scalar = 283/13 + 0 = 283/13
```

In Fr this is `283 · 13^(−1) mod q`.

## Verification

```
13 · C_scalar ≡ 283 (mod q)  ✓
```

The proof element `C` is `(283/13) · G1`.
