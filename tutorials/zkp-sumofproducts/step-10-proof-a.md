# Step 1.12: Proof element A

**What this step does.** Proof element `A` encodes the left witness polynomial `l(x)` evaluated at `τ`, mixed with the scalar `α`.

## Paper and pencil

```
l(x) = 1 + 2x
l(τ) = l(4) = 1 + 2·4 = 9

A = (l(τ) + α) · G1
  = (9 + 5) · G1
  = 14 · G1
```

The combined scalar is **`14`**.

## Verification

```
l(4) = 1 + 2·4 = 9  ✓
A = (9 + 5) · G1 = 14 · G1  ✓
```
