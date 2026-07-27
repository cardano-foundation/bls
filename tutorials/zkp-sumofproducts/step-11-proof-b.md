# Step 1.13: Proof element B

**What this step does.** Proof element `B` encodes the right witness polynomial `r(x)` evaluated at `τ`, mixed with the scalar `β`. It lives in G2, which is why it is larger (96 bytes compressed instead of 48).

## Paper and pencil

```
r(x) = 2 + 2x
r(τ) = r(4) = 2 + 2·4 = 10

B = (r(τ) + β) · G2
  = (10 + 7) · G2
  = 17 · G2
```

The combined scalar is **`17`**.

## Verification

```
r(4) = 2 + 2·4 = 10  ✓
B = (10 + 7) · G2 = 17 · G2  ✓
```
