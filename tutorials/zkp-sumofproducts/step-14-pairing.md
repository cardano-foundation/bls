# Step 1.16: Pairing check

**What this step does.** The verifier checks a single equation involving four pairings. If the equation holds, the proof is valid. If it does not, the proof is rejected. The equation is:

```
e(A, B) == e(α·G1, β·G2) · e(C, δ·G2) · e(V, γ·G2)
```

where `e` is the bilinear pairing on BLS12-381.

## Paper and pencil

We already know the scalars:

```
A = 14 · G1       (from Step 1.12)
B = 17 · G2       (from Step 1.13)
α·G1 = 5 · G1
β·G2 = 7 · G2
C = (283/13) · G1  (from Step 1.14)
δ·G2 = 13 · G2
V = (400/11) · G1  (from Step 1.15)
γ·G2 = 11 · G2
```

Check the exponents using bilinearity `e(s·P, t·Q) = e(P, Q)^(s·t)`:

- **Left side:** `e(14·G1, 17·G2) = e(G1, G2)^(14·17) = e(G1, G2)^238`

- **Right side:**
  ```
  e(5·G1, 7·G2) · e((283/13)·G1, 13·G2) · e((400/11)·G1, 11·G2)
  = e(G1, G2)^(5·7) · e(G1, G2)^((283/13)·13) · e(G1, G2)^((400/11)·11)
  = e(G1, G2)^35 · e(G1, G2)^283 · e(G1, G2)^400
  = e(G1, G2)^(35 + 283 + 400)
  = e(G1, G2)^718
  ```

**But 238 ≠ 718.** The pairing equation does NOT balance!

## Why the pairing fails

This is a direct consequence of `h(x) = 0` (from [Step 1.11](step-09-quotient.md)). The Groth16 pairing equation is designed to verify the QAP relation:

```
l(τ)·r(τ) = o(τ) + h(τ)·T(τ)
```

When `h(x) = 0`, this reduces to `l(τ)·r(τ) = o(τ)`, which is an identity — not a proof. The verifier cannot distinguish a valid witness from a forged one because the proof carries no information about the quotient.

**This is why the multiplier circuit (with non-zero `h(x)`) is more interesting for a tutorial.** The SumOfProducts circuit, with its disjoint variable sets, produces a degenerate case where the proof is trivially valid but also trivially forgeable.

## What would happen with τ = 3

If we had used `τ = 3` (as in the multiplier tutorial), then `T(3) = 0` and the SRS3 term would vanish. The pairing would still fail, but for a different reason: the SRS would not provide the necessary points to construct a valid proof.

## Key takeaway

The SumOfProducts circuit, while excellent for introducing the R1CS and QAP concepts, produces a degenerate Groth16 proof when each variable appears in exactly one constraint. For a non-trivial proof walkthrough, the 3-gate multiplier circuit (with shared intermediate variables) is the better choice. That is why the main tutorial traces the multiplier circuit in its implementation walkthrough.
