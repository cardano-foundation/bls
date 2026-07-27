# Step 1.11: Quotient polynomial

**What this step does.** We have established that `l(x)·r(x) − o(x)` vanishes at every constraint point, so it must be divisible by the target polynomial `T(x)`. The **quotient polynomial** `h(x)` is defined as:

```
h(x) = (l(x)·r(x) − o(x)) / T(x)
```

If the division has zero remainder, the constraints are satisfied. If there is a non-zero remainder, the witness is invalid.

## Paper and pencil

From [Step 1.10](step-08-witness-polys.md):

```
l(x) = 1 + 2x
r(x) = 2 + 2x
o(x) = 2 + 6x + 4x²
```

First, multiply `l(x)` and `r(x)`:

```
l(x)·r(x) = (1 + 2x)(2 + 2x)
           = 2 + 2x + 4x + 4x²
           = 2 + 6x + 4x²
```

Subtract `o(x)`:

```
p(x) = l(x)·r(x) − o(x)
     = (2 + 6x + 4x²) − (2 + 6x + 4x²)
     = 0
```

The polynomial `p(x)` is identically zero. Therefore:

```
h(x) = p(x) / T(x) = 0 / T(x) = 0
```

The quotient is the **zero polynomial**. This happens because the SumOfProducts circuit has a special structure: each variable appears in exactly one constraint, and the witness polynomials satisfy `l(x)·r(x) = o(x)` as polynomial identities — not just at the constraint points.

## Why h(x) = 0 is valid

The QAP relation requires that `T(x)` divides `l(x)·r(x) − o(x)`. Since `l·r − o = 0`, and `0` is divisible by any polynomial (with quotient `0`), the relation holds.

In the proof, the prover evaluates `h(τ) = 0` and computes `h(τ)·T(τ)/δ·G1 = 0·G1 = O` (the point at infinity). This means the quotient term contributes nothing to proof element `C`.

## Comparison with the multiplier circuit

In the 3-gate multiplier tutorial, `h(x) = 3` (a non-zero constant). That circuit has shared intermediate variables (`x5` and `x6` appear in multiple constraints), which prevents the witness polynomials from satisfying the constraint identically. The SumOfProducts circuit, with its disjoint variable sets per constraint, produces a degenerate `h(x) = 0`.

Both results are mathematically correct. The non-zero quotient is more interesting pedagogically because it exercises the full proof machinery.
