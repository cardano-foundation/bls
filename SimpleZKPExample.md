# A Simple Zero-Knowledge Proof Example

This document walks through a **complete, concrete Groth16 proof** that can be followed almost on paper. We use the same 3-constraint circuit that the Rust and Sage implementations exercise, but explain every step in plain language.

> **Goal:** Prove that you know numbers `x1, x2, x3, x4` such that  
> `((x1 · x2) · (x3 · x4)) = 48`  
> without revealing `x1, x2, x3, x4`.

---

## 1. The Problem

Alice wants to convince Bob that she knows four secret numbers whose product-chain equals 48. She does **not** want to disclose the numbers.

For concreteness, Alice's secrets are:

```
x1 = 2,  x2 = 2,  x3 = 3,  x4 = 4
```

Check: `(2·2)·(3·4) = 4·12 = 48`. ✅

---

## 2. Hiding Numbers inside Elliptic-Curve Points

BLS12-381 gives us two groups of points, **G1** and **G2**, with generators `G1` and `G2`.  
A scalar multiplication `s · G1` "hides" the scalar `s` inside a curve point. Given the point, it is computationally infeasible to recover `s`.

Because of **bilinearity**, pairings let us check multiplicative relationships between hidden scalars:

```
e(a·G1, b·G2) == e(G1, (a·b)·G2)
```

This is the trick that turns arithmetic into geometry.

---

## 3. Breaking the Computation into Tiny Steps (R1CS)

Alice cannot prove the whole formula in one go. Instead she breaks it into **three multiplication gates**, each of the form `left · right == out`.

| Gate | Meaning | Equation |
|------|---------|----------|
| 0 | `x1` times `x2` | `x1 · x2 == x5` |
| 1 | `x3` times `x4` | `x3 · x4 == x6` |
| 2 | `x5` times `x6` | `x5 · x6 == a` |

The intermediate variables are `x5 = 4` and `x6 = 12`. The public output is `a = 48`.

---

## 4. The Witness Vector

All variables (public and private) are packed into a single vector `a`:

```
a = [1, 48, 2, 2, 3, 4, 4, 12]
      │   │   │   │   │   │   │   └─ x6
      │   │   │   │   │   │   └───── x5
      │   │   │   │   │   └───────── x4
      │   │   │   │   └───────────── x3
      │   │   │   └───────────────── x2
      │   │   └───────────────────── x1
      │   └───────────────────────── public output a
      └───────────────────────────── constant 1 (needed for linear terms)
```

The first entry is always `1`. It acts like a "constant wire" so we can add fixed offsets if the circuit needs them.

---

## 5. Encoding the Gates as Matrices

Each gate is encoded by three **selector matrices**: `L` (left input), `R` (right input), and `O` (output).  
There is one row per gate and one column per witness variable.

For gate 0 (`x1 · x2 == x5`) we need:
- left = `x1`  → pick column 2
- right = `x2` → pick column 3
- out = `x5`   → pick column 6

So row 0 of the matrices looks like:

```
L[0] = [0, 0, 1, 0, 0, 0, 0, 0]   -- picks x1
R[0] = [0, 0, 0, 1, 0, 0, 0, 0]   -- picks x2
O[0] = [0, 0, 0, 0, 0, 0, 1, 0]   -- picks x5
```

Doing this for all three gates gives the full matrices:

```
L = [[0,0,1,0,0,0,0,0],      -- gate 0 left  = x1
     [0,0,0,0,1,0,0,0],      -- gate 1 left  = x3
     [0,0,0,0,0,0,1,0]]      -- gate 2 left  = x5

R = [[0,0,0,1,0,0,0,0],      -- gate 0 right = x2
     [0,0,0,0,0,1,0,0],      -- gate 1 right = x4
     [0,0,0,0,0,0,0,1]]      -- gate 2 right = x6

O = [[0,0,0,0,0,0,1,0],      -- gate 0 out   = x5
     [0,0,0,0,0,0,0,1],      -- gate 1 out   = x6
     [0,1,0,0,0,0,0,0]]      -- gate 2 out   = a
```

### Sanity check

Multiplying each matrix by the witness vector `a`:

```
L·a = [2, 3,  4]
R·a = [2, 4, 12]
O·a = [4, 12, 48]
```

Now check element-wise:

```
gate 0: 2 · 2  = 4   == O·a[0] ✅
gate 1: 3 · 4  = 12  == O·a[1] ✅
gate 2: 4 · 12 = 48  == O·a[2] ✅
```

This is the **R1CS** (Rank-1 Constraint System). It is nothing more than a spreadsheet that says "at every row, left × right must equal output".

---

## 6. From Gates to Polynomials (QAP)

Groth16 does not verify the matrix equation directly. It turns every *column* of the matrices into a **polynomial** that passes through the gate values.

The three gates live at the points `x = 0, 1, 2`.

Take column 2 of `L` (the column that selects `x1`):
```
L[:,2] = [1, 0, 0]   -- values at x = 0, 1, 2
```

There is a unique degree-2 polynomial `u₂(x)` that satisfies:
```
u₂(0) = 1,   u₂(1) = 0,   u₂(2) = 0
```

We do this for every column of `L`, `R`, and `O`, producing 24 polynomials:
- `u₀(x) … u₇(x)` from `L`
- `v₀(x) … v₇(x)` from `R`
- `w₀(x) … w₇(x)` from `O`

This family of polynomials is called the **QAP** (Quadratic Arithmetic Program).

### The target polynomial

Because the gates are at `0, 1, 2`, we define:

```
T(x) = (x - 0)(x - 1)(x - 2) = x³ - 3x² + 2x
```

`T(x)` is zero exactly at the gate points, and nowhere else. It will act as a "divisibility test" later.

---

## 7. Folding the Witness into One Polynomial

Alice now folds her witness vector into three big polynomials:

```
l(x) = a₀·u₀(x) + a₁·u₁(x) + … + a₇·u₇(x)
r(x) = a₀·v₀(x) + a₁·v₁(x) + … + a₇·v₇(x)
o(x) = a₀·w₀(x) + a₁·w₁(x) + … + a₇·w₇(x)
```

Because the `uᵢ`, `vᵢ`, `wᵢ` were built to reproduce the matrix columns at `x = 0, 1, 2`, we automatically get:

```
l(0)·r(0) = o(0)     -- gate 0 holds
l(1)·r(1) = o(1)     -- gate 1 holds
l(2)·r(2) = o(2)     -- gate 2 holds
```

This means the polynomial `l(x)·r(x) - o(x)` is zero at `x = 0, 1, 2`.  
Therefore it is divisible by `T(x)`.

### The quotient polynomial

Alice computes:

```
h(x) = (l(x)·r(x) - o(x)) / T(x)
```

Because the division is exact, there is **no remainder**. The existence of `h(x)` is the mathematical proof that all gates are satisfied.

---

## 8. Trusted Setup & Toxic Waste

To hide the proof, a setup phase generates random secret scalars (called **toxic waste**):

```
τ, α, β, γ, δ   ←   random elements of Fr
```

In a real deployment these numbers must be generated jointly and then destroyed (a multi-party computation ceremony). For this example we treat them as fixed test values.

From these secrets, the setup produces:
- **SRS** (structured reference string): powers of `τ` hidden in curve points, e.g. `G1, τ·G1, τ²·G1, …`
- **CRS** (common reference string): fixed points like `α·G1`, `β·G2`, `γ·G2`, `δ·G2`
- **Per-variable points**: for every witness variable a point that bundles `uᵢ(τ)`, `vᵢ(τ)`, and `wᵢ(τ)`

Alice (the prover) receives the **proving key**. Bob (the verifier) receives the **verification key**.

---

## 9. Building the Proof

Alice evaluates her polynomials at the secret point `τ`, but she does so **"in the exponent"** — using the SRS points instead of the raw scalars. This keeps `τ` hidden.

### Proof element A (in G1)

```
A = l(τ)·G1 + α·G1
```

### Proof element B (in G2)

```
B = r(τ)·G2 + β·G2
```

### Proof element C (in G1)

```
C = Σ(private_inputs) aᵢ·Psi_P_G1[i]  +  h(τ)·(T(τ)/δ)·G1
```

The first term is a weighted sum of the per-variable CRS points for Alice's private secrets. The second term incorporates the quotient polynomial `h(x)`.

The final proof is just **three curve points**: `(A, B, C)`.

---

## 10. Verification

Bob knows:
- the verification key (`alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2`, and the public-input points)
- the public inputs (`1` and `48`)
- the proof `(A, B, C)`

### Step 1 — Recompute the public-input commitment V

Bob aggregates the CRS points for the public variables using the public witness values:

```
V = 1·Psi_V_G1[0] + 48·Psi_V_G1[1]
```

### Step 2 — Pairing check

Bob checks the Groth16 equation:

```
e(A, B)  ==  e(alpha·G1, beta·G2) · e(V, gamma·G2) · e(C, delta·G2)
```

Because of bilinearity, the left-hand side expands to terms involving `l(τ)·r(τ)`, `α·r(τ)`, `β·l(τ)`, and `α·β`. The right-hand side cancels everything except the witness-correctness term, which is valid **if and only if** `h(x)` was computed honestly from a satisfying witness.

If Alice cheated (wrong witness, or no witness at all), the equation fails with overwhelming probability.

---

## 11. Summary Table

| Step | What happens | Who does it | Math level |
|------|--------------|-------------|------------|
| 1 | Pick secrets and public output | Alice | Grade-school arithmetic |
| 2 | Write R1CS matrices `L, R, O` | Circuit designer | Sparse matrix bookkeeping |
| 3 | Build QAP polynomials `uᵢ, vᵢ, wᵢ` | Prover software | Lagrange interpolation |
| 4 | Compute `l(x), r(x), o(x), h(x)` | Prover software | Polynomial mul/div |
| 5 | Trusted setup → SRS/CRS | Ceremony / test RNG | Random scalars + MSM |
| 6 | Assemble proof `(A, B, C)` | Prover | Scalar mul + point add |
| 7 | Recompute `V` from public inputs | Verifier | Small MSM |
| 8 | Pairing check | Verifier | 3 pairings + 2 multiplications in `GT` |

---

## 12. Concrete Numbers for this Example

The matrices, witness, and all intermediate polynomial coefficients used above are exactly the ones hard-coded in:

- `groth16-prover/src/r1cs.rs` — witness and matrices
- `groth16-prover/src/qap.rs` — interpolation and target polynomial
- `sage/groth16.sage` — full Sage reference with explicit prints

Running `cargo run --bin print_qap` prints every `uᵢ, vᵢ, wᵢ` and `T(x)` so you can compare them to the hand-calculated values.

---

## 13. Why This Matters for Cardano

Cardano's Plutus / Aiken builtins provide **pairing** and **BLS12-381 curve arithmetic**, which means step 8 (the verifier) can run **on-chain** inside a validator script. Steps 1–6 (proving) are far too heavy for on-chain execution and are performed **off-chain** in Rust or any other prover implementation.

This split — heavy proving off-chain, lightweight verification on-chain — is what makes zk-SNARKs practical for blockchain use.
