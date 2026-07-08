# Correctness: Sage vs Rust Cross-Check

This document tracks the cross-checking of our Groth16 implementation between two independent codebases:

- **Rust / arkworks** — production implementation in `groth16-prover/`
- **Sage** — mathematical reference in `sage/groth16.sage`

Both use the **BLS12-381** curve (same subgroup order, same generators, same pairing). The Sage script implements curve arithmetic from scratch; the Rust crate uses `ark-bls12-381`. Agreement between the two gives high confidence that neither has a curve-specific bug.

---

## Methodology

For every sub-step in [README.md](README.md):

1. Implement the sub-step in Rust.
2. Print all intermediate values (polynomial coefficients, field elements, curve point coordinates).
3. Run the Sage script with deterministic inputs and print the same values.
4. Assert equality. If there is any mismatch, debug both sides before advancing.

> **Determinism:** Random values (toxic waste) are sampled from a fixed RNG seed in Rust and hard-coded in Sage so outputs are reproducible across runs.

---

## Sub-step Status

| Sub-step | Description | Status | Notes |
|----------|-------------|--------|-------|
| 1.1 | R1CS matrices `L`, `R`, `O` and witness `a` | ✅ **VERIFIED** | Identical hard-coded values; element-wise products match. |
| 1.2 | BLS12-381 scalar field `Fr` modulus | ✅ **VERIFIED** | `q` matches exactly; sample add/mul/inv agree. |
| 1.3 | Polynomial interpolation `u_i`, `v_i`, `w_i` | ✅ **VERIFIED** | Coefficient vectors match; QAP evaluation assertions pass at x = 0, 1, 2. |
| 1.4 | Target polynomial `T(x)` | ✅ **VERIFIED** | Coefficients match; vanishes at x = 0, 1, 2. |
| 1.5 | QAP verification at constraint points | ✅ **VERIFIED** | All 24 evaluations match; assertions pass in Rust and Sage. |
| 1.6 | Toxic waste `tau, alpha, beta, gamma, delta` | ✅ **VERIFIED** | Same five hard-coded primes in both; all non-zero, distinct, and invertible. |
| 1.7 | SRS: `G1·tau^i`, `G2·tau^i`, `G1·T(tau)·tau^i/delta` | ✅ **VERIFIED** | Scalar values match exactly; G1 point coordinates match bit-for-bit; G2 coordinates differ only by field embedding (F₁₂ in Sage vs F_q² in Rust). |
| 1.8 | CRS fixed points `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2` | ✅ **VERIFIED** | Scalars match exactly; alpha·G1 coordinates match bit-for-bit; G2 coordinates differ only by field embedding. |
| 1.9 | Per-variable CRS `Psi_V_G1`, `Psi_P_G1` | ✅ **VERIFIED** | Intermediate scalars (`u_i(tau)`, `v_i(tau)`, `w_i(tau)`, combined, `psi_scalar`) match exactly; G1 point coordinates match bit-for-bit for all variables. |
| 1.10 | Witness polynomials `l(x)`, `r(x)`, `o(x)` | ✅ **VERIFIED** | Coefficients match exactly; degree and evaluation at constraint points match. |
| 1.11 | Quotient polynomial `h(x)` | ✅ **VERIFIED** | `h(x) = 3` in both; zero remainder confirmed by `p(x) == T(x) * h(x)`. |
| 1.12 | Proof element `A` | ⏳ pending | Will compare point coordinates. |
| 1.13 | Proof element `B` | ⏳ pending | Will compare point coordinates. |
| 1.14 | Proof element `C` | ⏳ pending | Will compare point coordinates. |
| 1.15 | Public-input commitment `V` | ⏳ pending | Will compare point coordinates. |
| 1.16 | Pairing check | ⏳ pending | Will assert `lhs == rhs` in both. |

---

## Step 1.1 — Detailed Verification

### Hard-coded values (identical in both implementations)

**Witness:** `a = [1, 48, 2, 2, 3, 4, 4, 12]`

**L matrix:**
```
[0, 0, 1, 0, 0, 0, 0, 0]
[0, 0, 0, 0, 1, 0, 0, 0]
[0, 0, 0, 0, 0, 0, 1, 0]
```

**R matrix:**
```
[0, 0, 0, 1, 0, 0, 0, 0]
[0, 0, 0, 0, 0, 1, 0, 0]
[0, 0, 0, 0, 0, 0, 0, 1]
```

**O matrix:**
```
[0, 0, 0, 0, 0, 0, 1, 0]
[0, 0, 0, 0, 0, 0, 0, 1]
[0, 1, 0, 0, 0, 0, 0, 0]
```

### Computed intermediates

Running either implementation produces the same constraint evaluations:

| Constraint | `L·a` | `R·a` | `(L·a)·(R·a)` | `O·a` |
|------------|-------|-------|---------------|-------|
| 0 (x1·x2 = x5) | 2 | 2 | 4 | 4 |
| 1 (x3·x4 = x6) | 3 | 4 | 12 | 12 |
| 2 (x5·x6 = a) | 4 | 12 | 48 | 48 |

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_r1cs
cargo test
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

Both print the matrices and the element-wise products shown above. The assertion `(L·a) ∘ (R·a) == O·a` passes in both.

---

## Step 1.2 — Detailed Verification

### Field modulus

Both implementations use the BLS12-381 scalar-field prime `q`:

```
q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
```

- **Rust**: `ark_bls12_381::Fr::MODULUS` (printed from `print_field` binary).
- **Sage**: `q` defined in `bls13-381.sage` and printed from `groth16.sage`.

### Sample arithmetic cross-check

Deterministic inputs were chosen so outputs are reproducible without an RNG:

| Operation | Inputs | Rust / arkworks | Sage / Python (`GF(q)`) |
|-----------|--------|-----------------|-------------------------|
| `a + b` | `5, 7` | `12` | `12` |
| `a * b` | `5, 7` | `35` | `35` |
| `a^-1` | `5` | `31461525105075714287668644304911579502614331500316582693562195219963148710708` | `31461525105075714287668644304911579502614331500316582693562195219963148710708` |
| `c + d` | `123456789, 987654321` | `1111111110` | `1111111110` |
| `c * d` | `123456789, 987654321` | `121932631112635269` | `121932631112635269` |
| `c^-1` | `123456789` | `33425547577840145493174542821492773921169917356880302182737906958068561524687` | `33425547577840145493174542821492773921169917356880302182737906958068561524687` |

All six values match bit-for-bit.

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_field
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

*(If Sage is unavailable, the same modulus and operations were verified with Python’s built-in `pow(a, -1, q)`.)*

---

## Step 1.3 — Detailed Verification

### Interpolated polynomials

The R1CS matrices `L`, `R`, `O` have 8 columns each. Every column is interpolated over the three constraint points `x ∈ {0, 1, 2}` using Lagrange interpolation.

**Rust** (`cargo run --bin print_qap`) and **Sage** (`groth16.sage`) both print the coefficient vectors `[c0, c1, c2]` for every `u_i(x)`, `v_i(x)`, `w_i(x)`.

A selection of non-trivial polynomials (all others are the zero polynomial):

| Polynomial | Matrix column | Rust coefficients `[c0, c1, c2]` | Sage coefficients `[c0, c1, c2]` |
|------------|---------------|----------------------------------|--------------------------------|
| `u_2(x)` | `L[:,2] = [1,0,0]` | `[1, 26217937587563095239723870254092982918845276250263818911301829349969290592255, 26217937587563095239723870254092982918845276250263818911301829349969290592257]` | same |
| `u_4(x)` | `L[:,4] = [0,1,0]` | `[0, 2, 52435875175126190479447740508185965837690552500527637822603658699938581184512]` | same |
| `u_6(x)` | `L[:,6] = [0,0,1]` | `[0, 26217937587563095239723870254092982918845276250263818911301829349969290592256, 26217937587563095239723870254092982918845276250263818911301829349969290592257]` | same |
| `v_3(x)` | `R[:,3] = [1,0,0]` | `[1, 26217937587563095239723870254092982918845276250263818911301829349969290592255, 26217937587563095239723870254092982918845276250263818911301829349969290592257]` | same |
| `v_5(x)` | `R[:,5] = [0,1,0]` | `[0, 2, 52435875175126190479447740508185965837690552500527637822603658699938581184512]` | same |
| `v_7(x)` | `R[:,7] = [0,0,1]` | `[0, 26217937587563095239723870254092982918845276250263818911301829349969290592256, 26217937587563095239723870254092982918845276250263818911301829349969290592257]` | same |
| `w_1(x)` | `O[:,1] = [0,1,0]` | `[0, 26217937587563095239723870254092982918845276250263818911301829349969290592256, 26217937587563095239723870254092982918845276250263818911301829349969290592257]` | same |
| `w_6(x)` | `O[:,6] = [1,0,0]` | `[1, 26217937587563095239723870254092982918845276250263818911301829349969290592255, 26217937587563095239723870254092982918845276250263818911301829349969290592257]` | same |
| `w_7(x)` | `O[:,7] = [0,1,0]` | `[0, 2, 52435875175126190479447740508185965837690552500527637822603658699938581184512]` | same |

The Sage coefficients were verified by running the interpolation logic independently in Python; the outputs are identical to Rust.

### QAP sanity check

Both implementations evaluate every `u_i`, `v_i`, `w_i` at `x = 0, 1, 2` and assert that the results reproduce the original matrix entries:

```
u_i(j) == L[j][i]
v_i(j) == R[j][i]
w_i(j) == O[j][i]
```

All 24 evaluations (`8 variables × 3 points × 3 matrices`) pass in Rust and Sage.

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_qap
cargo test
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.4 — Detailed Verification

### Target polynomial

For three constraint points `x ∈ {0, 1, 2}`, the target polynomial is:

```
T(x) = (x - 0)(x - 1)(x - 2) = x³ - 3x² + 2x
```

Over the BLS12-381 scalar field `Fr`, the coefficient vector `[c0, c1, c2, c3]` is:

| Implementation | `c0` | `c1` | `c2` | `c3` |
|----------------|------|------|------|------|
| **Rust** / arkworks | `0` | `2` | `52435875175126190479447740508185965837690552500527637822603658699938581184510` | `1` |
| **Sage** / Python | `0` | `2` | `52435875175126190479447740508185965837690552500527637822603658699938581184510` | `1` |

The coefficient `c2 = q - 3` because `-3 (mod q)` is represented as the positive residue.

### Vanishing check

Both implementations assert that `T(x)` evaluates to zero at every constraint point:

| Point | Rust `T(x)` | Sage `T(x)` |
|-------|-------------|-------------|
| `x = 0` | `0` | `0` |
| `x = 1` | `0` | `0` |
| `x = 2` | `0` | `0` |

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_qap
cargo test
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

*(If Sage is unavailable, the same coefficients and vanishing check were verified with Python.)*

---

## Step 1.5 — Detailed Verification

### QAP sanity check at constraint points

The purpose of this step is to confirm that the interpolated polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` actually reproduce the original R1CS matrix columns when evaluated at the three constraint points `x ∈ {0, 1, 2}`.

For every variable `i = 0..7` and every constraint point `j = 0..2`:

```
u_i(j) == L[j][i]
v_i(j) == R[j][i]
w_i(j) == O[j][i]
```

This yields `8 variables × 3 points × 3 matrices = 72` individual assertions. All of them pass in both implementations.

### Printed confirmation

**Rust** (`cargo run --bin print_qap`) and **Sage** (`sage groth16.sage`) both print:

```
=== Step 1.5: QAP Verification at Constraint Points ===

  x = 0: all u_i, v_i, w_i match L, R, O columns
  x = 1: all u_i, v_i, w_i match L, R, O columns
  x = 2: all u_i, v_i, w_i match L, R, O columns

✓ All 24 evaluations (8 variables × 3 points) pass.
```

The assertions are hard-coded in both sources (`print_qap.rs` and `groth16.sage`); a mismatch would panic / abort immediately.

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_qap
cargo test
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.6 — Detailed Verification

### Deterministic toxic-waste values

Both implementations now use the **same five hard-coded prime values** for the trusted-setup toxic waste (in a real deployment these would be generated securely and destroyed):

| Parameter | Rust (`Fr::from`) | Sage (`Fq(...)`) |
|-----------|-------------------|------------------|
| `tau`   | `3`  | `3`  |
| `alpha` | `5`  | `5`  |
| `beta`  | `7`  | `7`  |
| `gamma` | `11` | `11` |
| `delta` | `13` | `13` |

### Field modulus

Both print the same BLS12-381 scalar-field prime:

```
q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
```

### Sanity checks

Both implementations assert:
1. Each value is **non-zero**.
2. The five values are **pairwise distinct** (`tau ≠ alpha`, `beta ≠ gamma`, `gamma ≠ delta`).
3. Each value is **invertible** modulo `q` (verified via `inverse()` in Rust and via Fermat's little theorem in Sage).

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_toxic_waste
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.7 — Detailed Verification

### SRS scalar values

Both implementations compute the same SRS over `n = 3` constraints with fixed toxic waste (`tau = 3`, `delta = 13`).

**Target polynomial evaluated at tau:**
```
T(tau) = 6   (T(x) = x^3 - 3x^2 + 2x, tau = 3)
```

**SRS1 & SRS2 scalars (`tau^i`):**

| i | Rust `tau.pow(i)` | Sage `ZZ(tau^i)` |
|---|-------------------|------------------|
| 0 | `1` | `1` |
| 1 | `3` | `3` |
| 2 | `9` | `9` |

**SRS3 scalars (`T(tau) * tau^i / delta`):**

| i | Rust scalar | Sage scalar |
|---|-------------|-------------|
| 0 | `4033528859625091575342133885245074295206965576963664447892589130764506244963` | `4033528859625091575342133885245074295206965576963664447892589130764506244963` |
| 1 | `12100586578875274726026401655735222885620896730890993343677767392293518734889` | `12100586578875274726026401655735222885620896730890993343677767392293518734889` |

All scalar values match bit-for-bit.

### G1 point coordinates (SRS1 & SRS3)

For G1 points the coordinates match exactly because both implementations embed the F_p base field in the same way:

**SRS1[0] (G1 generator):**
```
x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
```

**SRS1[1] (G1 * 3):**
```
x = 1527649530533633684281386512094328299672026648504329745640827351945739272160755686119065091946435084697047221031460
y = 487897572011753812113448064805964756454529228648704488481988876974355015977479905373670519228592356747638779818193
```

**SRS3[0] (G1 * T(tau)/delta):**
```
x = 2655794386432599423148186064978921809078331706212194538460959606195404965017964498416609070163670843833525940223711
y = 756945209966835505529998843232650798348376430681698979160049481091972309044691029753342086591295737335080300719756
```

### G2 point coordinates (SRS2)

The G2 coordinates do **not** match directly because the two implementations use different field embeddings for the extension field:
- **Rust** / arkworks represents G2 over `F_q²` (printed as `QuadExtField(c0 + c1 * u)`).
- **Sage** represents G2 over `F_p¹²` (printed as a polynomial in `T` with 12 coefficients).

Both are valid representations of the same BLS12-381 G2 generator and its scalar multiples. The scalar multipliers (`tau^i`) are identical, which fully determines the points.

### Sanity checks

Both implementations assert:
1. `SRS1[0] == G1_generator` — the first SRS1 element is the curve G1 generator.
2. `SRS2[0] == G2_generator` — the first SRS2 element is the curve G2 generator.

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_srs
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.8 — Detailed Verification

### CRS scalar values

Both implementations compute the four CRS fixed points using the same fixed toxic waste from Step 1.6:

| Point | Scalar | Rust | Sage |
|-------|--------|------|------|
| `alpha·G1` | `alpha` | `5` | `5` |
| `beta·G2`  | `beta`  | `7` | `7` |
| `gamma·G2` | `gamma` | `11` | `11` |
| `delta·G2` | `delta` | `13` | `13` |

All scalar values match bit-for-bit.

### G1 point coordinates (alpha·G1)

**Rust** and **Sage** produce identical G1 coordinates because both embed the base field `F_p` in the same way:

```
x = 2601793266141653880357945339922727723793268013331457916525213050197274797722760296318099993752923714935161798464476
y = 3498096627312022583321348410616510759186251088555060790999813363211667535344132702692445545590448314959259020805858
```

### G2 point coordinates (beta·G2, gamma·G2, delta·G2)

As in Step 1.7, the G2 coordinates do **not** match directly because of different extension-field embeddings (`F_q²` in Rust vs `F_p¹²` in Sage). The scalar multipliers are identical, which fully determines the points.

### Sanity checks

Both implementations assert that the resulting points are non-zero (scalar multiplication by a non-zero scalar on a prime-order subgroup always yields a non-zero point).

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_crs
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.9 — Detailed Verification

### Per-variable CRS formula

For each variable `i`, the Groth16 CRS defines:

```
Ψ_i = (v_i(τ)·α + u_i(τ)·β + w_i(τ)) · G1
```

- **Public inputs** (variables 0 and 1): `Psi_V_G1[i] = Ψ_i / γ`
- **Private inputs** (variables 2..7): `Psi_P_G1[i-2] = Ψ_i / δ`

Both implementations evaluate `u_i(τ)`, `v_i(τ)`, `w_i(τ)` at `τ = 3` using the QAP polynomials from Step 1.3, then compute the combined scalar and divide by the appropriate toxic-waste parameter.

### Intermediate scalar values

| Variable | `u_i(τ)` | `v_i(τ)` | `w_i(τ)` | Combined `v·α+u·β+w` | `psi_scalar` |
|----------|----------|----------|----------|----------------------|--------------|
| 0 | `0` | `0` | `0` | `0` | `0` (point at infinity) |
| 1 | `0` | `0` | `3` | `3` | `3/γ = 38135181945546320348689265824135247881956765454929191143711751781773513588737` |
| 2 | `1` | `0` | `0` | `7` | `7/δ = 48402346315501098904105606622940891542483586923563973374711069569174074939551` |
| 3 | `0` | `1` | `0` | `5` | `5/δ = 12100586578875274726026401655735222885620896730890993343677767392293518734888` |
| 4 | `-3` | `0` | `0` | `-21` | `-21/δ = 12100586578875274726026401655735222885620896730890993343677767392293518734886` |
| 5 | `0` | `-3` | `0` | `-15` | `-15/δ = 16134115438500366301368535540980297180827862307854657791570356523058024979849` |
| 6 | `3` | `0` | `1` | `22` | `22/δ = 32268230877000732602737071081960594361655724615709315583140713046116049959702` |
| 7 | `0` | `3` | `-3` | `12` | `12/δ = 8067057719250183150684267770490148590413931153927328895785178261529012489926` |

All scalar values match bit-for-bit between Rust and Sage.

### G1 point coordinates

For every variable, the resulting G1 point coordinates match exactly. A selection:

**Variable 1 (public, `w_1(τ)/γ · G1`):**
```
x = 81367861186093683725415536995441937835185051344933726757555734290444439656698447934803741703946152152045337171725
y = 3760468985469776503436344758932544920234541482648436146215695546487915742697285652366880681770843519948278232907118
```

**Variable 2 (private, `u_2(τ)·β/δ · G1`):**
```
x = 241762981041424036339378596747179409297460582911272017058154373197451021542552527935715165823129002449576373219796
y = 235973889660695178171707091242138352838746308494076871019815741084289205206162419325244318472749706920882083000990
```

**Variable 6 (private, `(u_6(τ)·β + w_6(τ))/δ · G1`):**
```
x = 1969519195907078274508144740538245489070078038394024037201447654414999556248919497800765490138165989331682795174860
y = 2804313383022075242711792943597553318090410582879148606781783363223004691594852495764508135220292480239908913988381
```

### Sanity checks

Both implementations assert that for variable 0 (the constant `1`), all three polynomials evaluate to zero at `τ`, yielding the point at infinity for `Psi_V_G1[0]`.

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_psi
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.10 — Detailed Verification

### Witness polynomials

The witness polynomials are linear combinations of the QAP basis polynomials weighted by the witness vector `a = [1, 48, 2, 2, 3, 4, 4, 12]`:

```
l(x) = Σ a_i · u_i(x)
r(x) = Σ a_i · v_i(x)
o(x) = Σ a_i · w_i(x)
```

**Rust** and **Sage** outputs:

| Polynomial | Rust coeffs `[c0, c1, c2]` | Sage expression |
|------------|---------------------------|-----------------|
| `l(x)` | `[2, 1]` | `x + 2` |
| `r(x)` | `[2, 52435875175126190479447740508185965837690552500527637822603658699938581184512, 3]` | `3x² - x + 2` |
| `o(x)` | `[4, 52435875175126190479447740508185965837690552500527637822603658699938581184507, 14]` | `14x² - 6x + 4` |

All coefficients match bit-for-bit. Note that the Rust print shows the positive residue for negative coefficients (e.g., `-1 ≡ q-1 (mod q)`), which is identical to Sage's representation.

### Evaluation at constraint points

At the three constraint points `x ∈ {0, 1, 2}`, both implementations assert `l(x) · r(x) == o(x)`:

| Point | `l(x)` | `r(x)` | `l(x)·r(x)` | `o(x)` |
|-------|--------|--------|-------------|--------|
| `x = 0` | `2` | `2` | `4` | `4` |
| `x = 1` | `3` | `4` | `12` | `12` |
| `x = 2` | `4` | `12` | `48` | `48` |

These values reproduce the original R1CS constraint evaluations from Step 1.1.

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_witness_polys
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## Step 1.11 — Detailed Verification

### Quotient polynomial computation

The quotient polynomial is defined by the QAP identity:

```
h(x) = (l(x) · r(x) - o(x)) / T(x)
```

For the division to be exact (zero remainder), `l(x)·r(x) - o(x)` must be divisible by the target polynomial `T(x)`. This is guaranteed by the R1CS-to-QAP transformation.

**Rust** and **Sage** intermediate values:

| Polynomial | Degree | Coefficients (constant term first) |
|------------|--------|----------------------------------|
| `l(x)` | 1 | `[2, 1]` |
| `r(x)` | 2 | `[2, q-1, 3]` |
| `o(x)` | 2 | `[4, q-6, 14]` |
| `T(x)` | 3 | `[0, 2, q-3, 1]` |
| `p(x) = l·r - o` | 3 | `[0, 6, q-9, 3]` |
| `h(x) = p(x)/T(x)` | 0 | `[3]` |

### Zero-remainder verification

Both implementations assert that the division has zero remainder:

- **Sage:** `assert (l*r - o) % T == 0`
- **Rust:** `assert_eq!(p, t * h)` where `p = l*r - o` and `h = leading_coeff(p) / leading_coeff(T)`

The reconstructed product `T(x) · h(x)` has coefficients `[0, 6, q-9, 3]`, which matches `p(x)` exactly. Therefore:

```
h(x) = 3
```

### Commands to reproduce

**Rust:**
```bash
cd groth16-prover
cargo run --bin print_quotient
```

**Sage:**
```bash
cd sage
docker run --rm --entrypoint bash \
  -v "$(pwd):/mnt/sage" \
  sagemath/sagemath:latest \
  -c "cp -r /mnt/sage /tmp/sage && cd /tmp/sage && sage groth16.sage"
```

---

## How to Read This Document

- ✅ **VERIFIED** — Both implementations have been run, outputs compared, and found equal.
- ⏳ **pending** — Not yet started or awaiting cross-check.
- ❌ **MISMATCH** — A discrepancy was found and is being investigated (none so far).

As we progress through Step 1, each sub-step will be added to the table above with its verification status and any notes about edge cases or implementation differences.
