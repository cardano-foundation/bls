# zeroj Audit — Cross-Check Against Rust / Sage Groth16 Implementation

**Repo:** https://github.com/bloxbean/zeroj (submodule at `zeroj-audit/`)  
**Language:** Java (pure Java + BLST for compression)  
**Curve:** BLS12-381 (same as our Rust / Sage stack)  
**Scope:** Groth16 prover, trusted setup, and on-chain verifier for Cardano

---

## 1. What zeroj Provides

zeroj is a production-grade Java toolkit for zero-knowledge proofs on Cardano. It contains:

| Module | Purpose |
|--------|---------|
| `zeroj-crypto` | Pure Java BLS12-381 curve arithmetic, FFT, MSM, and Groth16 prover |
| `zeroj-onchain-julc` | JULC (Java → UPLC) on-chain verifier validators |
| `zeroj-circuit-dsl` | Circuit DSL + R1CS compiler |
| `zeroj-prover-gnark` | Optional Gnark-based prover backend |

The key classes for Groth16 are:
- `Groth16ProverBLS381` — pure Java prover
- `Groth16SetupBLS381` — single-party trusted setup (dev/test only)
- `Groth16BLS12381Verifier` — JULC spending validator
- `Groth16ProofBLS381` — proof record `(A, B, C)`

---

## 2. Step-by-Step Cross-Check

### 2.1 R1CS Matrices and Witness

**Our approach (Rust / Sage):**
- Hard-coded `L`, `R`, `O` as `[[u64; 8]; 3]`.
- Witness `a = [1, 48, 2, 2, 3, 4, 4, 12]`.
- Sanity check: `(L·a) ∘ (R·a) == O·a`.

**zeroj approach:**
- Circuit DSL (`CircuitBuilder`) generates R1CS constraints dynamically.
- Constraints are sparse maps `Map<Integer, BigInteger>` (wire → coefficient).
- Witness calculated by `circuit.calculateWitness(...)`.
- Prover validates `witness[0] == 1` and length matches `numWires`.

**Agreement:** Both enforce the same R1CS semantics: `A*w × B*w = C*w` element-wise.

**Difference:** zeroj is generic (any circuit via DSL); ours is hard-coded for the 3-constraint multiplication chain.

---

### 2.2 BLS12-381 Scalar Field `Fr`

**Our approach:**
- `ark_bls12_381::Fr` (Montgomery representation).
- Printed modulus `q = 52435875175126190479447740508185965837690552500527637822603658699938581184513`.

**zeroj approach:**
- `MontFr381` — custom Montgomery field implementation for BLS12-381.
- Same modulus (inherited from BLS12-381 standard).

**Agreement:** Both use the same prime field. zeroj's `MontFr381.modulus()` matches our `q` bit-for-bit.

---

### 2.3 & 2.4 Polynomial Interpolation and Target Polynomial

**Our approach:**
- Explicit Lagrange interpolation over points `{0, 1, 2}`.
- Prints coefficient vectors `[c0, c1, c2]` for every `u_i`, `v_i`, `w_i`.
- Target polynomial `T(x) = (x-0)(x-1)(x-2) = x³ - 3x² + 2x`.

**zeroj approach:**
- Uses **FFT over roots of unity** (`FieldFFTBLS381`).
- Does not materialize polynomial coefficients explicitly. Instead:
  1. Evaluates `A*w`, `B*w`, `C*w` at each constraint point (the domain).
  2. Performs coset FFT to get evaluations of `l(x)`, `r(x)`, `o(x)` on a coset.
  3. Computes `h(x)` point-wise on the coset: `h(ω·ζ^i) = (l·r - o) / T`.
  4. Inverse FFT back to coefficient form.
- Target polynomial is implicit: `T(x) = x^N - 1` over the full FFT domain.

> **Remark on FFT over roots of unity vs. dense Lagrange:**
>
> The dense Lagrange approach (our Rust / Sage) builds each column polynomial independently via the classical Lagrange formula. This yields degree-2 polynomials for 3 constraints and is trivial to verify by hand.
>
> The FFT approach (zeroj) works on an evaluation domain of size `N = next_power_of_2(constraints)`. For 3 constraints, `N = 4`. The constraint values are padded to length 4, treated as evaluations on the 4-th roots of unity, and transformed into coefficient form via IFFT. The resulting `u_i(x)` are still degree ≤ 2, but they are expressed in the **monomial basis** `1, x, x², x³` with the extra coefficient forced to zero by the padding.
>
> Both approaches produce the *same* polynomial values at the constraint points; they just travel through different algebraic representations. The FFT path is the production standard because it scales to millions of constraints in `O(N log N)` time, while dense Lagrange is `O(n²)` per column.

**Agreement:** Both compute the same mathematical object — a polynomial that vanishes at the constraint points.

**Difference:**
- Ours is **dense / coefficient-first** (good for pedagogical verification).
- zeroj is **FFT / evaluation-first** (good for performance on large circuits).
- For our 3-constraint circuit, zeroj pads the domain to size 4 (next power of 2).

---

### 2.5 QAP Verification at Constraint Points

**Our approach:**
- After interpolating, we explicitly evaluate `u_i(x)`, `v_i(x)`, `w_i(x)` at `x = 0, 1, 2` and assert they equal the original matrix entries.
- This is a pedagogical sanity check printed as **Step 1.5**.

**zeroj approach:**
- No explicit coefficient-level check. The FFT pipeline implicitly preserves the constraint evaluations because:
  - `l(x)` is the IFFT of the constraint evaluations `A*w`.
  - By construction, `l(ω^i) = (A*w)[i]` for each root of unity `ω^i`.
- Correctness is validated by the final pairing check instead.

**Cross-check feasibility:** We can still verify agreement by:
1. Taking zeroj's R1CS for the same circuit.
2. Running its FFT interpolation.
3. Reconstructing coefficients from the FFT output.
4. Comparing to our hard-coded `u_i`, `v_i`, `w_i`.

*(Not yet done — requires extracting FFT outputs from zeroj's internals.)*

---

### 2.6 Toxic Waste `τ, α, β, γ, δ`

**Our approach:**
- Deterministic RNG (fixed seed) so values are reproducible across runs.
- Printed and hard-coded for cross-checking.

**zeroj approach:**
- `Groth16SetupBLS381.setup()` samples via `SecureRandom` (Java's CSPRNG) by default.
- Single-party setup — explicitly marked **DEV/TEST ONLY**.
- For production, zeroj delegates to `snarkjs` MPC ceremony.

**What we changed for cross-checking:**
- Added `Groth16SetupBLS381.setupDeterministic(...)` which accepts the five scalars externally instead of generating them internally.
- Added `Groth16ProverBLS381.proveDeterministic(...)` which accepts explicit randomizers `r` and `s` (set to `0` for unblinded textbook proofs).

**Agreement:** Both sample 5 random scalars in `Fr`. With the deterministic overloads, the *same* toxic waste can be fed to both implementations.

**Deterministic values chosen for cross-checking:**
```
tau   = 5
alpha = 7
beta  = 11
gamma = 13
delta = 17
```

---

### 2.7 SRS: `G1·tau^i`, `G2·tau^i`, `G1·T(tau)·tau^i/delta`

**Our approach:**
- Explicit scalar multiplication loop: `SRS1[i] = tau^i · G1`.
- `SRS3[i] = T(tau) · tau^i / delta · G1`.
- Prints point coordinates for comparison.

**zeroj approach:**
- Uses **Lagrange basis evaluations at tau** rather than monomial powers.
- `pointsA[s] = u_s(tau) · G1` where `u_s(tau) = Σ_c A_c[s] · L_c(tau)`.
- `pointsH[i]` uses odd-indexed Lagrange basis on a double-sized domain: `L_{2i+1}^{(2N)}(tau) / delta · G1`.

**Agreement:** Both produce the same algebraic SRS — just via different basis representations. The Lagrange basis and monomial basis are linearly related through the FFT matrix.

**Difference:**
- Ours builds monomial SRS (simpler to verify by hand).
- zeroj builds Lagrange SRS (more efficient for FFT-based proving).

---

### 2.8 CRS Fixed Points

**Our approach:**
- `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2` computed directly.

**zeroj approach:**
- Same points computed in `Groth16SetupBLS381.setup()`:
  ```java
  AffineG1 alphaG1 = g1.scalarMul(alpha).toAffine();
  AffineG2 betaG2  = g2.scalarMul(beta).toAffine();
  ```

**Agreement:** Identical construction.

---

### 2.9 Per-Variable CRS: `Psi_V_G1`, `Psi_P_G1`

**Our approach:**
- `Psi_V_G1[i] = (beta·u_i(tau) + alpha·v_i(tau) + w_i(tau)) / gamma · G1` for public inputs.
- `Psi_P_G1[i] = (beta·u_i(tau) + alpha·v_i(tau) + w_i(tau)) / delta · G1` for private inputs.

**zeroj approach:**
- `ic[s]` (public) and `pointsL[j]` (private) are the exact same formulas:
  ```java
  BigInteger icVal = beta*us[s] + alpha*vs[s] + ws[s] * gammaInv mod FR;
  BigInteger lVal  = beta*us[s] + alpha*vs[s] + ws[s] * deltaInv mod FR;
  ```

**Agreement:** Identical formulas.

---

### 2.10 Witness Polynomials `l(x)`, `r(x)`, `o(x)`

**Our approach:**
- `l(x) = Σ a_i · u_i(x)` as dense polynomial addition.
- Prints coefficient vectors.

**zeroj approach:**
- `l(x)` is implicitly represented by the FFT of constraint evaluations.
- No explicit coefficient vector printed; the prover works entirely in evaluation form until the final MSM.

**Agreement:** Same algebraic object, different representation.

---

### 2.11 Quotient Polynomial `h(x)`

**Our approach:**
- Dense polynomial division: `h = (l*r - o) / T`.
- Asserts zero remainder.

**zeroj approach:**
- Coset FFT division:
  ```java
  var aCoset = cosetFFT(aEval, inc);
  var bCoset = cosetFFT(bEval, inc);
  var cCoset = cosetFFT(cEval, inc);
  // h(coset_i) = (a*b - c) / T(coset_i)
  ```
- No explicit remainder check (division is exact by construction on the coset).

**Agreement:** Both compute `h(x) = (l·r - o) / T`.

**Difference:** zeroj uses the optimized coset FFT path; ours uses dense polynomial division for clarity.

---

### 2.12–2.14 Proof Elements `A`, `B`, `C`

**Our approach:**
- `A = l(tau)·G1 + alpha·G1`
- `B = r(tau)·G2 + beta·G2`
- `C = Σ private a_i · Psi_P_G1 + h(tau)·T(tau)/delta · G1`

**zeroj approach:**
- `piA` (A): `alphaG1 + Σ witness[i]·pointsA[i] + r·deltaG1`
- `piB` (B): `betaG2 + Σ witness[i]·pointsB2[i] + s·deltaG2`
- `piC` (C): `H + L + s·piA + r·piB1 - r·s·deltaG1`
  - Where `piB1` is the G1 version of B (used for cross-term).

**Agreement:** Both follow the standard Groth16 proof construction with randomizers `r` and `s`.

**Difference:** zeroj includes the randomizers `r` and `s` by default (production-style). Our initial Sage/Rust tests use `r = s = 0` for deterministic cross-checking, matching the simpler `A = l(tau)·G1 + alpha·G1` formula.

---

### 2.15 Public-Input Commitment `V`

**Our approach:**
- `V = a_0·Psi_V_G1[0] + a_1·Psi_V_G1[1]` (MSM over public inputs).

**zeroj approach:**
- On-chain verifier recomputes `vk_x = IC[1] + Σ input[i] * IC[i+1]`.
- Off-chain test `compressVk()` builds the same IC vector from setup.

**Agreement:** Identical MSM formula.

---

### 2.16 Pairing Check

**Our approach:**
- `e(A, B) == e(alpha·G1, beta·G2) · e(V, gamma·G2) · e(C, delta·G2)`
- Verified in Rust with `ark_ec::pairing` and in Sage with `atePairing`.

**zeroj approach:**
- On-chain JULC validator calls `Groth16BLS12381Lib.verify(...)` which performs the same pairing equation using Cardano's BLS12-381 builtins.
- Test `Groth16BLS12381PureJavaProverTest` proves in Java, compresses points with BLST, passes them to the JULC VM, and asserts on-chain verification succeeds.

**Agreement:** Identical pairing equation.

**Difference:** zeroj's verifier runs inside a JULC-compiled Plutus V3 validator on the Cardano test VM; ours runs in Rust (`ark-bls12-381`) and Sage (`atePairing`). All three should agree on the same `GT` element.

---

## 3. Architectural Comparison

| Concern | Our Rust / Sage | zeroj Java |
|---------|-----------------|------------|
| **Curve** | BLS12-381 | BLS12-381 ✅ |
| **Circuit definition** | Hard-coded matrices | Circuit DSL → R1CS |
| **Interpolation** | Dense Lagrange (pedagogical) | FFT over roots of unity (performant) |
| **Trusted setup** | Deterministic test RNG | `SecureRandom` (dev); snarkjs MPC (prod) |
| **Prover** | Rust / arkworks | Pure Java + Pippenger MSM |
| **Serialization** | ark-serialize canonical | BLST compressed |
| **On-chain verifier** | Planned Aiken validator | JULC (Java → UPLC) validator ✅ working |
| **End-to-end test** | Rust proves + Rust verifies | Java proves + JULC VM verifies ✅ |

---

## 4. Deterministic Cross-Check Test

We added a dedicated JUnit test inside the `zeroj-audit` submodule that feeds zeroj **exactly** our circuit, witness, and deterministic toxic waste:

**Test class:** `DeterministicCrossCheckTest.java`

| Parameter | Value |
|-----------|-------|
| Circuit | 3 constraints, 8 wires (multiplication chain) |
| Witness | `[1, 48, 2, 2, 3, 4, 4, 12]` |
| Toxic waste | `tau=5, alpha=7, beta=11, gamma=13, delta=17` |
| Randomizers | `r=0, s=0` (unblinded textbook proof) |

The test prints:
- Witness vector
- Proof points `A` (G1), `B` (G2), `C` (G1) — uncompressed hex coordinates
- IC points (public-input commitment bases)
- Fixed VK points (`alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2`)

### Next step: reproduce in Rust / Sage

To perform the bit-for-bit comparison:
1. Implement deterministic toxic waste in `groth16-prover` (Step 1.6).
2. Feed the **same** scalars (`tau=5, alpha=7, beta=11, gamma=13, delta=17`) into the Rust setup.
3. Generate the proof with `r=0, s=0`.
4. Print `A`, `B`, `C`, and IC coordinates.
5. Assert equality with the Java output from `DeterministicCrossCheckTest`.

Because both implementations use the **same curve** (BLS12-381) and the **same algebraic formulas**, the coordinates must match exactly when the inputs are identical.

---

## 5. Files Referenced

### zeroj upstream (submodule at `zeroj-audit/`)

| File | Description |
|------|-------------|
| `zeroj-crypto/.../Groth16ProverBLS381.java` | Pure Java prover (coset FFT path) |
| `zeroj-crypto/.../Groth16SetupBLS381.java` | Trusted setup (Lagrange basis SRS) |
| `zeroj-crypto/.../Groth16ProvingKeyBLS381.java` | Proving key record |
| `zeroj-onchain-julc/.../Groth16BLS12381Verifier.java` | JULC on-chain validator |
| `zeroj-onchain-julc/.../Groth16BLS12381PureJavaProverTest.java` | E2E test: Java prove → JULC verify |

### Audit additions (local modifications inside submodule)

| File | Description |
|------|-------------|
| `zeroj-crypto/.../Groth16SetupBLS381.java` | Added `setupDeterministic(...)` overload |
| `zeroj-crypto/.../Groth16ProverBLS381.java` | Added `proveDeterministic(...)` overload |
| `zeroj-onchain-julc/.../DeterministicCrossCheckTest.java` | Deterministic cross-check test |

---

## 6. Summary

zeroj is a **valuable third reference** for our Groth16 implementation:

- It uses the **same curve** (BLS12-381) and the **same pairing equation**.
- Its prover uses FFT/Lagrange basis rather than dense monomials, which is the production-standard approach.
- It already has a **working on-chain verifier** compiled from Java to UPLC (JULC), giving us confidence that the verifier logic we plan to write in Aiken is sound.
- We have **injected deterministic toxic waste** into zeroj (`setupDeterministic`) and added a matching unblinded prover (`proveDeterministic`), removing the last barrier to a bit-for-bit cross-check.

**Current status:**
- ✅ zeroj side ready — `DeterministicCrossCheckTest` prints proof + VK coordinates for the fixed circuit and fixed toxic waste.
- ⏳ Rust / Sage side pending — need to implement Step 1.6 (deterministic toxic waste) and generate the same proof points for comparison.

**Recommendation:** Complete Step 1.6 in `groth16-prover`, feed it the exact same deterministic scalars (`tau=5, alpha=7, beta=11, gamma=13, delta=17`), and assert that the resulting uncompressed `A`, `B`, `C`, and IC coordinates match the Java output byte-for-byte.
