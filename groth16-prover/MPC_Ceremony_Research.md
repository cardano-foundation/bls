# MPC Ceremony Plan for Groth16 Trusted Setup

> **Context.** This document analyzes how to replace our current **single-party** trusted-setup ceremony with a **multi-party computation (MPC)** ceremony, and what that means for the Circom → Rust CLI → Aiken verifier pipeline.

---

## 1. Current State

### What the single-party ceremony does today

The `groth16-prover ceremony` command (in `src/ceremony.rs` and `cli/src/cmd/ceremony.rs`) currently:

1. Generates five random scalars (`tau`, `alpha`, `beta`, `gamma`, `delta`) using `rand::thread_rng()` (ChaCha12 CSPRNG)
2. Evaluates the QAP polynomials at `tau` to get per-variable scalars `u_i(tau)`, `v_i(tau)`, `w_i(tau)`
3. Computes group elements:
   - `alpha·G1`, `beta·G2`, `gamma·G2`, `delta·G2` — CRS fixed points
   - `ic[i] = gamma_inv·(beta·u_i(tau) + alpha·v_i(tau) + w_i(tau))·G1` — public-input commitment points (stored in the VerifyingKey)
4. Writes a `ProvingKey` file that **contains the raw scalars** plus the `VerifyingKey`

### How the prover uses the proving key today

The `prove` command (in `cli/src/cmd/prove.rs`) loads the `ProvingKey` and extracts the raw scalars:

```rust
let tau    = pk.toxic_waste.tau;
let alpha  = pk.toxic_waste.alpha;
let beta   = pk.toxic_waste.beta;
let gamma  = pk.toxic_waste.gamma;
let delta  = pk.toxic_waste.delta;
```

Then the prover recomputes **everything from scratch every proof**:

1. Re-evaluates the QAP at `tau` (`engine.evaluate_qap_at_tau`) to get fresh `u_i(tau)`, `v_i(tau)`, `w_i(tau)` scalars
2. Computes `l(tau) = Σ witness[i]·u_i(tau)` and `r(tau) = Σ witness[i]·v_i(tau)`
3. Computes `A = (l(tau) + alpha)·G1` and `B = (r(tau) + beta)·G2`
4. Computes `psi_scalar_i = (beta·u_i(tau) + alpha·v_i(tau) + w_i(tau))·delta_inv` for private variables
5. Computes `C = Σ private[i]·psi_scalar_i·witness[i]·G1 + h(tau)·T(tau)·delta_inv·G1`
6. Computes `V = Σ public[i]·psi_scalar_i·witness[i]·G1` with `gamma_inv` instead of `delta_inv`

### Why this is wrong for production

- **Toxic waste is stored in a file.** If an attacker reads the `.pk` file, they can forge proofs for that circuit.
- **The prover re-does expensive polynomial evaluation on every proof.** For a circuit with 10,000 variables, evaluating all QAP polynomials at `tau` is `O(n²)` in the dense path (or `O(N log N)` in FFT) — this is ceremony-level work, not per-proof work.
- **No MPC security.** Only one person ever saw the randomness.

---

## 2. What Needs to Change

### 2.1 The proving key must contain group elements, not scalars

In a production Groth16 deployment, the prover never sees `tau`, `alpha`, `beta`, `gamma`, `delta`. Instead, the proving key contains **pre-computed group elements** that the MPC ceremony produced:

| Element | Formula | Purpose |
|---------|---------|---------|
| `alpha_g1` | `alpha·G1` | Proof element A offset |
| `beta_g1` | `beta·G1` | Psi computation (C term) |
| `beta_g2` | `beta·G2` | Proof element B offset |
| `delta_g2` | `delta·G2` | C term pairing check |
| `gamma_g2` | `gamma·G2` | V term pairing check |
| `ic[i]` | `gamma_inv·(beta·u_i + alpha·v_i + w_i)(tau)·G1` | Public-input commitment points (already in VK) |
| `psi_p[i]` | `delta_inv·(beta·u_i + alpha·v_i + w_i)(tau)·G1` | Private-input commitment points |
| `u_tau_g1[i]` | `u_i(tau)·G1` | For computing `l(tau)·G1 = Σ witness[i]·u_tau_g1[i]` via MSM |
| `v_tau_g2[i]` | `v_i(tau)·G2` | For computing `r(tau)·G2 = Σ witness[i]·v_tau_g2[i]` via MSM |
| `h_query[j]` | `delta_inv·tau^j·T(tau)·G1` | For committing the quotient polynomial `h(x)` |

With these pre-computed points, the prover becomes:

```rust
// A = l(tau)·G1 + alpha·G1 = MSM(u_tau_g1, witness) + alpha_g1
let a = msm(&u_tau_g1, witness) + alpha_g1;

// B = r(tau)·G2 + beta·G2 = MSM(v_tau_g2, witness) + beta_g2
let b = msm(&v_tau_g2, witness) + beta_g2;

// C = Σ private[i]·witness[i]·psi_p[i] + h_commitment
let c = msm(&psi_p[2..], &witness[2..]) + h_commitment;

// V = Σ public[i]·witness[i]·ic[i]
let v = msm(&ic[0..n_public], &witness[0..n_public]);
```

No scalars needed. No polynomial evaluation at `tau` needed. The prover is now purely **group arithmetic** (multi-scalar multiplication) which is exactly what Pippenger already does.

### 2.2 The ceremony must be split into two phases

Groth16 MPC ceremonies are universally done in **two phases**:

**Phase 1 — Universal Powers of Tau:**
- Computes the raw SRS: `[tau^j·G1]` and `[tau^j·G2]` for `j = 0..N_max`
- This is **universal** — works for any circuit up to `N_max` constraints
- Uses a sequential MPC protocol (each participant contributes a random `delta` and updates the SRS)
- The result is a single artifact: the **universal SRS file**

**Phase 2 — Circuit-specific contribution:**
- Takes the universal SRS + the circuit R1CS
- Computes `alpha`, `beta`, `gamma`, `delta` (also via random contributions)
- Combines the universal SRS with the circuit-specific randomness to produce:
  - The `VerifyingKey` (public)
  - The `ProvingKey` (secret to the prover, but contains only group elements)

---

## 3. MPC Ceremony Alternatives — Investigation & Trade-offs

### 3.1 Three high-level approaches

| Approach | Description | Phase 1 | Phase 2 | Trusted Assumptions | Complexity | Reference |
|----------|-------------|---------|---------|-------------------|------------|-----------|
| **A. Full two-phase MPC** | Run both Phase 1 (Powers of Tau) and Phase 2 (circuit-specific) as sequential MPC protocols with multiple participants | Custom Rust implementation of sequential contribution protocol | Custom Rust implementation that consumes universal SRS + circuit | At least 1 honest participant in Phase 1 **and** at least 1 honest participant in Phase 2 | **High** — requires implementing the contribution/update/verification math from scratch | [Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau), snarkjs `powersoftau` |
| **B. Reuse existing Phase 1** | Use a publicly available universal SRS (e.g., Ethereum KZG ceremony, Filecoin, or snarkjs's own Powers of Tau), then run only Phase 2 as an MPC | **Skip** — download existing SRS | Custom Rust implementation of Phase 2 MPC | Trust the existing Phase 1 ceremony (widely scrutinized, hundreds of participants) + at least 1 honest participant in our Phase 2 | **Medium** — only need Phase 2 math + SRS parsing | [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony), [Filecoin Phase 1](https://github.com/filecoin-project/filecoin-phase1) |
| **C. Circuit-specific single-MPC** | Skip the universal SRS entirely; run a single MPC that directly produces all circuit-specific group elements | **None** — everything is circuit-specific | A single sequential MPC that updates all per-circuit group elements directly | At least 1 honest participant | **Medium-High** — simpler math than two-phase (no universal SRS), but less reusable; every new circuit needs a fresh ceremony | [Zcash Sapling ceremony](https://z.cash/technology/sapling/) (original approach) |

### 3.2 Detailed comparison

| Dimension | A. Full two-phase MPC | B. Reuse existing Phase 1 | C. Circuit-specific MPC |
|-----------|----------------------|--------------------------|------------------------|
| **Security model** | 1-of-N honesty in Phase 1 **and** 1-of-M honesty in Phase 2 | Trust external Phase 1 + 1-of-M honesty in our Phase 2 | 1-of-M honesty in single ceremony |
| **Ceremony artifacts** | Universal SRS ( Phase 1) + Circuit PK/VK (Phase 2) | Circuit PK/VK only | Circuit PK/VK only |
| **Reusability across circuits** | ✅ High — same Phase 1 SRS reused for any circuit | ✅ High — same external SRS reused for any circuit | ❌ None — new ceremony for every circuit |
| **Implementation effort** | ~2–3 weeks Phase 1 + ~1 week Phase 2 | ~1 week (Phase 2 only) + SRS import | ~1.5 weeks (single protocol) |
| **External dependencies** | None | Must import and validate external SRS format | None |
| **Community trust** | Must bootstrap trust from scratch | Leverages widely-trusted existing ceremony | Must bootstrap trust from scratch |
| **On-chain footprint** | Only VK is on-chain | Only VK is on-chain | Only VK is on-chain |
| **Prover changes needed** | Same for all approaches — prover must switch from scalars to group elements | Same for all approaches | Same for all approaches |
| **CLI changes needed** | Add `phase1` and `phase2` subcommands | Add `phase2` subcommand + `import-srs` | Add `mpc-ceremony` subcommand |
| **Aiken verifier changes** | None — VK structure stays the same | None | None |
| **Best for** | Projects that want full sovereignty and plan many circuits | Projects that want fast deployment with strong existing trust | Projects with few circuits and full sovereignty needs |

### 3.3 What snarkjs does (for reference)

The [snarkjs](https://github.com/iden3/snarkjs) toolkit implements **Approach A** internally:

```bash
# Phase 1 — Powers of Tau
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First" -v
snarkjs powersoftau contribute pot12_0001.ptau pot12_0002.ptau --name="Second" -v
snarkjs powersoftau prepare phase2 pot12_0002.ptau pot12_final.ptau -v

# Phase 2 — Circuit-specific
snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit_0000.zkey
snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="1st Contributor" -v
snarkjs zkey contribute circuit_0001.zkey circuit_0002.zkey --name="2nd Contributor" -v
snarkjs zkey export verificationkey circuit_0002.zkey verification_key.json
```

Key observations:
- Phase 1 produces a `.ptau` file containing the universal SRS (`[tau^j·G1]`, `[tau^j·G2]`)
- Phase 2 consumes the `.ptau` + `.r1cs` to produce a `.zkey` (the proving key with group elements)
- The `.zkey` contains **no scalars** — only group elements
- The `verification_key.json` contains only the VK group elements

### 3.4 What arkworks does (for reference)

The [arkworks](https://arkworks.rs/) `groth16` crate also follows Approach A internally:

```rust
use ark_groth16::Groth16;
use ark_snark::SNARK;

// Phase 1 equivalent: generate_random_parameters does a single-party ceremony
// In production, this would be replaced by MPC parameters
let params = Groth16::<Bls12_381>::generate_random_parameters(circuit, rng)?;

// params.pvk — prepared verifying key (for fast verification)
// params.pk — proving key (group elements only)
```

Arkworks' `ProvingKey` struct (from `ark-groth16`) contains:
- `alpha_g1`, `beta_g1`, `beta_g2`, `delta_g2` — CRS fixed points
- `a_query: Vec<G1Affine>` — `u_i(tau)·G1` for all variables
- `b_g1_query: Vec<G1Affine>` — `v_i(tau)·G1` for all variables
- `b_g2_query: Vec<G2Affine>` — `v_i(tau)·G2` for all variables
- `c_query: Vec<G1Affine>` — `delta_inv·(beta·u_i + alpha·v_i + w_i)(tau)·G1` for all variables
- `h_query: Vec<G1Affine>` — `delta_inv·tau^j·T(tau)·G1` for j=0..deg(h)
- `l_query: Vec<G1Affine>` — subset of `c_query` for public inputs

This is exactly the structure our prover needs to migrate to.

---

## 4. How MPC Changes the Pipeline

### 4.1 Current pipeline (single-party)

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌─────────────┐
│  circuit.   │────▶│   ceremony   │────▶│    prove    │────▶│   verify    │
│  r1cs       │     │ (single RNG) │     │  (scalars)  │     │  (pairing)  │
└─────────────┘     └──────────────┘     └─────────────┘     └─────────────┘
                           │                    │
                           ▼                    ▼
                      circuit.pk           proof.bin
                      circuit.vk           proof.pub
```

**CLI commands today:**

```bash
groth16-prover ceremony --circuit c.r1cs --proving-key c.pk --verifying-key c.vk
groth16-prover prove --circuit c.r1cs --witness w.wtns --proving-key c.pk --out proof.bin
groth16-prover verify --proof proof.bin --public proof.pub --verifying-key c.vk
```

### 4.2 Target pipeline (MPC)

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│  universal  │────▶│  Phase 2 MPC    │────▶│  circuit.pk  │
│  SRS file   │     │  (multi-party)  │     │  circuit.vk  │
└─────────────┘     └─────────────────┘     └──────────────┘
                           ▲
                           │
                    ┌─────────────┐
                    │  circuit.   │
                    │  r1cs       │
                    └─────────────┘

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  circuit.   │────▶│    prove    │────▶│   verify    │
│  r1cs       │     │  (groups)   │     │  (pairing)  │
└─────────────┘     └─────────────┘     └─────────────┘
      │                    │
      ▼                    ▼
witness.wtns          proof.bin
                      proof.pub
```

**CLI commands target (Approach B — reuse existing Phase 1):**

```bash
# One-time: download universal SRS from a trusted source
groth16-prover import-srs --url https://... --out universal.srs

# Per-circuit: run Phase 2 MPC (sequential contributions)
groth16-prover phase2 new --circuit c.r1cs --srs universal.srs --zkey c_0000.zkey
groth16-prover phase2 contribute --zkey-in c_0000.zkey --zkey-out c_0001.zkey --name "Alice"
groth16-prover phase2 contribute --zkey-in c_0001.zkey --zkey-out c_0002.zkey --name "Bob"
groth16-prover phase2 finalize --zkey-in c_0002.zkey --proving-key c.pk --verifying-key c.vk

# Proving (uses group elements, no scalars)
groth16-prover prove --circuit c.r1cs --witness w.wtns --proving-key c.pk --out proof.bin

# Verifying (unchanged)
groth16-prover verify --proof proof.bin --public proof.pub --verifying-key c.vk
```

**Key changes:**
1. **`c.pk` no longer contains scalars** — only group elements (safe to share with the prover)
2. **`c.pk` is much larger** — from ~200 bytes (5 scalars + small VK) to ~MBs (thousands of group elements)
3. **Prover is faster** — no more QAP re-evaluation at `tau`; pure MSM over pre-computed points
4. **Ceremony has two steps** — import universal SRS + run Phase 2 contributions
5. **Aiken verifier unchanged** — VK structure stays the same

### 4.3 What stays the same

| Component | Change? | Notes |
|-----------|---------|-------|
| Circom compilation | ❌ No | `circom *.circom --r1cs --wasm --prime bls12381` unchanged |
| Witness generation (snarkjs) | ❌ No | `snarkjs wtns calculate` unchanged |
| `.r1cs` format | ❌ No | Same binary format |
| `.wtns` format | ❌ No | Same binary format |
| Aiken verifier | ❌ No | VK contains same group elements |
| Proof format | ❌ No | Same 192-byte `A + B + C` |
| Public-input format | ❌ No | Same 48-byte `V` |
| Pairing equation | ❌ No | Same `e(A,B) = e(alpha·G1, beta·G2)·e(C, delta·G2)·e(V, gamma·G2)` |

---

## 5. Implementation Roadmap

### Phase 0: Prover migration (scalars → group elements)

**Priority: Critical — blocks everything else**

1. **Define `FullProvingKey` struct** containing:
   - `vk: VerifyingKey` (existing)
   - `alpha_g1: G1Affine`, `beta_g1: G1Affine`, `beta_g2: G2Affine`, `delta_g2: G2Affine`
   - `a_query: Vec<G1Affine>` — `u_i(tau)·G1`
   - `b_g1_query: Vec<G1Affine>` — `v_i(tau)·G1` (for A-term, if needed)
   - `b_g2_query: Vec<G2Affine>` — `v_i(tau)·G2`
   - `c_query: Vec<G1Affine>` — `delta_inv·(beta·u_i + alpha·v_i + w_i)(tau)·G1`
   - `h_query: Vec<G1Affine>` — `delta_inv·tau^j·T(tau)·G1`
   - `l_query: Vec<G1Affine>` — public-input subset of `c_query`

2. **Update `Prover` trait** to accept `&FullProvingKey` instead of raw scalars

3. **Rewrite `NaiveProver` and `PippengerProver`** to use MSM over pre-computed points
   - `A = MSM(a_query, witness) + alpha_g1`
   - `B = MSM(b_g2_query, witness) + beta_g2`
   - `C = MSM(c_query[private], witness[private]) + MSM(h_query, h_coeffs)`
   - `V = MSM(l_query, witness[public])`

4. **Add a `single_party_ceremony_full` function** that produces the `FullProvingKey` + `VerifyingKey` from scalars (bridge between old and new)

5. **Update CLI `prove` command** to load `FullProvingKey` and call the new prover

6. **Test parity** — old scalar-based prover and new group-element prover must produce identical proofs for the same toxic waste

### Phase 1: Phase 2 MPC (circuit-specific)

**Priority: High — enables multi-party security**

1. **Design contribution protocol**:
   - Participant generates random `alpha`, `beta`, `gamma`, `delta`, `tau`
   - Participant updates all group elements in the proving key
   - Participant produces a **contribution proof** (a hash chain + zero-knowledge proof of knowledge of their randomness)

2. **Implement `phase2 new`** — takes `.r1cs` + universal SRS → produces initial `zkey_0000.zkey`

3. **Implement `phase2 contribute`** — takes `zkey_in.zkey` + participant entropy → produces `zkey_out.zkey` with updated group elements and a contribution hash

4. **Implement `phase2 verify`** — validates that all contributions are well-formed (no participant learned the combined randomness)

5. **Implement `phase2 finalize`** — takes final `zkey_n.zkey` → produces `circuit.pk` + `circuit.vk`

### Phase 2: Phase 1 MPC (universal SRS)

**Priority: Medium — only if we don't reuse an existing SRS**

1. **Implement `powersoftau new`** — generates initial SRS `G1` and `G2` with `tau = 1`
2. **Implement `powersoftau contribute`** — participant contributes random `delta`, updates `[tau^j·G1]` and `[tau^j·G2]`
3. **Implement `powersoftau verify`** — validates contributions
4. **Implement `powersoftau prepare phase2`** — applies random beacon to finalize the universal SRS

### Phase 3: Integration & documentation

**Priority: Medium**

1. **Update all READMEs** with new CLI commands and pipeline diagrams
2. **Add MPC ceremony tests** with mock participants
3. **Document security assumptions** (1-of-N honesty, entropy sources, etc.)
4. **Add SRS import command** for reusing external Phase 1 ceremonies

---

## 6. Recommended Path Forward

Given our project context (didactic but moving toward production, Cardano ecosystem, BLS12-381), the **recommended approach is B + C hybrid**:

1. **Short-term (this month):** Implement Phase 0 (prover migration to group elements). This is purely internal refactoring — no MPC yet — but it makes the prover production-ready (no scalars in proving key).

2. **Medium-term:** Implement Phase 1 (circuit-specific Phase 2 MPC). Skip Phase 1 MPC initially by using a **single-party Phase 2** from an imported universal SRS. The Ethereum KZG ceremony or snarkjs's Perpetual Powers of Tau both provide BLS12-381-compatible universal SRS files.

3. **Long-term:** If sovereignty is required, implement Phase 2 (our own Phase 1 MPC). This is a large undertaking and should only be done if we cannot trust any existing universal SRS.

This gives us:
- ✅ Production-grade prover (no toxic waste in `.pk`)
- ✅ Multi-party security for circuit-specific randomness
- ✅ Fast path to deployment (reuse existing Phase 1)
- ✅ Option to bootstrap our own Phase 1 later

---

## 7. References

1. [Groth16 paper](https://eprint.iacr.org/2016/260.pdf) — original zk-SNARK construction
2. [Arkworks groth16 crate](https://docs.rs/ark-groth16/latest/ark_groth16/) — production reference implementation
3. [Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) — universal SRS ceremony
4. [snarkjs powersoftau](https://github.com/iden3/snarkjs/blob/master/src/powersoftau.js) — JavaScript reference
5. [Zcash Sapling ceremony](https://z.cash/technology/sapling/) — original Groth16 MPC
6. [Filecoin trusted setup](https://github.com/filecoin-project/filecoin-phase1) — large-scale Phase 1
7. [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony) — modern BLS12-381 SRS ceremony
8. [Arkworks Phase 2](https://github.com/arkworks-rs/cryptocontexts) — circuit-specific contribution math
