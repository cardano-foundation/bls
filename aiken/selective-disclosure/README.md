# Selective Disclosure with Hidden Transaction Address

> **One-line summary:** A credential holder proves they satisfy a predicate (age, role, residency) without revealing their identity, address, or any credential field. Authorization comes from a zero-knowledge proof verified by an Aiken Gate Script on Cardano.

---

## Table of Contents

1. [Overview](#overview)
2. [Design](#design)
3. [Step 0: Proof System Implementation (Prerequisite)](#step-0-proof-system-implementation-prerequisite)
4. [Step 1: Predicate Proofs with Aiken](#step-1-predicate-proofs-with-aiken)
5. [Step 2: Twisted ElGamal Extension](#step-2-twisted-elgamal-extension)
6. [Step 3: Privacy Pools & Shielded Transactions](#step-3-privacy-pools--shielded-transactions)
7. [Step 4: Future Directions](#step-4-future-directions)
8. [Compliance & Auditability](#compliance--auditability)
9. [Threat Model & Deployment](#threat-model--deployment)
10. [References](#references)

---

## Overview

This pattern enables a credential holder to prove they satisfy specific predicates (age, role, membership, etc.) without revealing:

1. The underlying credential fields
2. Their blockchain address or identity
3. Any link between separate transactions

The authorization to spend or access a resource comes from a **zero-knowledge proof** rather than a direct signature from a known address.

> **Design principle: Data minimization.** Inspired by the W3C Verifiable Credentials data model and the Panther Protocol principle that "the protocol verifies only what's required — nothing more," the system follows the principle that the holder should share *no more information than strictly necessary*. In this design, the holder does not reveal individual claims at all — they reveal only the truth value of a predicate computed over those claims.

---

## Design

<details>
<summary><b>Expand</b></summary>

### Actors

| Actor | Role |
|-------|------|
| **Issuer** | Signs a rich credential (multiple fields) and publishes commitment roots (e.g., approved country sets, revocation lists) |
| **Holder** | Receives the credential, generates predicate proofs, submits transactions without exposing identity |
| **Verifier / Gate** | A Cardano script that releases funds or grants access when presented with a valid proof |
| **Relayer (optional)** | Submits transactions on behalf of the holder; cannot forge proofs |

### Architecture

```
Issuer ──signed credential──▶ Holder
        ──published roots───▶ (Merkle roots, revocation lists)

Holder ──predicate proof───▶ Gate Script (parameterized by vk)
                               └── verifies proof on-chain ──▶ release resource
```

The holder's proof is generated **locally** on their device. The script never checks an address, staking key, or known signature — only the mathematical validity of the proof.

### Off-Chain Flow

1. **Credential Issuance:** The issuer creates a credential, computes `claimsCommitment = Hash(field_1, ..., field_n)`, signs it, and delivers the bundle privately to the holder. Published roots (approved sets, revocation lists) are made public.
2. **Predicate Proof Generation:** The holder generates a ZK proof locally. Public inputs (visible on-chain) include issuer public key, timestamp, Merkle roots, and an `eligible` flag. Private inputs (never revealed) include all credential fields, issuer signature, Merkle witnesses, and reduction witnesses.
3. **Transaction Construction:** The holder (or relayer) builds a transaction spending a UTxO locked at the Gate Script, providing the proof in the **redeemer**. The holder's blockchain address is **not** included in the datum or redeemer.

### On-Chain Flow

```
Phase 1: Funding
  Someone locks funds at Gate Script
  Datum: unit (no identity data)

Phase 2: Unlocking
  Holder submits unlock tx
  Redeemer: proof + public inputs
  Script verifies proof → releases funds
```

### Privacy Properties

| Property | How It Is Achieved |
|----------|-------------------|
| **Credential fields hidden** | All fields are private inputs; only the predicate result is public |
| **Transaction address hidden** | The script does not require or verify any holder address |
| **Anonymity set** | Any valid proof can unlock any UTxO at the same Gate Script |
| **Unlinkable proofs** | Proofs against different circuits are cryptographically independent |
| **No external services** | Verification is self-contained; no oracles or registries needed |

### Example Workflows

**Anonymous Access:** Alice holds a credential `(dob: 1990, country: DEU, role: Doctor)`. She generates a proof that `role == Doctor AND age ≥ 30`, submits it to the Healthcare Portal's Gate Script, and gains access without revealing her identity, birth year, or address.

**Cross-Border Reuse:** Bob uses the same residency credential to generate two different proofs for a Banking DApp (`age ≥ 21 AND country ∈ {DEU, FRA, GBR}`) and an Insurance DApp (`age ≥ 25 AND country ∈ {DEU, NLD}`). Neither learns his exact age or country, and neither can link the two transactions.

</details>

---

## Step 0: Proof System Implementation (Prerequisite)

<details>
<summary><b>Expand</b></summary>

Before any selective-disclosure flow can run end-to-end, we need a working proof system over BLS12-381 split into an off-chain prover and an on-chain verifier.

| Path | Off-chain prover | On-chain verifier | Trusted setup | Proof size | Status |
|------|-----------------|-------------------|---------------|------------|--------|
| **A — Groth16** | `circom` + [`groth16-prover`](../../groth16-prover/README.md) (Rust/arkworks) | [`aiken/groth16`](../../aiken/groth16/README.md) (pairing check) | Per-circuit Phase-2 | 192 bytes | ✅ Working e2e |
| **B — Nova IVC** | [`nova-slim`](../../../nova-slim/README.md) (Rust, folding) + Circom step circuits | [`nova-slim/cardano/nova-slim-verifier/`](../../../nova-slim/cardano/) (sumcheck verification) | None (transparent) | ~0.4–2.5 KiB slim | ✅ Working e2e |

**Path A** is the reference implementation: Circom circuits → R1CS → Rust Groth16 prover → Aiken on-chain pairing check.

**Path B** uses [`nova-slim`](../../../nova-slim/README.md): the predicate is decomposed into identical step circuits, the holder folds N steps off-chain into a single compressed proof, and the on-chain verifier checks a sumcheck argument. No trusted setup; proof size is ~0.4–2.5 KiB depending on step-circuit size.

Both paths use BLS12-381 and the same Circom circuit infrastructure. The key trade-off is **proof size vs. flexibility**: Groth16 gives 192-byte proofs but requires a separate circuit per predicate; Nova gives ~0.4–2.5 KiB proofs but allows predicate composition by folding different step circuits.

### When to Use Which

| Consideration | Groth16 (Path A) | Nova IVC (Path B) |
|---------------|-----------------|-------------------|
| **Proof size** | 192 bytes | ~0.4–2.5 KiB |
| **On-chain cost** | ~20% of script CPU (pairing check) | ~25% of script CPU (sumcheck verify) |
| **Trusted setup** | Per-circuit Phase-2 ceremony | None |
| **Predicate composition** | One circuit per predicate combination | Fold different step circuits freely |
| **Proof generation** | Single-shot (prover → proof) | Sequential folding (N steps → compress) |
| **Best for** | Fixed predicates, minimal on-chain cost | Dynamic predicates, credential composition |

### Ingredient Inventory (Path A)

The Step 1 predicate circuit requires five cryptographic primitives:

| Primitive | Needed for | Status | Source |
|-----------|-----------|--------|--------|
| **Poseidon hash (BLS12-381)** | `claims_msg = Poseidon(dob_year, country)`, Merkle tree nodes | ✅ Working e2e | `circom/PoseidonPreimage/poseidon_bls12_381.circom` |
| **Range proof** | `assert dob_year <= current_year - 21` | ✅ Working e2e | `circom/RangeProof/range_proof_simple.circom` |
| **Merkle verify (Poseidon-based)** | `Merkle_Verify(country, country_root, merkle_proof)` | ✅ Working e2e | `circom/PoseidonMerkle/poseidon_merkle.circom` |
| **EdDSA verify (JubJub)** | `EdDSA_Verify(issuer_pk, claims_msg, signature)` | ✅ Working e2e | `circom/EdDSAJubJub/eddsa_jubjub.circom` |
| **Groth16 prover + Aiken verifier** | All steps | ✅ Working e2e | `groth16-prover/` + `aiken/groth16/` |

### Quick-Start: Groth16 (Path A)

1. Compile a Circom circuit → `.r1cs` + `.wasm`
2. Generate a witness with `snarkjs` → `.wtns`
3. Run a dev ceremony with the Rust CLI → `.pk` + `.vk`
4. Generate a proof with the Rust CLI → `proof.bin`
5. Export the VK to Aiken → `.ak` source file
6. Verify in Aiken — paste the proof bytes into an Aiken test or validator

See [`aiken/groth16/README.md`](../../aiken/groth16/README.md) and [`circom/README.md`](../../circom/README.md) for step-by-step commands.

### Quick-Start: Nova IVC (Path B)

1. **Prepare step witnesses** — one JSON per step
2. **Fold** — `nova-slim fold --circuit <step.r1cs> --steps <witness-dir> --out <fold.json>`
3. **Compress** — `nova-slim compress --slim --ivc <fold.json> --out <proof.cbor>`
4. **Verify** — `nova-slim verify --ivc <fold.json> --slim-proof <proof.cbor>`
5. **On-chain** — the slim proof is submitted as a redeemer; the Aiken sumcheck verifier checks it

See [`nova-slim/README.md`](../../../nova-slim/README.md) and [`nova-slim/cardano/`](../../../nova-slim/cardano/) for details.

</details>

---

## Step 1: Predicate Proofs with Aiken

<details>
<summary><b>Expand</b></summary>

The simplest valid end-to-end flow: one issuer signs a two-field credential (`dobYear`, `country`), the holder generates a proof that `age >= 21 AND country in approved set`, and an Aiken Gate Script verifies the proof on-chain before releasing locked ADA.

```mermaid
graph LR
    subgraph OffChain["Off-Chain"]
        P1["Phase 1: Trusted Setup<br/>Circuit → R1CS → SRS → vk + pk"]
        P2["Phase 2: Issuance<br/>Issuer signs credential"]
        P5["Phase 5: Proof Generation<br/>Holder generates ZK proof"]
    end
    subgraph OnChain["On-Chain (Cardano)"]
        P3["Phase 3: Deploy Gate<br/>Aiken validator (vk)"]
        P4["Phase 4: Fund Gate<br/>Lock ADA at script"]
        P6["Phase 6: Unlock tx<br/>Script verifies proof → releases"]
    end
    P1 --> P3
    P2 --> P5
    P3 --> P4
    P5 --> P6
    P4 --> P6
```

---

### Path A: Groth16

#### Phase 1 — Trusted Setup & Circuit Compilation (Off-Chain)

The predicate circuit is compiled and a trusted setup ceremony is run to produce the proving key (`pk`) and verifying key (`vk`).

**Data created:** `proving_key` (holder use, off-chain), `verifying_key` (embedded in Gate Script), `circuit_hash` (cache validation).

**Example circuit (pseudocode):**
```
Public:  issuer_pk, current_year, country_root, eligible
Secret:  dob_year, country, signature, merkle_proof

1. claims_msg = Poseidon(dob_year, country)
2. EdDSA_Verify(issuer_pk, claims_msg, signature)
3. assert dob_year <= current_year - 21
4. Merkle_Verify(country, country_root, merkle_proof)
5. assert eligible == 1
```

#### Phase 2 — Credential Issuance (Off-Chain)

The issuer creates a credential, hashes its fields, signs the hash, and delivers the bundle privately to the holder. The issuer also publishes the approved-country Merkle root.

**Important:** The credential bundle lives entirely off-chain in the holder's wallet. Only the `country_root` needs to be publicly available.

#### Phase 3 — Deploy Gate Script (On-Chain)

An Aiken validator parameterized with the verifying key (`vk`) from Phase 1 is compiled and deployed to Cardano as a Plutus V3 script.

```aiken
validator gate(
  vk_alpha: ByteArray,
  vk_beta: ByteArray,
  vk_gamma: ByteArray,
  vk_delta: ByteArray,
  vk_ic: List<ByteArray>,
) {
  fn spend(_datum: Void, redeemer: ProofRedeemer, _ctx: ScriptContext) -> Bool {
    expect redeemer.eligible == #[1]
    let public_inputs = [
      redeemer.pk_u, redeemer.pk_v,
      redeemer.current_year, redeemer.country_root, redeemer.eligible,
    ]
    groth16_verify_bls12_381(public_inputs, redeemer.pi_a, redeemer.pi_b, redeemer.pi_c,
      vk_alpha, vk_beta, vk_gamma, vk_delta, vk_ic)
  }
}
```

**Data created:** `script_hash` (Gate address derivation), `gate_address` (where funds are locked).

#### Phase 4 — Fund the Gate (On-Chain)

Anyone locks ADA at the Gate script address. The datum is a unit (`()`), carrying no identity information. The funder's address is visible but irrelevant to the eventual holder.

#### Phase 5 — Proof Generation (Off-Chain)

The holder uses their credential, issuer signature, published `country_root`, and `proving_key` to generate a zero-knowledge proof entirely on their device.

**Public inputs (on-chain redeemer):** `issuer_pk.u`, `issuer_pk.v`, `current_year`, `country_root`, `eligible = 1`

**Private inputs (never leave holder's device):** `dob_year`, `country`, `signature.r`, `signature.s`, `k_mod_l`, `k_quotient`, `merkle_siblings`, `merkle_path_bits`

**Data created:** `pi_a` (G1, 48 B), `pi_b` (G2, 96 B), `pi_c` (G1, 48 B), public inputs.

#### Phase 6 — Unlock Transaction (On-Chain)

The holder (or relayer) constructs a transaction spending the locked UTxO. The proof and public inputs are in the **redeemer**. The Gate script validates and releases funds.

**Privacy outcome:** An observer sees that *someone* produced a valid proof. They cannot determine:
- Who the holder is
- The holder's birth year or country
- Whether this is the same person who used another gate yesterday

#### Is Groth16 on Cardano Actually Feasible?

**Yes.** Cardano's Plutus V3 has native BLS12-381 support: `bls12_381_G1_element`, `bls12_381_G2_element`, `bls12_381_millerLoop`, `bls12_381_finalVerify`, and scalar field operations.

| Concern | Reality |
|---------|---------|
| **Curve support** | Built-ins added specifically for ZK proof verification |
| **Verifier complexity** | ~3 Miller loops + 1 final pairing check + G1 MSMs; maps directly to Plutus V3 built-ins |
| **Execution budget** | A full Groth16 verification with 5 public inputs fits comfortably within current per-transaction limits |
| **Trusted setup** | Standard zkSNARK infrastructure; `vk` is a few kilobytes embedded as validator parameters |
| **Proving** | Entirely off-chain in the holder's wallet |

---

### Path B: NovaSlim e2e

Below is a complete end-to-end run of the same predicate flow using [`nova-slim`](../../../nova-slim/README.md). All commands assume you are in the `bls/` repo root and `nova-slim` is built as a sibling directory.

```bash
# Build the nova-slim CLI (one time)
cargo build --release --manifest-path ../nova-slim/cli/Cargo.toml
NOVA=../nova-slim/cli/target/release/nova-slim
```

#### Phase 1 — Compile the step circuit & prepare witnesses (off-chain)

```bash
cd circom/Predicate
circom --prime bls12381 -l ../../node_modules/circomlib/circuits \
  predicate_nova.circom --r1cs --wasm --sym
cd ../..
```

Generate one JSON witness per step. For a composite predicate this is typically 255 steps:

```bash
python3 ../nova-slim/benchmarks/gen_step_witnesses.py \
  --wasm circom/Predicate/predicate_nova_js/predicate_nova.wasm \
  --initial credential_input.json \
  --steps 255 --dir steps/
```

#### Phase 2 — Fold (off-chain)

```bash
$NOVA fold --curve bls12-381 \
  --circuit circom/Predicate/predicate_nova.r1cs \
  --steps steps/ --out predicate.ivc.cbor
```

#### Phase 3 — Compress (off-chain)

```bash
$NOVA compress --slim --curve bls12-381 \
  --ivc predicate.ivc.cbor --out predicate_slim.proof.cbor
```

#### Phase 4 — Verify off-chain (optional)

```bash
$NOVA verify --curve bls12-381 \
  --ivc predicate.ivc.cbor --slim-proof predicate_slim.proof.cbor
```

#### Phase 5 — Deploy Gate Script (on-chain)

Deploy the Aiken validator parameterized with the expected `CircuitParams` and `PredicatePolicy`. The script uses the NovaSlim sumcheck verifier instead of a Groth16 pairing check. See [`aiken/nova`](../../aiken/nova/README.md).

#### Phase 6 — Submit unlock tx (on-chain)

The redeemer contains the slim proof (~1.0 KiB for a 7.7K-constraint step circuit) and public inputs. The Gate Script re-derives Fiat-Shamir challenges on-chain, runs the sumcheck verifier, and releases funds.

</details>

---

## Step 2: Twisted ElGamal Extension

<details>
<summary><b>Expand</b></summary>

Only use this if your use case requires hiding **amounts** (balances, transfer values) in addition to hiding identity. Twisted ElGamal is realizable on Cardano by substituting Ristretto255 with **BLS12-381 G1** — all required operations (point addition, scalar multiplication, negation, equality) are already in Plutus V3. The catch is that messages live in the exponent, so amounts must be split into `u16` limbs and range proofs added to the Groth16 circuit.

**Skip this if your use case is identity-only.** For identity-only selective disclosure (age verification, role checks, residency), encrypted balances are pure overhead.

| Aspect | Step 1 Only | + Twisted ElGamal |
|--------|-------------|-------------------|
| **On-chain state** | Unit datum | Datum stores encrypted G1 points |
| **Circuit complexity** | Signature + Merkle + comparison | Same + ElGamal equations + range decomposition |
| **What is hidden** | Identity + credential fields | Identity + credential fields + amounts |

If you go this route, the composition is: **predicate proof for identity + ElGamal encryption for amounts**, verified by a single Groth16 proof checked by the same Aiken Gate Script.

</details>

---

## Step 3: Privacy Pools & Shielded Transactions

Steps 1 and 2 solve two independent problems: (1) hiding identity via predicate proofs, and (2) hiding amounts via Twisted ElGamal. **Step 3 composes both into a single system: a privacy pool where users can deposit, privately transfer, and withdraw funds without revealing their address, identity, or transaction value.**

| Aspect | Step 1 (Predicate Only) | Step 2 (+ ElGamal) | Step 3 (Privacy Pool) |
|--------|------------------------|-------------------|----------------------|
| **What is hidden** | Identity + credential fields | + Amounts | + Transaction graph |
| **On-chain state** | Unit datum | G1 ciphertexts | **Merkle root of note commitments** |
| **Circuit proves** | Signature + Merkle + comparison | + ElGamal + range constraints | **Merkle membership + range proofs + value conservation + nullifier uniqueness** |
| **Anonymity set** | All users of the same Gate | Same | **All users who ever deposited** |

The Pool Script maintains a Merkle root that evolves as notes are spent and created. The circuit is a direct composition of five gadgets already working end-to-end in `circom/`: Poseidon commitments, Merkle verification, range proofs, value conservation, and nullifier hashing. See [`groth16-prover/docs/F5_RESEARCH_DIRECTION.md`](../../groth16-prover/docs/F5_RESEARCH_DIRECTION.md) for the full constraint budget (~65K for 2-in/2-out/depth-20).

---

## Step 4: Future Directions

<details>
<summary><b>Expand</b></summary>

The Groth16-based design in Steps 0–3 provides practical, production-ready privacy today, but it relies on elliptic-curve cryptography that is not quantum-resistant. Long-term research directions are to complement or replace the zk-SNARK layer with post-quantum alternatives.

### FHE-Based Selective Disclosure

Fully homomorphic encryption (FHE) enables predicate evaluation on encrypted credential fields by any party. It is believed to be post-quantum but is currently too heavy for on-chain verification. Short term: keep Groth16 for production. Medium term: monitor zk-FHE / FHE-SNARKs that combine homomorphic evaluation with succinct correctness proofs. Long term: migrate predicate gates to FHE-first constructions when lattice-based FHE becomes cheap enough.

References: [LACTv2](https://github.com/jaymine/LACTv2) (lattice-based anonymous credentials); De Salve et al., *IET Information Security*, 2018 (FHE-based selective disclosure).

### STARK / zkVM Quantum-Resistance Path

Hash-based STARKs and zkVM backends (FRI-STARK, RISC Zero) are transparent, natively post-quantum, and verified on-chain by a hash-based verifier. Their cost is proof size (hundreds of KB today) and heavier on-chain verification.

Live production references:
- **CIP-1242 — ZKPoSP** (Botta et al., IACR ePrint 2026/1508): RISC Zero proofs of BIP-32-Ed25519 seed ownership for Cardano HD wallets.
- **Zcash quantum readiness** (CoinDesk Research, June 2026): Three-step path to a fully post-quantum pool with hybrid classical+PQ signatures and hash-based proof hardening.

The Step 1 predicate proof is a natural candidate for staged migration: issue credentials with Groth16 today, and move to a STARK/zkVM backend once proofs are small enough for the Plutus V3 budget. The issuer/holder/Gate Script architecture is unchanged; only the primitive inside the redeemer changes.

### Comparison: CIP-???? Native Confidential Transfers

A parallel proposal aims to hide transaction amounts at the **ledger layer** using Pedersen commitments over ristretto255 and Bulletproofs range proofs. Our research demonstrates that **the same amount confidentiality is achievable within Cardano's existing BLS12-381 primitive set** — without new curves, without new proof systems, and without a hard fork.

| Aspect | CIP-???? (Ledger-Native) | Our Research (Smart-Contract ZK) |
|--------|--------------------------|----------------------------------|
| **Amounts hidden?** | ✅ Yes | ✅ Yes |
| **Identity hidden?** | ❌ No | ✅ Yes |
| **Curve** | ristretto255 (NEW) | BLS12-381 G1 (already live) |
| **Hard fork required** | ✅ Yes | ❌ No |
| **Proof verification cost** | O(n log n) (Bulletproofs) | **O(1)** (Groth16) |
| **Script address support** | ❌ Deferred | ✅ Core architecture |

</details>

---

## Compliance & Auditability

Privacy-by-default does not mean absence of oversight. Production deployments can layer compliance on top without weakening privacy.

| Mechanism | How It Works |
|-----------|--------------|
| **Per-credential auditing** | Issuer encrypts a viewing key to auditor keys at issuance; no per-transaction overhead |
| **Permissioned gates** | Gate Script checks an additional on-chain policy (KYC registry, rate limit, allowlist) alongside the ZK proof |
| **Emergency controls** | Revocation (new Merkle root), global pause (`is_active` flag), freeze (frozen set), coercion resistance (proofs never reveal field values) |
| **Forensic Data Escrow** | Non-sensitive metadata encrypted to a governance multi-sig; decryptable under defined circumstances without exposing credential fields |

---

## Threat Model & Deployment

| Threat | Mitigation |
|--------|-----------|
| Credential theft | Bind credential to a holder secret (commitment in signed message) |
| Proof replay | Add nonce, epoch, or transaction hash as a public input |
| Sybil attacks | Issuer ensures one credential per real-world identity (out of cryptographic scope) |
| Colluding verifiers | Proofs are unlinkable by design |
| Holder coercion | Holder can only be forced to produce (or not produce) a proof; field values remain hidden |

### Deployment Checklist

- [ ] Define credential schema (fields, encoding)
- [ ] Define predicate circuits per use case
- [ ] Run trusted setup (universal Powers of Tau + per-circuit Phase 2)
- [ ] Deploy Gate Scripts parameterized by each circuit's verifying key
- [ ] Publish issuer public key and Merkle roots via trusted channel
- [ ] Implement holder-side proof generation
- [ ] Optional: deploy relayer infrastructure for address-less submission

### Hiding the Fee Payer

For full anonymity, even the transaction fee payer can be hidden via a **relayer network** (relayer pays fees, cannot forge proofs), **stealth addresses** (one-time addresses), or **coin mixing**.

---

## References

1. A. De Salve et al., "Selective disclosure approaches in Self-Sovereign Identity: an experimental comparison," *IEEE Access*, 2025. DOI: [10.1109/ACCESS.2025.3649167](https://doi.org/10.1109/ACCESS.2025.3649167)
2. W3C, *Verifiable Credentials Data Model 2.0*, 2025. https://www.w3.org/TR/vc-data-model-2.0/
3. W3C, *Decentralized Identifiers (DIDs) v1.0*, 2022. https://www.w3.org/TR/did-core/
4. Mysten Labs, *Confidential Transfers on Sui*, 2025. https://github.com/MystenLabs/confidential-transfers
5. Panther Protocol, "Programmable Privacy Is Live," May 2026. https://blog.pantherprotocol.io/programmable-privacy-is-live-panther-protocol-deploys-on-polygon/
6. **LACTv2** — lattice-based anonymous credentials. https://github.com/jaymine/LACTv2
7. A. De Salve, P. Mori, and L. Ricci, "A fully homomorphic encryption based scheme for verifiable credential selective disclosure," *IET Information Security*, 2018. DOI: [10.1049/iet-ifs.2018.5491](https://dl.acm.org/doi/10.1049/iet-ifs.2018.5491)
8. **ZKPoSP** — V. Botta et al., "ZKPoSP: Post-Quantum Zero-Knowledge Proofs for Hierarchical Deterministic Wallets," IACR ePrint [2026/1508](https://eprint.iacr.org/2026/1508); CIP draft in [cardano-foundation/CIPs PR 1242](https://github.com/cardano-foundation/CIPs/pull/1242)
9. CoinDesk Research, "Building the Zcash Machine: Tachyon and Quantum Readiness," June 2026. https://www.coindesk.com/research/building-the-zcash-machine-tachyon-and-quantum-readiness
