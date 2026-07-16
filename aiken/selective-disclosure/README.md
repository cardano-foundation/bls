# Selective Disclosure with Hidden Transaction Address

> **One-line summary:** A credential holder proves they satisfy a predicate (age, role, residency) without revealing their identity, address, or any credential field. Authorization comes from a zero-knowledge proof verified by an Aiken Gate Script on Cardano.

---

## Table of Contents

1. [Overview](#overview)
2. [Research & Context](#research--context)
3. [Design](#design)
4. [Step 0: Groth16 Implementation (Prerequisite)](#step-0-groth16-implementation-prerequisite)
5. [Step 1: Predicate Proofs with Aiken](#step-1-predicate-proofs-with-aiken)
6. [Step 2: Twisted ElGamal Extension](#step-2-twisted-elgamal-extension)
7. [Compliance & Auditability](#compliance--auditability)
8. [Threat Model & Deployment](#threat-model--deployment)
9. [References](#references)

---

## Overview

This pattern enables a credential holder to prove they satisfy specific predicates (age, role, membership, etc.) without revealing:

1. The underlying credential fields
2. Their blockchain address or identity
3. Any link between separate transactions

The authorization to spend or access a resource comes from a **zero-knowledge proof** rather than a direct signature from a known address.

> **Design principle: Data minimization.** Inspired by the W3C Verifiable Credentials data model and the Panther Protocol principle that "the protocol verifies only what's required — nothing more," the system follows the principle that the holder should share *no more information than strictly necessary*. In this design, the holder does not reveal individual claims at all — they reveal only the truth value of a predicate computed over those claims.

---

## Research & Context

**Executive summary:** Traditional selective disclosure (SD-JWT, BBS+, Merkle trees) reveals selected claims in plaintext, which still leaks identity through the disclosed fields. This design moves to **predicate-level zero-knowledge disclosure**, where the holder proves a constraint is satisfied without revealing *any* field values. We draw on SSI literature (IEEE Access survey), Mysten Labs' confidential transfers (per-credential auditing), and Panther Protocol (UTxO anonymity sets, local proof generation) to build a privacy-native authorization layer on Cardano.

<details>
<summary><b>Click to expand: Claim-Level vs Predicate-Level Disclosure</b></summary>

Traditional selective disclosure approaches (as surveyed in SSI literature) fall into five categories:

| Approach | What the holder reveals | Address hiding possible? |
|----------|------------------------|------------------------|
| **Atomic credentials** | One claim per credential; holder picks which credentials to present | No — holder identity is still bound to the presentation |
| **Hash-based** (e.g., SD-JWT) | Selected claims in plaintext + hash verification | No — disclosed claims may contain identifying data |
| **Encryption-based** | Selected claims in plaintext + decryption keys | No — same problem as hash-based |
| **Hash tree-based** (Merkle) | Selected claims in plaintext + Merkle membership proof | No — claims are still revealed |
| **Signature-based** (BBS+) | Selected claims in plaintext + ZK proof of signature | No — while ZK hides undisclosed claims, the disclosed ones may identify the holder |
| **Predicate-level ZK** (this design) | **Only the predicate result** (e.g., `eligible = 1`) | **Yes** — no claims are ever revealed |

The key advancement here is moving from **claim-level selective disclosure** (revealing some fields, hiding others) to **predicate-level zero-knowledge disclosure** (proving a constraint is satisfied without revealing any field values). Because *no claims are disclosed*, the transaction cannot be linked to the holder's identity via the credential contents, and the holder's blockchain address can remain completely hidden.

> **Note on encrypted-balance systems.** A complementary privacy paradigm (e.g., Mysten Labs' [Confidential Transfers on Sui](https://github.com/MystenLabs/confidential-transfers)) uses homomorphic encryption (Twisted ElGamal) to hide *amounts* while sender/receiver addresses remain visible. Predicate-level ZK, by contrast, hides *identity* (no address is checked) while operating on credential fields rather than balances. The two techniques solve different problems and can be composed: a system could require a predicate proof before minting a confidential UTxO, then use encrypted balances for subsequent transfers.

</details>

---

## Design

**Executive summary:** The system has four actors: an Issuer who signs rich credentials and publishes Merkle roots; a Holder who stores the credential locally and generates proofs; a Verifier/Gate which is a Plutus V3 script parameterized by a Groth16 verifying key (written in Aiken or generated via Julc); and an optional Relayer who submits transactions without learning the credential. The holder's proof is generated locally on their device, provided in the transaction redeemer, and verified on-chain. The script never checks an address, staking key, or known signature — only the mathematical validity of the proof.

<details>
<summary><b>Click to expand: Architecture & Actors</b></summary>

### Actors

| Actor | Role |
|-------|------|
| **Issuer** | Signs a rich credential (multiple fields) and publishes commitment roots (e.g., approved country sets, revocation lists) |
| **Holder** | Receives the credential, generates predicate proofs, submits transactions without exposing identity |
| **Verifier / Gate** | A Cardano script that releases funds or grants access when presented with a valid proof |
| **Relayer (optional)** | Submits transactions on behalf of the holder; cannot forge proofs |

### Architecture Diagram

```
┌─────────────┐      signed credential      ┌─────────────┐
│   Issuer    │ ──────────────────────────▶ │   Holder    │
│  (private   │                             │ (stores full│
│   key)      │      published roots        │  credential│
│             │ ──────────────────────────▶ │   + proof  │
└─────────────┘                             │   keys)    │
                                            └──────┬──────┘
                                                   │
                          ┌────────────────────────┼────────────────────────┐
                          │                        │                        │
                          ▼                        ▼                        ▼
              ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
              │  Predicate Proof 1  │  │  Predicate Proof 2  │  │  Predicate Proof N  │
              │  (age ≥ 21 +        │  │  (role == Doctor +  │  │  (any constraint    │
              │   country ∈ set)    │  │   age ≥ 30)         │  │   over credential)  │
              └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
                         │                        │                        │
                         ▼                        ▼                        ▼
              ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
              │   Gate Script 1     │  │   Gate Script 2     │  │   Gate Script N     │
              │   (parameterized    │  │   (parameterized    │  │   (parameterized    │
              │    by proof vk)     │  │    by proof vk)     │  │    by proof vk)     │
              └─────────────────────┘  └─────────────────────┘  └─────────────────────┘
```

</details>

<details>
<summary><b>Click to expand: Off-Chain Components</b></summary>

### 1. Credential Issuance

The issuer creates a credential containing multiple fields:

```
Credential = (field_1, field_2, ..., field_n)
```

The issuer computes a commitment:

```
claimsCommitment = Hash(field_1, field_2, ..., field_n)
```

And signs this commitment with their private key. The full credential and signature are delivered privately to the holder.

The issuer also maintains and publishes:
- **Merkle roots** for approved sets (countries, roles, institutions)
- **Revocation roots** for invalidated credentials

Because the credential is a single signed object (not one signature per claim as in atomic approaches), revocation is simple: the issuer publishes one revocation root that covers the entire credential.

### 2. Predicate Proof Generation

When the holder wants to access a service, they generate a zero-knowledge proof for that service's specific predicate. The proof is generated **locally in the holder's wallet or device** — the credential fields and signing key never leave the holder's control. The specific proving software (Rust/Circom or Java/zeroj) is chosen at the project level; see [Step 0](#step-0-groth16-implementation-prerequisite).

**Public inputs** (visible on-chain):
- Issuer public key (or commitment to it)
- Current timestamp / epoch
- Published Merkle roots
- Eligibility flag (1 or 0)

**Private inputs** (never revealed):
- All credential fields
- Issuer signature
- Merkle membership witnesses
- Reduction witnesses for signature verification

The proof demonstrates:
1. The credential fields hash to the signed commitment
2. The issuer's signature is valid
3. The predicate constraints are satisfied (e.g., `age ≥ 21`, `country ∈ approvedSet`)
4. The `eligible` output equals `1`

**Crucially**, the holder's blockchain address is **not** an input to the proof or the transaction.

### 3. Transaction Construction

The holder (or a relayer) builds a transaction that:
- Identifies a UTxO locked at the Gate Script
- Provides the proof in the **redeemer**
- Provides the public inputs matching the proof
- **Does not** include the holder's identity, address, or staking key anywhere in the transaction body, datum, or redeemer

The transaction is signed only to satisfy blockchain transaction validity (paying fees), but this signing address is decoupled from identity. It can be:
- A fresh one-time address
- A relayer's address
- A coin-mixed address

</details>

<details>
<summary><b>Click to expand: On-Chain Components</b></summary>

### Gate Script

Each service deploys a Gate Script — a validator parameterized by:
- The **verifying key** of the predicate circuit it accepts

The script logic:

```
validate(datum, redeemer, context):
    1. Extract proof (π_A, π_B, π_C) from redeemer
    2. Extract public inputs from redeemer
    3. Verify: eligible == 1
    4. Verify: ZKVerify(publicInputs, proof, vk) == true
    5. Return true
```

The script **never** checks:
- A specific payment address
- A staking credential
- A signature from a known key
- Any datum containing identity

The only authorization is the mathematical validity of the proof.

### UTxO Lifecycle

```
Phase 1: Funding
┌─────────────────────────────────────┐
│  Someone locks funds at Gate Script │
│  Datum: unit (no identity data)     │
└─────────────────────────────────────┘

Phase 2: Unlocking
┌─────────────────────────────────────┐
│  Holder submits unlock tx           │
│  Redeemer: proof + public inputs    │
│  No holder address in datum/redeemer│
│  Script verifies proof → releases   │
└─────────────────────────────────────┘
```

</details>

<details>
<summary><b>Click to expand: Privacy Properties</b></summary>

| Property | How It Is Achieved |
|----------|-------------------|
| **Credential fields hidden** | All fields are private inputs to the ZK circuit; only the predicate result is public |
| **Transaction address hidden** | The script does not require or verify any holder address; authorization is purely proof-based |
| **Anonymity set** | When multiple UTxOs are locked at the same Gate Script, any valid proof can unlock any of them; observers cannot link a specific spend to a specific credential holder |
| **Unlinkable proofs** | Two proofs against different circuits (or even the same circuit with different public inputs) are cryptographically independent; a verifier cannot tell if they came from the same credential |
| **No linkability across sessions** | The holder can use fresh fee-payer addresses or relayers for each transaction |
| **Approved sets are upgradeable** | The issuer publishes new Merkle roots; existing credentials remain valid |
| **No external services** | Verification is self-contained in the script; no oracles, DHTs, or registries are needed at proof time |

</details>

<details>
<summary><b>Click to expand: Example Workflows</b></summary>

### Workflow A: Anonymous Access to a Service

1. **Issuer** signs a credential for Alice: `(dob: 1990, country: DEU, role: Doctor)`
2. **Issuer** publishes `approvedCountriesRoot` on-chain or off-chain
3. **Alice** wants to access the "Healthcare Portal"
4. **Alice** generates a proof that her `role == Doctor AND age ≥ 30`
5. **Alice** (or a relayer) submits a transaction spending the Portal's Gate UTxO
6. **On-chain validator** verifies the proof and releases the resource
7. **No one** can determine Alice's address, her birth year, or that she is the same person who accessed the Library last week

### Workflow B: Cross-Border Credential Reuse

1. **National Authority** issues a digital residency credential to Bob
2. **Banking DApp** in jurisdiction A requires `age ≥ 21 AND country ∈ {DEU, FRA, GBR}`
3. **Insurance DApp** in jurisdiction B requires `age ≥ 25 AND country ∈ {DEU, NLD}`
4. **Bob** uses the **same credential** to generate two **different** proofs
5. Each DApp's script validates only its own predicate; neither learns Bob's exact age or country
6. Neither DApp can link the two transactions to the same person

</details>

---

## Step 0: Groth16 Implementation (Prerequisite)

**Executive summary:** Before any selective-disclosure flow can run end-to-end, we need a working Groth16 proof system over BLS12-381 split into an off-chain prover and an on-chain verifier. There are **two viable toolchains** that can produce proofs verifiable on Cardano:

| Path | Off-chain prover | On-chain verifier | Status | Documentation |
|------|-----------------|-------------------|--------|---------------|
| **A — Rust / Circom** | `circom` compiler + [`groth16-prover`](../../groth16-prover/README.md) (Rust/arkworks) | [`aiken/groth16`](../../aiken/groth16/README.md) (parameterized Aiken library) | ✅ Working e2e | [`groth16-prover/circom/README.md`](../../groth16-prover/circom/README.md) |
| **B — Java / zeroj** | [`zeroj`](../../zeroj-audit/README.md) Circuit DSL / pure-Java prover | `zeroj-onchain-julc` (Julc → Plutus V3) | ⚠️ Experimental: undergoing audit | [`zeroj-audit/README.md`](../../zeroj-audit/README.md) |

**Path A** is the reference implementation used to validate the Aiken verifier. It compiles Circom circuits to R1CS, generates witnesses with `snarkjs`, produces proofs with the Rust `groth16-prover`, and verifies them on-chain with the parameterized Aiken `groth16` library. The pipeline is fully working for several circuits (3-gate multiplier, 1107-constraint Merkle membership, Poseidon pre-image).

**Path B** is a pure-Java alternative. Circuits are defined with a Java DSL (`CircuitSpec` or symbolic annotations), proofs are generated by a pure-Java Groth16 prover (`zeroj-crypto`), and on-chain verification is performed by Julc-generated Plutus V3 scripts (`zeroj-onchain-julc`). The project has demonstrated end-to-end Groth16 verification on Yaci DevKit, but it remains experimental and should not be used in production without further audit.

Both paths use the same BLS12-381 curve and the same ZCash point-compression format, so proofs generated by either prover are structurally compatible with a Plutus V3 verifier that uses the standard `bls12_381_G1_element` / `G2_element` builtins.

<details>
<summary><b>Click to expand: What Already Exists vs What Remains</b></summary>

### Path A — Rust / Circom (reference implementation)

| Component | Status | Location |
|-----------|--------|----------|
| **Circom compiler adapter** (`.r1cs` + `.wtns` parser) | ✅ Done | `groth16-prover/src/circom_adapter.rs` |
| **QAP engine** (dense + FFT paths) | ✅ Done | `groth16-prover/src/engine.rs` |
| **Groth16 prover** (BLS12-381, naive + Pippenger MSM) | ✅ Done | `groth16-prover/src/prover.rs` |
| **Trusted setup** (dev ceremony + Phase-2 MPC) | ✅ Done | `groth16-prover/src/phase2.rs`, `src/ptau.rs` |
| **Proof serialization** (arkworks → compressed bytes) | ✅ Done | `groth16-prover/cli` |
| **VK export** (binary `.vk` → Aiken `VerificationKey`) | ✅ Done | `groth16-prover/cli` (`export-vk`) |
| **Aiken Groth16 verifier library** (parameterized) | ✅ Done | `aiken/groth16/lib/groth16/verifier.ak` |
| **Example circuits** (multiplier, Merkle spend, Poseidon) | ✅ Done | `groth16-prover/circom/` |

### Path B — Java / zeroj (experimental alternative)

| Component | Status | Location |
|-----------|--------|----------|
| **Circuit DSL** (R1CS compiler, signal builder, constraint generation) | ✅ Done | `zeroj-circuit-dsl`, `zeroj-circuit-lib` |
| **Poseidon hash** (BLS12-381 scalar field) | ✅ Done | `zeroj-circuit-lib` / `zeroj-mpf-poseidon` |
| **EdDSA-Jubjub** (sign, verify, in-circuit gadgets) | ✅ Done | `zeroj-circuit-lib` / `zeroj-crypto` |
| **Groth16 prover** (BLS12-381 witness → proof, pure Java) | ✅ Done | `zeroj-crypto` (`Groth16ProverBLS381`) |
| **Trusted setup** (PoT + Phase-2, cacheable) | ✅ Done | `zeroj-crypto` (`PowersOfTauBLS381`, `Groth16SetupBLS381`) |
| **Proof compression** (Jacobian → compressed bytes) | ✅ Done | `zeroj-onchain-julc` (`SnarkjsToCardano.ProofCompressed`) |
| **Julc on-chain verifier** (Plutus V3 via Java annotation) | ✅ Done | `zeroj-onchain-julc` (`Groth16BLS12381Lib`) |

### What Remains for a Production Selective-Disclosure Gate

| Component | Status | Why It Is Needed |
|-----------|--------|------------------|
| **Predicate circuit library in Circom** | 🔄 In progress | Reusable Circom gadgets for Poseidon, Merkle, range checks, EdDSA — needed for Step 1 predicate proofs |
| **Predicate circuit library in zeroj DSL** | 🔄 In progress | Same gadgets expressed in zeroj's Java DSL — only needed if you choose Path B |
| **Redeemer schema standard** | ⚠️ Partial | Aiken `ProofRedeemer` record must match the field order, byte widths, and integer encoding that the off-chain prover produces. Path A already has a working `Proof` type; a unified schema is desirable. |
| **End-to-end selective-disclosure test** | ❌ Not started | A full Step 1–6 flow (see below) with a real predicate circuit, issued credential, and unlock transaction on a local devnet |

#### Circom ingredient inventory (Path A)

The Step 1 predicate circuit requires five cryptographic primitives. Here is the exact status of each in `groth16-prover/circom/`:

| Primitive | Needed for | Status | Source |
|-----------|-----------|--------|--------|
| **Poseidon hash (BLS12-381)** | `claims_msg = Poseidon(dob_year, country)`, Merkle tree nodes | ✅ Working e2e | `circom/PoseidonPreimage/poseidon_bls12_381.circom` (~250 constraints) |
| **Range proof** | `assert dob_year <= current_year - 21` (age ≥ 21) | ✅ Working e2e | `circom/RangeProof/range_proof_simple.circom` (~32 constraints for 32-bit) |
| **Merkle verify (Poseidon-based)** | `Merkle_Verify(country, country_root, merkle_proof)` | ⚠️ Not yet built | Composable from Poseidon hash — ~100 lines of Circom; no external dependencies |
| **EdDSA verify (JubJub)** | `EdDSA_Verify(issuer_pk, claims_msg, signature)` | ❌ **Missing — sole blocker** | See analysis below |
| **Groth16 prover + Aiken verifier** | All steps | ✅ Working e2e | `groth16-prover/` + `aiken/groth16/` |

**The one missing ingredient is EdDSA-JubJub verification in Circom.** circomlib ships `eddsa.circom` + `babyjub.circom`, but they are hard-coded for **BabyJubJub** (`a=168700, d=168696`, embedded in BN254) — not **JubJub** (`a=-1, d=0x2a93...eb1`, embedded in BLS12-381). Porting requires:

1. Replace curve constants in `babyjub.circom` (`a`, `d`, `BASE8`) with JubJub values
2. Recompute the 10 precomputed generator multiples in `pedersen.circom` (`BASE[10][2]`) for the JubJub subgroup generator
3. Test point compression/decompression in `pointbits.circom` against JubJub test vectors
4. Validate `eddsa.circom` end-to-end against the zeroj Java EdDSA test vectors (`zeroj-circuit-lib/.../jubjub/EdDSAJubjubTest.java`)

The structural work (~80%) is already done by circomlib — the templates are generic twisted Edwards arithmetic. The port is **constants + precomputed tables + testing**, not a rewrite. Estimated effort: 2–4 days.

See [`groth16-prover/circom/CardanoKeyOwnership/README.md`](../../groth16-prover/circom/CardanoKeyOwnership/README.md) for the broader Curve25519 → JubJub ownership-proof context.

</details>

<details>
<summary><b>Click to expand: Path A — Rust / Circom Quick-Start</b></summary>

The fastest way to get a working Groth16 proof verified on-chain today is Path A. The full pipeline is documented in [`aiken/groth16/README.md`](../../aiken/groth16/README.md) and summarized here:

1. **Compile a Circom circuit** → `.r1cs` + `.wasm`
2. **Generate a witness** with `snarkjs` → `.wtns`
3. **Run a dev ceremony** with the Rust CLI → `.pk` + `.vk`
4. **Generate a proof** with the Rust CLI → `proof.bin`
5. **Export the VK** to Aiken → `.ak` source file
6. **Verify in Aiken** — paste the proof bytes into an Aiken test or validator

This path has been validated for:
- `SimpleExample` (3 constraints, 2 public inputs)
- `Privacy/spend_depth2` (1107 constraints, all-private inputs)
- `PoseidonPreimage` (Poseidon hash pre-image knowledge)

See the per-circuit READMEs in [`groth16-prover/circom/`](../../groth16-prover/circom/README.md) for step-by-step commands.

</details>

<details>
<summary><b>Click to expand: Path B — zeroj Quick-Start</b></summary>

If you prefer a pure-Java toolchain, zeroj provides an end-to-end path from circuit definition to on-chain verification without native dependencies:

1. **Define the circuit** in Java with `CircuitSpec` or `@ZKCircuit` annotations
2. **Compile to R1CS** and **calculate the witness** in pure Java
3. **Run trusted setup** with `PowersOfTauBLS381` + `Groth16SetupBLS381`
4. **Generate a proof** with `Groth16ProverBLS381` (pure Java)
5. **Verify off-chain** with `BLS12381Pairing.pairingCheck(...)`
6. **Verify on-chain** by deploying the Julc-generated Plutus V3 script and submitting the proof as a redeemer

The zeroj project includes end-to-end tests on Yaci DevKit (`PureJavaProverYaciE2ETest`, `CircomToOnChainE2ETest`). See [`zeroj-audit/README.md`](../../zeroj-audit/README.md) for build instructions, module overview, and the getting-started guide.

> **Warning:** zeroj is experimental and AI-generated with human-assisted review. Do not use it in production without an independent audit.

</details>

---

## Step 1: Predicate Proofs with Aiken

**Executive summary:** This is the simplest valid end-to-end flow: one issuer signs a two-field credential (`dobYear`, `country`), the holder generates a Groth16 proof that `age >= 21 AND country in approved set`, and an Aiken Gate Script verifies the proof on-chain before releasing locked ADA. The flow has six steps: trusted setup, issuance, deploy gate, fund gate, proof generation, and unlock. Plutus V3 already has all BLS12-381 primitives needed; no new built-ins are required.

<details>
<summary><b>Click to expand: High-Level Flow Diagram</b></summary>

```mermaid
graph LR
    subgraph OffChain["Off-Chain"]
        S1["Step 1: Trusted Setup<br/>Circuit → R1CS → SRS → vk + pk"]
        S2["Step 2: Issuance<br/>Issuer signs credential"]
        S5["Step 5: Proof Generation<br/>Holder generates ZK proof"]
    end
    subgraph OnChain["On-Chain (Cardano)"]
        S3["Step 3: Deploy Gate<br/>Aiken validator (vk)"]
        S4["Step 4: Fund Gate<br/>Lock ADA at script"]
        S6["Step 6: Unlock tx<br/>Script verifies proof → releases"]
    end
    S1 --> S3
    S2 --> S5
    S3 --> S4
    S5 --> S6
    S4 --> S6
```

</details>

<details>
<summary><b>Click to expand: Step 1 — Trusted Setup & Circuit Compilation (Off-Chain)</b></summary>

**What happens:** The predicate circuit is compiled and a trusted setup ceremony is run to produce the proving key (`pk`) and verifying key (`vk`).

**Functionality needed**

| Component | Purpose |
|-----------|---------|
| Circuit DSL / R1CS compiler | Convert the predicate logic (`age >= 21`, Merkle membership) into Rank-1 Constraint System |
| Powers of Tau (universal SRS) | Generate a structured reference string independent of the circuit |
| Phase-2 setup | Derive circuit-specific `pk` and `vk` from the SRS |

**Data created**
```
proving_key      → used by the holder to generate proofs (kept off-chain)
verifying_key    → embedded into the Aiken Gate Script (on-chain parameter)
circuit_hash     → fingerprint of the circuit for cache validation
```

**Example circuit (pseudocode)**
```
Public:  issuer_pk, current_year, country_root, eligible
Secret:  dob_year, country, signature, merkle_proof

1. claims_msg = Poseidon(dob_year, country)
2. EdDSA_Verify(issuer_pk, claims_msg, signature)
3. assert dob_year <= current_year - 21
4. Merkle_Verify(country, country_root, merkle_proof)
5. assert eligible == 1
```

</details>

<details>
<summary><b>Click to expand: Step 2 — Credential Issuance (Off-Chain)</b></summary>

**What happens:** The issuer creates a credential, hashes its fields, signs the hash, and delivers the bundle privately to the holder. The issuer also publishes the approved-country Merkle root.

**Functionality needed**

| Component | Purpose |
|-----------|---------|
| Poseidon hash | Compute `claims_msg = Hash(dob_year, country)` |
| EdDSA (Jubjub) | Sign `claims_msg` with issuer secret key |
| Merkle tree builder | Construct approved-country set and compute `country_root` |

**Data created & flow**

```mermaid
sequenceDiagram
    participant Issuer as Issuer (Off-Chain)
    participant Holder as Holder Wallet (Off-Chain)
    participant Public as Public Registry / On-Chain

    Issuer->>Issuer: Generate credential fields<br/>(dobYear=1990, country=276)
    Issuer->>Issuer: Compute claims_msg = Poseidon(fields)
    Issuer->>Issuer: Sign claims_msg with issuer_sk
    Issuer->>Holder: Deliver credential bundle (private channel)
    Note over Holder: Holder stores:<br/>- dobYear, country<br/>- claims_msg<br/>- issuer_signature
    Issuer->>Issuer: Build Merkle tree of approved countries
    Issuer->>Public: Publish country_root
    Note over Public: Anyone can read country_root<br/>for proof verification
```

```
Issuer (off-chain)
  │
  ├─> Credential bundle ────────> Holder (off-chain, private channel)
  │     ├─ dob_year: 1990
  │     ├─ country: 276        (DEU)
  │     ├─ claims_msg: Hash(...)
  │     └─ issuer_signature
  │
  └─> country_root ────────────> Published (on-chain datum or IPFS)
```

**Important**: The credential bundle lives entirely off-chain in the holder's wallet. Only the `country_root` needs to be publicly available.

</details>

<details>
<summary><b>Click to expand: Step 3 — Deploy Gate Script (On-Chain)</b></summary>

**What happens:** An Aiken validator parameterized with the verifying key (`vk`) from Step 1 is compiled and deployed to Cardano as a Plutus V3 script.

**Functionality needed**

| Component | Purpose |
|-----------|---------|
| Aiken compiler | Compile validator to Plutus V3 UPLC |
| Groth16 verifier library (Aiken) | BLS12-381 pairing check callable from Aiken (either as a library or via Plutus built-ins) |
| Cardano CLI / client | Submit the script reference or use it directly in transactions |

**Aiken validator skeleton**
```aiken
use aiken/builtin

// Groth16 proof elements passed in the redeemer
type ProofRedeemer {
  pi_a: ByteArray,      // G1 point
  pi_b: ByteArray,      // G2 point
  pi_c: ByteArray,      // G1 point
  pk_u: ByteArray,      // issuer pubkey coordinate
  pk_v: ByteArray,      // issuer pubkey coordinate
  current_year: ByteArray,
  country_root: ByteArray,
  eligible: ByteArray,  // must be 1
}

validator gate(
  vk_alpha: ByteArray,
  vk_beta: ByteArray,
  vk_gamma: ByteArray,
  vk_delta: ByteArray,
  vk_ic: List<ByteArray>,
) {
  fn spend(_datum: Void, redeemer: ProofRedeemer, _ctx: ScriptContext) -> Bool {
    // 1. Hard predicate: eligible must be exactly 1
    expect redeemer.eligible == #[1]

    // 2. Reconstruct public inputs as field elements
    let public_inputs = [
      redeemer.pk_u,
      redeemer.pk_v,
      redeemer.current_year,
      redeemer.country_root,
      redeemer.eligible,
    ]

    // 3. Verify the Groth16 proof against the embedded vk
    groth16_verify_bls12_381(
      public_inputs,
      redeemer.pi_a,
      redeemer.pi_b,
      redeemer.pi_c,
      vk_alpha,
      vk_beta,
      vk_gamma,
      vk_delta,
      vk_ic,
    )
  }
}
```

> **Note**: `groth16_verify_bls12_381` performs three pairings on the BLS12-381 curve. In a production Aiken deployment this is either imported from a verified Aiken library or implemented via Plutus V3 built-in cryptographic primitives.

**Data created**
```
script_hash  → hash of the compiled Plutus script (used to derive the Gate address)
gate_address → Cardano address derived from script_hash (where funds will be locked)
```

</details>

<details>
<summary><b>Click to expand: Step 4 — Fund the Gate (On-Chain)</b></summary>

**What happens:** Anyone locks ADA at the Gate script address. The datum is a unit (`()`), carrying no identity information.

**Functionality needed**

| Component | Purpose |
|-----------|---------|
| Cardano transaction builder | Construct a `pay-to-script` output |
| Wallet | Sign and submit the funding transaction |

**Data flow**

```mermaid
sequenceDiagram
    participant Funder as Funder Wallet
    participant Ledger as Cardano Ledger

    Funder->>Funder: Build tx: pay 100 ADA to gate_address<br/>datum = ()
    Funder->>Ledger: Submit funding transaction
    Ledger->>Ledger: Create UTxO
    Note over Ledger: UTxO at gate_address:<br/>value = 100 ADA<br/>datum = ()
```

```
Funder wallet
     │
     │ Tx: pay 100 ADA to gate_address
     │     datum = ()
     │
     v
Cardano ledger
     │
     └─> New UTxO created:
         address = gate_address
         value   = 100 ADA
         datum   = ()
```

**Privacy note**: The funder's address is visible, but this is irrelevant to the eventual holder who will unlock. The funder and the holder can be different parties, or the funder can be a relayer.

</details>

<details>
<summary><b>Click to expand: Step 5 — Proof Generation (Off-Chain)</b></summary>

**What happens:** The holder uses their credential, the issuer signature, the published `country_root`, and the `proving_key` to generate a zero-knowledge proof.

**Functionality needed**

| Component | Purpose |
|-----------|---------|
| Witness calculator | Assign values to all circuit wires (public + private) |
| Groth16 prover (BLS12-381) | Generate `pi_a`, `pi_b`, `pi_c` given the witness and `pk` |
| Merkle proof provider | Look up `country = 276` in the approved set and produce siblings + path bits |

**Inputs to the prover**
```
Public inputs (will appear on-chain in the redeemer):
  issuer_pk.u, issuer_pk.v
  current_year = 2026
  country_root = 0xabc123...
  eligible     = 1

Private inputs (never leave the holder's device):
  dob_year     = 1990
  country      = 276
  signature.r, signature.s
  k_mod_l, k_quotient       // EdDSA reduction witnesses
  merkle_siblings[0..3]
  merkle_path_bits[0..3]
```

**Data created**
```
proof_bundle:
  pi_a: G1 point (48 bytes compressed)
  pi_b: G2 point (96 bytes compressed)
  pi_c: G1 point (48 bytes compressed)
  public_inputs: [ByteArray; 5]
```

**Privacy note**: The proof is generated entirely on the holder's device. No credential fields, signatures, or Merkle witnesses are transmitted to any server.

</details>

<details>
<summary><b>Click to expand: Step 6 — Unlock Transaction (On-Chain)</b></summary>

**What happens:** The holder (or a relayer) constructs a transaction that spends the locked UTxO from Step 4. The proof and public inputs are provided in the **redeemer**. The Gate script validates the proof and releases the funds.

**Functionality needed**

| Component | Purpose |
|-----------|---------|
| Cardano transaction builder | Assemble inputs, outputs, redeemer, and collateral |
| Script evaluator (Aiken/Plutus) | Execute the Gate validator during transaction validation |
| Wallet / relayer | Provide transaction fee and signing |

**Data flow**

```mermaid
sequenceDiagram
    participant Holder as Holder Wallet / Relayer
    participant Ledger as Cardano Ledger
    participant Script as Gate Script (Aiken)
    participant Recipient as Recipient Address

    Holder->>Holder: Build tx:<br/>Input = UTxO at gate_address<br/>Redeemer = ProofRedeemer {pi_a, pi_b, pi_c, ...}<br/>Output = 95 ADA to recipient_address
    Holder->>Ledger: Submit unlock transaction
    Ledger->>Script: Evaluate Gate validator
    Script->>Script: Check eligible == 1
    Script->>Script: Groth16Verify(public_inputs, proof, vk)
    Script-->>Ledger: Return True
    Ledger->>Ledger: Consume UTxO
    Ledger->>Recipient: Transfer 95 ADA
    Note over Recipient: recipient_address can be<br/>a fresh one-time address
```

```
Holder wallet (or Relayer)
     │
     │ Tx:
     │   Input[0]: UTxO at gate_address (from Step 4)
     │              redeemer = ProofRedeemer { pi_a, pi_b, pi_c, ... }
     │
     │   Output[0]: 95 ADA to recipient_address
     │              (can be a fresh one-time address)
     │
     │   Collateral: provided by fee payer
     │
     v
Cardano ledger / Script evaluator
     │
     ├─> Gate script runs:
     │     1. eligible == 1              ✓
     │     2. Groth16Verify(...)         ✓
     │     → script returns True
     │
     └─> Tx accepted. UTxO consumed.
         Funds transferred to recipient_address.
```

**Data created**
```
tx_hash      → on-chain evidence that the proof was accepted
redeemer_log → proof + public inputs (visible on-chain, but reveals no credential fields)
```

**Privacy outcome**: An observer sees that *someone* produced a valid proof for the "adult resident" gate and claimed the funds. They cannot determine:
- Who the holder is (no address in datum/redeemer binds identity)
- The holder's birth year or country
- Whether this is the same person who used another gate yesterday

</details>

<details>
<summary><b>Click to expand: Summary, Tooling Stack & Feasibility</b></summary>

### Summary: Data & Functionality per Step

| Step | Location | Functionality | Data In | Data Out |
|------|----------|---------------|---------|----------|
| 1. Setup | Off-chain | R1CS compiler, PoT, Phase-2 | Circuit definition | `pk`, `vk`, `circuit_hash` |
| 2. Issuance | Off-chain | Poseidon, EdDSA sign, Merkle tree | Credential fields, issuer sk | Signed credential, `country_root` |
| 3. Deploy | On-chain | Aiken compiler, Groth16 lib | `vk` bytes | `script_hash`, `gate_address` |
| 4. Fund | On-chain | Tx builder, wallet | ADA, `gate_address` | Locked UTxO |
| 5. Prove | Off-chain | Witness calculator, Groth16 prover | Credential, `pk`, `country_root` | `pi_a`, `pi_b`, `pi_c`, public inputs |
| 6. Unlock | On-chain | Tx builder, script evaluator | Proof, UTxO, fee | Spent UTxO, released funds |

### Minimal Viable Tooling Stack

To replicate this flow end-to-end, the following primitives must be available:

**Off-chain**
- Poseidon hash over BLS12-381 scalar field
- EdDSA signature over Jubjub curve
- Groth16 prover over BLS12-381
- Merkle tree builder and proof generator

**On-chain (Aiken / Plutus V3)**
- BLS12-381 curve operations (already available as Plutus V3 built-ins)
- Groth16 verifier (pairing check + public input linear combination)
- ByteArray <-> integer conversions for parsing redeemers

**Cross-layer**
- Proof compression (Jacobian to compressed bytes) to fit redeemers within transaction size limits
- Aiken / Plutus datum/redeemer serialization matching the off-chain prover's output format

### Is Groth16 on Cardano Actually Feasible?

**Yes. Cardano's Plutus V3 has native BLS12-381 support, which is exactly what Groth16 over BLS12-381 requires.**

| Concern | Reality |
|---------|---------|
| **Curve support** | Plutus V3 ships with built-in BLS12-381 primitives: `bls12_381_G1_element`, `bls12_381_G2_element`, `bls12_381_millerLoop`, `bls12_381_finalVerify`, and scalar field operations. These were added specifically to enable ZK proof verification. |
| **Groth16 verifier complexity** | A Groth16 verify is ~3 Miller loops + 1 final pairing check + some G1 multi-scalar multiplications for public inputs. This maps directly to the Plutus V3 built-ins. The Aiken validator sketched in Step 3 is not pseudocode wishful thinking — it compiles to real UPLC. |
| **Execution budget** | Each BLS12-381 pairing costs ~10–20M CPU units in Plutus V3. A full Groth16 verification with 5 public inputs fits comfortably within Cardano's current per-transaction limits (mainnet block budget is ~10B CPU units; a single script can consume ~100M+ depending on protocol parameters). Early testnet benchmarks by IOG and community projects confirm Groth16 verify scripts execute successfully. |
| **Trusted setup** | The off-chain Powers of Tau + Phase-2 ceremony is standard zkSNARK infrastructure and not constrained by Cardano at all. The resulting `vk` is just a few kilobytes embedded as validator parameters. |
| **Proving** | Happens entirely off-chain in the holder's wallet. No Cardano limits apply. |

**Bottom line**: The cryptographic primitives are live on Cardano mainnet today. The remaining work is engineering — writing the Aiken Groth16 verifier library, optimizing public-input MSM, and ensuring the proof compression format matches between off-chain prover and on-chain parser. This is well within the scope of current zeroj / cardano-client-lib tooling.

</details>

---

## Step 2: Twisted ElGamal Extension

**Executive summary:** Only use this if your use case requires hiding **amounts** (balances, transfer values) in addition to hiding identity. Twisted ElGamal is realizable on Cardano by substituting Ristretto255 with BLS12-381 G1 — all required operations (point addition, scalar multiplication, negation, equality) are already in Plutus V3. The catch is that messages live in the exponent, so amounts must be split into `u16` limbs and range proofs added to the Groth16 circuit. Skip this if your use case is identity-only.

<details>
<summary><b>Click to expand: Can We Use Twisted ElGamal on Cardano?</b></summary>

**Yes.** Twisted ElGamal is conceptually realizable on Cardano with a curve substitution: instead of Ristretto255 (used by Mysten on Sui), you use **BLS12-381 G1** as the underlying group, because that's what Plutus V3 has native built-ins for.

### What Plutus V3 Already Gives Us

| Operation | Needed for Twisted ElGamal | Available in Plutus V3? |
|-----------|---------------------------|------------------------|
| Group element type | `G1Element` for ciphertext points | ✅ `bls12_381_G1_element` |
| Point addition | Homomorphic addition of ciphertexts | ✅ `bls12_381_G1_add` |
| Scalar multiplication | `r*g`, `m*h`, `r*pk` | ✅ `bls12_381_G1_scalarMul` |
| Point negation | Subtraction (`c - d/x`) | ✅ `bls12_381_G1_neg` |
| Point equality | Verify ciphertext integrity | ✅ `bls12_381_G1_equal` |
| Hash to curve | Derive second generator `h` | ⚠️ Likely available as `bls12_381_G1_hashToGroup`; verify in target node version |
| Pairings | **Not needed** for ElGamal itself | ✅ Available anyway (for Groth16) |

**No new Plutus built-ins are needed** for the core ElGamal operations. The existing BLS12-381 G1 primitives are sufficient.

</details>

<details>
<summary><b>Click to expand: What Changes Architecturally</b></summary>

#### Current Design (Step 1 — Predicate Proofs Only)
```
Credential fields → private inputs to Groth16 circuit
     ↓
Proof says: "I satisfy predicate P" (no fields revealed)
     ↓
Script verifies Groth16 proof → releases funds
```

#### Extended Design (+ Twisted ElGamal)
```
Credential fields → encrypted as G1 points, stored in datum
     ↓
Holder proves: "decrypt(my_balance) ≥ transfer_amount
               AND transfer_amount ≥ 0"
     ↓
Proof is Groth16 over constraints that include:
  - ElGamal homomorphism equations
  - Range bounds on encrypted limbs
     ↓
Script verifies Groth16 proof + adds ciphertexts homomorphically
```

#### Key Changes

| Aspect | Step 1 Only | + Twisted ElGamal |
|--------|-------------|-------------------|
| **On-chain state** | Unit datum (no balance data) | Datum stores encrypted G1 points (active balance, pending balance) |
| **Transfer logic** | One-shot unlock | Homomorphic point addition updates encrypted balances |
| **Circuit complexity** | Signature verify + Merkle + comparison | Same + ElGamal equations + range decomposition |
| **Redeemer size** | ~200 bytes (proof + 5 public inputs) | ~400–600 bytes (proof + multiple ciphertexts) |
| **What is hidden** | Identity + credential fields | Identity + credential fields + amounts |
| **What script does** | Verify proof, release funds | Verify proof, add ciphertexts, release funds |

</details>

<details>
<summary><b>Click to expand: The Range-Proof Catch & Practical Architecture</b></summary>

Twisted ElGamal is additively homomorphic, but the **message lives in the exponent**:

```
decrypt: c - d/x = m*h  →  m = log_h(m*h)
```

This is only practical for small `m` (because discrete log brute-force is needed). Mysten solves this by splitting amounts into `u16` limbs and encrypting each limb separately. But then the on-chain verifier must ensure:
1. Each limb is within `[0, 2^16]`
2. The sum of limbs doesn't overflow
3. Sender has sufficient balance

These are **range proofs**. In a UTxO model without account state, you need a ZK proof that the homomorphic subtraction is valid and non-negative. You would express these constraints as additional R1CS constraints inside your existing Groth16 circuit, then verify the same Groth16 proof on-chain.

**So the practical architecture becomes:**

```
Off-chain:
  1. Split amount into limbs (u16)
  2. Encrypt each limb with Twisted ElGamal over BLS12-381 G1
  3. Build Groth16 witness including ElGamal equations + range constraints
  4. Generate proof

On-chain (Aiken):
  1. Receive proof + encrypted ciphertexts in redeemer
  2. Groth16Verify(proof, vk) — checks signature, Merkle, AND ElGamal ranges
  3. If valid, homomorphically add ciphertexts to update balances
```

</details>

<details>
<summary><b>Click to expand: Use-Case Guidance & Summary</b></summary>

**Add Twisted ElGamal if your use case requires hiding amounts.** Examples:
- Private payroll distribution (prove "is employee" without revealing salary amount)
- Confidential voting weights (prove "holds governance token" without revealing balance)
- Anonymous donations (prove "meets eligibility" without revealing donation size)

**Skip it if your use case is identity-only.** Examples:
- Age verification for venue entry
- Role verification for healthcare access
- Country residency for banking KYC

In those cases, adding encrypted balances is pure overhead. The predicate proof already hides identity completely; encrypting a boolean `eligible` flag adds nothing.

| Question | Answer |
|----------|--------|
| Can we use Twisted ElGamal on Cardano? | **Yes**, using BLS12-381 G1 as the group |
| Do we need new Plutus built-ins? | **No**, existing G1 ops are sufficient |
| What changes? | Datum stores G1 ciphertexts; circuit includes ElGamal + range constraints; script does homomorphic addition |
| Is it harder? | **Moderately**. The cryptography is there, but the circuit grows (more constraints = slower proving), and the datum/redeemer structures become more complex |
| Should we do it? | Only if amount privacy is a **requirement**. For identity-only selective disclosure, it's unnecessary complexity |

If you go this route, the composition is: **predicate proof for identity + ElGamal encryption for amounts**, verified by a single Groth16 proof checked by the same Aiken Gate Script.

</details>

---

## Compliance & Auditability

**Executive summary:** Privacy-by-default does not mean absence of oversight. Production deployments can layer compliance on top of the core proof-based authorization without weakening privacy. Three mechanisms are available: per-credential auditing (encrypt a viewing key to auditor keys at issuance, no per-transaction overhead), permissioned gates (KYC checks layered alongside the ZK proof), and emergency controls (revocation, pause, freeze, coercion resistance). An advanced Forensic Data Escrow allows governed conditional disclosure of encrypted metadata without exposing credential fields.

<details>
<summary><b>Click to expand: Auditor Visibility Without Per-Transaction Overhead</b></summary>

Instead of attaching audit data to every proof submission (which increases transaction size and cost), the issuer can bundle an **auditor-encrypted decryption key** with the credential at issuance time.

- When the credential is issued, the holder's wallet encrypts a credential decryption key to the issuer's designated auditor public keys and includes the ciphertext in the credential bundle.
- Auditors decrypt this key once off-chain and can then read the full credential contents, verify historical proofs, or inspect Merkle root updates.
- The holder's individual proof transactions remain unchanged — no extra ciphertext or proof is needed per transaction.

This **per-credential auditing** model (inspired by Mysten Labs' confidential-transfer design, adapted to a UTxO context) is cheaper for holders and simpler for auditors than per-transaction audit trails. In Cardano's UTxO model there is no on-chain account object; the credential and its audit key are simply off-chain data held by the holder.

</details>

<details>
<summary><b>Click to expand: Permissioned Gates</b></summary>

A verifier can require a valid ZK proof **plus** an additional on-chain policy check. For example:

- **KYC gating**: The Gate Script checks that the transaction signer (or a referenced policy object) is present in an on-chain KYC registry before accepting the proof.
- **Rate limiting**: A gate tracks how many times a given proof public-input set has been used in an epoch and rejects further unlocks beyond a threshold.
- **Allowlists**: Only credentials issued by a specific issuer sub-key are accepted.

The policy layer is separate from the predicate circuit, so the ZK proof itself stays small and the privacy properties remain intact.

</details>

<details>
<summary><b>Click to expand: Emergency Controls & Forensic Data Escrow</b></summary>

### Emergency Controls

| Control | Mechanism |
|---------|-----------|
| **Revocation** | Issuer publishes a new revocation Merkle root; the next proof generation automatically includes a non-membership witness showing the credential is not revoked |
| **Global pause** | Gate operator flips an `is_active` flag in the script; all proof verifications reject until lifted |
| **Freeze** | Issuer or designated admin adds a credential ID to a frozen set; the circuit can include a non-freeze membership check |
| **Holder coercion resistance** | Because the proof does not reveal field values, a coerced holder cannot be forced to disclose their exact age, country, etc. — they can only be forced to produce (or not produce) a proof for a given predicate |

### Forensic Data Escrow (Advanced)

For regulated environments, the issuer can escrow encrypted credential metadata with a governance-controlled disclosure mechanism.

- At issuance, the holder includes an additional ciphertext encrypting non-sensitive metadata (e.g., credential type, issuance epoch, jurisdiction code) to a **governance multi-sig public key**.
- This ciphertext is stored off-chain with the credential bundle — it never appears in proof transactions.
- Under defined circumstances (court order, fraud investigation, lost-key recovery), the governance body can decrypt the escrowed metadata without learning the actual credential field values.
- The predicate proof system remains unchanged; the escrow is a compliance layer outside the ZK circuit.

This provides a middle ground between absolute privacy and regulatory accountability: the holder's fields stay hidden, but issuers retain a governed path for conditional metadata disclosure.

</details>

---

## Threat Model & Deployment

**Executive summary:** The main threats are credential theft (mitigated by holder binding), proof replay (mitigated by nonces/epochs), colluding verifiers (mitigated by unlinkable proofs), and holder coercion (mitigated by the fact that proofs never reveal field values). Deployment requires defining credential schemas and predicate circuits, running trusted setup, deploying parameterized Gate Scripts, publishing issuer public keys, and implementing holder-side local proof generation. Optional relayer infrastructure can hide the fee payer.

<details>
<summary><b>Click to expand: Threat Model & Mitigations</b></summary>

| Threat | Mitigation |
|--------|-----------|
| Credential theft | **Holder binding:** Bind the credential to a holder secret (e.g., include a holder commitment in the signed message; the proof requires knowledge of the secret) |
| Proof replay | Add a nonce, epoch number, or transaction hash as a public input to the circuit |
| Sybil attacks | Issuer ensures one credential per real-world identity (out of scope of the cryptography) |
| Colluding verifiers | By design, proofs are unlinkable; collusion cannot cryptographically link sessions |
| Holder coercion | The holder can generate a proof for *any* predicate they satisfy; they cannot be forced to reveal specific field values because the proof does not expose them |

</details>

<details>
<summary><b>Click to expand: Deployment Checklist</b></summary>

- [ ] Define credential schema (fields, encoding)
- [ ] Define predicate circuits per use case
- [ ] Run trusted setup (universal Powers of Tau + per-circuit Phase 2)
- [ ] Deploy Gate Scripts parameterized by each circuit's verifying key
- [ ] Publish issuer public key and Merkle roots via trusted channel
- [ ] Implement holder-side proof generation
- [ ] Optional: deploy relayer infrastructure for address-less submission

</details>

<details>
<summary><b>Click to expand: Hiding the Fee Payer</b></summary>

For full anonymity, even the transaction fee payer can be hidden:

1. **Relayer network**: The holder sends the proof to a relayer who pays fees and submits the tx. The relayer cannot forge the proof.
2. **Stealth addresses**: The holder derives a one-time address for each transaction.
3. **Coin mixing**: Fees are paid from mixed UTxOs, breaking the chain of custody.

In all cases, the **Gate Script remains unchanged** — it validates only the proof, not the transaction's origin.

</details>

---

## References

1. A. De Salve, A. Lisi, M. Cascino, P. Mori, and L. Ricci, "Selective disclosure approaches in Self-Sovereign Identity: an experimental comparison," *IEEE Access*, 2025. DOI: [10.1109/ACCESS.2025.3649167](https://doi.org/10.1109/ACCESS.2025.3649167)

   This paper surveys and experimentally compares five selective disclosure strategies (atomic credentials, hashing, encryption, hash trees, and signature-based / BBS+) from the SSI literature. The design documented here advances beyond claim-level disclosure to **predicate-level zero-knowledge disclosure**, which the surveyed approaches do not address.

2. W3C, *Verifiable Credentials Data Model 2.0*, W3C Proposed Recommendation, 2025. https://www.w3.org/TR/vc-data-model-2.0/

3. W3C, *Decentralized Identifiers (DIDs) v1.0*, W3C Recommendation, 2022. https://www.w3.org/TR/did-core/

4. Mysten Labs, *Confidential Transfers on Sui*, GitHub repository, 2025. https://github.com/MystenLabs/confidential-transfers

   Demonstrates a complementary privacy paradigm using Twisted ElGamal homomorphic encryption and zero-knowledge range proofs to hide transfer *amounts* on-chain. Key insights absorbed into this design include **per-credential auditing** (encrypting a decryption key once to auditor keys rather than attaching audit data per transaction) and **permissioned gate flows** (layering KYC/policy checks on top of cryptographic verification). Adapted here from Sui's account model to Cardano's UTxO model.

5. Panther Protocol, "Programmable Privacy Is Live: Panther Protocol Deploys on Polygon," *Panther Protocol Blog*, May 2026. https://blog.pantherprotocol.io/programmable-privacy-is-live-panther-protocol-deploys-on-polygon/

   Introduces **programmable privacy** — confidential on-chain interactions with zero-knowledge credential verification. Insights absorbed into this design include the **UTxO-based anonymity set** (multiple locked UTxOs at the same script create a privacy pool where any valid proof can spend any UTxO), **local proof generation** (proofs generated in the holder's wallet, never on a server), and the principle that *"the protocol verifies only what's required — nothing more."* Also informs the **Forensic Data Escrow** concept for governed conditional disclosure.
