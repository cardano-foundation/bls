# Selective Disclosure with Hidden Transaction Address

## Overview

This pattern enables a credential holder to prove they satisfy specific predicates (age, role, membership, etc.) without revealing:

1. The underlying credential fields
2. Their blockchain address or identity
3. Any link between separate transactions

The authorization to spend or access a resource comes from a **zero-knowledge proof** rather than a direct signature from a known address.

> **Design principle: Data minimization.** Inspired by the W3C Verifiable Credentials data model, the system follows the principle that the holder should share *no more information than strictly necessary*. In this design, the holder does not reveal individual claims at all — they reveal only the truth value of a predicate computed over those claims.

---

## Actors

| Actor | Role |
|-------|------|
| **Issuer** | Signs a rich credential (multiple fields) and publishes commitment roots (e.g., approved country sets, revocation lists) |
| **Holder** | Receives the credential, generates predicate proofs, submits transactions without exposing identity |
| **Verifier / Gate** | A Cardano script that releases funds or grants access when presented with a valid proof |
| **Relayer (optional)** | Submits transactions on behalf of the holder; cannot forge proofs |

---

## Architecture

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

---

## Selective Disclosure: Claim-Level vs Predicate-Level

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

---

## Off-Chain Components

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

When the holder wants to access a service, they generate a zero-knowledge proof for that service's specific predicate.

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

---

## On-Chain Components

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

---

## Privacy Properties

| Property | How It Is Achieved |
|----------|-------------------|
| **Credential fields hidden** | All fields are private inputs to the ZK circuit; only the predicate result is public |
| **Transaction address hidden** | The script does not require or verify any holder address; authorization is purely proof-based |
| **Unlinkable proofs** | Two proofs against different circuits (or even the same circuit with different public inputs) are cryptographically independent; a verifier cannot tell if they came from the same credential |
| **No linkability across sessions** | The holder can use fresh fee-payer addresses or relayers for each transaction |
| **Approved sets are upgradeable** | The issuer publishes new Merkle roots; existing credentials remain valid |
| **No external services** | Verification is self-contained in the script; no oracles, DHTs, or registries are needed at proof time |

---

## Example Workflows

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

---

## Threat Model & Mitigations

| Threat | Mitigation |
|--------|-----------|
| Credential theft | **Holder binding:** Bind the credential to a holder secret (e.g., include a holder commitment in the signed message; the proof requires knowledge of the secret) |
| Proof replay | Add a nonce, epoch number, or transaction hash as a public input to the circuit |
| Sybil attacks | Issuer ensures one credential per real-world identity (out of scope of the cryptography) |
| Colluding verifiers | By design, proofs are unlinkable; collusion cannot cryptographically link sessions |
| Holder coercion | The holder can generate a proof for *any* predicate they satisfy; they cannot be forced to reveal specific field values because the proof does not expose them |

---

## Deployment Checklist

- [ ] Define credential schema (fields, encoding)
- [ ] Define predicate circuits per use case
- [ ] Run trusted setup (universal Powers of Tau + per-circuit Phase 2)
- [ ] Deploy Gate Scripts parameterized by each circuit's verifying key
- [ ] Publish issuer public key and Merkle roots via trusted channel
- [ ] Implement holder-side proof generation
- [ ] Optional: deploy relayer infrastructure for address-less submission

---

## Extension: Hiding the Fee Payer

For full anonymity, even the transaction fee payer can be hidden:

1. **Relayer network**: The holder sends the proof to a relayer who pays fees and submits the tx. The relayer cannot forge the proof.
2. **Stealth addresses**: The holder derives a one-time address for each transaction.
3. **Coin mixing**: Fees are paid from mixed UTxOs, breaking the chain of custody.

In all cases, the **Gate Script remains unchanged** — it validates only the proof, not the transaction's origin.

---

## References

1. A. De Salve, A. Lisi, M. Cascino, P. Mori, and L. Ricci, "Selective disclosure approaches in Self-Sovereign Identity: an experimental comparison," *IEEE Access*, 2025. DOI: [10.1109/ACCESS.2025.3649167](https://doi.org/10.1109/ACCESS.2025.3649167)

   This paper surveys and experimentally compares five selective disclosure strategies (atomic credentials, hashing, encryption, hash trees, and signature-based / BBS+) from the SSI literature. The design documented here advances beyond claim-level disclosure to **predicate-level zero-knowledge disclosure**, which the surveyed approaches do not address.

2. W3C, *Verifiable Credentials Data Model 2.0*, W3C Proposed Recommendation, 2025. https://www.w3.org/TR/vc-data-model-2.0/

3. W3C, *Decentralized Identifiers (DIDs) v1.0*, W3C Recommendation, 2022. https://www.w3.org/TR/did-core/
