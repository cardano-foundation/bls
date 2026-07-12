# TO-DO: Interesting Groth16 Problems on Cardano

Source: [`groth16-prover/README.md`](../../groth16-prover/README.md) §**TO DO — Production innovations → (i) Additional Circom use-case circuits**.

Full pipeline for each item: **Circom → groth16-prover (dev ceremony) → Aiken on-chain validator**.

Tackle **one at a time**.

---

## 0. Pipeline Proof-of-Concept: SimpleExample Multiplier
**Status:** ✅ Completed

Validated the entire toolchain end-to-end with the existing `SimpleExample/multiplier.circom`.

### What was done
- Installed `circom` compiler + `snarkjs` witness generator
- Fixed critical bug in `circom_adapter.rs`: parser was only reading the first byte of 32-byte field coefficients, causing `-1` (used by Circom for output wires) to be read as `255` instead of being mapped to `1`. This corrupted the R1CS matrices and made public-input commitment points collapse to identity.
- Added `export-vk` CLI subcommand to `groth16-prover-cli` that reads a binary `.vk` and emits Aiken `VerificationKey` source code with hex-encoded compressed points.
- Compiled `multiplier.circom` → `.r1cs` + `.wasm`
- Generated `.wtns` witness from `input.json`
- Ran dev ceremony → `.pk` + `.vk`
- Generated proof with `.pk`
- Exported VK to Aiken-compatible format
- Wrote Aiken test `test_verify_circom_simple_example_proof()` that verifies the real Circom-generated proof on-chain using the exported VK and public inputs `[1, 48]`
- Added `test_verify_circom_rejects_wrong_public_input()` to confirm wrong public inputs are rejected

**Result:** All 16 Aiken tests pass, including the 2 new end-to-end Circom pipeline tests.

---

## 1. Merkle Membership (Privacy Coin Spend)
**Status:** 🔄 In Progress

Prove a coin commitment exists in a Merkle tree without revealing the leaf or path.

**Circuit:** `spend.circom` (already in `circom/Privacy/` — uses MiMC(x⁷) + `SelectiveSwitch`).  
**Public inputs:** `digest` (Merkle root), `nullifier`  
**Private inputs:** `nonce`, `sibling[path]`, `direction[path]`

**Use case:** ZCash-style shielded UTXO spending on Cardano.

---

## 1. Merkle Membership (Privacy Coin Spend)
**Status:** ⏳ Pending

Prove a coin commitment exists in a Merkle tree without revealing the leaf or path.

**Circuit:** `spend.circom` (already in `circom/Privacy/` — uses MiMC(x⁷) + `SelectiveSwitch`).  
**Public inputs:** `digest` (Merkle root), `nullifier`  
**Private inputs:** `nonce`, `sibling[path]`, `direction[path]`

**Use case:** ZCash-style shielded UTXO spending on Cardano.

---

## 2. Poseidon Hash Pre-image
**Status:** ⏳ Pending

Prove knowledge of a secret whose Poseidon hash equals a public commitment.

**Public input:** `hash_commitment`  
**Private input:** `secret`

**Use case:** Sealed-bid auctions, passwordless authentication.

---

## 3. Range Proof / Comparison
**Status:** ⏳ Pending

Prove a committed value lies in range `[0, 2^n)` without revealing the value.

**Public input:** `value_commitment`  
**Private inputs:** `value`, `blinding_factor`

**Use case:** Confidential transaction amounts.

---

## 4. Blake2b-224 Hash Pre-image (Cardano Key Hash)
**Status:** ⏳ Pending

Prove knowledge of a pre-image that hashes to a given Cardano key hash.

**Public input:** `blake2b_224_hash`  
**Private input:** `pre_image`

**Use case:** Proving ownership / linking proofs to on-chain Cardano addresses.

---

## 5. Private Key → Public Key Ownership Proof
**Status:** ⏳ Pending

Prove knowledge of the private scalar that generates a given public key / address.

**Public input:** `public_key`  
**Private input:** `private_scalar`

**Use case:** Wallet ownership proof without revealing the private key.

---

## 6. EdDSA / Ed25519 Signature Verification In-Circuit
**Status:** ⏳ Pending

Verify a standard Ed25519 signature inside a Groth16 circuit.

**Public inputs:** `message_hash`, `public_key`, `signature_R`, `signature_S`  
**Private inputs:** *(none — signature verification is entirely public)*

**Use case:** Attest to off-chain events signed by standard Ed25519 keys (SSH, TLS, other blockchains).

---

## Completed

*(none yet)*
