# Cardano Private Key → Public Key Ownership Proof

Prove knowledge of the private scalar that generates a given public key — without revealing the private key.

Two variants are provided:

| Variant | Curve | Constraints | Status | Use case |
|---------|-------|-------------|--------|----------|
| **JubJub ownership** | JubJub (BLS12-381-native) | ~4K | ✅ Working e2e | Fast proof, but **NOT** a real Cardano key |
| **Ed25519 ownership** | Curve25519 (Ed25519) | ~1.97M | ✅ Working e2e | Proves **real** Cardano wallet key ownership |

> **Do I need to recompile for every key?** **No.** The `.r1cs` and `.wasm` are compiled **once** and reused for any keypair. Only `input.json` is per-user.

---

## Prerequisites

| Tool | How to get it | Why we need it |
|------|---------------|----------------|
| `circom` | `cargo install circom` | Compile `.circom` → `.r1cs` + `.wasm` |
| `snarkjs` | `npm install -g snarkjs` | Generate `.wtns` from `.wasm` + `input.json` |
| `cardano-address` | [IntersectMBO/cardano-addresses releases](https://github.com/IntersectMBO/cardano-addresses/releases) | Derive real Cardano keys from BIP-39 mnemonic |
| `bech32` (CLI) | [IntersectMBO/bech32 releases](https://github.com/IntersectMBO/bech32/releases) | Decode bech32 key files |
| `groth16-prover` CLI | `cd cli && cargo build --release` | Ceremony, proof generation, verification |

---

<details>
<summary><b>Variant A: JubJub Key Ownership (~4K constraints) — click to expand</b></summary>

### What it proves

The prover knows a scalar `sk` such that `pk = [sk] · G_JubJub`, where `G_JubJub` is the JubJub base point. The verifier sees only `pk` — `sk` stays secret.

> **Caveat:** JubJub is a SNARK-friendly curve embedded in BLS12-381's scalar field. It is **not** a standard Cardano Ed25519 key. A separate off-chain commitment can link the JubJub key to a Cardano address, but the proof itself is for the JubJub key.

### End-to-end flow

```bash
cd groth16-prover/circom/CardanoKeyOwnership

# 1. Compile (once)
circom --prime bls12381 cardano_key_ownership.circom --r1cs --wasm --sym

# 2. Create input.json with your JubJub private key and public key
#    (example: sk = 12345, pk_x = ..., pk_y = ...)
cat > input.json << 'EOF'
{
  "sk": ["1","0","0","1","0","1","1","0","0","0","0","0","0","0","0","0"],
  "pk_x": ["123456789012345678901234567890123456789012345678901234567890","0","0"],
  "pk_y": ["987654321098765432109876543210987654321098765432109876543210","0","0"]
}
EOF

# 3. Generate witness
snarkjs wtns calculate \
  cardano_key_ownership_js/cardano_key_ownership.wasm \
  input.json witness.wtns

# 4. Dev ceremony
cd ../../cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/CardanoKeyOwnership/cardano_key_ownership.r1cs \
  --proving-key /tmp/jubjub.pk --verifying-key /tmp/jubjub.vk

# 5. Prove
cargo run --release -- prove \
  --circuit ../circom/CardanoKeyOwnership/cardano_key_ownership.r1cs \
  --witness ../circom/CardanoKeyOwnership/witness.wtns \
  --proving-key /tmp/jubjub.pk --out /tmp/jubjub_proof.bin

# 6. Verify
cargo run --release -- verify \
  --proof /tmp/jubjub_proof.bin \
  --public /tmp/jubjub_proof.pub \
  --verifying-key /tmp/jubjub.vk
# → Verification result: VALID
```

</details>

---

<details>
<summary><b>Variant B: Ed25519 Key Ownership (~1.97M constraints) — click to expand</b></summary>

### What it proves

The prover knows the **clamped Ed25519 scalar** `a` (derived from a Cardano BIP32-Ed25519 extended signing key) such that the public key `A` equals `PointCompress([a]·G)` on Curve25519.

This is a minimal subset of the full `Ed25519Verify` circuit: one scalar multiplication on the base point, plus point compression. No SHA-512, no signature components. It proves ownership of a **real Cardano wallet key**.

### End-to-end flow

#### Step 1: Derive a real Cardano payment key

```bash
cd groth16-prover/circom/CardanoKeyOwnership

# Generate a 15-word recovery phrase
cardano-address recovery-phrase generate --size 15 > phrase.prv

# Derive the extended root signing key
cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk

# Derive the payment signing key (path 1852H/1815H/0H/0/0)
cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk

# Extract the public key (without chain code)
cardano-address key public --without-chain-code < pay.xsk > pay.vk
```

**Key insight:** The payment signing key `pay.xsk` encodes the Ed25519 scalar in its first 32 bytes (`kL`). In Cardano's BIP32-Ed25519, `kL` is **already clamped** — exactly what the circuit needs as the private witness `sk[255]`. The `pay.vk` file contains the standard 32-byte Ed25519 compressed public key.

#### Step 2: Generate circuit input from bech32 keys

```bash
# Decode bech32 and convert to bit/chunk arrays
python3 gen_cardano_address_input.py --xsk pay.xsk --vk pay.vk -o input.json
```

This produces `input.json` with:
- `A[256]` — compressed public key bits (from `pay.vk`)
- `sk[255]` — clamped scalar bits (from `pay.xsk`)
- `PointA[4][3]` — decompressed public key in extended coordinates

#### Step 3: Compile, witness, ceremony, prove, verify

```bash
# 3a. Compile the circuit (once)
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_ed25519_ownership.circom --r1cs --wasm --sym

# 3b. Generate witness
snarkjs wtns calculate \
  cardano_ed25519_ownership_js/cardano_ed25519_ownership.wasm \
  input.json witness_ownership.wtns

# 3c. Dev ceremony (⚠️ MUST use --sparse)
#     Add --h-scalar to store a single scalar instead of the full h_query vector.
#     This halves the PK size and cuts prove time by ~10–15 %.
cd ../../cli
cargo run --release -- ceremony-dev --sparse --h-scalar \
  --circuit ../circom/CardanoKeyOwnership/cardano_ed25519_ownership.r1cs \
  --proving-key /tmp/cardano_ed25519.pk \
  --verifying-key /tmp/cardano_ed25519.vk

# 3d. Prove (⚠️ MUST use --sparse)
#     No extra flags needed — the prover auto-detects h_scalar from the PK.
cargo run --release -- prove --sparse \
  --circuit ../circom/CardanoKeyOwnership/cardano_ed25519_ownership.r1cs \
  --witness ../circom/CardanoKeyOwnership/witness_ownership.wtns \
  --proving-key /tmp/cardano_ed25519.pk \
  --out /tmp/cardano_ed25519_proof.bin

# 3e. Verify
cargo run --release -- verify \
  --proof /tmp/cardano_ed25519_proof.bin \
  --public /tmp/cardano_ed25519_proof.pub \
  --verifying-key /tmp/cardano_ed25519.vk
# → Verification result: VALID
```

#### Step 4: Export VK for on-chain deployment (optional)

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/cardano_ed25519.vk \
  --out /tmp/cardano_ed25519_vk.ak
```

</details>

---

## How it works (Ed25519 variant)

```circom
template CardanoEd25519Ownership() {
    signal input A[256];      // compressed public key (public)
    signal input sk[255];     // clamped scalar (private)
    signal input PointA[4][3]; // decompressed point (private)

    // 1. [sk] · G
    component pMul = ScalarMul();
    pMul.s <== sk;
    pMul.P <== G;   // Curve25519 base point

    // 2. Assert [sk]·G == PointA
    component equal = PointEqual();
    equal.p <== pMul.sP;
    equal.q <== PointA;

    // 3. Assert PointCompress(PointA) == A
    component compressA = PointCompress();
    compressA.P <== PointA;
    compressA.out === A;
}
```

Uses `ScalarMul`, `PointEqual`, and `PointCompress` from `Ed25519Verify/` (Electron-Labs templates adapted for BLS12-381).

---

## References

- [`Ed25519Verify/README.md`](../Ed25519Verify/README.md) — Full Ed25519 signature verification on BLS12-381
- [`EdDSAJubJub/README.md`](../EdDSAJubJub/README.md) — JubJub curve parameters
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — EdDSA / Ed25519 specification
- [Electron-Labs/ed25519-circom](https://github.com/Electron-Labs/ed25519-circom) — upstream Ed25519 Circom circuits
- [IntersectMBO/cardano-addresses](https://github.com/IntersectMBO/cardano-addresses) — Cardano key derivation (CIP-1852)
- [IntersectMBO/cardano-crypto](https://github.com/IntersectMBO/cardano-crypto) — Cardano key derivation logic

## License

MIT (same as upstream circomlib and EdDSAJubJub/Ed25519Verify circuits).
