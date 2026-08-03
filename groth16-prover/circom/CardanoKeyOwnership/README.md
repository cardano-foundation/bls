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

> ### ⭐ Recommended for Ed25519: use **Implementation 8** (the Nova step-chain) — it cuts e2e time by ~70 %
>
> The monolithic ~1.97M-constraint flow below is bottlenecked by its ceremony: **~5 min ceremony + ~1.7 min prove ≈ ~7 min e2e**. The [Implementation 8](../../README.md#implementation-8-nova-ivc--compression-snark) step-chain decomposes the same ownership proof into **255 × 7.7K-constraint steps** (`cardano_ed25519_ownership_nova.circom`): the ceremony drops to **~1.5 s** and the fold takes **~108 s**, i.e. **~2 min total e2e** — with per-step memory instead of ~3 GiB. The steps, keys, and transcript are all bound by a BLAKE2b512 state chain.
>
> ```bash
> circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
>   cardano_ed25519_ownership_nova.circom --r1cs --wasm --sym
> groth16-prover nova params --circuit cardano_ed25519_ownership_nova.r1cs
> groth16-prover nova ceremony --circuit cardano_ed25519_ownership_nova.r1cs \
>   --proving-key cko255.pk --verifying-key cko255.vk
> groth16-prover nova fold --circuit cardano_ed25519_ownership_nova.r1cs \
>   --proving-key cko255.pk --steps <witness-dir> --out cko255_ivc.json
> groth16-prover nova verify --ivc cko255_ivc.json --verifying-key cko255.vk
> ```
>
> Full worked example (witness generation, flags, expected output): the **End-to-end flow — Implementation 8 (Nova step-chain)** section below. The monolithic Implementation 7 flow that follows remains available as the reference single-proof path.

### End-to-end flow — Implementation 7 (monolithic + h-scalar)

> This is the **single-proof reference path**: one ~1.97M-constraint Groth16 proof, using the Implementation 7 sparse prover (`--sparse`) and h-query scalar compression (`--h-scalar`). Use it when you need one standalone proof for the whole key-ownership statement (e.g. a single on-chain verification). For interactive / step-heavy use, prefer the Implementation 8 step-chain below (~70 % faster e2e).

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

### End-to-end flow — Implementation 8 (Nova step-chain)

[`cardano_ed25519_ownership_nova.circom`](cardano_ed25519_ownership_nova.circom) decomposes the same ownership statement into **255 identical steps**, each one `BitElementMulAny` on extended Edwards coordinates `[4][3]` (each coordinate as 3 limbs of base 2^85):

- state `(dblIn[4][3], addIn[4][3])` — 24 public inputs / 24 public outputs, 1 private input `sel`.
- per step: `dblOut = 2·dblIn`, `addOut = addIn + sel·dblOut` (`sel` = scalar bit, LSB-first).
- after 255 steps: `addOut = 2·[sk]·G`; the final checks `addOut == PointA` (projective) and `PointCompress(PointA) == A` are done by the application *after* the fold (they cannot be folded per-step — the accumulator is only complete after all 255 bits).
- sizes: 7658 wires, 7724 constraints per step (vs ~1.97M monolithic). Same ceremony is reusable for **any** run of this step shape.

**1. Build the CLI**

```bash
cargo build --release --manifest-path ../../cli/Cargo.toml
# binary: ../../cli/target/release/groth16-prover (used as `groth16-prover` below)
```

**2. Compile the step circuit** (once; BLS12-381 field, `circomlib` include path)

```bash
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_ed25519_ownership_nova.circom --r1cs --wasm --sym
```

**3. Inspect the step circuit** (must report `n_pub_in == n_pub_out == 24`)

```bash
groth16-prover nova params --circuit cardano_ed25519_ownership_nova.r1cs
```

**4. One ceremony for the step circuit** (reusable for *any* run of the same step shape)

```bash
groth16-prover nova ceremony --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --verifying-key cko255.vk
```

**5. Generate the 255 step witnesses** `step_0000.wtns … step_0254.wtns` in one directory (full witness files, produced by the step circuit's wasm). Generate them **iteratively** so the chain invariant holds by construction:

```
dblIn := extended(G)          # base point, [4][3] x base-2^85 limbs
addIn := extended(O)          # identity
for i in 0..255:
    inputs = (dblIn, addIn, sel := (sk >> i) & 1)
    run wasm → full witness step_%04d.wtns
    read outputs (dblOut, addOut) → next (dblIn, addIn)
```

The `sel` bits come from the same clamped scalar `sk` as in the Implementation 7 flow (`sk[255]` produced by `gen_cardano_address_input.py`). Run each step through the step circuit's wasm (e.g. `snarkjs wtns calculate cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm`).

**6. Fold** — proves each step, checks the state chain, accumulates the transcript (≈2–4 min for 255 × 7.7K-constraint steps)

```bash
groth16-prover nova fold --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --steps <witness-dir> --out cko255_ivc.json
```

**7. Verify** — re-checks every Groth16 pairing, the state chain, and the transcript

```bash
groth16-prover nova verify --ivc cko255_ivc.json --verifying-key cko255.vk
# → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
```

> **Note:** `nova` verification is still **O(N)** — it re-checks every step proof. The constant-size compression SNARK (one pairing, O(1) verify) is [Implementation 9 / item (u)](../../README.md#pending) — not yet built.

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
