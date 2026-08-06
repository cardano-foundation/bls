# Blake2b-224 Hash Pre-image (Cardano Key Hash)

Prove knowledge of a 32-byte pre-image whose Blake2b-224 hash equals a publicly known Cardano key hash — without revealing the pre-image.

```
Public:  blake2b_224_hash[28]  — the 28-byte Cardano key hash
Secret:  pre_image[32]         — the 32-byte pre-image (e.g. an Ed25519 public key)

Constraint: Blake2b-224(pre_image) == blake2b_224_hash
```

Cardano uses Blake2b-224 for address and key hashing, so an in-circuit gadget is essential for any zk-proof that needs to reason about Cardano keys or addresses without revealing them.

---

## Circuit structure

| File | Purpose | Source |
|------|---------|--------|
| `blake2b_common.circom` | Helper templates: `ToBits`, `XorWord3`, `Sigma`, `Bits65/66`, etc. | [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) (MIT License) |
| `blake2b.circom` | Blake2b-512 primitives: `CompressionF`, `MixFunG`, `SingleRound`, `IV` | [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) (MIT License) |
| `blake2b224.circom` | **New** — `Blake2b224_bytes` template with `nn = 28` (Blake2b-224 output length) | Derived from `blake2b.circom` |
| `blake2b224_preimage.circom` | **Top-level circuit** — wires public hash input to the hasher and enforces equality | This project |

### Key change from upstream

The upstream `hash-circuits` repo only provides `Blake2b_bytes` with `nn = 32` (Blake2b-256). We created a new `Blake2b224_bytes` template that sets:
- `nn = 28` (output length in bytes)
- `nw = (nn + 7) \ 8 = 4` (output qwords)
- `p0 = 0x01010000 ^ (kk << 8) ^ nn` (parameter block, using `nn = 28`)

Everything else (the `CompressionF` function, the 12 rounds, the IV, the sigma permutation) is unchanged.

---

## Compilation results

```bash
cd groth16-prover/circom/Blake2b224Preimage
circom blake2b224_preimage.circom --r1cs --wasm --sym --prime bls12381
```

| Metric | Value |
|--------|-------|
| **Non-linear constraints** | 77,312 |
| **Linear constraints** | 2,059 |
| **Total constraints** | ~79,371 |
| **Public inputs** | 28 (`blake2b_224_hash` bytes) |
| **Private inputs** | 32 (`pre_image` bytes) |
| **Wires** | 78,605 |
| **Labels** | 217,394 |
| **Template instances** | 56 |

---

## Witness generation

```bash
snarkjs wtns calculate blake2b224_preimage_js/blake2b224_preimage.wasm input.json witness.wtns
```

The witness was generated successfully. The output hash bytes were cross-checked against Python's `hashlib.blake2b(pre_image, digest_size=28)` and match exactly:

```
pre_image  = [0, 1, 2, ..., 31]   (32 bytes)
hash       = [73, 17, 18, 221, 1, 21, 92, 7, 218, 180, 133, 247,
              27, 87, 46, 12, 174, 117, 158, 44, 211, 139, 28, 14,
              151, 85, 66, 151]    (28 bytes)
hash hex   = 491112dd01155c07dab485f71b572e0cae759e2cd38b1c0e97554297
```

---

## End-to-end pipeline

The pipeline runs with the sparse prover: use `--sparse` on the ceremony (the dense path would OOM at ~200 GB). Total e2e time is **~26 s** with ~280 MiB RAM.

### 1. Compile

```bash
cd groth16-prover/circom/Blake2b224Preimage
circom blake2b224_preimage.circom --r1cs --wasm --sym --prime bls12381
```

### 2. Generate witness input

Create `input.json` with a 32-byte pre-image and its Blake2b-224 hash:

```python
import json, hashlib
pre_image = list(range(32))  # 32 bytes
h = hashlib.blake2b(bytes(pre_image), digest_size=28)
circuit_input = {
    "pre_image": [str(b) for b in pre_image],
    "blake2b_224_hash": [str(b) for b in h.digest()]
}
json.dump(circuit_input, open("input.json", "w"), indent=2)
```

### 3. Calculate witness

```bash
snarkjs wtns calculate \
  blake2b224_preimage_js/blake2b224_preimage.wasm \
  input.json witness.wtns
```

### 4. Sparse dev ceremony

> The ceremony runs in the standalone `trusted-setup` CLI (built via `cd ../../../clis/trusted-setup && cargo build --release`), invoked here by its binary path.

```bash
cd ../../cli
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev --sparse \
  --circuit ../circom/Blake2b224Preimage/blake2b224_preimage.r1cs \
  --proving-key /tmp/blake2b224.pk \
  --verifying-key /tmp/blake2b224.vk
```

**Measured:** **~18 s** | Memory: ~280 MiB

### 5. Prove

```bash
cargo run --release -- prove --sparse \
  --circuit ../circom/Blake2b224Preimage/blake2b224_preimage.r1cs \
  --witness ../circom/Blake2b224Preimage/witness.wtns \
  --proving-key /tmp/blake2b224.pk \
  --out /tmp/blake2b224_proof.bin
```

**Measured:** **~5 s**

### 6. Verify

```bash
cargo run --release -- verify \
  --proof /tmp/blake2b224_proof.bin \
  --public /tmp/blake2b224_proof.pub \
  --verifying-key /tmp/blake2b224.vk
```

**Measured:** **~0.2 s** | Result: `Verification result: VALID`

### Total e2e time

| Step | Time |
|------|------|
| Compile | ~2 s |
| Witness | ~1 s |
| Ceremony (sparse) | **~18 s** |
| Prove (sparse) | **~5 s** |
| Verify | **~0.2 s** |
| **Total** | **~26 s** |

### 7. Export VK to Aiken (optional)

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/blake2b224.vk \
  --out /tmp/blake2b224_vk.ak
```

The exported Aiken source can be pasted into `aiken/groth16/lib/groth16/verifier.ak` for on-chain verification.

---

## Files

```
Blake2b224Preimage/
├── blake2b_common.circom     # From bkomuves/hash-circuits (MIT)
├── blake2b.circom            # From bkomuves/hash-circuits (MIT)
├── blake2b224.circom         # Blake2b-224 variant (nn = 28)
├── blake2b224_preimage.circom # Top-level circuit
├── input.json                # Test vector: pre_image = [0..31], hash = [73, 17, ...]
├── witness.wtns              # Generated witness (valid, cross-checked)
├── blake2b224_preimage.r1cs  # Compiled R1CS
└── README.md                 # This file
```

---

## References

- [bkomuves/hash-circuits](https://github.com/bkomuves/hash-circuits) — Blake2b Circom circuits (MIT License)
- [RFC 7693](https://tools.ietf.org/html/rfc7693) — The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
- [Cardano crypto specs](https://github.com/IntersectMBO/cardano-crypto) — Key derivation and Blake2b-224 usage in Cardano wallets
- [`groth16-prover/circom/README.md`](../../circom/README.md) — Parent directory with full pipeline documentation
