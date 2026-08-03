# Ed25519 Signature Verification In-Circuit

Verify a standard Ed25519 signature inside a Groth16 circuit — without revealing the signature components. This proves that a given message was signed by a specific Ed25519 public key, producing a zk-SNARK proof that can be verified on-chain (e.g., in Aiken on Cardano).

## What it proves

```
Public:   msg[n], A[256], R8[256]     — message bits, pubkey bits, signature-R bits
Private:  S[255], PointA[4][3], PointR[4][3]  — signature scalar, decompressed pubkey/R

Constraint: Ed25519Verify(msg, A, R8, S, PointA, PointR) == 1
```

The circuit follows RFC 8032 Section 6:
1. Compress `PointA` and `PointR` and assert they equal `A` and `R8`.
2. Hash `R8 || A || msg` with SHA-512 and reduce modulo `q`.
3. Compute `s·G` and `h·A` via scalar multiplication on Curve25519.
4. Assert `s·G == R + h·A` via point equality check.

**Status:** ✅ **Working end-to-end** — compiles with `circom --prime bls12381`, witness generation works for valid Ed25519 inputs, and the sparse dev ceremony + sparse prover produce and verify valid proofs.

## Circuit structure

| File | Purpose | Source |
|------|---------|--------|
| `verify.circom` | `Ed25519Verifier(n)` template — top-level verification logic | Electron-Labs/ed25519-circom (archived, MIT License) |
| `ed25519_verify.circom` | **New** — wrapper instantiating `Ed25519Verifier(256)` with `public [msg, A, R8]` | This project |
| `scalarmul.circom` | `ScalarMul()` — point multiplication on Curve25519 | Electron-Labs |
| `point-addition.circom` | `PointAdd()` — extended-coordinate point addition | Electron-Labs |
| `pointcompress.circom` | `PointCompress()` — compress extended point to 256 bits | Electron-Labs |
| `modulus.circom` | `ModulusWith25519Chunked51`, `ModulusAgainst2PChunked51`, etc. | Electron-Labs |
| `chunkedmul.circom` | `ChunkedMul()` — 85-bit/51-bit chunked multiplication | Electron-Labs |
| `chunkedadd.circom`, `chunkedsub.circom` | `ChunkedAdd()`, `ChunkedSub()` — chunked modular add/sub | Electron-Labs |
| `chunkify.circom` | `Chunkify()` — bit chunking utilities | Electron-Labs |
| `binadd.circom`, `binmul.circom`, `binsub.circom` | Binary adders/multipliers | Electron-Labs |
| `modinv.circom` | `BigModInv51()` — modular inverse via extended Euclid | Electron-Labs |
| `inversemodulo.circom` | Helper for modular inverse | Electron-Labs |
| `lt.circom` | `LessThanPower()`, `LessThanBounded()` — comparison gadgets | Electron-Labs |
| `utils.circom` | `calculateNumOutputs()` and other helpers | Electron-Labs |
| `node_modules/@electron-labs/sha512/circuits/sha512/sha512.circom` | `Sha512()` — SHA-512 hash (80 rounds, 1024-bit block) | `@electron-labs/sha512` npm package |
| `node_modules/circomlib/circuits/comparators.circom`, `gates.circom`, `bitify.circom` | `IsEqual()`, `AND()`, `Num2Bits()` | `circomlib` |

**Key design decisions from upstream:**
- Points are represented in **extended homogeneous coordinates** `[X, Y, Z, T]` with each coordinate split into **base-2⁸⁵ chunks** (3 chunks of 85 bits each).
- The circuit uses a **trick** to avoid expensive point decompression: the prover provides both the compressed bit representation and the decompressed point, and the circuit compresses the point and asserts equality.
- All modular arithmetic (add, sub, mul, inv) is performed via **custom chunked templates** rather than native field operations, because Curve25519's prime `2²⁵⁵ − 19` does not match either BN254 or BLS12-381.

---

## Compilation results

```bash
cd groth16-prover/circom/Ed25519Verify
circom ed25519_verify.circom --r1cs --wasm --sym --prime bls12381
```

| Metric | Value |
|--------|-------|
| **Non-linear constraints** | 2,564,493 |
| **Linear constraints** | 1,482,528 |
| **Total constraints** | ~4,047,021 |
| **Public inputs** | 768 (`msg[256]`, `A[256]`, `R8[256]`) |
| **Private inputs** | 279 (`S[255]`, `PointA[4][3]`, `PointR[4][3]`) |
| **Public outputs** | 1 (`out`) |
| **Wires** | 4,000,207 |
| **Labels** | 11,792,090 |
| **Template instances** | 210 |
| **Powers of Tau needed** | 2²² (4,194,304 max constraints) |

---

## End-to-end pipeline

### Step 1 — Compile the circuit

```bash
cd groth16-prover/circom/Ed25519Verify
circom ed25519_verify.circom --r1cs --wasm --sym --prime bls12381
```

Produces: `ed25519_verify.r1cs` (~4M constraints), `ed25519_verify.wasm`, `ed25519_verify.sym`.

### Step 2 — Generate the witness

Generate a valid Ed25519 test input (uses `pynacl`):

```bash
cd groth16-prover/circom/Ed25519Verify
python3 gen_verify_input.py
snarkjs wtns calculate ed25519_verify_js/ed25519_verify.wasm test_verify_input.json witness_verify.wtns
```

Witness generation works for valid signatures (`out = 1`). Invalid signatures produce `out = 0`.

### Step 3 — Run the sparse dev ceremony

⚠️ **Use `--sparse` flag.** Without it, the dense-matrix ceremony requires ~512 TB RAM and will OOM immediately.

```bash
cd groth16-prover/cli

cargo run --release -- ceremony-dev --sparse \
  --circuit ../circom/Ed25519Verify/ed25519_verify.r1cs \
  --proving-key /tmp/ed25519.pk \
  --verifying-key /tmp/ed25519.vk
```

**Measured:** **~16 min** | Memory: ~3 GiB (AMD Ryzen 9 7950X 16-core, 64 GiB RAM)

> **Optional: `--h-scalar`.** Adds `--h-scalar` to the ceremony to halve the proving-key size (~2.7 GB → ~1.3 GB uncompressed) and cut prove time by >2×. The prover auto-detects h_scalar with no extra flags.

**To monitor progress:**

```bash
# In another terminal, watch memory and CPU
watch -n 30 'ps -p $(pgrep -f "ed25519_verify.r1cs") -o pid,etime,%cpu,vsz,rss'

# Check if output files appeared
ls -lh /tmp/ed25519.pk /tmp/ed25519.vk
```

### Step 4 — Generate the proof

```bash
cd groth16-prover/cli
cargo run --release -- prove --sparse \
  --circuit ../circom/Ed25519Verify/ed25519_verify.r1cs \
  --witness ../circom/Ed25519Verify/witness_verify.wtns \
  --proving-key /tmp/ed25519.pk \
  --out /tmp/ed25519_proof.bin
```

**Measured:** **~5 min** (~2 min with `--h-scalar` ceremony)

### Step 5 — Export the VK to Aiken

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/ed25519.vk \
  --out /tmp/ed25519_vk.ak
```

### Step 6 — Verify in Aiken

Paste the exported VK and proof bytes into an Aiken test or validator. The verifier logic is identical to all other BLS12-381 circuits in `aiken/groth16/lib/groth16/verifier.ak`.

---

## Files

```
Ed25519Verify/
├── verify.circom                # Ed25519Verifier(n) — main logic (from upstream)
├── ed25519_verify.circom        # Top-level wrapper (this project)
├── scalarmul.circom             # Scalar multiplication on Curve25519
├── point-addition.circom        # Extended-coordinate point addition
├── pointcompress.circom         # Point compression (compress & assert)
├── modulus.circom               # Modular reduction templates
├── chunkedmul.circom            # Chunked multiplication
├── chunkedadd.circom           # Chunked addition
├── chunkedsub.circom           # Chunked subtraction
├── chunkify.circom              # Bit chunking
├── binadd.circom, binmul.circom, binsub.circom  # Binary arithmetic
├── modinv.circom                # Modular inverse
├── inversemodulo.circom         # Inverse helper
├── lt.circom                    # Comparison gadgets
├── utils.circom                 # Utility functions
├── batchverify.circom           # Batch verification (not used)
├── test_verify16.circom         # Test wrapper with n=16 (for debugging)
├── test_compress*.circom      # Isolated PointCompress debug circuits
├── gen_input.py                 # Python script to generate test inputs
├── gen_test16_input.py          # Python script for RFC test vectors
├── input.json                   # Test input (random Ed25519 signature)
├── test16_input.json            # RFC 8032 test vector input
├── ed25519_verify.r1cs          # Compiled R1CS (~4M constraints)
├── ed25519_verify_js/           # WebAssembly witness generator
├── package.json                 # npm dependencies (circomlib, @electron-labs/sha512)
├── node_modules/                # Resolved dependencies
└── README.md                    # This file
```

---

## References

- [Electron-Labs/ed25519-circom](https://github.com/Electron-Labs/ed25519-circom) — upstream Ed25519 Circom circuits (archived, MIT License)
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — EdDSA and Ed25519 specification
- [circomlib](https://github.com/iden3/circomlib) — standard Circom gadgets (`comparators`, `gates`, `bitify`)
- [@electron-labs/sha512](https://www.npmjs.com/package/@electron-labs/sha512) — SHA-512 Circom implementation
- [`groth16-prover/circom/README.md`](../../circom/README.md) — Parent directory with full pipeline documentation
