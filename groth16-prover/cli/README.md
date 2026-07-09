# groth16-prover-cli

Command-line interface for generating and verifying Groth16 zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).

## Usage

### Prove

```bash
# Generate a proof and print hex to stdout (defaults: --engine fft --prover pippenger)
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns

# Generate a proof and write raw binary to file
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --out proof.bin
```

### Verify

```bash
# Verify a proof against its public input
groth16-prover verify --proof proof.bin --public proof.pub
```

### All engine + prover combinations

```bash
# 1. fft + pippenger   (default — fastest, recommended for production)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine fft --prover pippenger

# 2. fft + naive       (good for debugging FFT path; same proof points as pippenger)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine fft --prover naive

# 3. dense + pippenger (fast MSM but slow QAP; useful for parity testing)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine dense --prover pippenger

# 4. dense + naive     (pedagogical — every step is scalar-by-scalar, easiest to trace)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine dense --prover naive
```

### Flags

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--witness FILE` | — | *required* | Path to `.wtns` witness file |
| `--engine ENGINE` | `dense`, `fft` | `fft` | QAP construction engine |
| `--prover PROVER` | `naive`, `pippenger` | `pippenger` | MSM strategy for proof assembly |
| `--out FILE` | — | — | Output file (raw binary); public input written to `FILE.pub` |
| `--proof FILE` | — | *required for verify* | Path to proof file (192 bytes) |
| `--public FILE` | — | *required for verify* | Path to public-input file (48 bytes) |

When `--out` is provided during proving, two files are written:
- `proof.bin` — the Groth16 proof (192 bytes: compressed G1 + G2 + G1)
- `proof.pub` — the public-input commitment (48 bytes: compressed G1)

## Build

```bash
cd groth16-prover/cli
cargo build --release
```

The binary will be at `target/release/groth16-prover`.

## How it works

1. **Load circuit** — parses the `.r1cs` binary format into dense L/R/O matrices
2. **Load witness** — parses the `.wtns` binary format into wire values
3. **Prove** — by default uses `FftQapEngine` + `PippengerProver` (FFT-accelerated QAP + batched MSM); can be switched to `DenseQapEngine` or `NaiveProver` via flags
4. **Serialize** — outputs the proof using `ark-serialize` compressed format
5. **Verify** — loads the proof and public input, then checks the Groth16 pairing equation using the hard-coded verification key

## Complete example

```bash
# 1. Compile the Circom circuit
cd ../circom
circom multiplier.circom --r1cs --wasm --prime bls12381

# 2. Generate witness
snarkjs wtns calculate multiplier.wasm input.json witness.wtns

# 3. Prove
cd ../cli
cargo run --release -- prove \
  --circuit ../circom/multiplier.r1cs \
  --witness ../circom/witness.wtns \
  --out /tmp/proof.bin

# 4. Verify
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub
```

---

## Proof serialization format (arkworks CanonicalSerialize)

The proof files produced by this CLI use **arkworks' standard compressed serialization**, defined by the `CanonicalSerialize` / `CanonicalDeserialize` traits from the `ark-serialize` crate. This is the same format used by the arkworks `groth16` module internally.

### What is ark-serialize?

`ark-serialize` is the canonical serialization library for the arkworks ecosystem. It defines how algebraic objects (field elements, curve points, polynomials) are encoded to and decoded from byte streams. The format is designed to be:

- **Deterministic** — same mathematical object always serializes to the same bytes
- **Compact** — compressed point encoding minimizes size
- **Validated** — deserialization checks that points lie on the curve and in the correct subgroup
- **Interoperable** — any arkworks-based library can read/write it

### Compressed point encoding

For BLS12-381, the compressed serialization uses the standard [Zcash serialization format](https://github.com/zcash/librustzcash/blob/main/pairing/src/bls12_381/README.md#point-representation):

- **G1Affine**: 48 bytes
  - Byte 0: flags in the most-significant 3 bits
    - bit 7 (MSB): point at infinity (`1` if infinity, `0` otherwise)
    - bit 6: sign of y-coordinate (when not infinity)
    - bit 5: always set to `1` for compressed format
  - Bytes 1..47: x-coordinate (381 bits, little-endian, padded with zeroes)

- **G2Affine**: 96 bytes
  - Same flag layout as G1, but the x-coordinate is an element of `F_q²` (two `F_q` coefficients)
  - Bytes 1..95: x-coordinate in `F_q²` (each `F_q` limb is 48 bytes, little-endian)

### Proof byte layout

A Groth16 proof is exactly **192 bytes**:

| Field | Type | Bytes | Offset |
|-------|------|-------|--------|
| `A` | G1Affine compressed | 48 | 0..48 |
| `B` | G2Affine compressed | 96 | 48..144 |
| `C` | G1Affine compressed | 48 | 144..192 |
| **Total** | | **192** | |

The public-input commitment `V` is exactly **48 bytes** (one G1Affine compressed point).

### Example: reading a proof in Rust

```rust
use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::CanonicalDeserialize;

let proof_bytes = std::fs::read("proof.bin").unwrap();
assert_eq!(proof_bytes.len(), 192);

let a = G1Affine::deserialize_compressed(&proof_bytes[0..48]).unwrap();
let b = G2Affine::deserialize_compressed(&proof_bytes[48..144]).unwrap();
let c = G1Affine::deserialize_compressed(&proof_bytes[144..192]).unwrap();
```

### Example: reading a proof in Python (for interoperability)

Because the format is just raw compressed bytes, any language with a BLS12-381 library can parse it:

```python
# Using py_ecc or another BLS12-381 library
with open("proof.bin", "rb") as f:
    data = f.read()

a_bytes = data[0:48]    # G1 point
b_bytes = data[48:144]  # G2 point
c_bytes = data[144:192] # G1 point

# Parse each point using your library's compressed-point decoder
```

### Compatibility notes

- ✅ **Arkworks-native** — `arkworks/groth16` uses this exact same format internally
- ⚠️ **snarkjs JSON** — snarkjs outputs proofs as JSON arrays of big integers (e.g. `{"pi_a": ["123", ...]}`). To exchange proofs with snarkjs you must convert between the binary format and JSON, or use snarkjs's `--protocol groth16` export.
- ⚠️ **Other curves** — The 48/96 byte sizes are specific to BLS12-381. For BN254, G1 is 32 bytes and G2 is 64 bytes.

### Why not JSON?

Raw binary serialization is:
- **~10× smaller** than JSON (192 bytes vs ~2 KB of ASCII)
- **Faster** — no parsing of big-int strings
- **Type-safe** — deserialization validates curve membership automatically
- **Standard** — any arkworks project can load it without custom parsing code

For human inspection, use `hexdump -C proof.bin` or `xxd proof.bin`.

---

## Verification key note

The `verify` subcommand currently uses a **hard-coded verification key** derived from deterministic toxic-waste parameters (`alpha=5, beta=7, gamma=11, delta=13`). This is sufficient for testing and end-to-end demos, but **not for production**.

In a real deployment:
1. Run a trusted-setup ceremony (or use a universal setup like PLONK)
2. Serialize the resulting verification key to a file
3. Load that VK file in the verifier instead of using hard-coded values

The pairing equation checked is the standard Groth16 equation:
```
e(A, B) == e(alpha·G1, beta·G2) · e(C, delta·G2) · e(V, gamma·G2)
```
where `e` is the optimal Ate pairing on BLS12-381.
