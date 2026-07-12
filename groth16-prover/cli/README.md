# groth16-prover-cli

Command-line interface for generating and verifying Groth16 zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).

## Usage

> **Ceremony modes.** The CLI supports two ceremony paths that produce the **same** `.pk` / `.vk` binary format. The prover and verifier are agnostic to which path was used.

### Dev ceremony (`ceremony-dev` — without MPC, for testing)

A single-party ceremony that generates randomness locally and outputs a `ProvingKey` containing only group elements (no raw scalars). This is the **fast, insecure path** for development, CI, and benchmarking.

```bash
# Generate proving + verifying keys instantly (dev only — never for production)
groth16-prover ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

### Production ceremony (`phase2` — with MPC, for mainnet)

A multi-party Phase 2 ceremony that reuses a publicly verified Phase 1 SRS (e.g., Perpetual Powers of Tau). Each participant contributes randomness locally; the coordinator is just a passive file host.

```bash
# 1. Initialize from universal SRS
groth16-prover phase2 new \
  --circuit circuit.r1cs \
  --srs universal.ptau \
  --zkey circuit_0000.zkey

# 2. Participant 1 contributes locally, uploads result
groth16-prover phase2 contribute \
  --zkey-in circuit_0000.zkey \
  --zkey-out circuit_0001.zkey \
  --name "Alice"

# 3. Participant N contributes
groth16-prover phase2 contribute \
  --zkey-in circuit_0001.zkey \
  --zkey-out circuit_final.zkey \
  --name "Bob"

# 4. Verify the accumulator before finalizing
groth16-prover phase2 verify \
  --zkey circuit_final.zkey

# 5. Finalize to the same .pk/.vk format as dev mode
groth16-prover phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

### Prove

```bash
# Generate a proof using a proving key from the ceremony step
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --proving-key circuit.pk \
  --out proof.bin

# Without a proving key (dev only — uses deterministic test values)
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --out proof.bin
```

### Export verifying key to Aiken source

After the ceremony step, convert the binary `.vk` into Aiken source code that declares a `VerificationKey` record with hex-encoded compressed points.

```bash
groth16-prover export-vk \
  --verifying-key circuit.vk \
  --out circuit_vk.ak
```

The output file is a self-contained Aiken snippet you can paste into a validator or library. It contains the `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, `ic` list, and `n_public` fields.

### Verify

```bash
# Verify a proof using a verifying key from the ceremony step
groth16-prover verify \
  --proof proof.bin \
  --public proof.pub \
  --verifying-key circuit.vk

# Without a verifying key (dev only — uses deterministic test values)
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
| **Dev ceremony (`ceremony-dev`)** |
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--proving-key FILE` | — | *required* | Output path for the proving key |
| `--verifying-key FILE` | — | *required* | Output path for the verification key |
| **Production ceremony (`phase2`)** |
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--srs FILE` | — | *required* | Path to universal Phase 1 SRS (`.ptau`) |
| `--zkey FILE` | — | *required* | Output path for the intermediate `.zkey` |
| **Prove** |
| **Prove** |
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--witness FILE` | — | *required* | Path to `.wtns` witness file |
| `--proving-key FILE` | — | — | Proving key from ceremony (optional, dev fallback) |
| `--engine ENGINE` | `dense`, `fft` | `fft` | QAP construction engine |
| `--prover PROVER` | `naive`, `pippenger` | `pippenger` | MSM strategy for proof assembly |
| `--out FILE` | — | — | Output file (raw binary); public input written to `FILE.pub` |
| **Verify** |
| `--proof FILE` | — | *required* | Path to proof file (192 bytes) |
| `--public FILE` | — | *required* | Path to public-input file (48 bytes) |
| `--verifying-key FILE` | — | — | Verifying key from ceremony (optional, dev fallback) |

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

1. **Ceremony** (once per circuit) — two switchable paths produce the same `*.pk` / `*.vk` format:
   - **Dev mode** (`ceremony-dev`) — single-party, instant, insecure. Generates randomness locally, evaluates QAP, and writes pre-computed group elements (`a_query`, `b_g2_query`, `h_query`, etc.).
   - **Production mode** (`phase2`) — multi-party MPC. Reuses a publicly verified Phase 1 SRS (e.g., Perpetual Powers of Tau). Participants sequentially contribute randomness; the final output is the same group-element-based `*.pk` / `*.vk`.
2. **Load circuit** — parses the `.r1cs` binary format into dense L/R/O matrices
3. **Load witness** — parses the `.wtns` binary format into wire values
4. **Prove** — loads the proving key (group elements only, no scalars) and uses `FftQapEngine` + `PippengerProver` to compute the proof via multi-scalar multiplication; can be switched to `DenseQapEngine` or `NaiveProver` via flags
5. **Serialize** — outputs the proof using `ark-serialize` compressed format
6. **Verify** — loads the proof, public input, and verifying key, then checks the Groth16 pairing equation

## Complete example (with dev ceremony)

This example uses the **dev ceremony** (`ceremony-dev`) for speed. The resulting `.pk` / `.vk` files are in the exact same format as a production MPC ceremony, so the proving and verifying steps are identical.

```bash
# 1. Compile the Circom circuit
cd ../circom/SimpleExample
circom multiplier.circom --r1cs --wasm --prime bls12381

# 2. Generate witness
snarkjs wtns calculate multiplier.wasm input.json witness.wtns

# 3. Dev ceremony (run once per circuit — instant, single-party)
cd ../../cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# 4. Prove (uses the proving key — group elements, no scalars)
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

# 5. Verify (uses the verification key from the ceremony)
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub \
  --verifying-key /tmp/multiplier.vk
```

## Dev-only shortcut (no proving key — deterministic test values)

For the quickest possible testing you can skip even the `ceremony-dev` step. The prover and verifier fall back to hard-coded deterministic toxic waste (`tau=3, alpha=5, beta=7, gamma=11, delta=13`). No `.pk` or `.vk` files are needed:

```bash
# Prove (no --proving-key)
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --out /tmp/proof.bin

# Verify (no --verifying-key)
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub
```

> **Note:** This uses deterministic test values (`tau=3`, `alpha=5`, etc.) and skips the ceremony step. Once `FullProvingKey` serialization lands, this shortcut may be redirected to auto-generate a dev proving key.

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

## Proving key format

The CLI produces two formats.  The **preferred** one (group elements only) is what `ceremony-dev` outputs today and what a future MPC `phase2 finalize` will also output.

| Property | Legacy `ProvingKey` (scalars) | `FullProvingKey` (group elements) |
|----------|------------------------------|-----------------------------------|
| `.pk` size | ~200 bytes | ~MBs (circuit-dependent) |
| Toxic waste in `.pk` | ❌ Yes — raw scalars | ✅ No — only curve points |
| Prover work per proof | Re-evaluates QAP at `tau` | Pure MSM over pre-computed points |
| Dev path | `ceremony-dev` (legacy path, kept for backward compat) | `ceremony-dev` (default since Phase 0) |
| Production path | — | `phase2` MPC |

**Backward compatibility.**  The `prove` command auto-detects the format on load: if the file starts with the legacy `ProvingKey` magic it falls back to the scalar-based prover; otherwise it loads a `FullProvingKey` and uses the fast MSM path.  New `.pk` files are always written as `FullProvingKey`.

See [`MPC_Ceremony_Research.md`](../MPC_Ceremony_Research.md) for the full ceremony roadmap.

## Pairing equation

The verifier checks the standard Groth16 equation:
```
e(A, B) == e(alpha·G1, beta·G2) · e(C, delta·G2) · e(V, gamma·G2)
```
where `e` is the optimal Ate pairing on BLS12-381.
