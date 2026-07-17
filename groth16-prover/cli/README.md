# groth16-prover-cli

Command-line interface for the full Groth16 zero-knowledge proof lifecycle on BLS12-381.

This CLI covers everything from trusted-setup ceremonies (both dev and multi-party MPC) through proof generation and verification, plus auxiliary tools for privacy-preserving circuits: witness-input computation for shielded spends and sparse Merkle tree operations. All outputs use arkworks' canonical compressed serialization so they are directly consumable by on-chain Aiken verifiers.

---

## What the CLI provides

| Command | Purpose |
|---------|---------|
| `ceremony-dev` | Single-party dev ceremony — instant, insecure, for testing |
| `phase2` | Multi-party Phase 2 MPC ceremony — for production deployments |
| `prove` | Generate a Groth16 proof from `.r1cs` + `.wtns` |
| `verify` | Verify a proof against its public input |
| `export-vk` | Convert a binary `.vk` to Aiken source code |
| `compute-inputs` | Build private Merkle-path JSON for the Spend(depth) circuit |
| `smt` | Sparse Merkle Tree operations (insert, digest, path) |

### Quickest possible workflow (dev ceremony)

```bash
cd groth16-prover/cli

# 1. Ceremony (once per circuit)
cargo run --release -- ceremony-dev \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# 2. Prove
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

# 3. Verify
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub \
  --verifying-key /tmp/multiplier.vk
```

---

## How it works

1. **Ceremony** (once per circuit) — two switchable paths produce the same `*.pk` / `*.vk` format:
   - **Dev mode** (`ceremony-dev`) — single-party, instant, insecure. Generates randomness locally, evaluates QAP, and writes pre-computed group elements (`a_query`, `b_g2_query`, `h_query`, etc.).
   - **Production mode** (`phase2`) — multi-party MPC. Reuses a publicly verified Phase 1 SRS (e.g., Perpetual Powers of Tau). Participants sequentially contribute randomness; the final output is the same group-element-based `*.pk` / `*.vk`.
2. **Load circuit** — parses the `.r1cs` binary format into dense L/R/O matrices
3. **Load witness** — parses the `.wtns` binary format into wire values
4. **Prove** — loads the proving key (group elements only, no scalars) and uses `FftQapEngine` + `PippengerProver` to compute the proof via multi-scalar multiplication; can be switched to `DenseQapEngine` or `NaiveProver` via flags
5. **Serialize** — outputs the proof using `ark-serialize` compressed format
6. **Verify** — loads the proof, public input, and verifying key, then checks the Groth16 pairing equation `e(A,B) == e(alpha·G1,beta·G2)·e(C,delta·G2)·e(V,gamma·G2)` where `e` is the optimal Ate pairing on BLS12-381

---

## Commands in detail

<details>
<summary><b>Ceremony commands — click to expand</b></summary>

Every Groth16 circuit needs a **trusted setup** that produces a proving key (`.pk`) and a verifying key (`.vk`). The CLI supports two paths that output the **same** binary format; the prover and verifier do not care which path was used.

#### `ceremony-dev` — development and CI

A single-party ceremony that generates randomness locally, evaluates the QAP polynomials, and writes pre-computed curve points into a `FullProvingKey`. This is **fast** (milliseconds) and **insecure** (the toxic waste lives in one person's RAM), which makes it perfect for development, benchmarking, and CI.

```bash
groth16-prover ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

**What happens under the hood:**
1. Load the circuit from `.r1cs` and count wires / constraints.
2. Generate random toxic waste (`tau`, `alpha`, `beta`, `gamma`, `delta`).
3. Evaluate every QAP polynomial at `tau` and multiply the results by the curve generators, producing group-element queries (`a_query`, `b_g2_query`, `h_query`, `l_query`).
4. Write the `FullProvingKey` (group elements only, no scalars) and the `VerifyingKey`.

Because the `.pk` contains only curve points, the prover can use pure multi-scalar multiplication (MSM) instead of re-evaluating polynomials from raw scalars on every proof. This is both faster and safer: there are no secret scalars left on disk.

#### `phase2` — production MPC ceremony

A **multi-party Phase 2** ceremony that reuses a publicly verified Phase 1 SRS (e.g., from the Perpetual Powers of Tau). Each participant contributes randomness locally; the coordinator is just a passive file host. Even if `N-1` participants collude, the ceremony remains secure as long as at least one participant honestly discards their contribution.

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
groth16-prover phase2 verify --zkey circuit_final.zkey

# 5. Finalize to the same .pk/.vk format as dev mode
groth16-prover phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

**What happens under the hood:**
1. `new` — loads the Phase 1 SRS (`.ptau`) and the circuit (`.r1cs`), then builds an initial accumulator containing the circuit-specific CRS elements.
2. `contribute` — the participant generates fresh randomness for `delta`, updates all delta-dependent group elements, and appends a Schnorr-like ratio proof that the update was performed correctly.
3. `verify` — checks every contribution proof and verifies that the delta chain is consistent.
4. `finalize` — strips the accumulator down to the same `.pk` / `.vk` binary format that `ceremony-dev` produces. From this point on, the prover and verifier work exactly as in the dev path.

</details>

<details>
<summary><b>Proof lifecycle — click to expand</b></summary>

#### `prove` — generate a Groth16 proof

```bash
# With a proving key (recommended)
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --proving-key circuit.pk \
  --out proof.bin

# Without a proving key (dev only — uses deterministic test values)
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --out proof.bin
```

**What happens under the hood:**
1. Parse the `.r1cs` file into dense L/R/O constraint matrices.
2. Parse the `.wtns` file into wire values (the witness).
3. Build the QAP polynomials. By default this uses `FftQapEngine` (FFT over roots of unity, `O(N log N)`); you can switch to `DenseQapEngine` (classical Lagrange interpolation, `O(N²)`) with `--engine dense`.
4. Compute the quotient polynomial `h(x) = (l(x)·r(x) - o(x)) / T(x)`.
5. Assemble the proof elements `A`, `B`, `C`. By default this uses `PippengerProver` (batched MSM, `O(n / log n)` group ops); you can switch to `NaiveProver` (scalar-by-scalar accumulation) with `--prover naive`.
6. Choose the QAP construction mode. By default the prover uses the group-element-only `FullProvingKey` path and builds the witness polynomials `l(x)`, `r(x)`, `o(x)` on-the-fly (Implementation 5). Use `--qap-not-on-fly` to force the legacy scalar-based QAP path (Implementation 4).
7. Serialize the proof and the public-input commitment using arkworks' compressed canonical format.

When `--out` is provided, two files are written:
- `proof.bin` — the Groth16 proof (192 bytes: compressed G1 + G2 + G1)
- `proof.pub` — the public-input commitment (48 bytes: compressed G1)

#### `verify` — check a proof

```bash
# With a verifying key
groth16-prover verify \
  --proof proof.bin \
  --public proof.pub \
  --verifying-key circuit.vk

# Without a verifying key (dev only)
groth16-prover verify --proof proof.bin --public proof.pub
```

**What happens under the hood:**
1. Deserialize the 192-byte proof into `A` (G1), `B` (G2), `C` (G1).
2. Deserialize the 48-byte public input into `V` (G1).
3. Load the verifying key (or fall back to deterministic test values in dev mode).
4. Compute the Groth16 pairing equation:
   ```
   e(A, B) == e(alpha·G1, beta·G2) · e(C, delta·G2) · e(V, gamma·G2)
   ```
   where `e` is the optimal Ate pairing on BLS12-381.
5. Print `Verification result: VALID` or `INVALID`.

#### `export-vk` — Aiken integration

Cardano smart contracts are written in Aiken. This command converts the binary `.vk` into a self-contained Aiken source file that declares a `VerificationKey` record with hex-encoded compressed points.

```bash
groth16-prover export-vk \
  --verifying-key circuit.vk \
  --out circuit_vk.ak
```

The output contains the `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, `ic` list, and `n_public` fields. You can paste it directly into an Aiken validator or library.

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
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--witness FILE` | — | *required* | Path to `.wtns` witness file |
| `--proving-key FILE` | — | — | Proving key from ceremony (optional, dev fallback) |
| `--engine ENGINE` | `dense`, `fft` | `fft` | QAP construction engine |
| `--prover PROVER` | `naive`, `pippenger` | `pippenger` | MSM strategy for proof assembly |
| `--qap-on-fly` | — | *default* | Use the group-element-only path with on-the-fly QAP construction (Implementation 5) |
| `--qap-not-on-fly` | — | — | Use the legacy scalar-based QAP path (Implementation 4) |
| `--out FILE` | — | — | Output file (raw binary); public input written to `FILE.pub` |
| **Verify** |
| `--proof FILE` | — | *required* | Path to proof file (192 bytes) |
| `--public FILE` | — | *required* | Path to public-input file (48 bytes) |
| `--verifying-key FILE` | — | — | Verifying key from ceremony (optional, dev fallback) |

</details>

<details>
<summary><b>Privacy / Shielded spend helpers — click to expand</b></summary>

The CLI includes tools for the **Spend(depth)** circuit — a Zcash-style shielded-spend proof adapted from Stanford CS251. The circuit proves that a private commitment (`H(nullifier, nonce)`) exists in a public Merkle tree, without revealing the nullifier, the nonce, or the Merkle path.

#### `compute-inputs` — witness generation for Spend(depth)

The Circom witness generator for `Spend(depth)` needs private Merkle-path data: the siblings and direction bits for the leaf being proven. This command reads a transcript file (one nullifier-nonce pair per line), builds a sparse Merkle tree, and emits the JSON that the Circom witness generator expects.

```bash
groth16-prover compute-inputs \
  --depth 2 \
  --transcript transcript.txt \
  --nullifier 2 \
  --out input.json
```

**Transcript format:** each line contains either one field element (raw commitment) or two space-separated field elements (`nullifier nonce`). Empty lines are skipped.

**Example transcript:**
```
1 100
2 200
3 300
```

**What happens under the hood:**
1. Parse every line into a `TranscriptEntry`.
2. For `NullifierNonce` entries, hash the pair with `MiMC(x⁷)` to produce the commitment.
3. Insert every commitment into a `SparseMerkleTree` of the given depth.
4. Look up the target nullifier, retrieve its nonce, and compute the Merkle path.
5. Emit `input.json` with `digest`, `nullifier`, `nonce`, `sibling[N]`, and `direction[N]` fields.

#### `smt` — Sparse Merkle Tree operations

A **Sparse Merkle Tree (SMT)** is a Merkle tree with a fixed depth where every leaf starts at a default value (the zero leaf). It is "sparse" because most leaves are empty, yet the root still commits to the entire tree. SMTs are the standard data structure for privacy-preserving applications because:

- **Membership proofs are succinct** — a Merkle path has exactly `depth` sibling hashes, regardless of how many items are in the tree.
- **Non-membership is trivial** — a leaf at its default value proves the item was never inserted.
- **They compose naturally with zk-SNARKs** — the Spend circuit verifies a Merkle path inside a Groth16 proof, turning a blockchain state root into a privacy-preserving credential.

This CLI uses **MiMC(x⁷)** as the SMT hash function. MiMC is an arithmetization-friendly hash designed to minimize the number of constraints inside a zk-SNARK circuit. The `x⁷` variant uses the exponent 7 (instead of the more common x⁵ or Feistel rounds) because it is well-suited to the BLS12-381 scalar field and matches the circomlib MiMC implementation.

**Subcommands:**

```bash
# Insert items and persist tree state
groth16-prover smt insert \
  --depth 2 \
  --items "1 100,2 200,3 300" \
  --state smt.json

# Print the current Merkle root
groth16-prover smt digest --state smt.json

# Print the Merkle path for a leaf
groth16-prover smt path --state smt.json --leaf <commitment>
```

**Item syntax:** each item is either a single field element (raw commitment) or two space-separated values (`nullifier nonce`). Items are comma-separated.

**What happens under the hood:**
1. `insert` — create a `SparseMerkleTree` of the given depth, hash each item with `MiMC(x⁷)` if needed, insert the commitments, and persist the depth and root digest to a JSON state file.
2. `digest` — load the persisted state and print the root digest.
3. `path` — load the state and (in a full implementation) rebuild the tree to retrieve the sibling hashes and direction bits for the requested leaf. The current implementation prints the digest and refers the user to `compute-inputs` for end-to-end witness generation.

</details>

---

## Complete example (dev ceremony)

This example uses the **dev ceremony** (`ceremony-dev`) for speed. The resulting `.pk` / `.vk` files are in the exact same format as a production MPC ceremony, so the proving and verifying steps are identical.

```bash
# 1. Compile the Circom circuit
cd ../circom/SimpleExample
circom multiplier.circom --r1cs --wasm

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

## Complete example (production ceremony)

This example walks through the full multi-party Phase 2 MPC ceremony. The resulting `.pk` / `.vk` files are in the exact same binary format as the dev ceremony.

```bash
cd groth16-prover/cli

# 1. Compile the Circom circuit
cd ../circom/SimpleExample
circom multiplier.circom --r1cs --wasm
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
cd ../../cli

# 2. Initialize from a universal Phase 1 SRS (e.g., Perpetual Powers of Tau)
cargo run --release -- phase2 new \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --srs ../universal.ptau \
  --zkey /tmp/multiplier_0000.zkey

# 3. Participants contribute sequentially
cargo run --release -- phase2 contribute \
  --zkey-in /tmp/multiplier_0000.zkey \
  --zkey-out /tmp/multiplier_0001.zkey \
  --name "Alice"

cargo run --release -- phase2 contribute \
  --zkey-in /tmp/multiplier_0001.zkey \
  --zkey-out /tmp/multiplier_final.zkey \
  --name "Bob"

# 4. Verify the accumulator
cargo run --release -- phase2 verify --zkey /tmp/multiplier_final.zkey

# 5. Finalize to .pk / .vk
cargo run --release -- phase2 finalize \
  --zkey /tmp/multiplier_final.zkey \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# 6. Prove and verify (same as dev ceremony)
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub \
  --verifying-key /tmp/multiplier.vk
```

## Privacy example (SMT + compute-inputs + prove)

This example walks through the shielded-spend flow: build a Merkle tree, compute private witness inputs, and prove membership.

```bash
cd groth16-prover/cli

# 1. Build a transcript and compute the Merkle root
cat > /tmp/transcript.txt << 'EOF'
1 100
2 200
3 300
EOF

# 2. Insert commitments into the SMT
cargo run --release -- smt insert \
  --depth 2 \
  --items "1 100,2 200,3 300" \
  --state /tmp/smt.json

# 3. Compute witness inputs for nullifier = 2
cargo run --release -- compute-inputs \
  --depth 2 \
  --transcript /tmp/transcript.txt \
  --nullifier 2 \
  --out /tmp/input.json

# 4. Generate the Circom witness (requires snarkjs)
cd ../circom/Privacy
snarkjs wtns calculate spend_depth2.wasm /tmp/input.json /tmp/witness.wtns

# 5. Dev ceremony for the Spend circuit
cd ../../cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/Privacy/spend_depth2.r1cs \
  --proving-key /tmp/spend.pk \
  --verifying-key /tmp/spend.vk

# 6. Prove
cargo run --release -- prove \
  --circuit ../circom/Privacy/spend_depth2.r1cs \
  --witness /tmp/witness.wtns \
  --proving-key /tmp/spend.pk \
  --out /tmp/spend_proof.bin

# 7. Verify
cargo run --release -- verify \
  --proof /tmp/spend_proof.bin \
  --public /tmp/spend_proof.pub \
  --verifying-key /tmp/spend.vk
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

## Build

```bash
cd groth16-prover/cli
cargo build --release
```

The binary will be at `target/release/groth16-prover`.

---

<details>
<summary><b>Proof serialization format (arkworks CanonicalSerialize) — click to expand</b></summary>

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

</details>

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

---

<details>
<summary><b>CLI test suite — click to expand</b></summary>

The integration tests in `tests/cli.rs` exercise every command via `assert_cmd`. They use synthetic `.r1cs` and `.wtns` artifacts so no external Circom compilation is needed.

### What is covered

| Test | What it checks |
|------|----------------|
| `full_ceremony_prove_verify_roundtrip` | Legacy `ceremony` → `prove` → `verify` with generated keys |
| `full_ceremony_dev_prove_verify_roundtrip` | `ceremony-dev` → `prove` → `verify` with `FullProvingKey` |
| `prove_default_stdout` | `prove` without `--out` prints 384 hex chars to stdout |
| `prove_to_file` | `prove --out` writes 192-byte proof + 48-byte public input |
| `prove_dense_engine` | `--engine dense` produces valid hex output |
| `prove_naive_prover` | `--prover naive` produces valid hex output |
| `prove_dense_naive` | `--engine dense --prover naive` combination works |
| `prove_fft_pippenger_explicit` | `--engine fft --prover pippenger` combination works |
| `prove_qap_on_fly_explicit` | `--qap-on-fly` produces a valid proof |
| `prove_qap_not_on_fly` | `--qap-not-on-fly` produces a valid proof |
| `prove_qap_on_fly_with_legacy_pk_suggests_not_on_fly` | Helpful error when a legacy `ProvingKey` is used without the flag |
| `prove_qap_not_on_fly_with_full_pk_suggests_on_fly` | Helpful error when a `FullProvingKey` is used with `--qap-not-on-fly` |
| `prove_all_combinations_produce_valid_hex` | All 4 engine/prover combinations produce 384 hex chars |
| `verify_valid_proof` | `verify` reports `VALID` for a freshly generated proof |
| `verify_all_combinations` | Every engine/prover combination produces a verifiable proof |
| `verify_tampered_public_input_fails` | Changing the public input causes `INVALID` |
| `verify_invalid_proof_length` | 100-byte proof file is rejected |
| `verify_invalid_public_length` | 10-byte public file is rejected |
| `prove_missing_circuit` / `prove_missing_witness` | Required-arg errors |
| `verify_missing_proof` / `verify_missing_public` | Required-arg errors |
| `prove_invalid_circuit_file` / `prove_invalid_witness_file` | Bad file format errors |
| `phase2_new_creates_accumulator` | `phase2 new` writes a non-empty accumulator |
| `phase2_contribute_and_verify` | `contribute` + `verify` passes for one participant |
| `phase2_full_roundtrip_prove_verify` | Full `new → contribute → finalize → prove → verify` |
| `smt_insert_and_digest` | Insert items, verify state JSON, digest output matches |
| `smt_insert_raw_commitments` | Insert raw field-element commitments |
| `smt_path_prints_digest` | Query path for a leaf after insertion |
| `smt_missing_state_file` | Error handling for missing state file |
| `compute_inputs_basic` | Basic transcript → JSON witness input generation |
| `compute_inputs_nullifier_not_found` | Error when nullifier is missing from transcript |
| `compute_inputs_with_raw_commitments` | Correct failure for raw-commitment transcripts |
| `compute_inputs_missing_transcript` | Error handling for missing transcript file |

Run the tests:

```bash
cd groth16-prover/cli
cargo test
```

</details>
