# groth16-cli

Command-line interface for the Groth16 zero-knowledge proof lifecycle on BLS12-381.

This CLI covers proof generation, verification, and verifying-key export. Trusted-setup ceremonies (both the single-party dev ceremony and the multi-party Phase-2 MPC) live in the standalone `trusted-setup` CLI (`clis/trusted-setup`), and sparse Merkle tree operations plus privacy-circuit witness-input generation live in the standalone `smt` CLI (`clis/smt`). All outputs use arkworks' canonical compressed serialization so they are directly consumable by on-chain Aiken verifiers.

The core proof logic lives in the `groth16-prover` crate; this crate only adds the command-line interface on top of it.

---

## Quick reference

Run any command with `--help` for full flag details:

```bash
groth16 --help
groth16 prove --help
groth16 verify --help
groth16 export-vk --help
trusted-setup --help     # ceremony / ceremony-dev / phase2 commands
smt --help
```

Top-level help output:

```
Groth16 prover CLI for BLS12-381

Usage: groth16 <COMMAND>

Commands:
  prove       Generate a Groth16 proof from Circom artifacts
  verify      Verify a Groth16 proof against its public input
  export-vk   Export a binary verifying key to Aiken source code
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

---

## Command reference

### `trusted-setup` — ceremonies (separate CLI)

Trusted-setup ceremonies moved to the standalone `trusted-setup` CLI (`clis/trusted-setup`):

```bash
trusted-setup --help
```

- `trusted-setup ceremony` — legacy single-party ceremony (deprecated; produces a legacy `ProvingKey` with scalar toxic waste)
- `trusted-setup ceremony-dev` — single-party dev ceremony producing a `FullProvingKey` (group elements only); supports `--sparse` (Implementation 6) and `--h-scalar` (Implementation 7)
- `trusted-setup phase2 new|contribute|verify|finalize` — multi-party Phase-2 MPC on top of a public Phase-1 SRS (`.ptau`)

Run `trusted-setup ceremony-dev --help` or `trusted-setup phase2 --help` for full flag details. See [`clis/trusted-setup/README.md`](../trusted-setup/README.md).

The `prove` command below consumes the `.pk` / `.vk` files produced by any of these ceremonies.

### `prove` — generate a Groth16 proof

Loads a circuit from `.r1cs` and a witness from `.wtns`, then produces a proof. If a `--proving-key` is provided, the proof uses the random toxic waste from the ceremony step. Otherwise deterministic test values are used (dev only).

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--witness FILE` | — | *required* | Path to `.wtns` witness file |
| `--proving-key FILE` | — | — | Proving key from ceremony (optional, dev fallback) |
| `--engine ENGINE` | `dense`, `fft` | `fft` | QAP construction engine |
| `--prover PROVER` | `naive`, `pippenger` | `pippenger` | MSM strategy for proof assembly |
| `--qap-on-fly` | — | *default* | Use the group-element-only path with on-the-fly QAP construction (Implementation 5) |
| `--qap-not-on-fly` | — | — | Use the legacy scalar-based QAP path (Implementation 4) |
| `--sparse` | — | — | Use sparse constraint representation (Implementation 6). Implies `--qap-on-fly` |
| `--out FILE` | — | — | Output file (raw binary); public input written to `FILE.pub` |

**Examples:**

```bash
# With a proving key (recommended)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --proving-key circuit.pk \
  --out proof.bin

# Without a proving key (dev only — deterministic test values)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --out proof.bin

# Sparse mode for large circuits (Implementation 6)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --sparse \
  --out proof.bin

# FFT engine + Pippenger prover (default, fastest)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --engine fft \
  --prover pippenger \
  --proving-key circuit.pk \
  --out proof.bin

# Dense engine + naive prover (pedagogical — trace every step)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --engine dense \
  --prover naive \
  --proving-key circuit.pk \
  --out proof.bin

# Legacy scalar-based QAP path (Implementation 4)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --qap-not-on-fly \
  --proving-key circuit.pk \
  --out proof.bin

# Print proof as hex to stdout (no --out)
groth16 prove \
  --circuit circuit.r1cs \
  --witness witness.wtns
```

**All engine + prover combinations:**

| # | Engine | Prover | Use case |
|---|--------|--------|----------|
| 1 | `fft` | `pippenger` | Default — fastest, recommended for production |
| 2 | `fft` | `naive` | Debugging FFT path; same proof points as pippenger |
| 3 | `dense` | `pippenger` | Fast MSM but slow QAP; useful for parity testing |
| 4 | `dense` | `naive` | Pedagogical — every step is scalar-by-scalar |

---

### `verify` — check a proof

Loads a proof file (192 bytes) and a public-input file (48 bytes), then checks the Groth16 pairing equation.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--proof FILE` | — | *required* | Path to proof file (192 bytes) |
| `--public FILE` | — | *required* | Path to public-input file (48 bytes) |
| `--verifying-key FILE` | — | — | Verifying key from ceremony (optional, dev fallback) |

**Examples:**

```bash
# With a verifying key
groth16 verify \
  --proof proof.bin \
  --public proof.pub \
  --verifying-key circuit.vk

# Without a verifying key (dev only — deterministic test values)
groth16 verify \
  --proof proof.bin \
  --public proof.pub
```

---

### `export-vk` — Aiken integration

Converts a binary `.vk` into a self-contained Aiken source file that declares a `VerificationKey` record with hex-encoded compressed points.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--verifying-key FILE` | — | *required* | Path to the binary verifying key file |
| `--out FILE` | — | — | Output path for the Aiken source file (prints to stdout if omitted) |

**Examples:**

```bash
# Write to file
groth16 export-vk \
  --verifying-key circuit.vk \
  --out circuit_vk.ak

# Print to stdout
groth16 export-vk \
  --verifying-key circuit.vk
```

The output contains the `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, `ic` list, and `n_public` fields. Paste it directly into an Aiken validator or library.

---

## Complete workflows

### Dev ceremony workflow

```bash
cd clis/groth16

# 1. Compile the Circom circuit
cd ../../circom/SimpleExample
circom multiplier.circom --r1cs --wasm --prime bls12381

# 2. Generate witness
snarkjs wtns calculate multiplier.wasm input.json witness.wtns

# 3. Dev ceremony (run once per circuit — instant, single-party)
cd ../../clis/trusted-setup
cargo run --release -- ceremony-dev \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# 4. Prove (uses the proving key — group elements, no scalars)
cd ../../clis/groth16
cargo run --release -- prove \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --witness ../../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

# 5. Verify (uses the verification key from the ceremony)
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub \
  --verifying-key /tmp/multiplier.vk
```

### Production ceremony workflow

```bash
cd clis/trusted-setup

# 1. Compile the Circom circuit
cd ../../circom/SimpleExample
circom multiplier.circom --r1cs --wasm --prime bls12381
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
cd ../../clis/trusted-setup

# 2. Initialize from a universal Phase 1 SRS
cargo run --release -- phase2 new \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --srs ../../circom/universal.ptau \
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
cd ../../clis/groth16
cargo run --release -- prove \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --witness ../../circom/SimpleExample/witness.wtns \
  --proving-key /tmp/multiplier.pk \
  --out /tmp/proof.bin

cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub \
  --verifying-key /tmp/multiplier.vk
```

### Privacy example (SMT + compute-inputs + prove)

The SMT tree and witness inputs come from the standalone `smt` CLI; the proof lifecycle stays in this CLI.

```bash
# 1. Build a transcript and compute the Merkle root
cat > /tmp/transcript.txt << 'EOF'
1 100
2 200
3 300
EOF

# 2. Insert commitments into the SMT (standalone `smt` CLI)
cd clis/smt
smt insert \
  --depth 2 \
  --items "1 100,2 200,3 300" \
  --state /tmp/smt.json

# 3. Compute witness inputs for nullifier = 2
smt compute-inputs \
  --depth 2 \
  --transcript /tmp/transcript.txt \
  --nullifier 2 \
  --out /tmp/input.json

# 4. Generate the Circom witness (requires snarkjs)
cd ../../circom/Privacy
snarkjs wtns calculate spend_depth2.wasm /tmp/input.json /tmp/witness.wtns

# 5. Dev ceremony for the Spend circuit
cd ../../clis/trusted-setup
cargo run --release -- ceremony-dev \
  --circuit ../../circom/Privacy/spend_depth2.r1cs \
  --proving-key /tmp/spend.pk \
  --verifying-key /tmp/spend.vk

# 6. Prove
cd ../../clis/groth16
cargo run --release -- prove \
  --circuit ../../circom/Privacy/spend_depth2.r1cs \
  --witness /tmp/witness.wtns \
  --proving-key /tmp/spend.pk \
  --out /tmp/spend_proof.bin

# 7. Verify
cargo run --release -- verify \
  --proof /tmp/spend_proof.bin \
  --public /tmp/spend_proof.pub \
  --verifying-key /tmp/spend.vk
```

### Dev-only shortcut (no proving key — deterministic test values)

For the quickest possible testing you can skip even the ceremony step. The prover and verifier fall back to hard-coded deterministic toxic waste (`tau=3, alpha=5, beta=7, gamma=11, delta=13`). No `.pk` or `.vk` files are needed:

```bash
cd clis/groth16

# Prove (no --proving-key)
cargo run --release -- prove \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --witness ../../circom/SimpleExample/witness.wtns \
  --out /tmp/proof.bin

# Verify (no --verifying-key)
cargo run --release -- verify \
  --proof /tmp/proof.bin \
  --public /tmp/proof.pub
```

> **Note:** This uses deterministic test values (`tau=3`, `alpha=5`, etc.) and skips the ceremony step. For large circuits, use `--sparse` (Implementation 6) to avoid dense matrix allocation.

---

## Build

```bash
cd clis/groth16
cargo build --release
```

The binary will be at `target/release/groth16`.

The `trusted-setup` binary (ceremony commands) builds separately:

```bash
cd clis/trusted-setup
cargo build --release
```

The binary will be at `target/release/trusted-setup`.

The `smt` binary (SMT + privacy witness inputs) builds separately:

```bash
cd clis/smt
cargo build --release
```

---

## Proof serialization format

The proof files produced by this CLI use **arkworks' standard compressed serialization**, defined by the `CanonicalSerialize` / `CanonicalDeserialize` traits from the `ark-serialize` crate. This is the same format used by the arkworks `groth16` module internally.

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

### Compatibility notes

- ✅ **Arkworks-native** — `arkworks/groth16` uses this exact same format internally
- ⚠️ **snarkjs JSON** — snarkjs outputs proofs as JSON arrays of big integers (e.g. `{"pi_a": ["123", ...]}`). To exchange proofs with snarkjs you must convert between the binary format and JSON, or use snarkjs's `--protocol groth16` export.
- ⚠️ **Other curves** — The 48/96 byte sizes are specific to BLS12-381. For BN254, G1 is 32 bytes and G2 is 64 bytes.

For human inspection, use `hexdump -C proof.bin` or `xxd proof.bin`.

---

## Proving key format

The trusted-setup CLI produces two formats. The **preferred** one (group elements only) is what `trusted-setup ceremony-dev` and `trusted-setup phase2 finalize` output today.

| Property | Legacy `ProvingKey` (scalars) | `FullProvingKey` (group elements) |
|----------|------------------------------|-----------------------------------|
| `.pk` size | ~200 bytes | ~MBs (circuit-dependent) |
| Toxic waste in `.pk` | ❌ Yes — raw scalars | ✅ No — only curve points |
| Prover work per proof | Re-evaluates QAP at `tau` | Pure MSM over pre-computed points |
| Dev path | `trusted-setup ceremony` (deprecated) | `trusted-setup ceremony-dev` (default) |
| Production path | — | `trusted-setup phase2` MPC |

**Backward compatibility.** The `prove` command auto-detects the format on load: if the file starts with the legacy `ProvingKey` magic it falls back to the scalar-based prover; otherwise it loads a `FullProvingKey` and uses the fast MSM path. New `.pk` files are always written as `FullProvingKey`.

See [`groth16-prover/docs/MPC_Ceremony_Research.md`](../../groth16-prover/docs/MPC_Ceremony_Research.md) for the full ceremony roadmap.

---

## CLI test suite

The integration tests in `tests/cli.rs` exercise every command via `assert_cmd`. They use synthetic `.r1cs` and `.wtns` artifacts so no external Circom compilation is needed. Two end-to-end tests use real Circom artifacts from `circom/AnonymousAirdrop` (compiled with `snarkjs`) when the `.r1cs` / `.wtns` files are present.

### What is covered

| Test | What it checks |
|------|----------------|
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
| `prove_missing_circuit` / `prove_missing_witness` | Required-arg errors |
| `prove_invalid_circuit_file` / `prove_invalid_witness_file` | Bad file format errors |
| `verify_valid_proof` | `verify` reports `VALID` for a freshly generated proof |
| `verify_all_combinations` | Every engine/prover combination produces a verifiable proof |
| `verify_missing_proof` / `verify_missing_public` | Required-arg errors |
| `verify_invalid_proof_length` | 100-byte proof file is rejected |
| `verify_invalid_public_length` | 10-byte public file is rejected |
| `verify_tampered_public_input_fails` | Changing the public input causes `INVALID` |
| `prove_sparse_stdout` / `prove_sparse_to_file` / `prove_sparse_naive` | `--sparse` proof paths (Implementation 6) |
| `prove_sparse_rejects_qap_not_on_fly` | `--sparse` with `--qap-not-on-fly` is rejected |
| `anonymous_airdrop_e2e_accepted` / `anonymous_airdrop_e2e_rejected` | E2E prove/verify with dev-ceremony keys |
| `export_vk_produces_aiken_source` / `export_vk_prints_to_stdout` | `export-vk` Aiken codegen |
| `export_vk_missing_file` / `export_vk_invalid_file` / `export_vk_missing_verifying_key` | `export-vk` error handling |
| `help_top_level` / `help_prove` / `help_verify` / `help_export_vk` | `--help` output matches the expected commands |
| `random_circuit_library_roundtrip` | Library-level roundtrip via `single_party_ceremony_full` + `prove_with_full_pk` |

Ceremony commands (`ceremony`, `ceremony-dev`, `phase2`) and their tests live in `clis/trusted-setup/tests/cli.rs`.

Run the tests:

```bash
cd clis/groth16
cargo test
```
