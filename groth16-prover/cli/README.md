# groth16-prover-cli

Command-line interface for the full Groth16 zero-knowledge proof lifecycle on BLS12-381.

This CLI covers proof generation and verification, plus Nova IVC folding for batched step proofs. Trusted-setup ceremonies (both the single-party dev ceremony and the multi-party Phase-2 MPC) live in the standalone `trusted-setup` CLI (`clis/trusted-setup`), and sparse Merkle tree operations plus privacy-circuit witness-input generation live in the standalone `smt` CLI (`clis/smt`). All outputs use arkworks' canonical compressed serialization so they are directly consumable by on-chain Aiken verifiers.

---

## Quick reference

Run any command with `--help` for full flag details:

```bash
groth16-prover --help
groth16-prover prove --help
groth16-prover verify --help
groth16-prover export-vk --help
groth16-prover nova --help
trusted-setup --help     # ceremony / ceremony-dev / phase2 commands
smt --help
```

Top-level help output:

```
Groth16 prover CLI for BLS12-381

Usage: groth16-prover <COMMAND>

Commands:
  prove           Generate a Groth16 proof from Circom artifacts
  verify          Verify a Groth16 proof against its public input
  export-vk       Export a binary verifying key to Aiken source code
  nova            Nova IVC folding + compression flow (Implementation 8)
  help            Print this message or the help of the given subcommand(s)

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

Run `trusted-setup ceremony-dev --help` or `trusted-setup phase2 --help` for full flag details. See [`clis/trusted-setup/README.md`](../../clis/trusted-setup/README.md).

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
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --proving-key circuit.pk \
  --out proof.bin

# Without a proving key (dev only — deterministic test values)
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --out proof.bin

# Sparse mode for large circuits (Implementation 6)
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --sparse \
  --out proof.bin

# FFT engine + Pippenger prover (default, fastest)
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --engine fft \
  --prover pippenger \
  --proving-key circuit.pk \
  --out proof.bin

# Dense engine + naive prover (pedagogical — trace every step)
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --engine dense \
  --prover naive \
  --proving-key circuit.pk \
  --out proof.bin

# Legacy scalar-based QAP path (Implementation 4)
groth16-prover prove \
  --circuit circuit.r1cs \
  --witness witness.wtns \
  --qap-not-on-fly \
  --proving-key circuit.pk \
  --out proof.bin

# Print proof as hex to stdout (no --out)
groth16-prover prove \
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
groth16-prover verify \
  --proof proof.bin \
  --public proof.pub \
  --verifying-key circuit.vk

# Without a verifying key (dev only — deterministic test values)
groth16-prover verify \
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
groth16-prover export-vk \
  --verifying-key circuit.vk \
  --out circuit_vk.ak

# Print to stdout
groth16-prover export-vk \
  --verifying-key circuit.vk
```

The output contains the `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, `ic` list, and `n_public` fields. Paste it directly into an Aiken validator or library.

---
### `nova` — Nova IVC folding + compression (Implementation 8)

Splits a long computation into `N` identical step circuits, folds their Groth16 proofs into a single verifiable bundle, and binds the state chain with a BLAKE2b transcript. Every step proof is individually verifiable, and the `verify` subcommand re-checks the entire chain.

The step circuits must satisfy one invariant (checked by `params`): the number of public inputs must equal the number of public outputs (`n_pub_in == n_pub_out`), so the public-input block of step `i+1` equals the public-output block of step `i`. Public inputs ARE the IVC state.

**Subcommands:**

| Subcommand | Purpose |
|------------|---------|
| `params` | Inspect a step circuit and emit a JSON descriptor |
| `ceremony` | Single-party ceremony for a step circuit |
| `fold` | Fold step witnesses into an IVC bundle |
| `verify` | Verify a folded IVC bundle |

#### `nova params` — inspect a step circuit

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to the step circuit `.r1cs` file |
| `--out FILE` | — | — | Optional JSON output path (prints to stdout if omitted) |

```bash
# Print descriptor to stdout
groth16-prover nova params \
  --circuit step_circuit.r1cs

# Write to a file
groth16-prover nova params \
  --circuit step_circuit.r1cs \
  --out descriptor.json
```

Emits a JSON descriptor with `n_wires`, `n_constraints`, `n_pub_out`, `n_pub_in`, and `n_prv_in`. Validates that the circuit satisfies the step-chain invariant.

#### `nova ceremony` — single-party ceremony for a step circuit

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to the step circuit `.r1cs` file |
| `--proving-key FILE` | — | *required* | Output path for the proving key |
| `--verifying-key FILE` | — | *required* | Output path for the verification key |
| `--h-scalar` | — | — | Use h-query scalar compression (Implementation 7) |

```bash
# Basic ceremony
groth16-prover nova ceremony \
  --circuit step_circuit.r1cs \
  --proving-key step.pk \
  --verifying-key step.vk

# With h-scalar compression
groth16-prover nova ceremony \
  --circuit step_circuit.r1cs \
  --proving-key step.pk \
  --verifying-key step.vk \
  --h-scalar
```

#### `nova fold` — fold step witnesses into an IVC bundle

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to the step circuit `.r1cs` file |
| `--proving-key FILE` | — | *required* | Path to the step proving key |
| `--steps DIR` | — | *required* | Directory containing step witness `.wtns` files (sorted) |
| `--out FILE` | — | *required* | Output path for the IVC bundle JSON |

```bash
groth16-prover nova fold \
  --circuit step_circuit.r1cs \
  --proving-key step.pk \
  --steps ./step_witnesses/ \
  --out bundle.ivc.json
```

Reads all `.wtns` files from the steps directory (sorted), proves each step with the provided proving key, and writes a JSON bundle containing the step proofs, state chain, and BLAKE2b transcript.

#### `nova verify` — verify a folded IVC bundle

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--ivc FILE` | — | *required* | Path to the IVC bundle JSON |
| `--verifying-key FILE` | — | *required* | Path to the step verifying key |

```bash
groth16-prover nova verify \
  --ivc bundle.ivc.json \
  --verifying-key step.vk
```

Re-checks every step's Groth16 pairing, verifies the state chain links correctly, and validates the BLAKE2b transcript. Prints the number of verified steps and the final transcript hash.

---

## Complete workflows

### Dev ceremony workflow

```bash
cd groth16-prover/cli

# 1. Compile the Circom circuit
cd ../circom/SimpleExample
circom multiplier.circom --r1cs --wasm

# 2. Generate witness
snarkjs wtns calculate multiplier.wasm input.json witness.wtns

# 3. Dev ceremony (run once per circuit — instant, single-party)
cd ../../../clis/trusted-setup
cargo run --release -- ceremony-dev \
  --circuit ../../groth16-prover/circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# 4. Prove (uses the proving key — group elements, no scalars)
cd ../../groth16-prover/cli
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

### Production ceremony workflow

```bash
cd clis/trusted-setup

# 1. Compile the Circom circuit
cd ../../groth16-prover/circom/SimpleExample
circom multiplier.circom --r1cs --wasm
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
cd ../../../clis/trusted-setup

# 2. Initialize from a universal Phase 1 SRS
cargo run --release -- phase2 new \
  --circuit ../../groth16-prover/circom/SimpleExample/multiplier.r1cs \
  --srs ../../groth16-prover/circom/universal.ptau \
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
cd ../../groth16-prover/cli
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
cd ../../groth16-prover/circom/Privacy
snarkjs wtns calculate spend_depth2.wasm /tmp/input.json /tmp/witness.wtns

# 5. Dev ceremony for the Spend circuit
cd ../../../clis/trusted-setup
cargo run --release -- ceremony-dev \
  --circuit ../../groth16-prover/circom/Privacy/spend_depth2.r1cs \
  --proving-key /tmp/spend.pk \
  --verifying-key /tmp/spend.vk

# 6. Prove
cd ../../groth16-prover/cli
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

### Dev-only shortcut (no proving key — deterministic test values)

For the quickest possible testing you can skip even the ceremony step. The prover and verifier fall back to hard-coded deterministic toxic waste (`tau=3, alpha=5, beta=7, gamma=11, delta=13`). No `.pk` or `.vk` files are needed:

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

> **Note:** This uses deterministic test values (`tau=3`, `alpha=5`, etc.) and skips the ceremony step. For large circuits, use `--sparse` (Implementation 6) to avoid dense matrix allocation.

---

## Build

```bash
cd groth16-prover/cli
cargo build --release
```

The binary will be at `target/release/groth16-prover`.

The `trusted-setup` binary (ceremony commands) builds separately:

```bash
cd clis/trusted-setup
cargo build --release
```

The binary will be at `target/release/trusted-setup`.

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

See [`MPC_Ceremony_Research.md`](../docs/MPC_Ceremony_Research.md) for the full ceremony roadmap.

---

## CLI test suite

The integration tests in `tests/cli.rs` exercise every command via `assert_cmd`. They use synthetic `.r1cs` and `.wtns` artifacts so no external Circom compilation is needed.

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
| `verify_valid_proof` | `verify` reports `VALID` for a freshly generated proof |
| `verify_all_combinations` | Every engine/prover combination produces a verifiable proof |
| `verify_tampered_public_input_fails` | Changing the public input causes `INVALID` |
| `verify_invalid_proof_length` | 100-byte proof file is rejected |
| `verify_invalid_public_length` | 10-byte public file is rejected |
| `prove_missing_circuit` / `prove_missing_witness` | Required-arg errors |
| `verify_missing_proof` / `verify_missing_public` | Required-arg errors |
| `prove_invalid_circuit_file` / `prove_invalid_witness_file` | Bad file format errors |
| `prove_sparse_stdout` / `prove_sparse_to_file` / `prove_sparse_naive` | `--sparse` proof paths (Implementation 6) |
| `prove_sparse_rejects_qap_not_on_fly` | `--sparse` with `--qap-not-on-fly` is rejected |
| `anonymous_airdrop_e2e_accepted` / `anonymous_airdrop_e2e_rejected` | E2E prove/verify with dev-ceremony keys |
| `nova_params_accepts_cardano_ed25519_ownership_step` | `nova params` accepts a valid step circuit |
| `nova_params_rejects_monolithic_ed25519_ownership` | `nova params` rejects non-step circuit |
| `nova_params_rejects_jubjub_ownership` | `nova params` rejects wrong public I/O ratio |
| `nova_params_rejects_non_step_circuit` | `nova params` rejects circuit where `n_pub_in != n_pub_out` |
| `nova_params_missing_circuit` | Required-arg error for `nova params` |
| `nova_params_invalid_circuit` | Bad file format error for `nova params` |
| `nova_ceremony_and_fold` | `nova ceremony` + `nova fold` produces a valid IVC bundle |
| `nova_verify_basic` | `nova verify` passes for a freshly folded bundle |
| `cardano_ed25519_ownership_nova_fold_verify_e2e` | Full Nova IVC fold + verify e2e |
| `cardano_ed25519_ownership_nova_fold_rejects_broken_chain` | `nova verify` fails for a broken state chain |
| `cardano_ed25519_ownership_nova_verify_rejects_tampered_bundle` | `nova verify` fails for a tampered bundle |
| `export_vk_produces_aiken_source` / `export_vk_prints_to_stdout` | `export-vk` Aiken codegen |
| `export_vk_missing_file` / `export_vk_invalid_file` | `export-vk` error handling |
| `random_circuit_library_roundtrip` | Library-level roundtrip via `single_party_ceremony_full` + `prove_with_full_pk` |

Ceremony commands (`ceremony`, `ceremony-dev`, `phase2`) and their tests live in `clis/trusted-setup/tests/cli.rs`.

Run the tests:

```bash
cd groth16-prover/cli
cargo test
```