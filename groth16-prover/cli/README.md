# groth16-prover-cli

Command-line interface for the full Groth16 zero-knowledge proof lifecycle on BLS12-381.

This CLI covers everything from trusted-setup ceremonies (both dev and multi-party MPC) through proof generation and verification, plus auxiliary tools for privacy-preserving circuits: witness-input computation for shielded spends and sparse Merkle tree operations. All outputs use arkworks' canonical compressed serialization so they are directly consumable by on-chain Aiken verifiers.

---

## Quick reference

Run any command with `--help` for full flag details:

```bash
groth16-prover --help
groth16-prover ceremony-dev --help
groth16-prover prove --help
groth16-prover phase2 --help
groth16-prover nova --help
groth16-prover smt --help
```

Top-level help output:

```
Groth16 prover CLI for BLS12-381

Usage: groth16-prover <COMMAND>

Commands:
  ceremony        Run a trusted-setup ceremony for a circuit
  ceremony-dev    Run a single-party dev ceremony that outputs a FullProvingKey (group elements only)
  prove           Generate a Groth16 proof from Circom artifacts
  verify          Verify a Groth16 proof against its public input
  export-vk       Export a binary verifying key to Aiken source code
  compute-inputs  Compute witness inputs for the Spend(depth) circuit
  smt             Sparse Merkle Tree operations for BLS12-381
  phase2          Run a Phase-2 multi-party ceremony for a circuit
  nova            Nova IVC folding + compression flow (Implementation 8)
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

---

## Command reference

### `ceremony` — legacy trusted setup (deprecated)

> ⚠️ **Deprecated.** Use `ceremony-dev` (for dev/testing) or `phase2` (for production) instead. Produces a legacy `ProvingKey` that contains scalar toxic waste, making it unsuitable for production use.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--proving-key FILE` | — | *required* | Output path for the proving key |
| `--verifying-key FILE` | — | *required* | Output path for the verification key |

**Examples:**

```bash
# Basic usage
groth16-prover ceremony \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

---

### `ceremony-dev` — single-party dev ceremony

A single-party ceremony that generates randomness locally, evaluates the QAP polynomials, and writes a `FullProvingKey` (group elements only, no scalars). Fast (milliseconds) and insecure — perfect for development, benchmarking, and CI.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--proving-key FILE` | — | *required* | Output path for the proving key |
| `--verifying-key FILE` | — | *required* | Output path for the verification key |
| `--sparse` | — | — | Use sparse constraint representation (Implementation 6). Avoids dense matrix allocation for large circuits (e.g. Blake2b-224, Ed25519) |
| `--h-scalar` | — | — | Use h-query scalar compression (Implementation 7). Stores a single scalar `delta_inv * T(tau)` instead of the full `h_query` G1 vector, cutting PK size and eliminating the h MSM |

**Examples:**

```bash
# Basic dev ceremony
groth16-prover ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk

# Sparse mode for large circuits
groth16-prover ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --sparse

# With h-scalar compression (Implementation 7)
groth16-prover ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --h-scalar

# Sparse + h-scalar combined
groth16-prover ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --sparse \
  --h-scalar
```

---

### `phase2` — production MPC ceremony

A multi-party Phase 2 ceremony that reuses a publicly verified Phase 1 SRS (e.g., Perpetual Powers of Tau). Each participant contributes randomness locally; the coordinator is just a passive file host. Even if `N-1` participants collude, the ceremony remains secure as long as at least one participant honestly discards their contribution.

**Subcommands:**

| Subcommand | Purpose |
|------------|---------|
| `new` | Create initial accumulator from `.ptau` SRS + `.r1cs` |
| `contribute` | Add your randomness contribution |
| `verify` | Check all contributions are valid |
| `finalize` | Convert accumulator to `.pk` / `.vk` |

#### `phase2 new`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--srs FILE` | — | *required* | Path to universal Phase 1 SRS (`.ptau`) |
| `--zkey FILE` | — | *required* | Output path for the intermediate `.zkey` |

```bash
groth16-prover phase2 new \
  --circuit circuit.r1cs \
  --srs universal.ptau \
  --zkey circuit_0000.zkey
```

#### `phase2 contribute`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--zkey-in FILE` | — | *required* | Input accumulator (.zkey) |
| `--zkey-out FILE` | — | *required* | Output accumulator (.zkey) |
| `--name NAME` | — | — | Optional participant name |

```bash
# Participant 1 contributes
groth16-prover phase2 contribute \
  --zkey-in circuit_0000.zkey \
  --zkey-out circuit_0001.zkey \
  --name "Alice"

# Participant 2 contributes
groth16-prover phase2 contribute \
  --zkey-in circuit_0001.zkey \
  --zkey-out circuit_final.zkey \
  --name "Bob"
```

#### `phase2 verify`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--zkey FILE` | — | *required* | Accumulator to verify (.zkey) |

```bash
groth16-prover phase2 verify --zkey circuit_final.zkey
```

#### `phase2 finalize`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--zkey FILE` | — | *required* | Final accumulator (.zkey) |
| `--proving-key FILE` | — | *required* | Output path for the proving key (.pk) |
| `--verifying-key FILE` | — | *required* | Output path for the verification key (.vk) |

```bash
groth16-prover phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

**Full workflow:**

```bash
# 1. Initialize from universal SRS
groth16-prover phase2 new \
  --circuit circuit.r1cs \
  --srs universal.ptau \
  --zkey circuit_0000.zkey

# 2. Participants contribute sequentially
groth16-prover phase2 contribute \
  --zkey-in circuit_0000.zkey \
  --zkey-out circuit_0001.zkey \
  --name "Alice"

groth16-prover phase2 contribute \
  --zkey-in circuit_0001.zkey \
  --zkey-out circuit_final.zkey \
  --name "Bob"

# 3. Verify the accumulator
groth16-prover phase2 verify --zkey circuit_final.zkey

# 4. Finalize to .pk / .vk
groth16-prover phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

---

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

### `compute-inputs` — witness generation for Spend(depth)

Reads a transcript file (one nullifier-nonce pair per line) and produces a JSON file with the private Merkle-path data needed by the Circom witness generator for the Spend(depth) circuit.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--depth N` | — | *required* | Merkle tree depth |
| `--transcript FILE` | — | *required* | Path to the transcript file |
| `--nullifier VALUE` | — | *required* | Target nullifier to prove membership for |
| `--out FILE` | — | `input.json` | Output path for the JSON witness input |

**Transcript format:** each line contains either one field element (raw commitment) or two space-separated field elements (`nullifier nonce`). Empty lines are skipped.

**Example transcript:**

```
1 100
2 200
3 300
```

**Examples:**

```bash
# Basic usage
groth16-prover compute-inputs \
  --depth 2 \
  --transcript transcript.txt \
  --nullifier 2 \
  --out input.json

# With default output path (input.json in current directory)
groth16-prover compute-inputs \
  --depth 2 \
  --transcript transcript.txt \
  --nullifier 2
```

---

### `smt` — Sparse Merkle Tree operations

Provides insert-only SMT commands backed by MiMC(x⁷) hashing, plus Ed25519 key-derivation helpers for the CardanoKeyOwnershipSMT circuit. Subcommands: `key`, `leaf`, `insert`, `digest`, `path`, `verify`, `export`, `cardano-input`.

#### `smt key` — derive CardanoKeyOwnershipSMT witness data from a key

Decompresses an Ed25519 public key into the extended coordinates `[X, Y, Z, T]`, splits each coordinate into three base-2^85 limbs, computes the MiMC leaf commitment, and bit-decomposes `A` (the 256 compressed-key bits) and optionally `sk` (the 255 clamped-scalar bits). This is the full witness-generation pipeline for the `CardanoKeyOwnershipSMT` circuit — previously done in Python.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--vk HEX` | 64 hex chars | *required* | Compressed Ed25519 public key |
| `--xsk HEX` | 64 hex chars | — | 32-byte scalar (clamped to the 255-bit `sk` witness input). Omitted from the output when not given |
| `--json` | — | off | Emit a machine-readable key record consumed by `smt cardano-input` |

```bash
# Human-readable (PointA limbs, MiMC leaf, A and sk bit counts)
groth16-prover smt key --vk <pk-hex> --xsk <scalar-hex>

# Machine-readable record for `smt cardano-input`
groth16-prover smt key --vk <pk-hex> --xsk <scalar-hex> --json
```

The `--json` record contains `vk`, `PointA` (`[X,Y,Z,T]` × 3 limbs each), `leaf`, `A` (256 bits), and `sk` (255 bits, only with `--xsk`).

#### `smt leaf` — compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs, k = 0)

Hashes the six base-2^85 limbs `x0,x1,x2,y0,y1,y2` of a decompressed Ed25519 public key via `MultiMiMC7(6, 91)` with `k = 0` — exactly the `leaf` commitment the `CardanoKeyOwnershipSMT` circuit re-derives in-circuit from `PointA`. The output is what you insert with `smt insert`.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--items ITEMS` | — | *required* | Six comma-separated limbs: `x0,x1,x2,y0,y1,y2` |
| `--json` | — | off | Emit machine-readable `{"leaf": "..."}` |

```bash
# Human-readable (prints the leaf field element)
groth16-prover smt leaf --items "x0,x1,x2,y0,y1,y2"

# Machine-readable
groth16-prover smt leaf --items "x0,x1,x2,y0,y1,y2" --json
```

#### `smt insert` — insert items and persist tree state

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--depth N` | — | *required* | Merkle tree depth |
| `--items ITEMS` | — | — | Comma-separated items (single value or `nullifier nonce` pairs). Conflicts with `--transcript` |
| `--transcript FILE` | — | — | Path to transcript file (one item per line). Conflicts with `--items` |
| `--state FILE` | — | `smt.json` | Path to persist/load the tree state (JSON) |

**Item syntax:** each item is either a single field element (raw commitment) or two space-separated values (`nullifier nonce`).

**Examples:**

```bash
# Insert items via --items
groth16-prover smt insert \
  --depth 2 \
  --items "1 100,2 200,3 300" \
  --state smt.json

# Bulk insert from a transcript file
groth16-prover smt insert \
  --depth 2 \
  --transcript transcript.txt \
  --state smt.json
```

#### `smt digest` — print the current Merkle root

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |

```bash
groth16-prover smt digest --state smt.json
```

#### `smt path` — print the Merkle path for a leaf

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--leaf VALUE` | — | *required* | Leaf value to compute the path for (string field element) |

```bash
groth16-prover smt path --state smt.json --leaf <commitment>
```

#### `smt verify` — verify a Merkle path hashes back to the stored digest

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--leaf VALUE` | — | *required* | Leaf value to verify (string field element) |

```bash
groth16-prover smt verify --state smt.json --leaf <commitment>
```

#### `smt export` — export witness input JSON for the Privacy circuit

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--nullifier VALUE` | — | *required* | Target nullifier to prove membership for |
| `--out FILE` | — | `input.json` | Output path for the JSON witness input |

```bash
groth16-prover smt export \
  --state smt.json \
  --nullifier 1 \
  --out input.json
```

#### `smt cardano-input` — assemble the full CardanoKeyOwnershipSMT circuit input

Combines a `smt key` record and a persisted tree state into the complete witness-input JSON for the `CardanoKeyOwnershipSMT` circuit: `A[256]`, `sk[255]`, `PointA[4][3]`, `smt_root`, `smt_siblings`, `smt_directions`. Locates the leaf's Merkle path inside the tree state automatically.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--key FILE` | — | *required* | Key record JSON produced by `smt key --json` |
| `--out FILE` | — | `input.json` | Output path for the JSON witness input |

```bash
groth16-prover smt key --vk <pk-hex> --xsk <scalar-hex> --json > key.json
groth16-prover smt insert --depth 4 --items "<leaf>,40404" --state smt.json
groth16-prover smt cardano-input --state smt.json --key key.json --out input.json
```

The record must contain `sk` bits — re-run `smt key --xsk` if it was generated without them.

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

### Production ceremony workflow

```bash
cd groth16-prover/cli

# 1. Compile the Circom circuit
cd ../circom/SimpleExample
circom multiplier.circom --r1cs --wasm
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
cd ../../cli

# 2. Initialize from a universal Phase 1 SRS
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

### Privacy example (SMT + compute-inputs + prove)

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

### Dev-only shortcut (no proving key — deterministic test values)

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

> **Note:** This uses deterministic test values (`tau=3`, `alpha=5`, etc.) and skips the ceremony step. For large circuits, use `--sparse` (Implementation 6) to avoid dense matrix allocation.

---

## Build

```bash
cd groth16-prover/cli
cargo build --release
```

The binary will be at `target/release/groth16-prover`.

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

The CLI produces two formats. The **preferred** one (group elements only) is what `ceremony-dev` and `phase2 finalize` output today.

| Property | Legacy `ProvingKey` (scalars) | `FullProvingKey` (group elements) |
|----------|------------------------------|-----------------------------------|
| `.pk` size | ~200 bytes | ~MBs (circuit-dependent) |
| Toxic waste in `.pk` | ❌ Yes — raw scalars | ✅ No — only curve points |
| Prover work per proof | Re-evaluates QAP at `tau` | Pure MSM over pre-computed points |
| Dev path | `ceremony` (deprecated) | `ceremony-dev` (default) |
| Production path | — | `phase2` MPC |

**Backward compatibility.** The `prove` command auto-detects the format on load: if the file starts with the legacy `ProvingKey` magic it falls back to the scalar-based prover; otherwise it loads a `FullProvingKey` and uses the fast MSM path. New `.pk` files are always written as `FullProvingKey`.

See [`MPC_Ceremony_Research.md`](../docs/MPC_Ceremony_Research.md) for the full ceremony roadmap.

---

## CLI test suite

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
| `smt_verify_valid` | `smt verify` reports VALID for a correct path |
| `smt_verify_invalid` | `smt verify` reports INVALID for a wrong path |
| `smt_export` | `smt export` produces valid JSON for Privacy circuit |
| `smt_leaf_computes_mimc_commitment` | MiMC leaf matches the Python `multi_mimc7` reference |
| `smt_key_computes_witness_data` | `smt key` decompresses, chunks, and bit-decomposes a key |
| `smt_key_json_output_matches_python` | `smt key --json` PointA/leaf match the Python reference |
| `smt_key_rejects_bad_hex` | Non-hex or wrong-length `--vk` / `--xsk` are rejected |
| `smt_cardano_input_assembles_full_input` | `key` + `insert` → full circuit input; root matches `smt digest` |
| `smt_cardano_input_requires_sk_bits` | Missing `--xsk` is caught with a helpful error |
| `compute_inputs_basic` | Basic transcript → JSON witness input generation |
| `compute_inputs_nullifier_not_found` | Error when nullifier is missing from transcript |
| `compute_inputs_with_raw_commitments` | Correct failure for raw-commitment transcripts |
| `compute_inputs_missing_transcript` | Error handling for missing transcript file |
| `nova_params_rejects_monolithic_ed25519_ownership` | `nova params` rejects non-step circuit |
| `nova_params_rejects_jubjub_ownership` | `nova params` rejects wrong public I/O ratio |
| `nova_params_rejects_non_step_circuit` | `nova params` rejects circuit where `n_pub_in != n_pub_out` |
| `nova_params_missing_circuit` | Required-arg error for `nova params` |
| `nova_params_invalid_circuit` | Bad file format error for `nova params` |
| `nova_ceremony_basic` | `nova ceremony` produces a `FullProvingKey` |
| `nova_ceremony_h_scalar` | `nova ceremony --h-scalar` works |
| `nova_fold_basic` | `nova fold` produces a valid IVC bundle JSON |
| `nova_verify_basic` | `nova verify` passes for a freshly folded bundle |
| `nova_verify_tampered_proof` | `nova verify` fails for a tampered step proof |
| `nova_verify_tampered_transcript` | `nova verify` fails for a tampered transcript |

Run the tests:

```bash
cd groth16-prover/cli
cargo test
```