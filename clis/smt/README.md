# smt-cli

Command-line interface for Sparse Merkle Tree (SMT) operations on BLS12-381, plus witness-input generation for the privacy-preserving circuits built on top of the tree.

Backed by MiMC(x⁷) hashing, the CLI builds insert-only SMTs, derives CardanoKeyOwnershipSMT witness data from Ed25519 payment keys, and produces the Circom witness inputs for the Spend(depth) and CardanoKeyOwnershipSMT circuits. This functionality previously lived inside `groth16-prover-cli` under the `smt` subcommand.

## Quick reference

Run any command with `--help` for full flag details:

```bash
smt --help
smt key --help
smt insert --help
smt cardano-input --help
```

Top-level help output:

```
Sparse Merkle Tree CLI for BLS12-381

Usage: smt <COMMAND>

Commands:
  compute-inputs  Compute witness inputs for the Spend(depth) circuit
  key             Derive CardanoKeyOwnershipSMT witness data from a payment key
  leaf            Compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs, k = 0)
  insert          Insert items into the SMT and persist the updated tree state
  digest          Print the current Merkle root (digest) of a persisted tree
  path            Print the Merkle authentication path for a given leaf
  verify          Verify that a Merkle path hashes back to the stored digest
  export          Export witness input JSON for the Privacy circuit
  cardano-input   Assemble the full CardanoKeyOwnershipSMT circuit input
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Command reference

### `key` — derive CardanoKeyOwnershipSMT witness data from a key

Decompresses an Ed25519 public key into the extended coordinates `[X, Y, Z, T]`, splits each coordinate into three base-2^85 limbs, computes the MiMC leaf commitment, and bit-decomposes `A` (the 256 compressed-key bits) and optionally `sk` (the 255 clamped-scalar bits). This is the full witness-generation pipeline for the `CardanoKeyOwnershipSMT` circuit — previously done in Python.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--vk HEX` | — | *required* | Compressed Ed25519 public key (64 hex chars) |
| `--xsk HEX` | — | — | 32-byte Ed25519 scalar (first 32 bytes of the extended signing key). Without it the `sk` bits are omitted |
| `--json` | — | off | Emit a machine-readable key record consumed by `cardano-input` |

**Examples:**

```bash
# Human-readable derivation
smt key --vk <pk-hex> --xsk <scalar-hex>

# Machine-readable record for `cardano-input`
smt key --vk <pk-hex> --xsk <scalar-hex> --json
```

The `--json` output is:

```json
{"vk": "...", "PointA": [[...]], "leaf": "...", "A": ["0","1",...], "sk": ["0","1",...]}
```

### `leaf` — compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs, k = 0)

Hashes the six base-2^85 limbs `x0,x1,x2,y0,y1,y2` of a decompressed Ed25519 public key via `MultiMiMC7(6, 91)` with `k = 0` — exactly the `leaf` commitment the `CardanoKeyOwnershipSMT` circuit re-derives in-circuit from `PointA`. The output is what you insert with `insert`.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--items ITEMS` | — | *required* | Six comma-separated limbs `x0,x1,x2,y0,y1,y2` |
| `--json` | — | off | Emit `{"leaf": "..."}` JSON |

**Examples:**

```bash
smt leaf --items "x0,x1,x2,y0,y1,y2"
smt leaf --items "x0,x1,x2,y0,y1,y2" --json
```

### `insert` — insert items and persist tree state

Builds a tree of the given depth and inserts the items, then persists the tree state (digest + transcript) to `--state` so it can be reused by `digest`, `path`, `verify`, `export`, and `cardano-input`.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--depth N` | — | *required* | Merkle tree depth (number of levels) |
| `--items ITEMS` | — | — | Comma-separated list of items; each item is one field element (raw commitment) or `nullifier nonce`. Mutually exclusive with `--transcript` |
| `--transcript FILE` | — | — | Path to a transcript file (one item per line). Mutually exclusive with `--items` |
| `--index N` | — | — | Place a single raw-commitment `--items` value at this explicit leaf index (0-padded tree) |
| `--state FILE` | — | `smt.json` | Path to persist/load the tree state (JSON) |

**Examples:**

```bash
# Two nullifier-nonce commitments
smt insert \
  --depth 2 \
  --items "1 100,2 200" \
  --state smt.json

# A single raw commitment at an explicit leaf index (0-padded tree)
smt insert \
  --depth 2 \
  --items "42" \
  --index 3 \
  --state smt.json

# Bulk-load from a transcript file
smt insert --depth 2 --transcript transcript.txt --state smt.json
```

### `digest` — print the current Merkle root

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |

```bash
smt digest --state smt.json
```

### `path` — print the Merkle path for a leaf

Rebuilds the tree from the persisted state and prints each sibling together with its direction. With `--json`, emits `{"digest", "siblings", "directions"}` where both lists are decimal field-element strings (direction `1` = sibling on the left).

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--leaf VALUE` | — | *required* | Leaf value to compute the path for (string field element) |
| `--json` | — | off | Emit machine-readable JSON |

```bash
smt path --state smt.json --leaf <commitment>
smt path --state smt.json --leaf <commitment> --json
```

### `verify` — verify a Merkle path hashes back to the stored digest

Rebuilds the tree, computes the path for the given leaf, and checks that re-hashing the path reproduces the stored digest.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--leaf VALUE` | — | *required* | Leaf value to verify (string field element) |

```bash
smt verify --state smt.json --leaf <commitment>
```

### `export` — export witness input JSON for the Privacy circuit

Reads the persisted tree state and produces the Merkle-path data needed by the Circom witness generator for the Spend circuit.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--nullifier VALUE` | — | *required* | Target nullifier to prove membership for |
| `--out FILE` | — | `input.json` | Output path for the JSON witness input |

```bash
smt export \
  --state smt.json \
  --nullifier 1 \
  --out input.json
```

### `cardano-input` — assemble the full CardanoKeyOwnershipSMT circuit input

Combines a `key` record and a persisted tree state into the complete witness-input JSON for the `CardanoKeyOwnershipSMT` circuit: `A[256]`, `sk[255]`, `PointA[4][3]`, `smt_root`, `smt_siblings`, `smt_directions`. Locates the leaf's Merkle path inside the tree state automatically.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--state FILE` | — | `smt.json` | Path to the persisted tree state |
| `--key FILE` | — | *required* | Key record JSON produced by `key --json` |
| `--out FILE` | — | `input.json` | Output path for the JSON witness input |

```bash
smt key --vk <pk-hex> --xsk <scalar-hex> --json > key.json
smt insert --depth 4 --items "<leaf>,40404" --state smt.json
smt cardano-input --state smt.json --key key.json --out input.json
```

The record must contain `sk` bits — re-run `key --xsk` if it was generated without them.

### `compute-inputs` — witness generation for Spend(depth)

Reads a transcript file (one nullifier-nonce pair per line) and produces a JSON file with the private Merkle-path data needed by the Circom witness generator for the Spend(depth) circuit. This is the `export` equivalent for a plain transcript file instead of a persisted tree state.

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--depth N` | — | *required* | Merkle tree depth |
| `--transcript FILE` | — | *required* | Path to the transcript file |
| `--nullifier VALUE` | — | *required* | Target nullifier to prove membership for |
| `--out FILE` | — | `input.json` | Output path for the JSON witness input |

**Transcript format:** each line contains either one field element (raw commitment) or two space-separated field elements (`nullifier nonce`). Empty lines are skipped.

```bash
smt compute-inputs \
  --depth 2 \
  --transcript transcript.txt \
  --nullifier 2 \
  --out input.json
```

## Build

```bash
cargo build --release
```

The binary is `target/release/smt`. The crate depends on the `groth16-prover` library with its `privacy` feature enabled (`groth16-prover/src/{mimc,sparse_merkle_tree,ed25519,privacy_inputs}.rs`).

## Test suite

```bash
cargo test --release
```

The integration tests in `tests/cli.rs` cover every command via `assert_cmd`, with a fixed-seed Ed25519 test vector cross-checked against the Python reference math (`gen_smt_input.py`).
