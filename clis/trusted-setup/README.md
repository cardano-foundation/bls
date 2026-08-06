# trusted-setup

Standalone CLI (and library `trusted_setup`) for Groth16 trusted-setup ceremonies on BLS12-381.

This crate hosts the ceremony functionality that previously lived in the `groth16-prover` CLI: the single-party dev ceremony, the legacy `ceremony` command, and the multi-party Phase-2 MPC on top of a public Phase-1 SRS (`.ptau`). Proof generation, verification, and Nova IVC folding remain in the `groth16-prover` CLI (`groth16-prover/cli`).

## Build

```bash
cd clis/trusted-setup
cargo build --release
```

The binary will be at `target/release/trusted-setup`.

## Commands

### `ceremony` — legacy trusted setup (deprecated)

> ⚠️ **Deprecated.** Use `ceremony-dev` (for dev/testing) or `phase2` (for production) instead. Produces a legacy `ProvingKey` that contains scalar toxic waste, making it unsuitable for production use.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--proving-key FILE` | — | *required* | Output path for the proving key |
| `--verifying-key FILE` | — | *required* | Output path for the verification key |

```bash
trusted-setup ceremony \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

### `ceremony-dev` — single-party dev ceremony

A single-party ceremony that generates randomness locally, evaluates the QAP polynomials, and writes a `FullProvingKey` (group elements only, no scalars). Fast (milliseconds) and insecure — perfect for development, benchmarking, and CI.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--proving-key FILE` | — | *required* | Output path for the proving key |
| `--verifying-key FILE` | — | *required* | Output path for the verification key |
| `--sparse` | — | — | Use sparse constraint representation (Implementation 6). Avoids dense matrix allocation for large circuits (e.g. Blake2b-224, Ed25519) |
| `--h-scalar` | — | — | Use h-query scalar compression (Implementation 7). Stores a single scalar `delta_inv * T(tau)` instead of the full `h_query` G1 vector, cutting PK size and eliminating the h MSM |

```bash
# Basic dev ceremony
trusted-setup ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk

# Sparse mode for large circuits
trusted-setup ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --sparse

# With h-scalar compression (Implementation 7)
trusted-setup ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --h-scalar

# Sparse + h-scalar combined
trusted-setup ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --sparse \
  --h-scalar
```

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
trusted-setup phase2 new \
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
trusted-setup phase2 contribute \
  --zkey-in circuit_0000.zkey \
  --zkey-out circuit_0001.zkey \
  --name "Alice"

# Participant 2 contributes
trusted-setup phase2 contribute \
  --zkey-in circuit_0001.zkey \
  --zkey-out circuit_final.zkey \
  --name "Bob"
```

#### `phase2 verify`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--zkey FILE` | — | *required* | Accumulator to verify (.zkey) |

```bash
trusted-setup phase2 verify --zkey circuit_final.zkey
```

#### `phase2 finalize`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--zkey FILE` | — | *required* | Final accumulator (.zkey) |
| `--proving-key FILE` | — | *required* | Output path for the proving key (.pk) |
| `--verifying-key FILE` | — | *required* | Output path for the verification key (.vk) |

```bash
trusted-setup phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

**Full workflow:**

```bash
# 1. Initialize from universal SRS
trusted-setup phase2 new \
  --circuit circuit.r1cs \
  --srs universal.ptau \
  --zkey circuit_0000.zkey

# 2. Participants contribute sequentially
trusted-setup phase2 contribute \
  --zkey-in circuit_0000.zkey \
  --zkey-out circuit_0001.zkey \
  --name "Alice"

trusted-setup phase2 contribute \
  --zkey-in circuit_0001.zkey \
  --zkey-out circuit_final.zkey \
  --name "Bob"

# 3. Verify the accumulator
trusted-setup phase2 verify --zkey circuit_final.zkey

# 4. Finalize to .pk / .vk
trusted-setup phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

## Consuming the keys

The `.pk` / `.vk` files produced by any of these ceremonies are consumed by the `groth16-prover` CLI (`prove` / `verify` / `export-vk`) and by the on-chain Aiken verifiers. Both formats are auto-detected on load:

- `FullProvingKey` (group elements only, from `ceremony-dev` / `phase2 finalize`) uses the fast MSM prover path.
- Legacy `ProvingKey` (contains scalars, from `ceremony`) falls back to the scalar-based prover path.

## Library

The crate also exposes the ceremony core as a library (`trusted_setup`) with modules `r1cs`, `qap`, `engine`, `ceremony`, `phase2`, `ptau`, `circom_adapter`, `prover`, and `cmd`. The `groth16-prover` library re-exports these modules, so `groth16_prover::ceremony` and friends keep working for existing callers.

## Tests

```bash
cd clis/trusted-setup
cargo test
```

Unit tests cover the ceremony/prove/verify roundtrips, the `.ptau` parser, and the Phase-2 accumulator; integration tests in `tests/cli.rs` exercise the full CLI (`ceremony`, `ceremony-dev`, `phase2 new/contribute/verify/finalize`) via `assert_cmd`.
