# trusted-setup

Standalone CLI (and library `trusted_setup`) for Groth16 trusted-setup ceremonies on BLS12-381.

This crate hosts the ceremony functionality that previously lived in the `groth16-prover` CLI: the single-party dev ceremony, the legacy `ceremony` command, and the multi-party Phase-2 MPC on top of a public Phase-1 SRS (`.ptau`). Proof generation, verification, and verifying-key export live in the `groth16` CLI (`clis/groth16`).

---

## Executive Summary

The `trusted-setup` CLI generates the proving and verifying keys needed by Groth16. It supports two modes:

- **`ceremony-dev`** — Single-party, instant (milliseconds). For development, CI, and benchmarking. Produces a `FullProvingKey` with no embedded scalars.
- **`phase2`** — Multi-party MPC ceremony on top of a public Phase-1 SRS (e.g., Perpetual Powers of Tau). Production-ready; security holds if at least one participant is honest.

**What you get:**
- `.pk` file → consumed by `groth16 prove`
- `.vk` file → consumed by `groth16 verify` and `groth16 export-vk`
- Bit-for-bit compatibility with arkworks `ProvingKey` / `VerifyingKey`
- Sparse-circuit support (`--sparse`) for large circuits (Blake2b, Ed25519)
- h-scalar optimization (`--h-scalar`) to reduce proving key size

**Quick start:**
```bash
cd clis/trusted-setup
cargo build --release

# Dev ceremony (instant)
./target/release/trusted-setup ceremony-dev \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk

# Production Phase-2 ceremony
./target/release/trusted-setup phase2 new \
  --circuit ../../circom/SimpleExample/multiplier.r1cs \
  --srs ../../circom/universal.ptau \
  --zkey /tmp/multiplier_0000.zkey

./target/release/trusted-setup phase2 contribute \
  --zkey-in /tmp/multiplier_0000.zkey \
  --zkey-out /tmp/multiplier_0001.zkey \
  --name "Alice"

./target/release/trusted-setup phase2 finalize \
  --zkey /tmp/multiplier_0001.zkey \
  --proving-key /tmp/multiplier.pk \
  --verifying-key /tmp/multiplier.vk
```

**Ceremony benchmarks (Intel i7-7500U):**

| Circuit | Constraints | Dev ceremony | Phase-2 init | Contribute | Finalize |
|---------|-------------|--------------|--------------|------------|----------|
| Multiplier | 3 | 12 ms | 45 ms | 30 ms | 25 ms |
| Airdrop | 1,210 | 45 ms | 180 ms | 120 ms | 90 ms |
| Privacy Pool | 33,615 | 580 ms | 2.1 s | 1.4 s | 950 ms |
| Blake2b-224 | 78,882 | 2.1 s | 7.5 s | 4.8 s | 3.2 s |

---

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

The `.pk` / `.vk` files produced by any of these ceremonies are consumed by the `groth16` CLI (`prove` / `verify` / `export-vk`) and by the on-chain Aiken verifiers. Both formats are auto-detected on load:

- `FullProvingKey` (group elements only, from `ceremony-dev` / `phase2 finalize`) uses the fast MSM prover path.
- Legacy `ProvingKey` (contains scalars, from `ceremony`) falls back to the scalar-based prover path.

## Library

The crate also exposes the ceremony core as a library (`trusted_setup`) with modules `r1cs`, `qap`, `engine`, `ceremony`, `phase2`, `ptau`, `circom_adapter`, `prover`, and `cmd`. The `groth16-prover` library re-exports these modules, so `groth16_prover::ceremony` and friends keep working for existing callers.

## Native (blst) backend

The proving/verifying hot paths (MSM and pairings) can run on the **Cpu** backend — pure Rust [arkworks](https://arkworks.rs/) — or on the **Native** backend — the vendored [blst](https://github.com/supranational/blst) `libblst.a`, called through a C shim and an `unsafe` FFI layer. The **library** keeps a run-time `Backend` selection (`set_groth16_ref(Backend::Cpu|Native)`), so both implementations stay in the tree and are cross-checked against each other. The **CLI artifact**, by contrast, bakes the choice in at compile time via the `BLS_BACKEND` environment variable, so a given binary provably contains exactly one path.

### Choosing the backend at compile time (CLI)

`build.rs` in `clis/groth16` reads `BLS_BACKEND` while the `groth16` CLI is being compiled:

- `BLS_BACKEND=cpu` — arkworks-only binary; `--backend native` is rejected by the parser and the CLI's blst FFI dispatch path is not compiled in.
- `BLS_BACKEND=native` — FFI-only binary; `--backend cpu` is rejected and the CLI's arkworks MSM/pairing dispatch path is not compiled in. Requires `--features native`.
- `BLS_BACKEND=both` (default) — both implementations compiled, `--backend` selects at run time (default `cpu`); the mode used by the parity tests and the benchmark.

```bash
cd clis/groth16
# Pure-Rust artifact
BLS_BACKEND=cpu cargo run --release -- prove ...
# FFI-only artifact
BLS_BACKEND=native cargo run --release --features native -- prove --backend native ...
# Both backends, run-time selectable (default)
cargo run --release --features native -- prove --backend native ...
```

### Building with the native feature

The native backend is an optional feature so the pure-Rust path stays buildable on any toolchain. Enabling it requires a C/C++ toolchain, **CMake, `make`, and `nasm`** on the host (Debian/Ubuntu: `build-essential cmake nasm`). The blst sources are **vendored in-tree** (`native/vendored/blst`, pinned Apache-2.0 checkout) and are compiled automatically by `build.rs` → CMake → blst's own `build.sh` into a static `libblst.a`; nothing is downloaded and no blst installation is needed:

```bash
cd clis/trusted-setup
cargo build --release --features native
```

Feature chain: `clis/groth16` (`native`) → `groth16-prover` (`native`) → `trusted-setup` (`native`). Building the crate without the feature compiles the C shim but keeps every backend call on the Cpu path. `BLS_BACKEND=native` without `--features native` aborts the build with a clear message (the FFI code must be compiled in for an FFI-only artifact).

### How it works

- `native/` holds the vendored blst source and the thin C shim `bls_backend.cpp` + `bls_backend.h`. The FFI defines fixed-width byte types (`bls_backend_g1_t` 48 bytes, `bls_backend_g2_t` 96 bytes, `bls_backend_fr_t` 32 bytes, all **little-endian** canonical field coordinates — the blst convention), so there is no heap allocation or `Arc` crossing the boundary.
- `backend.rs` exposes `native_msm_g1`, `native_msm_g2`, `native_pairing_batch_check`, and `native_ntt`, and either owns the blst types or converts arkworks elements to the byte ABI at the boundary.
- blst's Pippenger MSM and the pairing checks are single-threaded; the arkworks `Cpu` numbers below are therefore shown both on the default rayon pool and on a 1-thread pool. arkworks is built here **without** its `parallel` feature, so the two Cpu columns are near-identical; the end-to-end prover recovers the multithread gap by running the four independent proof MSMs in parallel.
- Correctness is enforced four ways: per-call parity checks on the *inputs* (`backend.rs`), arkworks `assert_eq!` cross-validation tests (`native_g1_matches_ark_msm`, `native_g2_matches_ark_msm`, `native_pairing_matches_ark_multi`, `native_ntt_matches_ark_ifft`), an independent C++ unit test (`native/tests/test_bls_backend.cpp`, including an NTT oracle), and the `prover.rs` parity tests (`native_prover_matches_cpu_fixed_multiplier`, `native_prover_matches_cpu_random_sparse_circuits`) that assert the Cpu and Native backends produce bit-for-bit identical proof artifacts.
- Every decoded point is still validated: on-curve and subgroup checks run once on each batch's *output*; per-point validation is skipped inside the hot loops (a full final exponentiation per point would otherwise dwarf the MSM).

### Measured numbers

The benchmark can be regenerated on any machine (release build, native feature) with:

```bash
cd clis/trusted-setup
cargo run --release --features native --bin benchmark_backend
# larger MSMs: --max-msm 4194304; isolate a section: --g1-only --g2-only --pairing-only --ntt-only
```

Every row is a min-of-3 timing, and both backends are fed identical deterministic fixtures and asserted equal before timing, so the ratio column is for provably-equal output. All numbers below were **measured on this machine** (Intel i7-7500U, aggressively throttled, ~4-thread rayon pool); absolute numbers are machine-specific, the ratios are representative.

| G1 MSM (`n`) | cpu (Nt) | cpu (1t) | native (1t) | vs cpu Nt | vs cpu 1t |
|---:|---:|---:|---:|:---:|:---:|
| 1 000 | 157.3 ms | 161.8 ms | 91.1 ms | 1.73× | 1.78× |
| 16 384 | 2388.9 ms | 2479.7 ms | 1174.0 ms | 2.03× | 2.11× |

| G2 MSM (`n`) | cpu (Nt) | cpu (1t) | native (1t) | vs cpu Nt | vs cpu 1t |
|---:|---:|---:|---:|:---:|:---:|
| 1 000 | 620.2 ms | 625.2 ms | 325.2 ms | 1.91× | 1.92× |
| 16 384 | 5891.3 ms | 5783.3 ms | 2743.4 ms | 2.15× | 2.11× |

| Pairing batch (`n`) | cpu (Nt) | cpu (1t) | native (1t) | vs cpu Nt | vs cpu 1t |
|---:|---:|---:|---:|:---:|:---:|
| 1 | 9.6 ms | 5.1 ms | 3.5 ms | 2.75× | 1.45× |
| 4 | 14.5 ms | 16.8 ms | 6.5 ms | 2.23× | 2.59× |
| 16 | 42.1 ms | 29.2 ms | 18.1 ms | 2.32× | 1.61× |
| 64 | 149.7 ms | 148.3 ms | 63.7 ms | 2.35× | 2.33× |
| 256 | 702.6 ms | 657.4 ms | 248.1 ms | 2.83× | 2.65× |
| 1 024 | 2697.0 ms | 3495.2 ms | 1412.4 ms | 1.91× | 2.47× |

| Radix-2 NTT (Fr, forward) | cpu (Nt) | cpu (1t) | native (1t) | vs cpu Nt | vs cpu 1t |
|---:|---:|---:|---:|:---:|:---:|
| 1 024 | 1.4 ms | 1.5 ms | 1.9 ms | 0.71× | 0.79× |
| 16 384 | 26.3 ms | 38.9 ms | 32.8 ms | 0.80× | 1.19× |
| 131 072 | 340.4 ms | 301.0 ms | 373.7 ms | 0.91× | 0.81× |

At 1M+ scale the G1 MSM speedup is larger on more representative hardware; on this throttled laptop a 2²⁰ G1 MSM (~2.05×) takes several minutes and a 2²² run is only reachable via `--max-msm 4194304`. The NTT kernel sits at parity with arkworks' radix-2 FFT (its cost is dominated by the byte↔Montgomery ABI round trip at the boundary); the decisive wins are the MSMs (1.7–2.2×) and pairings (1.4–2.8×), which are 90%+ of prove/verify time.

## Tests

```bash
cd clis/trusted-setup
cargo test
```

Unit tests cover the ceremony/prove/verify roundtrips, the `.ptau` parser, and the Phase-2 accumulator; integration tests in `tests/cli.rs` exercise the full CLI (`ceremony`, `ceremony-dev`, `phase2 new/contribute/verify/finalize`) via `assert_cmd`. The native cross-validation and parity tests run under `cargo test --features native`.
