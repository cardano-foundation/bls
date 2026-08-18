# lattice CLI

Command-line interface for the Lova post-quantum folding scheme. This binary wraps the [`lattice-prover`](../lattice-prover/) crate, providing `fold`, `verify`, and `params` subcommands.

> **Status:** 🔬 Research / evaluation — part of the post-quantum proof system track.

## Prerequisites

Requires Rust nightly toolchain `nightly-2025-05-01` (or compatible). The `lattice-prover` crate depends on `lattirust-arithmetic` which needs nightly features.

## Usage

```bash
cd clis/lattice

# Display Lova parameters for given dimensions
lattice --lova params --m 256 --n 128

# Fold 32 steps with specified dimensions
lattice --lova fold --steps 32 --m 256 --n 128

# Fold with toy parameters (fast, for testing)
lattice --lova fold --steps 256 --m 16 --n 8

# Verify a folded instance
lattice --lova verify --m 256 --n 128
```

### Flags

| Flag | Description |
|------|-------------|
| `--lova` | Use Lova post-quantum folding scheme (required) |
| `--m` | Commitment matrix rows (default: 256) |
| `--n` | Witness dimension (default: 128) |
| `--steps` | Number of folding steps (default: 8) |
| `--rounds` | Decomposition rounds (default: 64) |

## Benchmarks

### Lova-native benchmarks

Run synthetic benchmarks with random witnesses across parameter configurations:

```bash
cd clis/lattice

# Run all parameter configurations (toy/small/medium/default + scaling)
cargo run --release --bin benchmark_lova -- --all

# Custom configuration
cargo run --release --bin benchmark_lova -- --m 64 --n 32 --steps 128
```

### R1CS-to-Lova benchmarks

Run benchmarks using real Circom circuit witnesses, converted via 4-limb BLS12-381 → Z_{2^64} decomposition:

```bash
cd clis/lattice

# Benchmark with EdDSA circuit (15 signals, fast)
cargo run --release --bin benchmark_lova_r1cs -- \
  --steps-dir /tmp/opencode/bench/eddsa_steps --limit 32

# Benchmark with Airdrop circuit (1,210 signals)
cargo run --release --bin benchmark_lova_r1cs -- \
  --steps-dir /tmp/opencode/bench/airdrop_steps

# Benchmark with Ed25519 circuit (7,658 signals, slow)
cargo run --release --bin benchmark_lova_r1cs -- \
  --steps-dir /tmp/opencode/bench/ed25519_steps --limit 16
```

#### `--rns` flag

Use RNS (Residue Number System) decomposition instead of 4-limb. Decomposes each BLS12-381 element into 8 × 32-bit residues, halving `decompose_digits` (32 vs 64) but doubling the witness dimension (2×n):

```bash
# RNS mode — add --rns to any benchmark command
cargo run --release --bin benchmark_lova_r1cs -- \
  --steps-dir /tmp/opencode/bench/eddsa_steps --limit 64 --rns

# Compare: 4-limb vs RNS on the same circuit
cargo run --release --bin benchmark_lova_r1cs -- --steps-dir /tmp/opencode/bench/eddsa_steps --limit 64
cargo run --release --bin benchmark_lova_r1cs -- --steps-dir /tmp/opencode/bench/eddsa_steps --limit 64 --rns
```

#### Lova-native benchmark results

Measured on a single machine with synthetic random witnesses (release mode, single core). Proof size is constant — independent of step count.

| Parameters | Steps | Fold/step | Verify/step | Proof size |
|------------|-------|-----------|-------------|------------|
| **toy** (m=16, n=8) | 8 | 0.04 ms | 0.00 ms | 4.4 KiB |
| **toy** (m=16, n=8) | 256 | 0.06 ms | 0.00 ms | 4.4 KiB |
| **small** (m=32, n=16) | 128 | 0.11 ms | 0.01 ms | 8.8 KiB |
| **medium** (m=64, n=32) | 128 | 0.16 ms | 0.01 ms | 17.5 KiB |
| **default** (m=256, n=128) | 32 | 1.43 ms | 0.28 ms | 70.0 KiB |

#### R1CS-to-Lova benchmark results

Measured with real Circom circuit witnesses via 4-limb adapter (release mode, single core):

| Circuit | Signals | Lova limbs (n) | Steps | Fold/step | Verify/step | Proof size |
|---------|---------|----------------|-------|-----------|-------------|------------|
| **EdDSA** | 15 | 60 | 63 | 0.45 ms | 0.03 ms | 31.9 KiB |
| **Airdrop** | 1,210 | 4,840 | 4 | 1,204 ms | 282 ms | 2,571 KiB |
| **Ed25519** | 7,658 | 30,632 | 15 | 35.5 s | 10.7 s | 16,273 KiB |

#### RNS decomposition mode (`--rns`)

RNS decomposes each BLS12-381 element into 8 × 32-bit residues instead of 4 × 64-bit limbs. This halves `decompose_digits` (32 vs 64) but doubles the witness dimension (2×n).

**RNS vs 4-limb comparison (EdDSA, 15 signals, 63 steps):**

| Mode | n | decompose_digits | Fold/step | Verify/step | Proof size |
|------|---|-----------------|-----------|-------------|------------|
| **4-limb** (default) | 60 | 64 | **0.45 ms** | **0.03 ms** | **31.9 KiB** |
| **RNS** (8×32-bit) | 120 | 32 | 0.63 ms | 0.09 ms | 33.8 KiB |

**RNS vs 4-limb comparison (Airdrop, 1,210 signals, 4 steps):**

| Mode | n | decompose_digits | Fold/step | Verify/step | Proof size |
|------|---|-----------------|-----------|-------------|------------|
| **4-limb** (default) | 4,840 | 64 | **1,204 ms** | **282 ms** | **2,571 KiB** |
| **RNS** (8×32-bit) | 9,680 | 32 | 4,909 ms | 1,133 ms | 2,723 KiB |

**RNS vs 4-limb comparison (Ed25519, 7,658 signals, 15 steps):**

| Mode | n | decompose_digits | Fold/step | Verify/step | Proof size |
|------|---|-----------------|-----------|-------------|------------|
| **4-limb** (default) | 30,632 | 64 | **35.5 s** | **10.7 s** | **16,273 KiB** |
| **RNS** (8×32-bit) | 61,264 | 32 | 283.5 s | 65.5 s | 17,231 KiB |

**Finding:** RNS is currently slower for all circuit sizes because the 2× dimension increase (O(n²) matrix operations) outweighs the 2× decompose_digits reduction. The real RNS benefit would come from integrating RNS into the commitment scheme itself (multiple smaller matrix multiplications instead of one large one) — a deeper architectural change tracked as Phase 2 in the roadmap.

Key observations:

- **Small circuits are practical** — EdDSA (15 signals) folds at 0.45 ms/step, faster than Nova's NIFS (185 ms/step).
- **Proof size is constant** regardless of step count — a key Lova advantage over Nova's linear-in-step-count proofs.
- **Performance scales with witness dimension** — the 4-limb BLS12-381 expansion multiplies the effective dimension by 4×.
- **Large circuits need optimization** — module-SIS commitments or RNS decomposition could reduce the expansion overhead.

## Comparison with Nova (same machine)

| Metric | Nova NIFS (Impl 9/10) | Lova (EdDSA, 4-limb) | Lova (Ed25519, 4-limb) |
|--------|----------------------|----------------------|------------------------|
| Fold/step | 185 ms | **0.45 ms** | 35.5 s |
| Verify/step | 7.87 s (sumcheck) | **0.03 ms** | 10.7 s |
| Proof size | 472.8 KiB (sumcheck) | **31.9 KiB** | 16,273 KiB |
| Post-quantum | No | **Yes** | **Yes** |

## Project structure

```
clis/lattice/
├── Cargo.toml
├── Cargo.lock          # Pinned from lattice-prover for dependency compatibility
├── rust-toolchain.toml # nightly-2025-05-01
├── src/
│   ├── main.rs         # CLI entry point (lattice --lova <SUBCOMMAND>)
│   ├── lib.rs          # run_fold_lova, run_verify_lova, run_params wrappers
│   └── cmd/
│       ├── fold.rs     # fold subcommand
│       ├── verify.rs   # verify subcommand
│       └── params.rs   # params subcommand
└── src/bin/
    ├── benchmark_lova.rs        # Lova-native benchmark (synthetic witnesses)
    └── benchmark_lova_r1cs.rs   # R1CS-to-Lova benchmark (real circuits)
```

## Next steps

1. **Phase 2: RNS in commitment scheme** — instead of converting RNS→Z_{2^64} before folding, run the Ajtai commitment as 8 smaller matrix multiplications (each mod 32-bit prime). This eliminates the 2× dimension overhead and is the real RNS speedup.
2. **Streaming decomposition** — decompose witnesses on-the-fly during fold instead of all-up-front, reducing peak memory.
3. **Parallelization** — use Rayon for multi-core fold (matrix operations are embarrassingly parallel).
4. **Generate more Airdrop witnesses** — only 5 available; need 37 for full IVC chain benchmark.

## License

Apache-2.0
