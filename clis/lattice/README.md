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

Lova folds witnesses represented as vectors over Z_{2^64} (unsigned 64-bit integers). There are two ways to convert a BLS12-381 field element (256 bits) into Z_{2^64} values:

**4-limb mode (default)** — split the 256-bit number into 4 pieces of 64 bits each:

```
BLS12-381 element (256 bits):
┌──────────────────────────────────────────────────────────────────────┐
│                          256-bit value                               │
└──────────────────────────────────────────────────────────────────────┘

Split into 4 × 64-bit limbs:

  limb₀ = value & 0xFFFFFFFFFFFFFFFF             (bits  0–63)
  limb₁ = (value >>  64) & 0xFFFFFFFFFFFFFFFF    (bits 64–127)
  limb₂ = (value >> 128) & 0xFFFFFFFFFFFFFFFF    (bits 128–191)
  limb₃ = (value >> 192) & 0xFFFFFFFFFFFFFFFF    (bits 192–255)
```

Each limb is up to 2⁶⁴ − 1. A circuit with 15 signals becomes a Lova vector of length 15 × 4 = **60**.

**RNS mode (`--rns`)** — instead of splitting by bit position, compute the
number's remainder (modular residue) under 8 different prime numbers, each
fitting in 32 bits:

```
BLS12-381 element (256 bits):
┌──────────────────────────────────────────────────────────────────────┐
│                          256-bit value                               │
└──────────────────────────────────────────────────────────────────────┘

Compute residues mod 8 primes (each < 2³²):

  r₀ = value mod 4294967291    (2³² − 5)
  r₁ = value mod 4294967279    (2³² − 17)
  r₂ = value mod 4294967231    (2³² − 65)
  r₃ = value mod 4294967197    (2³² − 99)
  r₄ = value mod 4294967189    (2³² − 107)
  r₅ = value mod 4294967161    (2³² − 135)
  r₆ = value mod 4294967143    (2³² − 153)
  r₇ = value mod 4294967111    (2³² − 185)
```

Each residue is up to ~2³². A circuit with 15 signals becomes a Lova vector of length 15 × 8 = **120**.

**Simple numeric example.** Take the number 42 (small enough to do by hand):

```
4-limb:   42 = 0·2¹⁹² + 0·2¹²⁸ + 0·2⁶⁴ + 42
          → [42, 0, 0, 0]           (4 values, each up to 2⁶⁴−1)

RNS:      42 mod 7  = 0      42 mod 11 = 9
          42 mod 13 = 3      42 mod 17 = 8
          42 mod 19 = 4      42 mod 23 = 19
          42 mod 29 = 13     42 mod 31 = 11
          → [0, 9, 3, 8, 4, 19, 13, 11]   (8 values, each up to 31)
```

Both represent the same number. RNS uses more values but each is much smaller.

**Why RNS should help (but doesn't yet).** The Lova folding speed depends on
two things:

1. **Witness dimension** — how many Z_{2^64} values per signal. More values = bigger matrix = slower.
2. **Decomposition digits** — how many rounds of digit decomposition per fold. Fewer digits = less work per round.

RNS trades one for the other: it **halves** the decomposition digits (32 vs 64, because each residue fits in 32 bits instead of 64) but **doubles** the dimension (8 residues per element instead of 4 limbs). The math:

```
Matrix operations scale with n².  Doubling n → 4× slower.
Decomposition scales with digits. Halving digits → 2× faster.

Net effect: 4× slower × 2× faster = 2× slower overall.
```

That's exactly what the benchmarks show — RNS is 1.4× slower for EdDSA and 8× slower for Ed25519:

**EdDSA (15 signals, 63 steps):**

| Mode | n | decompose_digits | Fold/step | Verify/step | Proof size |
|------|---|-----------------|-----------|-------------|------------|
| **4-limb** (default) | 60 | 64 | **0.45 ms** | **0.03 ms** | **31.9 KiB** |
| **RNS** (8×32-bit) | 120 | 32 | 0.63 ms | 0.09 ms | 33.8 KiB |

**Airdrop (1,210 signals, 4 steps):**

| Mode | n | decompose_digits | Fold/step | Verify/step | Proof size |
|------|---|-----------------|-----------|-------------|------------|
| **4-limb** (default) | 4,840 | 64 | **1,204 ms** | **282 ms** | **2,571 KiB** |
| **RNS** (8×32-bit) | 9,680 | 32 | 4,909 ms | 1,133 ms | 2,723 KiB |

**Ed25519 (7,658 signals, 15 steps):**

| Mode | n | decompose_digits | Fold/step | Verify/step | Proof size |
|------|---|-----------------|-----------|-------------|------------|
| **4-limb** (default) | 30,632 | 64 | **35.5 s** | **10.7 s** | **16,273 KiB** |
| **RNS** (8×32-bit) | 61,264 | 32 | 283.5 s | 65.5 s | 17,231 KiB |

**How to actually make RNS useful (Phase 2).** The real win comes from doing
the matrix multiplication *inside* the RNS representation — 8 small matrix
multiplications (each over 32-bit numbers) instead of one big one (over 64-bit
numbers). This eliminates the 2× dimension penalty entirely. That requires
changes to the Ajtai commitment scheme and is tracked as Phase 2 in the roadmap
below.

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
