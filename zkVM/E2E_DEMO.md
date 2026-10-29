# End-to-End Demo: Aiken → zkVM (OpenVM/Jolt)

This document visualizes how an Aiken program flows through OpenVM and Jolt, provides step-by-step commands, and compares the approaches with benchmarks and trade-offs.

## High-level architecture

```mermaid
graph TB
    A[Aiken source *.ak] --> B[aiken build/check/test]
    B --> C[UPLC - Untyped Plutus Core]
    C --> D{Integration approach}
    D -->|Route 1a: Port to RISC-V guest| E[Write Rust guest calling same logic e.g. sha2_256]
    D -->|Route 1b: UPLC interpreter in guest| F[Embed UPLC evaluator in guest + load .flat program]
    E --> G[zkVM guest compilation]
    F --> G
    G --> H{zkVM}
    H --> I[OpenVM: RV32IM guest compiled via rustc nightly + transpile to vmexe]
    H --> J[Jolt: RV64IMAC guest compiled, host drives Jolt SDK]
    I --> K[Execution trace / constraints generation]
    J --> K
    K --> L[Proving: STARK/lookup argument over trace]
    L --> M[Proof artifact]
    M --> N[Verification on host/CPU]
    N --> O[Public output - digest/revealed value]
    O --> P[Cardano verification path - future: wrap to BLS12-381 Groth16]
```

## Detailed flow per zkVM

### OpenVM flow (RV32IM)

```mermaid
sequenceDiagram
    participant Dev
    participant Aiken
    participant Guest as Rust Guest (RV32IM)
    participant CargoOpenVM as cargo-openvm
    participant Prover
    participant Verifier

    Dev->>Aiken: aiken build / export
    Note over Aiken: produces UPLC, for hello_hash equivalent use same hash
    Dev->>Guest: Write guest using openvm-sha2 / logic
    Dev->>CargoOpenVM: cargo openvm build
    CargoOpenVM->>Guest: Build with nightly-2026-01-18 for riscv32im-risc0-zkvm-elf
    CargoOpenVM->>CargoOpenVM: Transpile to openvm/release/*.vmexe
    Dev->>CargoOpenVM: cargo openvm keygen (once per openvm.toml)
    Dev->>CargoOpenVM: cargo openvm setup (once, global)
    Dev->>CargoOpenVM: cargo openvm run (execute only)
    Dev->>CargoOpenVM: cargo openvm prove app
    CargoOpenVM->>Prover: Generate app proof (STARK)
    Prover-->>Dev: *.app.proof
    Dev->>CargoOpenVM: cargo openvm verify app
    CargoOpenVM->>Verifier: Verify app proof
    Verifier-->>Dev: OK
    Dev->>CargoOpenVM: cargo openvm prove stark (optional aggregation)
    Note over Prover: Public output = revealed bytes32 (e.g. digest)
```

### Jolt flow (RV64IMAC)

```mermaid
sequenceDiagram
    participant Dev
    participant Aiken
    participant Guest as Guest crate (RV64IMAC)
    participant Host as Host binary (Jolt SDK)
    participant JoltProver
    participant JoltVerifier

    Dev->>Aiken: aiken build / export
    Dev->>Guest: Write #[jolt::provable] fn with jolt-inlines-sha2
    Dev->>Host: cargo run --release
    Host->>Guest: guest::compile_* (compile guest to RISC-V)
    Host->>JoltProver: preprocess_shared_* and preprocess_prover_*
    Note over JoltProver: Shared/prover preprocessing cached in memory/dir
    Host->>JoltProver: build_prover_* and prove()
    JoltProver-->>Host: (output, proof, io_device)
    Host->>JoltVerifier: verify(output, io_device.panic, proof)
    JoltVerifier-->>Host: OK
    Note over Host: Public output returned directly (e.g. 32-byte array)
```

## Complete E2E demonstration

### Prerequisites

- Rust toolchain managed by rustup
- For OpenVM: `cargo-openvm` v2.0.2, `cargo openvm setup` done (keys in `~/.openvm/`)
- For Jolt: Jolt CLI optional; project deps pull from git
- Aiken v1.1.19+ (for building/testing Aiken side)

### Path 1: OpenVM - run Aiken-equivalent (hello_hash)

```bash
# 1) Verify Aiken side
cd zkVM/hello-world
aiken check  # should pass, tests hello_hash("Hello, world!") == 315f5bdb...
aiken export --module hello --name hello_hash .  # produces export/UPLC artifact

# 2) Run equivalent in OpenVM
cd ../openvm/hello-aiken  # or openvm/hello
cargo openvm run
# Expected: prints digest 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3

# 3) Build, keygen (once per config), prove, verify
cargo openvm build
cargo openvm keygen  # if not already done for this toml
cargo openvm prove app
cargo openvm verify app
# app proof written (e.g. openvm-hello-aiken.app.proof)

# 4) Optional: aggregated STARK proof
cargo openvm prove stark
cargo openvm verify stark
```

### Path 2: Jolt - run Aiken-equivalent (hello_hash)

```bash
# 1) Verify Aiken side (same as above)
cd zkVM/hello-world && aiken check

# 2) Run in Jolt
cd ../jolt/hello-aiken  # or jolt/hello
cargo run --release
# Host will compile guest, preprocess, prove, verify
# Look for logs: preprocessing time, prove time, verify time, output (hex) = 315f5b...
# Proof serialized to /tmp/jolt-hello-aiken.proof
```

### Path 3: Full Aiken program via UPLC (evaluator integrated in guests)

```bash
# Decode/examine the exported artifact
cd zkVM/hello-world
aiken uplc decode -c hello_hash.flat
# (program 1.1.0 (lam i_0 [ (builtin sha2_256) [ (builtin unBData) i_0 ] ]))

# Evaluate the real artifact with the no_std evaluator
cd ../uplc-guest
cargo test  # includes differential checks against `aiken uplc eval`
cargo run --bin uplc-eval -- \
  ../hello-world/hello_hash.flat \
  --data-bytes 48656c6c6f2c20776f726c6421
# 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3

# Run in OpenVM guest
cd ../openvm/hello-aiken
cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421

# Run in Jolt guest
cd ../../jolt/hello-aiken
cargo run --release --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421

# The evaluator is `no_std` and builds for riscv32im-unknown-none-elf:
cd ../../uplc-guest
cargo build --no-default-features --target riscv32im-unknown-none-elf
# Supports hashes, Data, bytearray/integer, BLS12-381 builtins.
```

## Comparison table (OpenVM vs Jolt)

| Aspect | OpenVM v2.0.2 | Jolt (a16z) |
|---|---|---|
| ISA | RV32IM | RV64IMAC |
| Proving system | Plonky3 STARKs (BabyBear), app proof + recursive aggregation to wrap | Dory-based polynomial commitments over BN254 (sumcheck/lookup), folding-style SNARK |
| Tooling | `cargo-openvm` CLI: build/keygen/setup/prove/verify/run | Jolt SDK in Rust: compile/preprocess/prove/verify all in host code |
| Guest model | `#![no_std]` with `openvm::entry!`, reveal via `openvm::io::reveal_*` | `#[jolt::provable(...)]` functions, return values become public output |
| One-time setup | `cargo openvm setup` for recursive keys (~20 min), keygen per app | No global long setup like OpenVM's internal recursive keys; preprocessing is per-program (~seconds) |
| Proof size (hello world) | App: 547 KiB, Aggregated STARK: 522 KiB | ~68.1 kB |
| Prove time (hello world, 4 cores CPU) | ~658 s (app) / ~25 min (stark) | ~11.6 s |
| Verify time (hello world) | ~0.55 s (app) / ~1 s (stark) | ~0.66 s |
| Memory (prover peak) | ~2.6 GB observed | Not measured in detail, generally efficient; varies by trace size |
| GPU support | OpenVM has GPU acceleration support in general; we tested CPU-only | Jolt has GPU paths evolving; tested CPU-only here |
| On-chain verification | Path exists via aggregation/wrapping (EVM) - targeted for recursion/wrapping to Groth16 | More complex on-chain path; recursion/folding story differs, on-chain verification less turnkey today |
| Maturity for this use case | More CLI-driven, explicit keys/flows, good for reproducible app proofs | Developer-friendly Rust API, fast iteration, small proofs, preprocessing-oriented |
| Notes for Aiken/UPLC | `no_std` UPLC evaluator integrated in guests (OpenVM/Jolt), supports full builtin set | Same; integrated with extended Data arg support |

## Trade-offs

- **Fidelity vs effort**: Porting equivalent logic (Route 1a) is fastest and matches exactly for pure functions like hash; running actual UPLC (Route 1b) gives full script fidelity. The `no_std` evaluator is implemented and integrated into OpenVM/Jolt guests with full builtin support (hashes, Data, bytearray/integer, BLS12-381).
- **Speed vs proof system**: Jolt is much faster to prove on CPU for this tiny program with smaller proofs; OpenVM's STARK path is more established for aggregation/recursion flows.
- **Tooling**: OpenVM feels more "CLI + artifacts"; Jolt feels more "library/SDK integrated into Rust build".
- **Memory**: OpenVM's app proving used ~2.6 GB for this small guest - need to watch for larger guests.
- **Future Cardano integration**: Both VMs use BN254 internally and need wrapping to BLS12-381 Groth16 for Cardano verification (see `zkVM/benchmarks.md`). OpenVM's recursion story is clearer; Jolt on-chain paths are evolving.
