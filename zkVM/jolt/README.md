# Jolt

Minimal end-to-end Jolt run: compile a Rust function to a RV64IMAC guest,
prove it, and verify the proof. The guest computes
`SHA-256("Hello, world!")` and returns the digest as public output.

Verified on **Jolt `main` (`5aa807b`, v0.1.0 alpha)**, CPU only (4 cores,
31 GB RAM, no GPU).

## Result

| Step | Command | Time | Notes |
|---|---|---|---|
| Build host (first time) | `cargo build --release` | ~20 min | fat LTO; ~107 MB host binary |
| Preprocessing | (inside host run) | ~6 s | program-dependent, reusable |
| Prove | (inside host run) | **11.6 s** | 68.1 kB proof |
| Verify | (inside host run) | **0.66 s** | |

Public output: `315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3`
= `SHA-256("Hello, world!")`, identical to the OpenVM guest.

## One-time install

```bash
# CLI
cargo install --git https://github.com/a16z/jolt --force --bins jolt

# Project scaffold
jolt new hello
```

Jolt's own `rust-toolchain.toml` pins Rust `1.95` with the RISC-V targets
`riscv32imac-unknown-none-elf` and `riscv64imac-unknown-none-elf`; rustup
installs them on first `cargo` invocation. (Note: Jolt's dependency
`sysinfo 0.39` requires **rustc >= 1.95**, so building with an older default
toolchain fails.)

## Run the example

```bash
cd zkVM/jolt/hello
cargo run --release     # compiles the guest, preprocesses, proves, verifies
```

The host (`src/main.rs`) drives the four stages:

```rust
let mut program = guest::compile_hello_world(&target_dir);
let shared = guest::preprocess_shared_hello_world(&mut program).unwrap();
let pk = guest::preprocess_prover_hello_world(shared);
let vk = guest::verifier_preprocessing_from_prover_hello_world(&pk);
let prove  = guest::build_prover_hello_world(program, pk);
let verify = guest::build_verifier_hello_world(vk);

let (output, proof, io) = prove();
verify(output, io.panic, proof).expect("proof verification failed");
```

## Guest

`hello/guest/src/lib.rs` declares a provable function:

```rust
#![cfg_attr(feature = "guest", no_std)]

use jolt_inlines_sha2::Sha256;

#[jolt::provable(heap_size = 32768, max_trace_length = 65536)]
fn hello_world() -> [u8; 32] {
    Sha256::digest(b"Hello, world!")
}
```

Two crates are needed for the inline (accelerated) SHA-2 instruction:

- host (`hello/Cargo.toml`): `jolt-inlines-sha2` with feature `host` — registers
  the lookup-table inlines with the prover.
- guest (`hello/guest/Cargo.toml`): `jolt-inlines-sha2` with
  `default-features = false` — emits the inline instructions from the guest.

## Notes and gotchas

- **The `host` feature on `jolt-inlines-sha2` is mandatory** in the *host*
  crate. Without it the guest builds but proving panics with
  `Expansion(UnsupportedInstruction)`.
- The ISA is **RV64IMAC** (64-bit).
- Default backend is **Dory over BN254**; the `zk` feature enables BlindFold
  zero-knowledge. `[u8; 32]` public output does not implement `Display`, so
  format it (e.g. `hex::encode`).
- Jolt is **alpha / unaudited**; on-chain verification and recursion are still
  roadmap items (https://jolt.a16zcrypto.com/roadmap/on-chain-verifier.html).
- Never `cargo install` in the project dir: `/tmp` was wiped by a reboot during
  this experiment, so use a persistent `CARGO_TARGET_DIR` for long builds.

## Artifacts (not to be committed)

`target/`, `/tmp/jolt-guest-targets/`, `/tmp/jolt-hello.proof` and
`~/.cache/dory/` are build outputs and can be deleted freely.
