# OpenVM

Minimal end-to-end OpenVM run: compile a Rust guest to RISC-V, prove it, and
verify the proof. The guest computes `SHA-256("Hello, world!")` and reveals the
digest as public output.

Verified on **OpenVM v2.0.2**, CPU only (4 cores, 31 GB RAM, no GPU).

## Result

| Step | Command | Time | Notes |
|---|---|---|---|
| Build + transpile | `cargo openvm build` | ~25 s (after deps cached) | produces `openvm/release/openvm-hello.vmexe` (87 KiB) |
| Keygen (once) | `cargo openvm keygen` | ~2 min | `app.pk`, `app.vk`, `agg_prefix.pk` |
| Aggregation setup (once) | `cargo openvm setup` | ~20 min | `~/.openvm/internal_recursive.{pk,vk}` |
| Prove (app) | `cargo openvm prove app` | **657 s** | 2.6 GB peak RSS, 547 KiB proof |
| Verify (app) | `cargo openvm verify app` | **0.55 s** | 20 MB RSS |
| Prove (stark) | `cargo openvm prove stark` | ~25 min | 522 KiB proof + `baseline.json` |
| Verify (stark) | `cargo openvm verify stark` | ~1 s | |

Public output: `315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3`
= `SHA-256("Hello, world!")`, identical to the Jolt guest.

## One-time install

```bash
# CLI (builds the full prover; ~70 min on 4 cores, release profile)
cargo install --git https://github.com/openvm-org/openvm --tag v2.0.2 --locked cargo-openvm

# Aggregation/recursion keys used by `prove stark`
cargo openvm setup
```

The guest build downloads the RISC-V toolchain (`rustc 1.91.1` + target
`riscv32im-risc0-zkvm-elf`) automatically on first use; network access is
required.

## Run the example

```bash
cd zkVM/openvm/hello

cargo openvm run        # execute only (no proof), prints the guest output
cargo openvm build      # compile + transpile to .vmexe
cargo openvm keygen     # app proving/verifying keys (once per openvm.toml)
cargo openvm prove app  # STARK app proof -> openvm-hello.app.proof
cargo openvm verify app # verify the app proof
```

`prove app` proves execution and writes a continuation-style app proof. The
`stark`/`evm` subcommands produce the aggregated proof intended for
recursive/on-chain verification:

```bash
cargo openvm prove stark   # aggregated STARK proof
cargo openvm verify stark  # verifies against openvm-hello.baseline.json
```
## UPLC evaluator guest (`hello-aiken`)

`hello-aiken/src/bin/uplc.rs` runs a real Aiken `.flat` artifact inside the
zkVM using the `uplc-guest` CEK evaluator. The program and `Data` arguments
(`Data::B` only for now) are supplied at runtime instead of being hardcoded.

Run the UPLC guest on the host (fast, no proof):

```bash
cd zkVM/openvm/hello-aiken
cargo run --bin uplc -- ../../hello-world/hello_hash.flat \
  --data-bytes 48656c6c6f2c20776f726c6421
# UPLC output sha256 = 315f5bdb...
```

To run it inside the zkVM, first generate the OpenVM input JSON from the same
CLI arguments:

```bash
cd zkVM/openvm/hello-aiken
cargo run --bin uplc -- ../../hello-world/hello_hash.flat \
  --data-bytes 48656c6c6f2c20776f726c6421 \
  --write-input /tmp/uplc_input.json

cargo openvm run --bin uplc --input /tmp/uplc_input.json
```

To prove and verify (the existing `app.pk`/`app.vk` from the SHA-256
hello-world guest still work because `openvm.toml` is unchanged):

```bash
cd zkVM/openvm/hello-aiken
cargo openvm build --bin uplc
cargo openvm prove app --bin uplc --exe openvm/release/uplc.vmexe \
  --input /tmp/uplc_input.json
cargo openvm verify app --bin uplc
```

Status: ✅ end-to-end verified. Host execution, zkVM execution, `prove app`,
and `verify app` all output the same digest as `aiken uplc eval`.

## Guest

`hello/src/main.rs` is `no_std` Rust:

```rust
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

use openvm_sha2::{Digest, Sha256};
openvm::entry!(main);

pub fn main() {
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, world!");
    let digest: [u8; 32] = hasher.finalize().into();
    #[cfg(target_os = "zkvm")]
    openvm::io::reveal_bytes32(digest);
}
```

`hello/openvm.toml` selects the VM extensions used by the guest:

```toml
[app_vm_config.rv32i]
[app_vm_config.rv32m]
[app_vm_config.io]
[app_vm_config.sha2]
```

Changing `openvm.toml` changes the VM commit and therefore requires re-running
`keygen` (and `setup` if aggregation config changes).

## Notes and gotchas

- **`prove stark` requires `cargo openvm setup` first.** Without
  `~/.openvm/internal_recursive.pk` it fails with
  `Failed to read internal-recursive proving key`.
- **`prove app` needs keys.** Without `keygen` it fails with
  `reading from .../app.pk failed`.
- OpenVM 2.0 guests are **32-bit (RV32IM)**; 64-bit is only in the v2.1 preview.
- The SHA-2 extension uses the `openvm-sha2` guest crate (`openvm_sha2`), not
  the vanilla `sha2` crate, to hit the accelerated instructions.
- On-chain path: aggregate to BN254/Halo2 and verify with the generated
  Solidity verifier, or verify the STARK in a guest (`openvm-verify-stark`) —
  neither is BLS12-381, see `../../README.md`.

## Artifacts (not to be committed)

`.proof`, `.vmexe`, `.pk`/`.vk` and `target/` are build outputs; delete them
with `rm -rf target openvm* ./*.proof` when not needed.
