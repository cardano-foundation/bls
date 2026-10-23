# zkVM on Cardano

Run an Aiken program inside a zero-knowledge VM (OpenVM or Jolt) and verify the
resulting proof on Cardano.

**Status**:

- OpenVM and Jolt prove and verify the same `SHA-256("Hello, world!")` guest end
  to end on CPU.
- The `no_std` UPLC CEK evaluator in [`uplc-guest`](./uplc-guest/README.md)
  decodes the real `hello-world/hello_hash.flat` artifact and matches
  `aiken uplc eval`. It builds for `riscv32im-unknown-none-elf`, but is not yet
  wired into either zkVM.
- Implemented builtins: `sha2_256`, `unBData`. That covers `hello-world`, not
  real validators.

Next: run the evaluator inside both zkVM guests and measure scaling, extend the
builtin set for real Aiken programs (`aiken/kdf`, `aiken/vrf`,
`aiken/selective-disclosure`), then produce a BLS12-381 Groth16 proof for the
existing on-chain verifier.

## Quick start

```bash
# OpenVM (RV32IM, ~11 min prove on 4 cores)
cd zkVM/openvm/hello
cargo openvm run && cargo openvm build && cargo openvm keygen
cargo openvm prove app && cargo openvm verify app

# Jolt (RV64IMAC, ~12 s prove on 4 cores)
cd zkVM/jolt/hello
cargo run --release

# UPLC evaluator on the real Aiken artifact (host, no zkVM yet)
cd zkVM/uplc-guest
cargo test
cargo run --bin uplc-eval -- \
  ../hello-world/hello_hash.flat \
  --data-bytes 48656c6c6f2c20776f726c6421
```

Full instructions, one-time setup and gotchas:
[OpenVM](./openvm/README.md) - [Jolt](./jolt/README.md).

### Aiken guest integration strategies
Aiken compiles to UPLC, not RISC-V, so there are two routes:

1. **Port the logic** to a Rust guest and differential-test it against the
   Plutus VM (simplest, loses "run the actual script").
2. **Run a UPLC interpreter in the guest** on the real `.flat` artifact (keeps
   script fidelity, much more work). The `no_std` evaluator is implemented and
   differential-tested for `hello-world`, but still has to be wired into the
   OpenVM/Jolt guests and extended to the full builtin set.

### Proof generation
Make the proof cheap enough to be practical on CPU-only hardware; measure
segments, memory and proof sizes for realistic Aiken programs.

### On-chain verification
Produce a BLS12-381 Groth16 proof that the existing verifier in
[`aiken/groth16`](../aiken/groth16/README.md) can check. Both zkVMs currently
aggregate over **BN254**, so this is a wrapping step on the aggregation side,
not a guest-side change.

<details><summary><b>Why zkVM (click to expand)</b></summary>

## Why

- Off-chain execution of Aiken/UPLC logic with succinct proofs.
- On-chain verification on Cardano via the existing BLS12-381 Groth16 verifier.
- A comparison of OpenVM and Jolt as proof systems for this use case.

</details>

<details><summary><b>Design notes (click to expand)</b></summary>

## Design notes

- **One guest, two VMs.** Both run RISC-V, so the hello-world guest is the same
  SHA-256 computation in both. This keeps the comparison honest and gives a
  differential test for later phases.
- **Public output is a digest.** Both guests reveal a single 32-byte SHA-256
  digest instead of the whole trace, so the host (and later Aiken) can
  recompute and compare it.
- **BLS12-381 wrapping.** OpenVM's EVM path is Halo2 over BN254; Jolt's Dory
  backend is BN254. Neither is directly verifiable by Cardano's builtins, so
  Phase 3 wraps the inner proof in a BLS12-381 Groth16 circuit.
- **Jolt on-chain support is a roadmap item**, so OpenVM is currently the only
  one of the two with a plausible on-chain verifier path today.

</details>

<details><summary><b>Consequences of design (click to expand)</b></summary>

- Aiken is UPLC, not RISC-V: porting vs. interpreting is the central design
  choice
- BLS12-381 Groth16 wrapping of a BN254 proof is expensive
- Jolt is alpha and has no on-chain verifier or recursion yet.
- Proving is CPU-bound here; OpenVM's 658 s hello-world proof is dominated by
  fixed overhead and will not scale linearly.
- Disk is tight on the dev machine (OpenVM and Jolt builds are several GB each).

</details>

<details><summary><b>Comparison between zkVMs (click to expand)</b></summary>

## Comparison

| Aspect | OpenVM | Jolt |
|---|---|---|
| ISA | RV32IM (v2.0.2), RV64IM_Zicclsm in v2.1 | RV64IMAC |
| Proof system | STARK + Halo2 aggregation | Dory (BN254) / Akita (lattice, PQ, non-ZK) |
| ZK | yes | optional (`zk` feature, BlindFold) |
| Prove (hello world) | 658 s | 11.6 s |
| Proof size | 522-547 KiB | 68.1 kB |
| On-chain verifier | Halo2/Solidity, EVM-oriented | coming |
| Maturity | audited components, formal RV32IM verification | unaudited |
| Guest toolchain | Rust nightly + risc0 RV32 target | Rust 1.95 + RV64 target |

</details>

<details><summary><b>LAYOUT (click to expand)</b></summary>

## Layout

```
zkVM/
├── openvm/     # OpenVM CLI harness + hello world (RV32IM)
├── jolt/       # Jolt host + guest (RV64IMAC)
├── hello-world/  # the Aiken program to prove
├── uplc-guest/   # no_std UPLC CEK evaluator (hello-world subset)
└── onchain/      # BN254 -> BLS12-381 wrapping + Aiken verifier (coming)
```

</details>

<details><summary><b>Useful sources (click to expand)</b></summary>

## Sources

- OpenVM: <https://github.com/openvm-org/openvm>, <https://book.openvm.dev>
- Jolt: <https://github.com/a16z/jolt>, <https://jolt.a16zcrypto.com>
- Plutus/UPLC: <https://plutus.cardano.iot/>

</details>
