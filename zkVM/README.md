# zkVM on Cardano

Run an Aiken program inside a zero-knowledge VM (OpenVM or Jolt) and verify the
resulting proof on Cardano.

Phase 0 (baselines) is complete: both zkVMs prove and verify the same
`SHA-256("Hello, world!")` hello-world program end to end on CPU.

## Quick start

```bash
# OpenVM (RV32IM, ~11 min prove on 4 cores)
cd zkVM/openvm/hello
cargo openvm run && cargo openvm build && cargo openvm keygen
cargo openvm prove app && cargo openvm verify app

# Jolt (RV64IMAC, ~12 s prove on 4 cores)
cd zkVM/jolt/hello
cargo run --release
```

Full instructions, one-time setup and gotchas:
[OpenVM](./openvm/README.md) - [Jolt](./jolt/README.md).

## Phase 0 results

Same guest output for both VMs:
`315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3`
(`SHA-256("Hello, world!")`).

| | OpenVM v2.0.2 | Jolt 0.1.0 (`main`) |
|---|---|---|
| ISA | RV32IM | RV64IMAC |
| Prove | 658 s | **11.6 s** |
| Verify | 0.55 s | 0.66 s |
| Proof size | 547 KiB (app) / 522 KiB (stark) | **68.1 kB** |
| Peak RAM (prover) | 2.6 GB | - |
| One-time cost | 70 min CLI build, ~20 min setup | 20 min host build, ~6 s preprocessing |

Machine: 4 cores, 31 GB RAM, no GPU, CPU backend for both.

<details><summary><b>PLAN (click to expand)</b></summary>

## Plan

### Phase 0: Baselines (done)
Run a hello-world program end to end in both zkVMs, prove and verify on CPU, and
document the simplest possible run instructions plus metrics.

- [x] OpenVM: install CLI, run hello world e2e, record metrics
- [x] Jolt: install CLI, run hello world e2e, record metrics
- [x] Top-level quick start and results

### Phase 1: Aiken guest integration
Aiken compiles to UPLC, not RISC-V, so there are two routes:

1. **Port the logic** to a Rust guest and differential-test it against the
   Plutus VM (simplest, loses "run the actual script").
2. **Run a UPLC interpreter in the guest** on the real `.plc` artifact (keeps
   script fidelity, much more work).

### Phase 2: Proof generation
Make the proof cheap enough to be practical on CPU-only hardware; measure
segments, memory and proof sizes for realistic Aiken programs.

### Phase 3: On-chain verification
Produce a BLS12-381 Groth16 proof that the existing verifier in
[`aiken/groth16`](../aiken/groth16/README.md) can check. Both zkVMs currently
aggregate over **BN254**, so this is a wrapping step on the aggregation side,
not a guest-side change.

### Phase 4: Hardening
Real programs (`aiken/kdf`, `aiken/vrf`, `aiken/selective-disclosure`),
recursion/aggregation as feasible, and a differential-test harness.

</details>

<details><summary><b>WHY ZKVM (click to expand)</b></summary>

## Why

- Off-chain execution of Aiken/UPLC logic with succinct proofs.
- On-chain verification on Cardano via the existing BLS12-381 Groth16 verifier.
- A comparison of OpenVM and Jolt as proof systems for this use case.

</details>

<details><summary><b>DESIGN NOTES (click to expand)</b></summary>

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

<details><summary><b>COMPARISON (click to expand)</b></summary>

## Comparison

| Aspect | OpenVM | Jolt |
|---|---|---|
| ISA | RV32IM (v2.0.2), RV64IM_Zicclsm in v2.1 | RV64IMAC |
| Proof system | STARK + Halo2 aggregation | Dory (BN254) / Akita (lattice, PQ, non-ZK) |
| ZK | yes | optional (`zk` feature, BlindFold) |
| Prove (hello world) | 658 s | 11.6 s |
| Proof size | 522-547 KiB | 68.1 kB |
| On-chain verifier | Halo2/Solidity, EVM-oriented | roadmap |
| Maturity | audited components, formal RV32IM verification | alpha, unaudited |
| Guest toolchain | Rust nightly + risc0 RV32 target | Rust 1.95 + RV64 target |

</details>

<details><summary><b>LAYOUT (click to expand)</b></summary>

## Layout

```
zkVM/
├── openvm/     # OpenVM CLI harness + hello world (RV32IM)
├── jolt/       # Jolt host + guest (RV64IMAC)
├── hello-world/  # planned: the Aiken program to prove
├── uplc-guest/   # planned: UPLC interpreter guest
└── onchain/      # planned: BN254 -> BLS12-381 wrapping + Aiken verifier
```

</details>

<details><summary><b>RISKS (click to expand)</b></summary>

## Open questions and risks

- Aiken is UPLC, not RISC-V: porting vs. interpreting is the central design
  choice of Phase 1.
- BLS12-381 Groth16 wrapping of a BN254 proof is expensive and is the main
  unknown of Phase 3.
- Jolt is alpha and has no on-chain verifier or recursion yet.
- Proving is CPU-bound here; OpenVM's 658 s hello-world proof is dominated by
  fixed overhead and will not scale linearly.
- Disk is tight on the dev machine (OpenVM and Jolt builds are several GB each).

</details>

<details><summary><b>SOURCES (click to expand)</b></summary>

## Sources

- OpenVM: <https://github.com/openvm-org/openvm>, <https://book.openvm.dev>
- Jolt: <https://github.com/a16z/jolt>, <https://jolt.a16zcrypto.com>
- Plutus/UPLC: <https://plutus.cardano.iot/>

</details>

## Phase 1: Aiken differential testing

- [x] Created `zkVM/hello-world/` — an Aiken library exporting `hello_hash(msg: ByteArray) -> ByteArray` (`sha2_256`), with a test matching `SHA-256("Hello, world!") = 315f5bdb...94edd3`.
- [x] Confirmed the same hash value on-chain/off-chain via Aiken stdlib and in both zkVM guests (Phase 0).
- Exported UPLC artifact via `aiken export` for potential guest-side evaluation; next step: run the real UPLC program inside OpenVM/Jolt (or a UPLC interpreter guest) and prove the same digest.
