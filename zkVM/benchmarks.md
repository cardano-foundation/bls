# Benchmarks & Trade-offs

## zkVM vs Cardano-native approaches

| Metric | Groth16 (aiken/groth16) | Nova IVC (aiken/nova/upstream nova-slim) | OpenVM (this repo) | Jolt (this repo) |
|--------|-------------------------|------------------------------------------|-------------------|-----------------|
| Setup | Per-circuit trusted setup | Transparent or compression setup | VM keys (once per VM config) | VM preprocessing (per program) |
| Proof size | ~192 bytes | ~0.4-1.5 KB | 522-658 KB → 192 B (wrapped) | ~68 KB → 192 B (wrapped) |
| Prove time (CPU) | Varies by circuit | Fold+compress varies | ~11 min (hello_hash) | ~12-24 s (hello_hash) |
| Verify time (on-chain) | 1 pairing (BLS12-381) | Sumcheck/pairing depending on variant | Wrap + 1 pairing (BLS12-381) | Wrap + 1 pairing (BLS12-381) |
| Program flexibility | Fixed circuit only | Step-circuit IVC | Any UPLC/Aiken program | Any UPLC/Aiken program |
| On-chain ready | Yes (BLS12-381 builtins) | Yes (sumcheck verifier in aiken/nova) | No (BN254 aggregation) | No (BN254) |

## hello_hash baseline

From READMEs (measured on 4-core CPU):

| Step | OpenVM | Jolt |
|------|--------|------|
| Build/preprocess | ~25s + keygen/setup | ~20min first build, ~6s preprocess |
| Prove | 657s (app), ~25min (stark/agg) | 11.6s |
| Verify | 0.55s | 0.66s |
| Proof size | 547 KiB (app), 522 KiB (agg) | 68.1 KiB |

## UPLC guest performance (host)

| Artifact | eval time | notes |
|----------|-----------|-------|
| hello_hash | ~0.01s | simple sha2 |
| vrf_verify | ~0.025s | BLS12-381 pairing ops |
| vrf_keys_from_secret | <0.01s | BLS hash-to-group |
| kdf_hkdf | <0.01s | hash builtins |

## Bringing zkVMs to Cardano

What was needed:

1. **UPLC evaluator in no_std** - CEK machine with full builtin support (hashes, Data CBOR, BLS12-381). Most complex part: BLS12-381 arithmetic using `bls12_381` crate, constant decoding, CBOR indefinite length.
2. **VM guests** - OpenVM and Jolt harnesses reading flat+args, returning digest as public output.
3. **Input encoding** - Custom blob format for passing program+args to zkVM.
4. **Aiken integration** - `aiken export` produces compiledCode; evaluator must match Plutus semantics (tested via differential tests).
5. **On-chain bridging** - Both VMs use BN254 internally; Cardano needs BLS12-381 Groth16. Wrapping framework added in `zkVM/onchain/` with tests, Verus specs, and e2e script. Full circuit implementation in progress.

## Comparison to upstream nova-slim

| Aspect | In-tree nova-prover (this repo) | Upstream nova-slim |
|--------|-------------------------------|-------------------|
| Location | `nova-prover/`, `clis/nova/`, `aiken/nova/` | `../nova-slim/` (separate repo) |
| Default | Impl 9 (Groth16 compressed) | Transparent sumcheck/slim |
| Proof size | ~580 KiB (Impl 9) or varies | ~0.4 KiB (slim) |
| Setup | Compression circuit trusted setup (Impl 9) | None (transparent) |
| Focus | Integrated with Cardano Aiken verifiers | Modular, multi-curve, active development |
| Status | Snapshot for e2e scripts | Cutting-edge upstream |

Use nova-slim for new Nova work; in-tree is pinned for existing e2e compatibility.
