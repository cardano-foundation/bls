# zkVM on Cardano

Run Aiken/UPLC programs in OpenVM or Jolt zkVMs and prove them. Compare with native Groth16/Nova on Cardano.

## Quick start

```bash
# OpenVM (RV32IM) - hello world
cd zkVM/openvm/hello && cargo openvm run && cargo openvm prove app && cargo openvm verify app

# Jolt (RV64IMAC) - hello world  
cd zkVM/jolt/hello && cargo run --release

# UPLC guest with real Aiken artifact
cd zkVM/uplc-guest && cargo test
cd zkVM/openvm/hello-aiken && cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421
```

## VMs

| VM | ISA | Prover | Proof | On-chain | Status |
|---|---|---|---|---|---|
| [OpenVM](openvm/README.md) | RV32IM | STARK+Halo2 (BN254) | 522-658 KiB | Possible via BN254→BLS12-381 wrap | Verified |
| [Jolt](jolt/README.md) | RV64IMAC | Dory (BN254) | 68 KiB | Possible via BN254→BLS12-381 wrap | Verified |

## Aiken programs supported

The `uplc-guest` evaluator runs real `.flat` artifacts with full builtin support (hashes, Data, BLS12-381, etc.).

| Program | Module | Flat artifact | Notes |
|---------|--------|---------------|-------|
| hello_hash | hello-world/ | `hello-world/hello_hash.flat` | Baseline test |
| vrf | aiken/vrf | `hello-world/vrf_verify.flat`, `vrf_keys_from_secret.flat`, `vrf_prove.flat` | BLS12-381 VRF |
| kdf | aiken/kdf | `hello-world/kdf_hkdf.flat` | HKDF/PBKDF2 |

## Comparison to Cardano-native approaches

| Approach | Setup | Proof size | Verify cost | Notes |
|----------|-------|-----------|-------------|-------|
| Groth16 (aiken/groth16) | Per-circuit trusted setup | ~192 bytes | 1 pairing | Cheapest on-chain, fixed circuit |
| Nova IVC (aiken/nova, upstream nova-slim) | Transparent or compression setup | ~0.4-1.5 KB | Sumcheck/pairing | Fold many steps, composable |
| zkVM (OpenVM/Jolt) | VM keys (per config) | 68-658 KB | Expensive (wrap needed) | Run arbitrary Aiken code without circuit writing |

**Trade-off:** zkVMs give programmability (run any UPLC program) at the cost of larger proofs and need BN254→BLS12-381 wrapping for Cardano verification. Native Groth16/Nova are smaller but require circuit design.

## Layout

```
zkVM/
├── openvm/       # OpenVM harness
├── jolt/         # Jolt harness  
├── hello-world/  # Test artifacts
├── uplc-guest/   # no_std UPLC evaluator
├── onchain/      # BN254→BLS12-381 wrapping to BLS12-381 Groth16 for Cardano
└── tools/        # Helper tools (artifact generation)
```

## References

- [OpenVM](https://github.com/openvm-org/openvm) | [Jolt](https://github.com/a16z/jolt) | [Plutus/UPLC](https://plutus.cardano.intersectmbo.org/)
- [Cardano Groth16](../aiken/groth16/) | [Nova](../aiken/nova/) | [nova-slim](https://github.com/paweljakubas/nova-slim)
