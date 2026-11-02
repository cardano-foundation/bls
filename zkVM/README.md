# zkVM on Cardano

Run Aiken/UPLC programs in OpenVM or Jolt zkVMs and prove them. Compare with native Groth16/Nova on Cardano.

## Featured use case — CardanoKeyOwnershipStrong

Prove knowledge of a 96-byte Cardano master `XPrv` that derives the payment
public key at `m/1852H/1815H/0H/0/0` — the full BIP32-Ed25519 / CIP-1852
derivation chain — inside a zkVM.

```bash
# OpenVM (RV32IM) — easiest to build, larger app proof
cd zkVM/openvm/cardano-key-ownership-strong
cargo run                              # host execution (<1 s)
cargo openvm build
cargo openvm keygen
cargo openvm prove app --input /tmp/strong_master.json   # ~21 min, 702 KiB

# Jolt (RV64IMAC) — fastest zkVM proof today
cd zkVM/jolt/cardano-key-ownership-strong
cargo run --release                    # ~4.5 min end-to-end, 89 KiB proof
```

Both produce the same public key as the reference Circom circuit:
`63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c`.
See [`comparison.md`](comparison.md) for Groth16, Nova/NovaSlim, OpenVM, and
Jolt side-by-side numbers.

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
| [OpenVM](openvm/README.md) | RV32IM | STARK+Halo2 (BN254) | 522-658 KiB app | Possible via BN254→BLS12-381 wrap | Verified |
| [Jolt](jolt/README.md) | RV64IMAC | Dory (BN254) | ~89 KiB for `strong` | Possible via BN254→BLS12-381 wrap | Verified |

Both VMs run the same [`CardanoKeyOwnershipStrong`](../circom/CardanoKeyOwnershipStrong)
derivation in Rust — see [`openvm/cardano-key-ownership-strong`](openvm/cardano-key-ownership-strong)
and [`jolt/cardano-key-ownership-strong`](jolt/cardano-key-ownership-strong).

## Aiken programs supported

The `uplc-guest` evaluator runs real `.flat` artifacts with full builtin support (hashes, Data, BLS12-381, etc.). Both OpenVM and Jolt guests support all Plutus Data argument types (`B`, `I`, `List`, `Map`, `Constr`).

| Program | Module | Flat artifact | Notes |
|---------|--------|---------------|-------|
| hello_hash | hello-world/ | `hello-world/hello_hash.flat` | Baseline test |
| vrf | aiken/vrf | `hello-world/vrf_verify.flat`, `vrf_keys_from_secret.flat`, `vrf_prove.flat` | BLS12-381 VRF |
| kdf | aiken/kdf | `hello-world/kdf_hkdf.flat` | HKDF/PBKDF2 |

## Comparison

See [`comparison.md`](comparison.md) for Groth16, Nova/NovaSlim, OpenVM, and
Jolt side-by-side numbers. In short: zkVMs trade proof size for programmability
(no hand-written circuits), and still need a BN254→BLS12-381 wrap for native
Cardano verification.

## Layout

```
zkVM/
├── openvm/                       # OpenVM harness
│   └── cardano-key-ownership-strong/  # full CIP-1852 derivation in OpenVM
├── jolt/                         # Jolt harness
│   └── cardano-key-ownership-strong/  # full CIP-1852 derivation in Jolt
├── hello-world/                  # Test artifacts
├── uplc-guest/                   # no_std UPLC evaluator
├── onchain/                      # BN254→BLS12-381 wrapping to BLS12-381 Groth16 for Cardano
├── tools/                        # Helper tools (artifact generation)
├── e2e-examples/                 # VRF/KDF e2e examples for OpenVM and Jolt
├── comparison.md                 # Groth16 vs NovaSlim vs zkVM comparison
└── ci/                           # CI scripts and Makefile
```

## References

- [OpenVM](https://github.com/openvm-org/openvm) | [Jolt](https://github.com/a16z/jolt) | [Plutus/UPLC](https://plutus.cardano.intersectmbo.org/)
- [Cardano Groth16](../aiken/groth16/) | [Nova](../aiken/nova/) | [nova-slim](https://github.com/paweljakubas/nova-slim)
