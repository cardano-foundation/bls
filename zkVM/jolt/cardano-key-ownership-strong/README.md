# Jolt zkVM — CardanoKeyOwnershipStrong

This crate proves knowledge of a 96-byte Cardano master `XPrv` that derives the
payment public key at the standard CIP-1852 path `m/1852H/1815H/0H/0/0`, using
the [Jolt](https://github.com/a16z/jolt) zkVM.

It is a zkVM counterpart to the Circom implementation in
[`circom/CardanoKeyOwnershipStrong`](../../circom/CardanoKeyOwnershipStrong)
and to the OpenVM implementation in
[`openvm/cardano-key-ownership-strong`](../openvm/cardano-key-ownership-strong).

## What it proves

- **Private input:** 96-byte master extended private key (`kL ‖ kR ‖ chainCode`).
- **Public output:** 32-byte Ed25519 compressed public key `A` at the fixed path.
- **Relation:** `A` is the payment public key obtained by applying the
  BIP32-Ed25519 / CIP-1852 child-key derivation chain inside the guest.

## Algorithm

The guest performs six derivation steps exactly like the reference Circom circuit:

1. `ckd_hardened(master, 1852H)`
2. `ckd_hardened(_, 1815H)`
3. `ckd_hardened(_, 0H)`
4. `ckd_soft(_, role=0, Apub)`
5. `ckd_soft(_, index=0, Apub)`
6. Compress `[kL mod n]·G` to obtain the final payment public key.

HMAC-SHA512 is computed with the `hmac` + `sha2::Sha512` crates; Ed25519 scalar
multiplication uses `curve25519-dalek`.

## Quick start

```bash
cd zkVM/jolt/cardano-key-ownership-strong
cargo run --release
```

Expected output (host `nebula`, Ryzen 9 9950X3D, 16C/32T, 64 GB RAM):

```text
preprocessing time: 79.945s
prove time: 267.475s
proof size: 88.9 kB
verify time: 1.049s
output (hex): 63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c
fixture OK
```

The hardcoded fixture (`master = bytes(range(96))`) and expected `apk` match the
Circom circuit's golden output exactly.

## Project layout

- `guest/` — the `#[jolt::provable]` guest function.
- `src/main.rs` — host driver that compiles the guest, runs preprocessing,
  proves, verifies, and checks the fixture.

## Notes

- Jolt uses the `jolt-sdk` proc-macros to generate `compile_*`, `preprocess_*`,
  `build_prover_*`, and `build_verifier_*` functions from the `guest` crate.
- The guest takes the master key as `&[u8]` because Jolt's input serialization
  (postcard) does not implement `Serialize` for fixed arrays larger than 32 bytes.
- Proving time is dominated by the many SHA-512 hashes and the Ed25519 scalar
  multiplication performed in the guest.

## Comparison with other backends

See [`zkVM/comparison.md`](../comparison.md) for Groth16, Nova/NovaSlim,
OpenVM, and Jolt side-by-side numbers.

## License

Same as the rest of the repository.
