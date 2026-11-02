# OpenVM zkVM — CardanoKeyOwnershipStrong

This crate proves knowledge of a 96-byte Cardano master `XPrv` that derives the
payment public key at the standard CIP-1852 path `m/1852H/1815H/0H/0/0`.

It is a zkVM counterpart to the Circom implementation in
[`circom/CardanoKeyOwnershipStrong`](../../circom/CardanoKeyOwnershipStrong).

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

HMAC-SHA512 is computed with the `hmac` + `openvm-sha2::Sha512` crates;
Ed25519 scalar multiplication uses `curve25519-dalek`.

## Quick start

### Host execution (development / test vector check)

```bash
cd zkVM/openvm/cardano-key-ownership-strong
cargo run
# expected output:
# derived apk: 63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c
# fixture OK
```

The hardcoded fixture (`master = bytes(range(96))`) and expected `apk` match the
Circom circuit's golden output exactly.

### zkVM proving

```bash
cd zkVM/openvm/cardano-key-ownership-strong

# 1. Build the zkVM executable
cargo openvm build

# 2. Keygen (once)
cargo openvm keygen

# 3. Prepare input: 96-byte master XPrv as a hex string
echo '"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"' > /tmp/strong_master.json

# 4. Prove
cargo openvm prove app --input /tmp/strong_master.json

# 5. Verify
cargo openvm verify app
```

> **Note:** full proving is CPU-only in this configuration and can take several
> minutes. Use host execution for development.

## Input format

`openvm::io::read_vec()` expects the 96-byte master key as a plain byte vector.
When using the OpenVM CLI, wrap the hex string as a JSON string.

## Output

`openvm::io::reveal_bytes32(apk)` commits the final 32-byte compressed Ed25519
public key as the public output of the proof.

## Comparison with the Circom path

| Property | Circom + Nova | OpenVM zkVM |
|---|---|---|
| Backend | R1CS folding (Nova / NovaSlim) | OpenVM (RV32IM) |
| Trust setup | Transparent | Transparent |
| Prover work | Heavy folding (~5.2 h single-core on `pure`) | zkVM cycle count (TBD) |
| Proof size | Nova ~179 KB; NovaSlim ~0.4–42 KiB | App proof (OpenVM) |
| Verifier | Custom Nova verifier / Aiken (NovaSlim) | OpenVM verifier |
| Statement flexibility | Fixed R1CS | General Rust code |

See [`zkVM/comparison.md`](../comparison.md) for a comparison that also includes
Groth16 and NovaSlim.

## License

Same as the rest of the repository.
