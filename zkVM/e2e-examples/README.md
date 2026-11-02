# E2E Examples

End-to-end examples for running Aiken/UPLC programs and native Cardano
proof-of-derivation guests on OpenVM and Jolt zkVMs.

## VRF/KDF

| Program | Artifact | Description |
|---------|----------|-------------|
| vrf/keys_from_secret | `../hello-world/vrf_keys_from_secret.flat` | Generate keys from secret |
| vrf/prove | `../hello-world/vrf_prove.flat` | Generate VRF proof |
| vrf/verify | `../hello-world/vrf_verify.flat` | Verify VRF proof |
| kdf/hkdf | `../hello-world/kdf_hkdf.flat` | HKDF key derivation |

```bash
./scripts/run_vrf_kdf.sh
```

## CardanoKeyOwnershipStrong

Run the BIP32-Ed25519 / CIP-1852 derivation guest on both zkVMs in host
execution mode:

```bash
./scripts/run_cardano_key_ownership_strong.sh
```

Full prove/verify commands are in the project READMEs:
[`openvm/cardano-key-ownership-strong`](../openvm/cardano-key-ownership-strong)
and [`jolt/cardano-key-ownership-strong`](../jolt/cardano-key-ownership-strong).

## Argument encoding

The zkVM input format now supports all Plutus Data types:
- `B(bytes)` - byte strings
- `I(integer)` - integers (big integers supported)
- `List([...])` - lists
- `Map([(k,v),...])` - maps
- `Constr(tag, fields)` - constructors

See `src/encoder.rs` for helper functions.

## Tests

```bash
cargo test
```

## Verus specs

Formal specifications for encoding correctness are in `src/verus_specs.rs` (enabled with `--features verus`).
