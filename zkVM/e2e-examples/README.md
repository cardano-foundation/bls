# VRF/KDF E2E Examples

End-to-end examples for running VRF and KDF Aiken programs on OpenVM and Jolt zkVMs.

## Artifacts

| Program | Artifact | Description |
|---------|----------|-------------|
| vrf/keys_from_secret | `../hello-world/vrf_keys_from_secret.flat` | Generate keys from secret |
| vrf/prove | `../hello-world/vrf_prove.flat` | Generate VRF proof |
| vrf/verify | `../hello-world/vrf_verify.flat` | Verify VRF proof |
| kdf/hkdf | `../hello-world/kdf_hkdf.flat` | HKDF key derivation |

## Quick start

```bash
# Run all examples
./scripts/run_vrf_kdf.sh

# Or run individually
cd ../openvm/hello-aiken
cargo run --bin uplc -- ../../hello-world/vrf_verify.flat

cd ../jolt/hello-aiken
cargo run --release --bin uplc -- ../../hello-world/kdf_hkdf.flat
```

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
