# Jolt UPLC guest

Run Aiken/UPLC programs on Jolt (RV64IMAC). Uses `#[jolt::provable]` to wrap the evaluator.

## Quick start

```bash
cd zkVM/jolt/hello-aiken

# Prove/verify end-to-end
cargo run --release --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421
```

## Examples

Same artifacts as OpenVM:
- `../../hello-world/hello_hash.flat` - baseline
- `../../hello-world/vrf_*.flat` - VRF functions
- `../../hello-world/kdf_hkdf.flat` - HKDF

Only `Data::B` args supported.

## Notes

- Requires Rust 1.95 (Jolt toolchain)
- First build takes long; release mode with thin LTO configured
- Proving is fast vs OpenVM but proof larger than native Groth16
