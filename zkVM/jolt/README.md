# Jolt UPLC guest

Run Aiken/UPLC programs on Jolt (RV64IMAC). Uses `#[jolt::provable]` to wrap the evaluator.

## Quick start

```bash
cd zkVM/jolt/hello-aiken

# Prove/verify end-to-end
cargo run --release --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421
```

## Native Cardano proof of wallet derivation

- [`cardano-key-ownership-strong`](cardano-key-ownership-strong) — proves
  knowledge of a 96-byte Cardano master `XPrv` that derives the payment public
  key at `m/1852H/1815H/0H/0/0` inside the Jolt guest. End-to-end proving takes
  ~4.5 minutes and produces an ~89 kB proof on the reference host.

## Examples

Same artifacts as OpenVM:
- `../../hello-world/hello_hash.flat` - baseline
- `../../hello-world/vrf_*.flat` - VRF functions
- `../../hello-world/kdf_hkdf.flat` - HKDF

Input format supports all Plutus Data types: `B`, `I`, `List`, `Map`, `Constr` (tagged).

## Notes

- Requires Rust 1.95 (Jolt toolchain)
- First build takes long; release mode with thin LTO configured
- Proving is fast vs OpenVM but proof larger than native Groth16
