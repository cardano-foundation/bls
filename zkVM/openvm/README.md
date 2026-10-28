# OpenVM UPLC guest

Run Aiken/UPLC programs on OpenVM (RV32IM). Proves real `.flat` artifacts with runtime args.

## Quick start

```bash
cd zkVM/openvm/hello-aiken

# Host execution
cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421

# Generate zkVM input
cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421 --write-input /tmp/uplc.json

# Prove/verify
cargo openvm build --bin uplc
cargo openvm keygen  # once
cargo openvm prove app --bin uplc --exe openvm/release/uplc.vmexe --input /tmp/uplc.json
cargo openvm verify app --bin uplc
```

## Examples

### hello_hash (baseline)
```bash
cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421
# output: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
```

### VRF (kdf/keys/prove/verify)
```bash
# keys_from_secret expects secret bytes as Data::B
cargo run --bin uplc -- ../../hello-world/vrf_keys_from_secret.flat --data-bytes <SECRET_HEX>

# prove/verify need specific arg encoding (see aiken/vrf tests)
# Currently only Data::B supported in zkVM input format
```

### KDF (hkdf)
```bash
cargo run --bin uplc -- ../../hello-world/kdf_hkdf.flat
```

## Notes

- Only `Data::B` args supported in input blob format
- Existing `app.pk`/`app.vk` from hello-world work if `openvm.toml` unchanged
- Full proving takes minutes on CPU; use host execution for development
