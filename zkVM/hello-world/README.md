# Aiken hello world

Simple program computing `sha2_256("Hello, world!")` to differential-test
against OpenVM and Jolt guests.

## Expected results

Same output for both VMs and for the UPLC evaluator:
`315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3`
(`SHA-256("Hello, world!")`).

## Artifacts

- `hello_hash.flat` — the real compiled script, CBOR-wrapped flat:
  `(program 1.1.0 (lam i_0 [ (builtin sha2_256) [ (builtin unBData) i_0 ] ]))`.
- `hello_hash_direct.uplc` — textual variant that applies the bytestring
  directly, without `unBData`.

## Differential check against the real artifact

```bash
cd ../uplc-guest
cargo test
cargo run --bin uplc-eval -- \
  ../hello-world/hello_hash.flat \
  --data-bytes 48656c6c6f2c20776f726c6421
```

The `.flat` script expects a Plutus `Data` bytestring argument. The evaluator
produces the same digest as `aiken uplc eval` on the equivalent applied program.
