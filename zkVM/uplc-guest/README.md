# UPLC guest evaluator

A minimal `no_std` UPLC CEK evaluator intended for RISC-V zkVM guests. It decodes
real Aiken `.flat` artifacts (raw or CBOR-wrapped) and evaluates them without
`std`, C dependencies or host syscalls. Builds for
`riscv32im-unknown-none-elf` with `--no-default-features`.

**Status**: evaluates the committed `../hello-world/hello_hash.flat` artifact and
matches the Aiken CLI output. Builtins currently implemented:
- Hashes: `sha2_256`
- Data: `unBData`
- Bytearray: `appendByteString`, `sliceByteString`, `lengthOfByteString`,
  `indexByteString`, `equalsByteString`, `lessThanByteString`,
  `lessThanEqualsByteString`
- Integer: `addInteger`, `subtractInteger`, `multiplyInteger`, `divideInteger`,
  `quotientInteger`, `remainderInteger`, `modInteger`, `equalsInteger`,
  `lessThanInteger`, `lessThanEqualsInteger`

Other builtins are decoded but return `UnsupportedBuiltin` when executed. The
next step is more hash algorithms (`sha3_256`, `blake2b_256`, `keccak_256`) and
Data constructors / destructors.

## Layout

| File | Purpose |
|---|---|
| `src/flat.rs` | Flat decoder: terms, constants, Plutus Data CBOR, CBOR-wrapped flat |
| `src/machine.rs` | CEK machine: environments, continuations, builtins |
| `src/term.rs` | Terms, constants, builtin tags, hex helpers |
| `src/data.rs` | Plutus `Data` and minimal CBOR decoder |
| `src/bin/uplc_eval.rs` | Host CLI |
| `tests/differential.rs` | Compares our output with `aiken uplc eval` |

## Evaluate the hello-world artifact

```bash
cd zkVM/uplc-guest

# hello_hash expects a Plutus Data bytestring argument
cargo run --bin uplc-eval -- \
  ../hello-world/hello_hash.flat \
  --data-bytes 48656c6c6f2c20776f726c6421
# 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
```

## Differential test

```bash
cargo test
```

`hello_hash_matches_aiken` runs `aiken uplc eval` on the equivalent textual
program and asserts that both produce the same digest. If `aiken` is not on
`PATH`, the test skips the comparison and only checks the known digest.

## Guest build check

```bash
cargo build --no-default-features --target riscv32im-unknown-none-elf
```

## Notes and limitations

- De Bruijn indices are 1-based, matching the Plutus/UPLC flat encoding.
- Constants support integers (arbitrary precision), bytestrings, strings, bools,
  unit, `Data`, lists, arrays and pairs. BLS and ledger-value constants are not
  decoded yet.
- The current builtin set is intentionally small. Extending it is required
  before running non-trivial Aiken validators (see the parent README).
- Evaluation does not charge or enforce an `ExBudget` yet.
