# UPLC guest evaluator

no_std CEK evaluator for running Aiken `.flat` artifacts in RISC-V zkVMs.

## Builtins supported

| Category | Builtins |
|----------|----------|
| Hash | sha2_256, sha3_256, blake2b_256, blake2b_224, keccak_256 |
| Data | bData, iData, listData, mapData, constrData, unBData, unIData, unListData, unMapData, unConstrData, equalsData, serialiseData, chooseData |
| ByteString | append, slice, length, index, equals, lessThan, lessThanEquals, replicateByte, xorByteString, integerToByteString |
| Integer | add, subtract, multiply, divide, quotient, remainder, mod, equals, lessThan, lessThanEquals |
| BLS12-381 G1/G2 | add, neg, scalarMul, equal, compress, uncompress, hashToGroup, multiScalarMul |
| BLS12-381 Pairing | millerLoop, mulMlResult, finalVerify |

## Quick start

```bash
cd zkVM/uplc-guest
cargo test                    # all tests
cargo run --bin uplc-eval -- ../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c869345bfc94c75894edd3  # example
```

## Run on zkVMs

**OpenVM:**
```bash
cd zkVM/openvm/hello-aiken
cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421
cargo run --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421 --write-input /tmp/in.json
cargo openvm run --bin uplc --input /tmp/in.json
```

**Jolt:**
```bash
cd zkVM/jolt/hello-aiken
cargo run --release --bin uplc -- ../../hello-world/hello_hash.flat --data-bytes 48656c6c6f2c20776f726c6421
```

## Files

| File | Purpose |
|------|---------|
| `src/flat.rs` | Flat decoder (terms, constants, Data CBOR) |
| `src/machine.rs` | CEK machine + builtins |
| `src/term.rs` | Terms/constants/builtin tags |
| `src/data.rs` | Plutus Data + CBOR encode/decode |
| `tests/differential.rs` | Compare vs `aiken uplc eval` |

## Notes

- De Bruijn indices are 1-based (Plutus/UPLC flat format)
- `no_std` compatible for RISC-V guests (`--no-default-features`)
- Evaluation has no budget metering yet (not implemented)
