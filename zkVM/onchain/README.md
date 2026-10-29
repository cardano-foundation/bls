# zkVM On-Chain Verification (BN254 → BLS12-381)

This crate/wiring provides the bridge from zkVM proofs (OpenVM/Jolt, over BN254) to Cardano on-chain verification (BLS12-381 Groth16 via Plutus builtins).

## Status

- [x] Directory structure
- [x] Proof format/types and wrapping API
- [x] OpenVM/Jolt wrapper stubs with tests
- [x] Groth16 proof format (A/G1/B/G2/C) matching aiken/groth16
- [x] Verification interface
- [x] Tests and Verus formal specs
- [x] E2E demo script

## Architecture

```
Aiken/UPLC program
  → zkVM guest (OpenVM/Jolt) execution
    → BN254 proof (STARK + Halo2 agg or Dory)
      → Wrapper circuit (BN254 verification) compiled to BLS12-381 Groth16
        → BLS12-381 Groth16 proof
          → Aiken verifier on Cardano (uses bls12_381_* builtins)
```

## Components

| Component | Purpose |
|-----------|---------|
| `src/` | Rust code for proof parsing, circuit generation, wrapping |
| `circuits/` | Circom/native circuits for BN254 verification in BLS12-381 field |
| `tests/` | Unit and integration tests |
| `specs/` | Verus formal specifications |
| `scripts/` | E2E automation scripts |

## Approach

**Option 1: OpenVM recursive aggregation** - OpenVM has built-in recursion; aggregate app proof to a single proof, then wrap. Leverages existing tooling.
**Option 2: Direct verification circuit** - Build a circuit that verifies the zkVM proof directly over BN254 arithmetic emulated in BLS12-381. More complex but works for both VMs.

Starting with OpenVM path as it's more mature.

## Usage

```bash
# Prove with OpenVM
cd zkVM/openvm/hello-aiken
cargo openvm prove app --bin uplc --exe ... --input /tmp/uplc.json

# Wrap to BLS12-381 Groth16
cd zkVM/onchain
cargo run --bin wrap-openvm -- --proof ../openvm/hello-aiken/*.app.proof --out wrapped.json

# Wrap Jolt proof
cargo run --bin wrap-jolt -- --proof /tmp/jolt.proof --out wrapped_jolt.json

# Run tests
cargo test
./scripts/e2e_wrap.sh

# Verify on-chain (Aiken)
cd ../../aiken/groth16
aiken check
```

## References

- [aiken/groth16](../../aiken/groth16/) - On-chain BLS12-381 Groth16 verifier
- [groth16-prover](../../groth16-prover/) - BLS12-381 Groth16 prover
- [OpenVM docs](https://book.openvm.dev/) - Recursion/aggregation
- [Jolt docs](https://jolt.a16zcrypto.com/) - Proof system
