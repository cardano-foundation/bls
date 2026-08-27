# NovaSlim On-Chain Verifier (Aiken)

An Aiken eUTXO validator for verifying NovaSlim slim proofs on Cardano.

> **Note:** NovaSlim is a Rust-based folding proof system that produces
> sub-kilobyte transparent proofs with no trusted setup.  The project will be
> publicly available at `https://github.com/paweljakubas/nova-slim`.

## What this verifier does

This validator checks a **slim proof** — the sumcheck protocol only, with no
commitment openings.  It is **commitment-scheme agnostic**: the same on-chain
verifier works for all three NovaSlim commitment schemes (Pedersen, SIS, Hash)
because the on-chain check is purely the sumcheck protocol.  The commitment
binding is verified off-chain by auditors who check the HashPC truth tables
against the commitment hashes stored in the datum.

## Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  NovaSlim   │      │   Aiken Validator │      │  Cardano Chain  │
│   (Rust)    │─────▶│  (this project)   │─────▶│  (eUTXO script) │
│             │      │                   │      │                 │
│ Fold +      │      │  • Sumcheck verify│      │  • Verify slim  │
│ Compress    │      │  • Fiat-Shamir    │      │    proof        │
│             │      │  • Final eval     │      │  • No openings  │
└─────────────┘      └──────────────────┘      └─────────────────┘
```

## Prerequisites

- [Aiken](https://aiken-lang.org) v1.1.21 or later
- A Cardano node or wallet for deployment (e.g., `cardano-cli`, `demeter.run`)

## Quick start

```bash
# Clone the verifier
git clone https://github.com/paweljakubas/nova-slim.git
cd nova-slim

# Type-check and run tests
aiken check

# Build the validator (produces a Plutus blueprint)
aiken build
```

## Validator API

The validator is parameterised by the **expected public input** (applied at
compile time or via `aiken apply`):

```aiken
validator(expected_public_input: ByteArray) {
  fn nova_slim_verify(
    datum: NifsBundle,      // folded instance commitments
    redeemer: SlimProof,     // the slim proof
    _context: ScriptContext,
  ) {
    // succeeds iff sumcheck protocol accepts
  }
}
```

### Datum (`NifsBundle`)

| Field | Type | Description |
|---|---|---|
| `com_w_hash` | `ByteArray` | BLAKE2b-512 hash of witness commitment |
| `com_e_hash` | `ByteArray` | BLAKE2b-512 hash of error commitment |
| `transcript_hash` | `ByteArray` | Fiat-Shamir transcript hash from folding |

### Redeemer (`SlimProof`)

| Field | Type | Description |
|---|---|---|
| `rounds` | `List<RoundPoly>` | Sumcheck round polynomials (degree-2) |
| `challenges` | `List<Scalar>` | Fiat-Shamir challenges r₁…rₖ |
| `az_r` | `Scalar` | Claimed A·Z evaluation at r |
| `bz_r` | `Scalar` | Claimed B·Z evaluation at r |
| `cz_r` | `Scalar` | Claimed C·Z evaluation at r |
| `er_r` | `Scalar` | Claimed error E evaluation at r |
| `public_input` | `ByteArray` | Public input x |
| `u` | `Scalar` | Slack scalar (usually 1) |

## How it works

1. **Round verification**: For each round *i*, check that
   `hᵢ(0) + hᵢ(1) == hᵢ₋₁(rᵢ₋₁)`.

2. **Fiat-Shamir**: Re-derive challenges from the NIFS bundle and round
   polynomials using BLAKE2b-256, and verify they match the proof.

3. **Final evaluation**: Check that
   `azᵣ · bzᵣ - u · czᵣ - eᵣ == hₖ(rₖ)`.

All arithmetic is performed in the **BLS12-381 scalar field** (`Fr`), which
Plutus V3 supports natively.

## Supported curves and commitments

This verifier is **field-agnostic at the type level** — it operates on
`bls12_381/scalar.Scalar` values.  In practice, it is designed for the
BLS12-381 curve (Cardano's native curve).  The same verifier works for slim
proofs produced with any of NovaSlim's three commitment schemes:

| Commitment | On-chain verifier | Off-chain audit |
|---|---|---|
| Pedersen | ✅ Sumcheck only | Pedersen opening check |
| SIS | ✅ Sumcheck only | SIS opening check |
| Hash | ✅ Sumcheck only | Hash opening check |

## End-to-end test

Run the built-in tests:

```bash
aiken check
```

Expected output:
```
  Compiling paweljakubas/nova-slim
   Collecting all tests scenarios across all modules
{
  "summary": {
    "total": 3,
    "passed": 3,
    "failed": 0
  }
}
```

## Deployment

1. Build the validator:
```bash
aiken build
```

2. The blueprint is written to `plutus.json`.  Apply the parameter
   (`expected_public_input`) using `aiken apply`:
```bash
aiken apply plutus.json \
  --parameter-bytes "<hex-encoded public input>" \
  > validator.uplc
```

3. Submit the UPLC to the Cardano chain via `cardano-cli` or your preferred
   wallet integration.

## Integration with NovaSlim

The Rust prover (`nova-slim`) outputs a slim proof as a CBOR-encoded byte
array.  Convert it to the Aiken `SlimProof` type before submitting:

```rust
// In your Rust off-chain code
let slim_proof_bytes = nova_slim_prover.generate_slim_proof(...);
// Serialize to Aiken's expected format (CBOR map)
```

A helper script for this conversion will be provided in the NovaSlim CLI
(`nova-slim export --format aiken`).

## Project structure

```
.
├── aiken.toml              # Project manifest
├── lib/
│   ├── verifier.ak         # Core sumcheck verification library
│   └── tests.ak            # Unit and e2e tests
├── validators/
│   └── nova_slim.ak        # On-chain validator script
└── README.md               # This file
```

## License

Apache-2.0

## See also

- **NovaSlim prover** (Rust): `https://github.com/paweljakubas/nova-slim`
- **Aiken language**: `https://aiken-lang.org`
- **Cardano eUTXO model**: `https://docs.cardano.org`
