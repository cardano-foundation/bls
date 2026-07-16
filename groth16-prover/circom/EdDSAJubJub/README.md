# EdDSA-JubJub Verifier Circuit

Groth16-provable EdDSA signature verification over the **JubJub** curve
embedded in BLS12-381's scalar field. Proves knowledge of a secret key
whose deterministic EdDSA-JubJub signature is valid — without revealing
the key.

## What it proves

```
I know sk  such that:
  1. R  = [r]·G         where r = Poseidon(sk, msg) mod l   (deterministic nonce)
  2. [S]·G = R + [k]·pk where k = PoseidonT6(R, pk, msg) mod l
```

Knowledge of `pk = [sk]·G` is implicit: the challenge `k` binds `pk`,
and the verification equation requires knowing `sk` for that `pk`.

### Signals

| Direction  | Name | Description |
|------------|------|-------------|
| **Public** | `Ru`, `Rv` | R point (nonce commitment) |
| **Public** | `pku`, `pkv` | Public key on JubJub |
| **Public** | `msg` | Message hash |
| **Public** | `S` | Signature scalar |
| **Private** | `sk` | Secret key in [1, l) |

**Circuit size:** 12 601 wires, 12 600 constraints.

## Circuit architecture

The top-level template `EdDSAVerifyJubJub` (`eddsa_jubjub.circom`) performs
seven steps:

| Step | What | Component |
|------|------|-----------|
| 1 | `r = Poseidon(sk, msg) mod l` | `PoseidonBLS12_381` + `ModuloL` |
| 2 | `R' = [r]·G`, verify `R' == R` | `Num2Bits` + `EscalarMulFixJubJub(254)` |
| 3 | `k = PoseidonT6(R, pk, msg) mod l` | `PoseidonBLS12_381_T6` + `ModuloL` |
| 4 | `lhs = [S]·G` | `Num2Bits` + `EscalarMulFixJubJub(254)` |
| 5 | `rhs_point = [k]·pk` | `Num2Bits` + `EscalarMulAnyJubJub(254)` |
| 6 | `R + [k]·pk` | `JubJubAdd` |
| 7 | `lhs == R + [k]·pk` | equality constraints |

### ModuloL template

Reduces a BLS12-381 field element `in` modulo the JubJub subgroup order
`l = 6554484396890773809930967563523245729705921265872317281365359162392183254199`.

Since `p ≈ 8·l` (cofactor 8), the quotient `q = in / l` is in [0, 7].
The template computes `out = in % l` via modular inverse, then range-checks
`q` by decomposing it into 3 bits: `q = b₀ + 2·b₁ + 4·b₂` with each bit
constrained to {0, 1}. The "wrong" reduction attack (picking a quotient
≥ 8) is prevented by the surrounding circuit — for nonce, `R' = [r]·G`
must equal the public `R`; for challenge, `[S]·G` must equal `R + [k]·pk`.

### Poseidon hashes

Two Poseidon instances are used:

| Instance | Width (t) | Alpha | Inputs | Output | Purpose |
|----------|-----------|-------|--------|--------|---------|
| `PoseidonBLS12_381` | 3 | 5 | `sk`, `msg` | `r` | Deterministic nonce |
| `PoseidonBLS12_381_T6` | 6 | 5 | `Ru`, `Rv`, `pku`, `pkv`, `msg` | `k` | Challenge hash |

Constants are generated with `generate_parameters_grain.sage` and
inlined directly into the `.circom` templates (see `poseidon_bls12_381.circom`
and `poseidon_bls12_381_t6.circom`).

### Component files

| File | Role |
|------|------|
| `eddsa_jubjub.circom` | Top-level EdDSA verifier + `ModuloL` |
| `jubjub_primitives.circom` | Edwards point add/double + Montgomery form ops |
| `jubjub.circom` | `JubJubPbk` (public key derivation) |
| `escalarmulfix_jubjub.circom` | Fixed-base scalar multiplication (windowed, Montgomery ladder) |
| `scalarmul_jubjub.circom` | Variable-base scalar multiplication (segmented Montgomery ladder) |
| `pointbits_jubjub.circom` | Point compression / decompression (zkcrypto encoding) |

## End-to-end pipeline

### 0. Prerequisites

```bash
# circom compiler (v2.2.3)
cargo install circom          # or build from source

# snarkjs for witness generation
npm install -g snarkjs

# Rust Groth16 prover
cargo build --release -p groth16-prover
# binary: target/release/groth16-prover
```

### 1. Compile

```bash
cd groth16-prover/circom/EdDSAJubJub

circom eddsa_jubjub.circom \
  --r1cs --wasm --sym \
  --prime bls12381 \
  -o eddsa_out

# Produces:
#   eddsa_out/eddsa_jubjub.r1cs   — constraint system (12 601 wires)
#   eddsa_out/eddsa_jubjub_js/eddsa_jubjub.wasm
#   eddsa_out/eddsa_jubjub.sym
```

> **Important:** Always pass `--prime bls12381`. Without it, circom
> defaults to BN254 which mismatches the Rust prover's curve.

### 2. Prepare input

The `input.json` file must contain **string** values (not JSON numbers)
to avoid JavaScript floating-point truncation of BLS12-381 field elements:

```json
{
  "sk": "12345",
  "msg": "42",
  "Ru": "<field element as string>",
  "Rv": "<field element as string>",
  "pku": "<field element as string>",
  "pkv": "<field element as string>",
  "S": "<field element as string>"
}
```

Use `gen_test_vectors.py` to compute correct values for any `sk` and `msg`:

```bash
python3 gen_test_vectors.py
```

This outputs `input.json` with all signals pre-filled for `sk=12345, msg=42`.

### 3. Generate witness

```bash
snarkjs wtns calculate \
  eddsa_out/eddsa_jubjub_js/eddsa_jubjub.wasm \
  input.json \
  eddsa_out/eddsa_jubjub.wtns
```

### 4. Trusted setup (development ceremony)

```bash
mkdir -p /tmp/eddsa_ceremony
cd /tmp/eddsa_ceremony

# Generate Powers of Tau (phase 1, 2^17 = 131072 > 12601)
snarkjs powersoftau new bls12-381 17 pot_0000.ptau -v
snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau \
  --name="dev contribution" -e="random entropy"
snarkjs powersoftau prepare phase2 pot_0001.ptau pot_final.ptau -v

# Phase 2 (circuit-specific)
snarkjs groth16 setup \
  /path/to/eddsa_out/eddsa_jubjub.r1cs \
  pot_final.ptau \
  eddsa_jubjub_0000.zkey

snarkjs zkey contribute eddsa_jubjub_0000.zkey eddsa_jubjub_0001.zkey \
  --name="dev contribution" -e="random entropy"
snarkjs zkey export verificationkey eddsa_jubjub_0001.zkey eddsa_jubjub.vk.json
```

**Or** use the Rust prover's built-in single-party ceremony:

```bash
target/release/groth16-prover ceremony-dev \
  eddsa_out/eddsa_jubjub.r1cs \
  /tmp/eddsa_ceremony/eddsa_jubjub.pk \
  /tmp/eddsa_ceremony/eddsa_jubjub.vk
```

### 5. Prove

```bash
target/release/groth16-prover prove \
  --pk /tmp/eddsa_ceremony/eddsa_jubjub.pk \
  --vk /tmp/eddsa_ceremony/eddsa_jubjub.vk \
  --r1cs eddsa_out/eddsa_jubjub.r1cs \
  --wtns eddsa_out/eddsa_jubjub.wtns \
  --proof /tmp/eddsa_ceremony/eddsa_jubjub.proof \
  --public-inputs /tmp/eddsa_ceremony/eddsa_jubjub.pub
```

### 6. Verify (off-chain)

```bash
target/release/groth16-prover verify \
  --vk /tmp/eddsa_ceremony/eddsa_jubjub.vk \
  --proof /tmp/eddsa_ceremony/eddsa_jubjub.proof \
  --public-inputs /tmp/eddsa_ceremony/eddsa_jubjub.pub
# Expected: "Verification result: VALID"
```

### 7. Export VK for on-chain verification (Aiken)

```bash
target/release/groth16-prover export-vk \
  --vk /tmp/eddsa_ceremony/eddsa_jubjub.vk \
  --format aiken \
  --output /tmp/eddsa_ceremony/eddsa_jubjub_vk.ak
```

This produces an Aiken source file with 7 public inputs and the VK
points in compressed form, ready for an on-chain Groth16 verifier.

## Test vectors

| Variable | Value |
|----------|-------|
| `sk` | `12345` |
| `msg` | `42` |
| `r` (computed) | `Poseidon(12345, 42) mod l` |
| `k` (computed) | `PoseidonT6(R, pk, msg) mod l` |

`test_pbk_only.circom` is a minimal test circuit that exercises the
fixed-base scalar multiplication independently (no Poseidon hashing).
Its full pipeline also passes end-to-end.
