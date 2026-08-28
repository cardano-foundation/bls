# Predicate — Composite Selective-Disclosure Circuit

A holder proves they satisfy a predicate over a **signed credential** without revealing any credential field or their identity. This is the core Step 1 circuit of the selective-disclosure design documented in [`aiken/selective-disclosure/README.md`](../../aiken/selective-disclosure/README.md).

This circuit is a **composite** of the four validated building blocks from `circom/`:
1. **Poseidon hash** (`PoseidonBLS12_381`) — commits the credential fields into a single `claims_msg`.
2. **EdDSA-JubJub signature verification** (third-party) — proves an issuer signed `claims_msg`.
3. **Comparison** (`GreaterEqThan` from `circomlib`) — proves `current_year >= dob_year + 21` (age ≥ 21).
4. **Merkle membership** (`PoseidonMerkle`) — proves the country is in the issuer's approved-countries tree.

The tuple of credential fields is reduced to a single public eligibility flag; nothing else leaks.

---

## What it proves

```
Public:  pku, pkv               (issuer JubJub public key)
         current_year           (e.g. 2026)
         country_root           (Merkle root of approved countries)
         eligible               (must equal 1)

Private: dob_year, country      (credential fields)
         Ru, Rv, S              (issuer's EdDSA-JubJub signature on claims_msg)
         sibling, direction     (Merkle membership witness for `country`)

1. claims_msg = Poseidon(dob_year, country)
2. k = PoseidonT6(R, pk, claims_msg) mod l
   [S]·G = R + [k]·pk                       (third-party EdDSA verification)
3. current_year >= dob_year + 21            (age >= 21)
4. country ∈ approvedCountries              (Merkle membership, leaf = Poseidon(country, 0))
5. eligible == 1
```

The signature is verified **third-party**: the holder never learns the issuer's secret key. The verification equation `[S]·G = R + [k]·pk` only requires public signature data and the public key.

**Circuit size (depth 2):** 10 458 wires, 7 887 non-linear + 2 569 linear constraints. Public inputs: 5, private inputs: 9 (excluding array elements).

---

## Circuit design

`predicate.circom` defines two reusable templates:

| Template | Purpose |
|----------|---------|
| `EdDSAVerifyThirdParty()` | Standard EdDSA verification: `[S]·G = R + [k]·pk`, `k = PoseidonT6(R,pk,msg) mod l`. No secret key. |
| `Predicate(depth)` | Composes Poseidon + third-party EdDSA + range + Merkle into the credential predicate. |

`predicate_depth2.circom` instantiates `Predicate(2)` with `pku, pkv, current_year, country_root, eligible` as public inputs.

**Public inputs:** `pku`, `pkv`, `current_year`, `country_root`, `eligible`
**Private inputs:** `dob_year`, `country`, `Ru`, `Rv`, `S`, `sibling[depth]`, `direction[depth]`

> **Note:** `claims_msg` is a **private** intermediate signal — it is computed in-circuit from the field values and used as the EdDSA message. It does not appear on-chain, so it cannot be used to brute-force the fields.

---

## Full CLI flow

### 1. Compile the circuit

```bash
cd circom/Predicate
mkdir -p pred_out
circom predicate_depth2.circom --r1cs --wasm --sym --prime bls12381 \
  -o pred_out \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits
```

Result: `pred_out/predicate_depth2.r1cs` (10 456 constraints) + `pred_out/predicate_depth2_js/predicate_depth2.wasm`.

### 2. Generate the witness input

The issuer builds an approved-countries Merkle tree (leaf = `Poseidon(country, 0)`), issues a credential `(dob_year, country)`, and signs `claims_msg = Poseidon(dob_year, country)`. The holder's input bundles the fields, the signature, and the Merkle witness:

```bash
python3 gen_predicate_input.py --depth 2 --output input.json [--seed N]
```

Options: `--dob-year`, `--country`, `--seed`. The approved set is fixed at `{276, 250, 756, 40}` (DEU, FRA, CHE, AT) for depth 2; edit the script to extend it.

### 3. Compute the witness

```bash
snarkjs wtns calculate pred_out/predicate_depth2_js/predicate_depth2.wasm \
  input.json pred_out/predicate_depth2.wtns
```

### 4. Run the dev ceremony

```bash
cd ../../clis/trusted-setup
cargo build --release
./target/release/trusted-setup ceremony-dev \
  --circuit ../../circom/Predicate/pred_out/predicate_depth2.r1cs \
  --proving-key /tmp/pred_ceremony/predicate.pk \
  --verifying-key /tmp/pred_ceremony/predicate.vk
```

Output:
```
Dev ceremony complete. Full proving key generated.
  Proving key:  /tmp/pred_ceremony/predicate.pk  (3799122 bytes)
  Verifying key: /tmp/pred_ceremony/predicate.vk (502336 bytes)
```

### 5. Generate the proof

```bash
cd ../../clis/groth16
cargo build --release
./target/release/groth16 prove \
  --circuit ../../circom/Predicate/pred_out/predicate_depth2.r1cs \
  --witness ../../circom/Predicate/pred_out/predicate_depth2.wtns \
  --proving-key /tmp/pred_ceremony/predicate.pk \
  --out /tmp/pred_ceremony/predicate.proof
```

### 6. Verify the proof

```bash
./target/release/groth16 verify \
  --verifying-key /tmp/pred_ceremony/predicate.vk \
  --proof /tmp/pred_ceremony/predicate.proof \
  --public /tmp/pred_ceremony/predicate.pub
```

Output:
```
Verification result: VALID
```

### 7. Rejected cases (should fail to build a witness)

| Tamper | Why it fails |
|--------|--------------|
| Change `dob_year` only | The issuer signature no longer validates against the new `claims_msg` (sig binding) |
| `--dob-year 2010` (age 16) | `ageGte.out === 1` fails — underage |
| Corrupt `sibling`/`direction` | `digest === current[depth]` fails in `PoseidonMerkle` — not in the approved set |

---

## Files

| File | Description |
|------|-------------|
| `predicate.circom` | Reusable `EdDSAVerifyThirdParty` + `Predicate(depth)` templates |
| `predicate_depth2.circom` | Instantiation with depth = 2 |
| `gen_predicate_input.py` | Issuer + holder witness generator (reuses `EdDSAJubJub/gen_test_vectors.py`) |
| `input.json` | Valid witness input (holder, approved, adult) |
