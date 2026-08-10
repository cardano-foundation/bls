# Range Proof + Poseidon Commitment

Prove that a committed value lies in a range `[0, 2^n)` without revealing the value itself.

## What it proves

### Circuit A — Simple Range Proof (`RangeProofSimple`)

```
Public:  value
Prove:   value ∈ [0, 2^n)
```

The circuit decomposes `value` into `n` bits and enforces that each bit is either 0 or 1. If `value >= 2^n`, the decomposition would require more than `n` bits, causing a constraint violation.

### Circuit B — Committed Range Proof (`RangeProofCommitted`)

```
Public:  commitment
Private: value, blinding_factor
Prove:   value ∈ [0, 2^n)  AND  commitment == Poseidon(value, blinding_factor)
```

The prover reveals only the commitment (a single field element). The actual value and blinding factor remain secret. The verifier checks:
1. The commitment was correctly formed from the hidden value and blinding factor.
2. The hidden value fits within `n` bits (i.e., is non-negative and less than `2^n`).

---

## Circuit structure

| Circuit | Template | What it does | Constraints |
|---------|----------|--------------|-------------|
| `range_proof_simple.circom` | `RangeProofSimple(n)` | `Num2Bits(n)` decomposition + bit validity | ~`n` |
| `range_proof_committed.circom` | `RangeProofCommitted(n)` | `Num2Bits(n)` + `PoseidonBLS12_381` hash equality | ~`n + 250` |
| `PoseidonBLS12_381` (imported) | `PoseidonBLS12_381()` | BLS12-381 Poseidon permutation (t=3, alpha=5, RF=8, RP=57) | ~250 |
| `Num2Bits` (from circomlib) | `Num2Bits(n)` | Decompose signal into `n` bits, each constrained to `{0,1}` | ~`n` |

Both circuits are instantiated with `n = 32`.

---

## End-to-end pipeline (validated)

### Circuit A — Simple Range Proof

```bash
# 1. Compile (run from the circuit directory)
cd circom/RangeProof
circom range_proof_simple.circom --r1cs --wasm --sym --prime bls12381

# 2. Generate witness (value = 123456789, which is < 2^32)
echo '{"value": 123456789}' > input.json
snarkjs wtns calculate range_proof_simple_js/range_proof_simple.wasm input.json witness.wtns

# 3. Dev ceremony (run from clis/groth16/)
cd ../../clis/groth16
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev \
  --circuit ../../circom/RangeProof/range_proof_simple.r1cs \
  --proving-key /tmp/rp_simple.pk \
  --verifying-key /tmp/rp_simple.vk

# 4. Generate proof
cargo run --release -- prove \
  --circuit ../../circom/RangeProof/range_proof_simple.r1cs \
  --witness ../../circom/RangeProof/witness.wtns \
  --proving-key /tmp/rp_simple.pk \
  --out /tmp/proof_simple.bin

# 5. Verify
cargo run --release -- verify \
  --proof /tmp/proof_simple.bin \
  --public /tmp/proof_simple.pub \
  --verifying-key /tmp/rp_simple.vk
# → Verification result: VALID
```

**Invalid case (value >= 2^32):**
```bash
cd circom/RangeProof
echo '{"value": 4294967297}' > input_invalid.json
snarkjs wtns calculate range_proof_simple_js/range_proof_simple.wasm input_invalid.json witness_invalid.wtns
# → ERROR: Assert Failed (Num2Bits constraint violated)
```

### Circuit B — Committed Range Proof

```bash
# 1. Compile (run from the circuit directory)
cd circom/RangeProof
circom range_proof_committed.circom --r1cs --wasm --sym --prime bls12381

# 2. Generate test inputs with correct Poseidon commitment
#    (commitment must be passed as a STRING to avoid JS precision loss)
python3 -c "
import json
# Poseidon(987654321, 42) = 14552169037149848092889607379555146473462630327079531275196027443808903025477
d = {'commitment': '14552169037149848092889607379555146473462630327079531275196027443808903025477',
     'value': 987654321, 'blinding_factor': 42}
json.dump(d, open('input.json', 'w'))
"

# 3. Generate witness
snarkjs wtns calculate range_proof_committed_js/range_proof_committed.wasm input.json witness.wtns

# 4. Dev ceremony (run from clis/groth16/)
cd ../../clis/groth16
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev \
  --circuit ../../circom/RangeProof/range_proof_committed.r1cs \
  --proving-key /tmp/rp_committed.pk \
  --verifying-key /tmp/rp_committed.vk

# 5. Generate proof
cargo run --release -- prove \
  --circuit ../../circom/RangeProof/range_proof_committed.r1cs \
  --witness ../../circom/RangeProof/witness.wtns \
  --proving-key /tmp/rp_committed.pk \
  --out /tmp/proof_committed.bin

# 6. Verify
cargo run --release -- verify \
  --proof /tmp/proof_committed.bin \
  --public /tmp/proof_committed.pub \
  --verifying-key /tmp/rp_committed.vk
# → Verification result: VALID
```

**Invalid case (value out of range, same commitment):**
```bash
cd circom/RangeProof
python3 -c "
import json
d = {'commitment': '14552169037149848092889607379555146473462630327079531275196027443808903025477',
     'value': 4294967297, 'blinding_factor': 42}
json.dump(d, open('input_invalid.json', 'w'))
"
snarkjs wtns calculate range_proof_committed_js/range_proof_committed.wasm input_invalid.json witness_invalid.wtns
# → ERROR: Assert Failed (Num2Bits constraint violated)
```

---

## ⚠️ Important: JSON integer precision

BLS12-381 field elements are ~255-bit integers (~77 decimal digits). **JavaScript's `Number` type only preserves integers up to 2^53 (~16 decimal digits).** When passing large field elements (like Poseidon commitments) in `input.json`, you must pass them as **strings**, not raw numbers.

**Wrong (loses precision):**
```json
{"commitment": 14552169037149848092889607379555146473462630327079531275196027443808903025477}
```

**Correct (preserves precision):**
```json
{"commitment": "14552169037149848092889607379555146473462630327079531275196027443808903025477"}
```

This is a common pitfall when using snarkjs with BLS12-381. Always use strings for field elements larger than `Number.MAX_SAFE_INTEGER`.

---

## Files

```
RangeProof/
├── range_proof_simple.circom        # Simple range proof (public value)
├── range_proof_committed.circom     # Committed range proof (private value + blinding)
├── package.json                     # npm dependency manifest (circomlib)
├── package-lock.json                # (generated by npm install)
└── README.md                        # This file
```

Dependencies (imported from sibling directories / npm):
- `../PoseidonPreimage/poseidon_bls12_381.circom` — Poseidon permutation
- `../PoseidonPreimage/poseidon_constants_bls12_381.circom` — Round constants
- `circomlib` (via npm) — `Num2Bits`, comparators

---

## References

- [circomlib](https://github.com/iden3/circomlib) — Standard Circom gadgets (`Num2Bits`, comparators)
- [`PoseidonPreimage/README.md`](../PoseidonPreimage/README.md) — Our BLS12-381 Poseidon implementation
- [Poseidon paper](https://eprint.iacr.org/2019/458.pdf) — Original Poseidon hash function specification
- [ZeroJ PoseidonParamsBLS12_381T3](https://github.com/bloxbean/zeroj) — Round constants and MDS matrix source
