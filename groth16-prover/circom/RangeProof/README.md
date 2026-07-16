# Range Proof + Poseidon Commitment

Prove that a committed value lies in a range `[0, 2^n)` without revealing the value itself. This is the building block for confidential transaction amounts, sealed-bid auctions, and any zk-SNARK application that needs bounded private inputs.

> **Status:** Design complete. Implementation in progress.

---

## What it proves

### Circuit A — Simple Range Proof

```
Public:  value
Prove:   value ∈ [0, 2^n)
```

The circuit decomposes `value` into `n` bits and enforces that each bit is either 0 or 1. If `value >= 2^n`, the decomposition would require more than `n` bits, causing a constraint violation.

**Use case:** Proving a counter, timestamp, or index is within bounds. No commitment — the value itself is public.

### Circuit B — Committed Range Proof

```
Public:  commitment
Private: value, blinding_factor
Prove:   value ∈ [0, 2^n)  AND  commitment == Poseidon(value, blinding_factor)
```

The prover reveals only the commitment (a single field element). The actual value and blinding factor remain secret. The verifier checks:
1. The commitment was correctly formed from the hidden value and blinding factor.
2. The hidden value fits within `n` bits (i.e., is non-negative and less than `2^n`).

**Use case:** Confidential transaction amounts. A user can prove "I know an amount `v` such that `0 <= v < 2^32` and `commit = Poseidon(v, r)`" without revealing `v` or `r`.

---

## Circuit structure

| Circuit | Template | What it does | Constraints |
|---------|----------|--------------|-------------|
| `range_proof_simple.circom` | `RangeProofSimple(n)` | `Num2Bits(n)` decomposition + bit validity | ~`n` |
| `range_proof_committed.circom` | `RangeProofCommitted(n)` | `Num2Bits(n)` + `PoseidonBLS12_381` hash equality | ~`n + 250` |
| `PoseidonBLS12_381` (imported) | `PoseidonBLS12_381()` | BLS12-381 Poseidon permutation (t=3, alpha=5, RF=8, RP=57) | ~250 |
| `Num2Bits` (from circomlib) | `Num2Bits(n)` | Decompose signal into `n` bits, each constrained to `{0,1}` | ~`n` |

**Key design decisions:**
- **Poseidon for commitment:** SNARK-friendly hash (~250 constraints) vs Blake2b (~77K constraints) or SHA-256 (~thousands). We already have `PoseidonBLS12_381` in this repo with BLS12-381 round constants.
- **Num2Bits for range proof:** Standard, minimal-constraint approach. No curve-specific constants — works on any field.
- **BLS12-381 safe:** Unlike Ed25519 (which uses chunked Curve25519 arithmetic), `Num2Bits` and Poseidon are fully compatible with BLS12-381.

---

## Parameter: n = 32

We instantiate both circuits with `n = 32`, proving a 32-bit unsigned integer range:

| Circuit | Constraints | Dense matrix RAM | Status |
|---------|-------------|------------------|--------|
| `RangeProofSimple(32)` | ~32 | ~1 KB | Trivial |
| `RangeProofCommitted(32)` | ~282 | ~9 KB | Trivial |

Both are **orders of magnitude smaller** than our smallest working end-to-end circuit (`PoseidonPreimage` at ~300 constraints). No memory risk.

---

## End-to-end pipeline (planned)

```bash
# 1. Compile
circom range_proof_simple.circom --r1cs --wasm --sym --prime bls12381
circom range_proof_committed.circom --r1cs --wasm --sym --prime bls12381

# 2. Generate witness
snarkjs wtns calculate range_proof_simple_js/range_proof_simple.wasm input.json witness.wtns
snarkjs wtns calculate range_proof_committed_js/range_proof_committed.wasm input.json witness.wtns

# 3. Dev ceremony
groth16-prover ceremony-dev --circuit range_proof_simple.r1cs --proving-key rp.pk --verifying-key rp.vk

# 4. Generate proof
groth16-prover prove --circuit range_proof_simple.r1cs --witness witness.wtns --proving-key rp.pk --out proof.bin

# 5. Export VK to Aiken
groth16-prover export-vk --verifying-key rp.vk --out rp_vk.ak
```

---

## Comparison with other circuits in this repo

| Circuit | Constraints | Wires | Dense matrix RAM | Status |
|---------|-------------|-------|------------------|--------|
| SimpleExample Multiplier | 3 | 8 | ~768 B | ✅ Working e2e |
| **RangeProofSimple(32)** | **~32** | **~35** | **~1 KB** | 🔄 In progress |
| **RangeProofCommitted(32)** | **~282** | **~290** | **~9 KB** | 🔄 In progress |
| Poseidon Pre-image | ~300 | ~400 | ~5 MB | ✅ Working e2e |
| Privacy / Spend(depth=2) | 1,107 | 1,110 | ~39 MB | ✅ Working e2e |
| Blake2b-224 Pre-image | ~79K | ~78K | ~200 GB | ⏳ Blocked (memory) |
| Ed25519 Verify | ~4M | ~4M | ~512 TB | ⏳ Blocked (field + memory) |

---

## Files (planned)

```
RangeProof/
├── range_proof_simple.circom        # Simple range proof (public value)
├── range_proof_committed.circom   # Committed range proof (private value + blinding)
├── input.json                       # Test inputs (generated)
├── witness.wtns                     # Witness (generated)
├── README.md                        # This file
```

Dependencies (imported from sibling directories):
- `../PoseidonPreimage/poseidon_bls12_381.circom` — Poseidon permutation
- `../PoseidonPreimage/poseidon_constants_bls12_381.circom` — Round constants
- `circomlib` (via npm or local copy) — `Num2Bits`, comparators

---

## References

- [circomlib](https://github.com/iden3/circomlib) — Standard Circom gadgets (`Num2Bits`, comparators)
- [`PoseidonPreimage/README.md`](../PoseidonPreimage/README.md) — Our BLS12-381 Poseidon implementation
- [Poseidon paper](https://eprint.iacr.org/2019/458.pdf) — Original Poseidon hash function specification
- [ZeroJ PoseidonParamsBLS12_381T3](https://github.com/bloxbean/zeroj) — Round constants and MDS matrix source
