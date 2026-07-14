# Poseidon Hash Pre-image

Prove knowledge of a secret whose Poseidon hash equals a public commitment.

> **What it proves.** Given a public `hash_commitment`, the prover demonstrates knowledge of a private `pre_image` such that `hash_commitment = PoseidonBLS12_381(pre_image, 0)` — without revealing the pre-image.

> **Pipeline overview.** This example walks through every artifact produced and consumed by each tool in the stack. Only the witness-generation step uses snarkjs; proving and verifying are done by our own Rust CLI and Aiken on-chain verifier respectively.

---

## Circuit

```
hash_commitment = PoseidonBLS12_381(pre_image, 0)
```

| Signal | Visibility | Meaning |
|--------|-----------|---------|
| `pre_image` | private | The secret value being proven |
| `hash_commitment` | public | The Poseidon hash of the pre-image |

The Poseidon permutation uses BLS12-381 parameters:
- **State width (t):** 3
- **S-box exponent (alpha):** 5
- **Full rounds (RF):** 8
- **Partial rounds (RP):** 57
- **Total rounds:** 65

Round constants and MDS matrix are from ZeroJ's `PoseidonParamsBLS12_381T3`, generated via the Grain LFSR following the Poseidon paper specification.

---

## Files

| File | Description |
|------|-------------|
| `poseidon_preimage.circom` | Top-level circuit: constrains `hash_commitment == Poseidon(pre_image, 0)` |
| `poseidon_bls12_381.circom` | Poseidon permutation template (t=3, alpha=5, RF=8, RP=57) |
| `poseidon_constants_bls12_381.circom` | Round constants (195 values) and 3x3 MDS matrix for BLS12-381 |
| `input.json` | Sample witness input (`pre_image = 42`) |

---

## Pipeline — step by step

### Step 1: Compile the circuit (circom)

**Input:** `poseidon_preimage.circom` (+ `poseidon_bls12_381.circom` + `poseidon_constants_bls12_381.circom`)  
**Outputs:**

| File | What it is |
|------|------------|
| `poseidon_preimage.r1cs` | Rank-1 constraint system (binary, consumed by the Rust prover) |
| `poseidon_preimage.wasm` | Witness calculator (WebAssembly, consumed by snarkjs) |
| `poseidon_preimage.sym` | Symbol file (human-readable wire names, optional) |

```bash
cd groth16-prover/circom/PoseidonPreimage
circom poseidon_preimage.circom --r1cs --wasm --sym
```

> This project is strictly focused on BLS12-381. BN254 is not supported.

---

### Step 2: Generate the witness (snarkjs — temporary)

**Input:** `poseidon_preimage.wasm` (from Step 1) + `input.json`  
**Output:** `witness.wtns` — binary witness file consumed by the Rust prover

```bash
snarkjs wtns calculate poseidon_preimage.wasm input.json witness.wtns
```

> **Why snarkjs?** Circom produces a `.wasm` witness calculator. Until we have a Rust-native witness generator, snarkjs runs that WASM to produce the `.wtns` file. The proving and verifying steps below use **only** our Rust tools.

---

### Step 3: Run the dev ceremony (groth16-prover CLI)

**Inputs:**
- `poseidon_preimage.r1cs` — constraints from Step 1

**Outputs:**
- `/tmp/poseidon_preimage.pk` — binary proving key (group elements only, no scalars)
- `/tmp/poseidon_preimage.vk` — binary verifying key

```bash
cd ../../cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/PoseidonPreimage/poseidon_preimage.r1cs \
  --proving-key /tmp/poseidon_preimage.pk \
  --verifying-key /tmp/poseidon_preimage.vk
```

> **What happens.** The CLI loads the `.r1cs`, counts public variables (`n_public = 2` — constant wire + `hash_commitment`), then runs a single-party trusted setup. It computes all CRS group elements from random scalars and drops the scalars before writing the key files.

---

### Step 4: Produce the proof (groth16-prover CLI)

**Inputs:**
- `poseidon_preimage.r1cs` — constraints from Step 1
- `witness.wtns` — witness from Step 2
- `/tmp/poseidon_preimage.pk` — proving key from Step 3

**Outputs:**
- `/tmp/poseidon_preimage.proof` — binary Groth16 proof (192 bytes)
- `/tmp/poseidon_preimage.pub` — binary public-input commitment (48 bytes)

```bash
cargo run --release -- prove \
  --circuit ../circom/PoseidonPreimage/poseidon_preimage.r1cs \
  --witness ../circom/PoseidonPreimage/witness.wtns \
  --proving-key /tmp/poseidon_preimage.pk \
  --engine fft --prover pippenger \
  --out /tmp/poseidon_preimage.proof
```

The CLI uses `FftQapEngine` + `PippengerProver` internally for fast proof generation. The proof is serialized in standard arkworks compressed format.

---

### Step 5: Verify the proof off-chain

```bash
cargo run --release -- verify \
  --proof /tmp/poseidon_preimage.proof \
  --public /tmp/poseidon_preimage.pub \
  --verifying-key /tmp/poseidon_preimage.vk
```

Expected output: `Verification result: VALID`

---

### Step 6: Export the verification key for Aiken

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/poseidon_preimage.vk \
  --out /tmp/poseidon_preimage_vk.ak
```

The generated `/tmp/poseidon_preimage_vk.ak` is a self-contained Aiken function returning a `VerificationKey`. Because `n_public = 2`, the `ic` list contains two points (constant wire + `hash_commitment`).

---

### Step 7: Verify on-chain (Aiken test)

Copy the exported VK and the proof bytes into an Aiken test. The proof bytes can be read with:

```bash
xxd -p /tmp/poseidon_preimage.proof | tr -d '\n' | fold -w 96 -s
```

This emits three chunks: `A` (96 hex chars), `B` (192 hex chars), `C` (96 hex chars).

An Aiken test would look like:

```aiken
test test_verify_poseidon_preimage_proof() {
  verify(poseidon_preimage_proof(), [1, 51191423336626179944841251760023912585519132135457039538281110745651405953568], poseidon_preimage_vk())
}
```

Run the tests:

```bash
cd aiken/groth16
aiken check
```

---

## Computing your own hash commitment

To create a proof with a different secret, compute the Poseidon hash off-chain and update `input.json`:

```bash
# Using the Rust library or any BLS12-381 Poseidon implementation
# hash = PoseidonBLS12_381(pre_image, 0)
```

Then update `input.json`:

```json
{
  "pre_image": "<your-secret>",
  "hash_commitment": "<computed-hash>"
}
```

---

## Curve focus

This project is exclusively focused on BLS12-381. We are inspired by prior work on BN254, but we do not support it. All field arithmetic, point serialization, and trusted-setup artifacts target the BLS12-381 curve only.

> **Production note:** The Poseidon parameters (t=3, alpha=5, RF=8, RP=57) and round constants were generated specifically for the BLS12-381 scalar field using the standard Grain LFSR procedure from the Poseidon paper.

## References

- [Poseidon Paper](https://eprint.iacr.org/2019/458.pdf) — Grassi et al., 2021
- [circomlib](https://github.com/iden3/circomlib) — reference Circom implementations (BN254-oriented)
- [ZeroJ PoseidonParamsBLS12_381T3](https://github.com/bloxbean/zeroj) — BLS12-381 Poseidon parameters used here
