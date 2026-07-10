# Privacy — Shielded Spend (Merkle Membership) Circuit

A privacy-preserving donation / shielded-spend circuit adapted from **Stanford CS251 Programming Project #4** (Zcash-style Merkle-path verification).

> **What it proves.** Given a public Merkle root `digest` and a public `nullifier`, the prover demonstrates knowledge of a private `nonce` and a valid Merkle path (siblings + directions) showing that `H(nullifier, nonce)` is present in the tree — without revealing the nonce or the path.

> **Pipeline overview.** This example walks through every artifact produced and consumed by each tool in the stack. Only the witness-generation step uses snarkjs; proving and verifying are done by our own Rust CLI and Aiken on-chain verifier respectively.

---

## Circuit Templates

### `IfThenElse`

```circom
out = condition ? true_value : false_value
```

Enforces `condition ∈ {0, 1}` using a helper quadratic signal.

### `SelectiveSwitch`

```circom
if (s == 0) { out0 = in0; out1 = in1; }
if (s == 1) { out0 = in1; out1 = in0; }
```

Composed from two `IfThenElse` gadgets; enforces `s ∈ {0, 1}`.

### `Spend(depth)`

1. Computes `commitment = MiMC2(nullifier, nonce)`
2. Walks up the Merkle tree for `depth` levels, at each level:
   - Uses `SelectiveSwitch` to place `commitment` / current hash on the correct side (left/right) based on `direction[i]`
   - Hashes the two children with `MiMC2` to get the parent
3. Constrains the final computed root to equal the public `digest`

---

## Files

| File | Description |
|------|-------------|
| `spend.circom` | Library templates: `IfThenElse`, `SelectiveSwitch`, `Spend(depth)` |
| `mimc.circom` | MiMC(x⁷) hash (`Mimc2`, `Mimc7`, `Mimc7Compression`) from circomlib |
| `spend_depth2.circom` | Top-level circuit: `Spend(2)` with public inputs `digest`, `nullifier` |
| `transcript.txt` | Sample transaction transcript (nullifier + nonce pairs) |
| `compute_spend_inputs.js` | Node.js script that computes the witness input JSON from a transcript |
| `mimc.js` | Native BigInt MiMC implementation for BLS12-381 |
| `sparse_merkle_tree.js` | Sparse Merkle tree used by the input computer |
| `input.json` | Pre-computed witness input for `spend_depth2` (nullifier `2`, depth `2`) |

---

## Pipeline — step by step

### Step 1: Compile the circuit (circom)

**Input:** `spend_depth2.circom` (+ `spend.circom` + `mimc.circom`)  
**Outputs:**

| File | What it is |
|------|------------|
| `spend_depth2.r1cs` | Rank-1 constraint system (binary, consumed by the Rust prover) |
| `spend_depth2.wasm` | Witness calculator (WebAssembly, consumed by snarkjs) |
| `spend_depth2.sym` | Symbol file (human-readable wire names, optional) |

```bash
cd groth16-prover/circom/Privacy
circom spend_depth2.circom --r1cs --wasm --sym --prime bls12381
```

> `--prime bls12381` is required so that field arithmetic matches the BLS12-381 curve used by the Rust prover and the Aiken verifier.

---

### Step 2: Generate the witness input (compute_spend_inputs.js)

**Input:** `transcript.txt` — one line per commitment. Each line is either:
- a single number (raw commitment), or
- two space-separated numbers: `nullifier nonce`

**Output:** `input.json` — JSON mapping of signal names to string-represented field elements

```bash
node compute_spend_inputs.js 2 transcript.txt 2 input.json
# arguments: <depth> <transcript-file> <target-nullifier> [output-file]
```

Example `input.json` for depth 2, proving nullifier `2`:

```json
{
  "digest": "38673394090979759302004417930828797036438405768250383626926274618229205537243",
  "nullifier": "2",
  "nonce": "200",
  "sibling[0]": "51331088441058323668003070092384951403691579578458800872412919206058194176401",
  "direction[0]": "1",
  "sibling[1]": "5779291168359415739781538643165041305924408008656544905888278487211941807471",
  "direction[1]": "0"
}
```

---

### Step 3: Generate the witness (snarkjs — temporary)

**Input:** `spend_depth2.wasm` (from Step 1) + `input.json` (from Step 2)  
**Output:** `witness.wtns` — binary witness file consumed by the Rust prover

```bash
snarkjs wtns calculate spend_depth2.wasm input.json witness.wtns
```

> **Why snarkjs?** Circom produces a `.wasm` witness calculator. Until we have a Rust-native witness generator, snarkjs runs that WASM to produce the `.wtns` file. The proving and verifying steps below use **only** our Rust tools.

---

### Step 4: Produce the proof (groth16-prover CLI)

**Inputs:**
- `spend_depth2.r1cs` — constraints from Step 1
- `witness.wtns` — witness from Step 3
- Optional: `--proving-key` / `--verifying-key` files (or let the CLI run the trusted-setup ceremony on the fly)

**Output:** `/tmp/privacy_proof.bin` — a binary Groth16 proof (arkworks serialization)

```bash
cd ../../cli
cargo run --release -- prove \
  --circuit ../circom/Privacy/spend_depth2.r1cs \
  --witness ../circom/Privacy/witness.wtns \
  --out /tmp/privacy_proof.bin
```

The CLI uses `FftQapEngine` + `PippengerProver` internally for fast proof generation.

---

### Step 5: Verify the proof (Aiken on-chain verifier)

**Inputs:**
- `privacy_proof.bin` — proof from Step 4
- Verifying key (produced by the ceremony in Step 4, or reused)
- Public inputs (`digest`, `nullifier`)

**Output:** On-chain accept / reject

Use the Aiken smart-contract verifier (see the top-level `aiken/` directory) to submit the proof and public inputs for on-chain verification.

---

## Adapting for BLS12-381

The `mimc.circom` round constants are the standard BN254 MiMC constants. When compiled with `--prime bls12381`, Circom automatically reduces them modulo the BLS12-381 scalar field. The companion `mimc.js` witness generator uses the BLS12-381 prime (`52435875175126190479447740508185965837690552500527637822603658699938581184513`) so that off-chain hashes are consistent with in-circuit hashes.

> **Production note:** For a production deployment on BLS12-381, the MiMC round constants should be regenerated specifically for the BLS12-381 field using the standard Iden3 seed procedure.

## References

- [Stanford CS251 Project #4](https://securitylab.github.io/cs251-fall20/hw/proj4.pdf) — original assignment description
- [circomlib](https://github.com/iden3/circomlib) — source of `mimc.circom`
