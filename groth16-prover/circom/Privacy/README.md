# Privacy — Shielded Spend (Merkle Membership) Circuit

> **In one sentence:** Prove that a secret coin exists in a Merkle tree — without revealing which coin, where it sits in the tree, or the path used to find it.
>
> **Business angle:** This is the core building block for private transactions on Cardano. A user can spend a shielded UTXO by proving "I own a coin whose commitment is in this public Merkle tree" while keeping the coin's identity, the Merkle path, and the spending key completely secret. The on-chain verifier only sees a public Merkle root and a nullifier (preventing double-spends), making the transaction both private and auditable.

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
| `helpers_js/compute_spend_inputs.js` | Node.js script that computes the witness input JSON from a transcript |
| `helpers_js/mimc.js` | Native BigInt MiMC implementation for BLS12-381 |
| `helpers_js/sparse_merkle_tree.js` | Sparse Merkle tree used by the input computer |
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
circom spend_depth2.circom --r1cs --wasm --sym
```

> This project is strictly focused on BLS12-381. BN254 is not supported.

---

### Step 2: Generate the witness input

The witness input (`input.json`) contains the private Merkle-path data. You can produce it with **either** the JavaScript helpers or the Rust library — both use the same MiMC hash and BLS12-381 field arithmetic.

**Input:** `transcript.txt` — one line per commitment. Each line is either:
- a single number (raw commitment), or
- two space-separated numbers: `nullifier nonce`

**Output:** `input.json` — JSON mapping of signal names to string-represented field elements

#### Option A — JavaScript (Node.js)

```bash
node helpers_js/compute_spend_inputs.js 2 transcript.txt 2 input.json
# arguments: <depth> <transcript-file> <target-nullifier> [output-file]
```

#### Option B — Rust CLI (installed `groth16-prover` binary)

```bash
cd ../../cli
cargo run --release -- compute-inputs \
  --depth 2 \
  --transcript ../circom/Privacy/transcript.txt \
  --nullifier 2 \
  --out ../circom/Privacy/input.json
```

#### Option C — Rust library (from the `groth16-prover` crate)

```rust
use groth16_prover::privacy_inputs::{
    compute_spend_inputs, parse_transcript_lines, TranscriptEntry
};

let lines = std::fs::read_to_string("transcript.txt")?
    .lines()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();

let transcript = parse_transcript_lines(&lines)?;
let inputs = compute_spend_inputs(2, &transcript, "2")?;

// `inputs.to_json_map()` gives Vec<(String, String)> ready for JSON serialization
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

### Step 4: Run the dev ceremony (groth16-prover CLI)

**Inputs:**
- `spend_depth2.r1cs` — constraints from Step 1

**Outputs:**
- `/tmp/spend_depth2.pk` — binary proving key (group elements only, no scalars)
- `/tmp/spend_depth2.vk` — binary verifying key

```bash
cd ../../cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/Privacy/spend_depth2.r1cs \
  --proving-key /tmp/spend_depth2.pk \
  --verifying-key /tmp/spend_depth2.vk
```

> **What happens.** The CLI loads the `.r1cs`, counts public variables (`n_public = 1` — only the constant wire, because all user inputs are private), then runs a single-party trusted setup. It computes all CRS group elements from random scalars and drops the scalars before writing the key files.

---

### Step 5: Produce the proof (groth16-prover CLI)

**Inputs:**
- `spend_depth2.r1cs` — constraints from Step 1
- `witness.wtns` — witness from Step 3
- `/tmp/spend_depth2.pk` — proving key from Step 4

**Outputs:**
- `/tmp/spend_depth2.proof` — binary Groth16 proof (192 bytes)
- `/tmp/spend_depth2.pub` — binary public-input commitment (48 bytes)

```bash
cargo run --release -- prove \
  --circuit ../circom/Privacy/spend_depth2.r1cs \
  --witness ../circom/Privacy/witness.wtns \
  --proving-key /tmp/spend_depth2.pk \
  --engine fft --prover pippenger \
  --out /tmp/spend_depth2.proof
```

The CLI uses `FftQapEngine` + `PippengerProver` internally for fast proof generation. The proof is serialized in standard arkworks compressed format.

---

### Step 6: Verify the proof off-chain

```bash
cargo run --release -- verify \
  --proof /tmp/spend_depth2.proof \
  --public /tmp/spend_depth2.pub \
  --verifying-key /tmp/spend_depth2.vk
```

Expected output: `Verification result: VALID`

---

### Step 7: Export the verification key for Aiken

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/spend_depth2.vk \
  --out /tmp/spend_depth2_vk.ak
```

The generated `/tmp/spend_depth2_vk.ak` is a self-contained Aiken function returning a `VerificationKey`. Because `n_public = 1`, the `ic` list contains only one point (the constant wire), making the VK tiny (~15 lines).

---

### Step 8: Verify on-chain (Aiken test)

Copy the exported VK and the proof bytes into an Aiken test. The proof bytes can be read with:

```bash
xxd -p /tmp/spend_depth2.proof | tr -d '\n' | fold -w 96 -s
```

This emits three chunks: `A` (96 hex chars), `B` (192 hex chars), `C` (96 hex chars).

An Aiken test has already been added to `aiken/groth16/lib/groth16/verifier.ak`:

```aiken
test test_verify_circom_spend_depth2_proof() {
  verify(spend_depth2_proof(), [1], spend_depth2_vk())
}
```

Run the tests:

```bash
cd aiken/groth16
aiken check
```

All tests pass, including the new end-to-end `spend_depth2` test.

---

## Curve focus

This project is exclusively focused on BLS12-381. We are inspired by prior work on BN254, but we do not support it. All field arithmetic, point serialization, and trusted-setup artifacts target the BLS12-381 curve only.

> **Production note:** For a production deployment, the MiMC round constants should be regenerated specifically for the BLS12-381 field using the standard Iden3 seed procedure.

## References

- [Stanford CS251 Project #4](https://securitylab.github.io/cs251-fall20/hw/proj4.pdf) — original assignment description
- [circomlib](https://github.com/iden3/circomlib) — source of `mimc.circom`
