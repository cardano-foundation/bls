# SimpleExample — 3-gate multiplication chain

> **In one sentence:** A minimal "hello world" circuit that proves `a = b × c × d × e` without revealing the four secret multipliers.
>
> **Business angle:** This is the foundational proof-of-concept for our entire Groth16 stack. It validates that a Rust prover can consume Circom artifacts, generate a zk-SNARK proof, and have it verified on-chain by an Aiken smart contract on Cardano. Every other circuit in this repo builds on this same pipeline.

A minimal Circom circuit that demonstrates the full **Circom → Groth16 Rust Prover → Aiken Verifier** pipeline end-to-end.

> **Pipeline overview.** This example walks through every artifact produced and consumed by each tool in the stack. Only the witness-generation step uses snarkjs; proving and verifying are done by our own Rust CLI and Aiken on-chain verifier respectively.

## Circuit

```
x5 = x1 * x2
x6 = x3 * x4
a  = x5 * x6
```

| Signal | Visibility | Meaning |
|--------|-----------|---------|
| `x1, x2, x3, x4` | private | Multiplicands |
| `a` | public | Final product (constraint: `a = x1·x2·x3·x4`) |

With `input.json`:

```json
{ "x1": "2", "x2": "2", "x3": "3", "x4": "4" }
```

the witness vector is `[1, 48, 2, 2, 3, 4, 4, 12]`.

---

## Pipeline — step by step

### Step 1: Compile the circuit (circom)

**Input:** `multiplier.circom`  
**Outputs:**

| File | What it is |
|------|------------|
| `multiplier.r1cs` | Rank-1 constraint system (binary, consumed by the Rust prover) |
| `multiplier.wasm` | Witness calculator (WebAssembly, consumed by snarkjs for witness generation) |
| `multiplier.sym` | Symbol file (human-readable wire names, optional) |

```bash
cd groth16-prover/circom/SimpleExample
circom multiplier.circom --r1cs --wasm --sym --prime bls12381
```

> `--prime bls12381` is required so that field arithmetic matches the BLS12-381 curve used by the Rust prover and the Aiken verifier.

---

### Step 2: Generate the witness (snarkjs — temporary)

**Input:** `multiplier.wasm` + `input.json` (private/public assignments)  
**Output:** `witness.wtns` (binary witness file, consumed by the Rust prover)

```bash
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
```

> **Why snarkjs?** Circom produces a `.wasm` witness calculator. Until we have a Rust-native witness generator, snarkjs runs that WASM to produce the `.wtns` file. The proving and verifying steps below use **only** our Rust tools.

---

### Step 3: Produce the proof (groth16-prover CLI)

**Inputs:**
- `multiplier.r1cs` — constraints from Step 1
- `witness.wtns` — witness from Step 2
- Optional: `--proving-key` / `--verifying-key` files (or let the CLI run the trusted-setup ceremony on the fly)

**Output:** `/tmp/proof.bin` — a binary Groth16 proof (arkworks serialization)

```bash
cd ../../cli
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --out /tmp/proof.bin
```

The CLI uses `FftQapEngine` + `PippengerProver` internally for fast proof generation.

---

### Step 4: Export the verification key for Aiken

**Input:** `multiplier.vk` from the dev ceremony  
**Output:** Aiken source file containing the `VerificationKey` record

```bash
cd ../../cli
cargo run --release -- export-vk \
  --verifying-key /tmp/multiplier.vk \
  --out /tmp/multiplier_vk.ak
```

The file `/tmp/multiplier_vk.ak` is a self-contained Aiken snippet. It declares a `verification_key()` function that returns a `groth16/verifier.VerificationKey` with all CRS points encoded as hex literals. You can paste it directly into an Aiken project.

### Step 5: Verify the proof in Aiken

**Inputs:**
- `proof.bin` — proof from Step 3 (192 bytes)
- `multiplier_vk.ak` — verification key from Step 4
- Public inputs (`[1, 48]` in this case: constant wire + output `a`)

**Output:** `True` iff the Groth16 pairing equation holds

Read the proof bytes and split them into the three compressed curve points:

```bash
# Convert binary proof to hex
xxd -p /tmp/proof.bin | tr -d '\n'
```

The hex string is 384 characters (192 bytes). Split it:
- First 96 chars → proof `A` (48 bytes compressed G1)
- Next 192 chars → proof `B` (96 bytes compressed G2)
- Last 96 chars → proof `C` (48 bytes compressed G1)

Then write an Aiken test or validator:

```aiken
use groth16/verifier as groth16

fn real_circom_vk() -> groth16.VerificationKey {
  // Paste the contents of /tmp/multiplier_vk.ak here,
  // or import it as a module.
  verification_key()
}

test verify_real_circom_proof() {
  let proof = groth16.Proof {
    a: #"<first 96 hex chars from proof.bin>",
    b: #"<next 192 hex chars from proof.bin>",
    c: #"<last 96 hex chars from proof.bin>",
  }
  // Public inputs: constant wire = 1, output a = 48
  groth16.verify(proof, [1, 48], real_circom_vk())
}
```

See the [`aiken/groth16` README](../../../../aiken/groth16/README.md) §**Circom pipeline** for a complete walkthrough including the parameterized API and validator-level integration.

---

## Files in this directory

| File | Description |
|------|-------------|
| `multiplier.circom` | The 3-gate circuit source |
| `input.json` | Private/public input assignments |
| `multiplier.r1cs` | Generated R1CS (Step 1 output) |
| `multiplier.wasm` | Generated witness calculator (Step 1 output) |
| `witness.wtns` | Generated witness (Step 2 output) |
