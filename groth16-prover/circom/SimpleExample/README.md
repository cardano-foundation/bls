# SimpleExample — 3-gate multiplication chain

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

### Step 4: Verify the proof (Aiken on-chain verifier)

**Inputs:**
- `proof.bin` — proof from Step 3
- Verifying key (produced by the ceremony in Step 3, or reused)
- Public inputs (`a = 48` in this case)

**Output:** On-chain accept / reject

Use the Aiken smart-contract verifier (see the top-level `aiken/` directory) to submit the proof and public inputs for on-chain verification.

---

## Files in this directory

| File | Description |
|------|-------------|
| `multiplier.circom` | The 3-gate circuit source |
| `input.json` | Private/public input assignments |
| `multiplier.r1cs` | Generated R1CS (Step 1 output) |
| `multiplier.wasm` | Generated witness calculator (Step 1 output) |
| `witness.wtns` | Generated witness (Step 2 output) |
