# SimpleExample — 3-gate multiplication chain

This is the simplest Circom circuit used to demonstrate the full Groth16 pipeline end-to-end.

## Circuit

```
x5 = x1 * x2
x6 = x3 * x4
a  = x5 * x6
```

**Inputs:** `x1, x2, x3, x4` (private)  
**Output:** `a` (public)

With `input.json`:

```json
{ "x1": "2", "x2": "2", "x3": "3", "x4": "4" }
```

the witness vector is `[1, 48, 2, 2, 3, 4, 4, 12]`.

## How to use

```bash
cd groth16-prover/circom/SimpleExample

# 1. Compile
circom multiplier.circom --r1cs --wasm --sym --prime bls12381

# 2. Generate witness (requires snarkjs + Node.js)
snarkjs wtns calculate multiplier.wasm input.json witness.wtns

# 3. Prove (from groth16-prover/cli)
cd ../../cli
cargo run --release -- prove \
  --circuit ../circom/SimpleExample/multiplier.r1cs \
  --witness ../circom/SimpleExample/witness.wtns \
  --out /tmp/proof.bin
```

## Files

| File | Description |
|------|-------------|
| `multiplier.circom` | The 3-gate circuit |
| `input.json` | Private/public inputs for this proof |
| `multiplier.r1cs` | Generated R1CS constraint system |
| `multiplier.wasm` | Generated witness calculator |
| `witness.wtns` | Generated witness (run snarkjs) |
