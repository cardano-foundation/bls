# groth16-prover-cli

Command-line interface for generating Groth16 zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).

## Usage

```bash
# Generate a proof and print hex to stdout
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns

# Generate a proof and write raw binary to file
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --out proof.bin
```

When `--out` is provided, two files are written:
- `proof.bin` — the Groth16 proof (192 bytes: compressed G1 + G2 + G1)
- `proof.pub` — the public-input commitment (48 bytes: compressed G1)

## Build

```bash
cd groth16-prover/cli
cargo build --release
```

The binary will be at `target/release/groth16-prover`.

## How it works

1. **Load circuit** — parses the `.r1cs` binary format into dense L/R/O matrices
2. **Load witness** — parses the `.wtns` binary format into wire values
3. **Prove** — uses `FftQapEngine` + `PippengerProver` (FFT-accelerated QAP + batched MSM)
4. **Serialize** — outputs the proof using `ark-serialize` compressed format

## Complete example

```bash
# 1. Compile the Circom circuit
cd ../circom
circom multiplier.circom --r1cs --wasm --prime bls12381

# 2. Generate witness
snarkjs wtns calculate multiplier.wasm input.json witness.wtns

# 3. Prove
cd ../cli
cargo run --release -- prove \
  --circuit ../circom/multiplier.r1cs \
  --witness ../circom/witness.wtns \
  --out /tmp/proof.bin

# 4. Verify (from Rust code or any Groth16 verifier)
#    The proof format is standard arkworks compressed serialization.
```
