# groth16-prover-cli

Command-line interface for generating Groth16 zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).

## Usage

```bash
# Generate a proof and print hex to stdout (defaults: --engine fft --prover pippenger)
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns

# Generate a proof and write raw binary to file
groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --out proof.bin
```

### All engine + prover combinations

```bash
# 1. fft + pippenger   (default — fastest, recommended for production)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine fft --prover pippenger

# 2. fft + naive       (good for debugging FFT path; same proof points as pippenger)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine fft --prover naive

# 3. dense + pippenger (fast MSM but slow QAP; useful for parity testing)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine dense --prover pippenger

# 4. dense + naive     (pedagogical — every step is scalar-by-scalar, easiest to trace)
groth16-prover prove --circuit c.r1cs --witness w.wtns --engine dense --prover naive
```

### Flags

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--circuit FILE` | — | *required* | Path to `.r1cs` circuit file |
| `--witness FILE` | — | *required* | Path to `.wtns` witness file |
| `--engine ENGINE` | `dense`, `fft` | `fft` | QAP construction engine |
| `--prover PROVER` | `naive`, `pippenger` | `pippenger` | MSM strategy for proof assembly |
| `--out FILE` | — | — | Output file (raw binary); public input written to `FILE.pub` |

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
3. **Prove** — by default uses `FftQapEngine` + `PippengerProver` (FFT-accelerated QAP + batched MSM); can be switched to `DenseQapEngine` or `NaiveProver` via flags
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
