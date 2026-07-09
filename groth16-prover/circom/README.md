# Circom circuit for the 3-gate multiplication chain

This directory contains the same 3-constraint circuit (`x1·x2 = x5`, `x3·x4 = x6`, `x5·x6 = a`) expressed in Circom language.

## Prerequisites

Install the Circom compiler (see [Circom installation docs](https://docs.circom.io/getting-started/installation/)):

```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```

Also install `snarkjs` for witness generation:

```bash
npm install -g snarkjs
```

## Compiling the circuit

```bash
cd groth16-prover/circom

# Compile to BLS12-381 (must match the Rust prover curve)
circom multiplier.circom --r1cs --wasm --sym --prime bls12381

# This produces:
#   multiplier.r1cs   — binary R1CS constraint system
#   multiplier.wasm   — WebAssembly witness calculator
#   multiplier.sym    — signal name map (human-readable)
```

## Generating the witness

Create `input.json` with the private inputs:

```json
{
    "x1": "2",
    "x2": "2",
    "x3": "3",
    "x4": "4"
}
```

Then run the WASM witness calculator via `snarkjs`:

```bash
snarkjs wtns calculate multiplier.wasm input.json witness.wtns
```

## Using in the Rust prover

The Rust crate can load `multiplier.r1cs` and `witness.wtns` directly:

```rust
use groth16_prover::circom_adapter::CircomCircuit;

let circuit = CircomCircuit::from_r1cs("circom/multiplier.r1cs").unwrap();
circuit.load_witness("circom/witness.wtns").unwrap();
```

The parsed `L`, `R`, `O` matrices and witness vector are then fed into any `QapEngine` + `Prover` combination, producing a proof identical to the hard-coded circuit.
