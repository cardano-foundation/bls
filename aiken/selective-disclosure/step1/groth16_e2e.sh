#!/usr/bin/env bash
#
# Step 1 — Predicate Proofs: reproducible Groth16 end-to-end.
#
# Reproduces, from scratch, a VALID Groth16 proof that the holder satisfies
# `age >= 21 AND country is in the approved set`, over a signed credential.
#
#   Public : pku, pkv, current_year, country_root, eligible(=1)
#   Private: dob_year, country, Ru, Rv, S, sibling[2], direction[2]
#
# Off-chain pipeline: input gen -> circom compile -> snarkjs witness
#   -> dev trusted-setup ceremony (--sparse) -> prove (--sparse) -> verify.
# Emits the artifacts the on-chain Aiken `gate` validator consumes:
#   $OUT/predicate.proof, $OUT/predicate.pub and $OUT/predicate_vk.ak
#   (the latter is pasted into aiken/groth16's gate validator).
#
# Run from anywhere: repo root is auto-detected.
set -euo pipefail

# --- repo layout ------------------------------------------------------------
SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PRED="$ROOT/circom/Predicate"
OUT="${OUT:-/tmp/sd_step1_groth16}"
DEPTH="${DEPTH:-2}"
SEED="${SEED:-1}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"

echo "== Step 1 | Groth16 e2e =="
echo "   repo : $ROOT"
echo "   out  : $OUT"

# 0. build the two Rust CLIs (idempotent)
echo "[0/6] building Rust CLIs (trusted-setup, groth16)..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. deterministic off-chain scenario
echo "[1/6] generating deterministic witness input (seed=$SEED, depth=$DEPTH)..."
python3 "$PRED/gen_predicate_input.py" --depth "$DEPTH" --seed "$SEED" \
  --output "$OUT/input.json"

# 2. compile the circuit
echo "[2/6] compiling predicate_depth2.circom (BLS12-381)..."
cd "$PRED"
circom predicate_depth2.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits
cd "$ROOT"

# 3. witness
echo "[3/6] computing witness..."
snarkjs wtns calculate "$OUT/predicate_depth2_js/predicate_depth2.wasm" \
  "$OUT/input.json" "$OUT/predicate.wtns"

# 4. dev ceremony (--sparse for this ~10.4K-constraint circuit)
echo "[4/6] dev trusted-setup ceremony (--sparse)..."
"$TS" ceremony-dev --sparse \
  --circuit "$OUT/predicate_depth2.r1cs" \
  --proving-key "$OUT/predicate.pk" \
  --verifying-key "$OUT/predicate.vk"

# 5. prove (holder device)
echo "[5/6] generating Groth16 proof (--sparse)..."
"$G16" prove --sparse \
  --circuit "$OUT/predicate_depth2.r1cs" \
  --witness "$OUT/predicate.wtns" \
  --proving-key "$OUT/predicate.pk" \
  --out "$OUT/predicate.proof"

# 6. verify + export vk for on-chain Aiken gate
echo "[6/6] verifying off-chain + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/predicate.proof" \
  --public "$OUT/predicate.pub" \
  --verifying-key "$OUT/predicate.vk"
"$G16" export-vk \
  --verifying-key "$OUT/predicate.vk" \
  --out "$OUT/predicate_vk.ak"

echo
echo "== result: VALID =="
echo "   proof     : $OUT/predicate.proof"
echo "   public    : $OUT/predicate.pub"
echo "   aiken vk  : $OUT/predicate_vk.ak  (paste into aiken/groth16 gate validator)"
