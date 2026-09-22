#!/usr/bin/env bash
#
# Step 8 — Anonymous Delegation: reproducible Groth16 end-to-end.
#
# A holder delegates proof-generation rights to a proxy.  The proxy can
# generate the ZK proof but cannot forge proofs for other holders or circuits.
#
# Circuit: predicate_delegatable_depth2.circom
# Generator: gen_delegation_input.py
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
DEL="$ROOT/circom/Delegation"
OUT="${OUT:-/tmp/sd_step8_groth16}"
DEPTH="${DEPTH:-2}"
SEED="${SEED:-1}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"

echo "== Step 8 | Groth16 e2e (anonymous delegation) =="
echo "   repo : $ROOT"
echo "   out  : $OUT"

# 0. build the two Rust CLIs
echo "[0/6] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. generate witness input (with delegation token)
echo "[1/6] generating delegatable witness input (seed=$SEED)..."
cd "$DEL"
python3 gen_delegation_input.py --depth "$DEPTH" --seed "$SEED" --output "$OUT/input.json"
cd "$ROOT"

# 2. compile the circuit
echo "[2/6] compiling predicate_delegatable_depth2.circom (BLS12-381)..."
cd "$DEL"
circom predicate_delegatable_depth2.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ../PoseidonMerkle
cd "$ROOT"

# 3. witness
echo "[3/6] computing witness..."
snarkjs wtns calculate "$OUT/predicate_delegatable_depth2_js/predicate_delegatable_depth2.wasm" \
  "$OUT/input.json" "$OUT/predicate_delegatable.wtns"

# 4. dev ceremony
echo "[4/6] dev trusted-setup ceremony..."
"$TS" ceremony-dev --sparse \
  --circuit "$OUT/predicate_delegatable_depth2.r1cs" \
  --proving-key "$OUT/predicate_delegatable.pk" \
  --verifying-key "$OUT/predicate_delegatable.vk"

# 5. prove
echo "[5/6] generating Groth16 proof..."
"$G16" prove --sparse \
  --circuit "$OUT/predicate_delegatable_depth2.r1cs" \
  --witness "$OUT/predicate_delegatable.wtns" \
  --proving-key "$OUT/predicate_delegatable.pk" \
  --out "$OUT/predicate_delegatable.proof"

# 6. verify + export vk
echo "[6/6] verifying + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/predicate_delegatable.proof" \
  --public "$OUT/predicate_delegatable.pub" \
  --verifying-key "$OUT/predicate_delegatable.vk"
"$G16" export-vk \
  --verifying-key "$OUT/predicate_delegatable.vk" \
  --out "$OUT/predicate_delegatable_vk.ak"

echo
echo "== result: VALID =="
echo "   proof     : $OUT/predicate_delegatable.proof"
echo "   public    : $OUT/predicate_delegatable.pub"
echo "   aiken vk  : $OUT/predicate_delegatable_vk.ak"
