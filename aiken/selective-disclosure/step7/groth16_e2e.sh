#!/usr/bin/env bash
#
# Step 7 — Revocable Predicate Proofs: reproducible Groth16 end-to-end.
#
# Extends Step 1 with two production features:
#   1. Expiry:  credential has an expiry_year; the circuit checks
#      expiry_year >= current_year.
#   2. Revocation:  the issuer maintains a Sparse Merkle Tree of revoked
#      credentials.  The holder proves non-membership via a path from the
#      default empty leaf (0) at their credential's position.
#
# Circuit: predicate_revocable_depth2.circom
# Generator: gen_revocable_input.py
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
REV="$ROOT/circom/Revocation"
OUT="${OUT:-/tmp/sd_step7_groth16}"
DEPTH="${DEPTH:-2}"
REV_DEPTH="${REV_DEPTH:-2}"
SEED="${SEED:-1}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"

echo "== Step 7 | Groth16 e2e (revocable predicate: expiry + revocation) =="
echo "   repo : $ROOT"
echo "   out  : $OUT"

# 0. build the two Rust CLIs
echo "[0/6] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. generate deterministic witness input (with expiry and revocation proof)
echo "[1/6] generating revocable witness input (seed=$SEED)..."
cd "$REV"
python3 gen_revocable_input.py --depth "$DEPTH" --revocation-depth "$REV_DEPTH" \
  --seed "$SEED" --output "$OUT/input.json"
cd "$ROOT"

# 2. compile the circuit
echo "[2/6] compiling predicate_revocable_depth2.circom (BLS12-381)..."
cd "$REV"
circom predicate_revocable_depth2.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ../PoseidonMerkle
cd "$ROOT"

# 3. witness
echo "[3/6] computing witness..."
snarkjs wtns calculate "$OUT/predicate_revocable_depth2_js/predicate_revocable_depth2.wasm" \
  "$OUT/input.json" "$OUT/predicate_revocable.wtns"

# 4. dev ceremony
echo "[4/6] dev trusted-setup ceremony..."
"$TS" ceremony-dev --sparse \
  --circuit "$OUT/predicate_revocable_depth2.r1cs" \
  --proving-key "$OUT/predicate_revocable.pk" \
  --verifying-key "$OUT/predicate_revocable.vk"

# 5. prove
echo "[5/6] generating Groth16 proof..."
"$G16" prove --sparse \
  --circuit "$OUT/predicate_revocable_depth2.r1cs" \
  --witness "$OUT/predicate_revocable.wtns" \
  --proving-key "$OUT/predicate_revocable.pk" \
  --out "$OUT/predicate_revocable.proof"

# 6. verify + export vk
echo "[6/6] verifying + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/predicate_revocable.proof" \
  --public "$OUT/predicate_revocable.pub" \
  --verifying-key "$OUT/predicate_revocable.vk"
"$G16" export-vk \
  --verifying-key "$OUT/predicate_revocable.vk" \
  --out "$OUT/predicate_revocable_vk.ak"

echo
echo "== result: VALID =="
echo "   proof     : $OUT/predicate_revocable.proof"
echo "   public    : $OUT/predicate_revocable.pub"
echo "   aiken vk  : $OUT/predicate_revocable_vk.ak"
