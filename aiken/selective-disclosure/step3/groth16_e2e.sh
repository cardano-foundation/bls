#!/usr/bin/env bash
#
# Step 3 — Privacy Pool: reproducible Groth16 end-to-end (shielded transfer).
# 1-in / 2-out spend: Merkle membership + nullifier uniqueness + range checks
# + conservation (in == out1 + out2 + fee), ~7.1K constraints at depth 4.
#
#   Public : merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee
#   Private: nullifier, in_amount, in_blinding, out_{nullifier,amount,blinding}*,
#            sibling[4], direction[4]
#
# Emits on-chain artifacts: $OUT/pp.proof, pp.pub, pp_vk.ak (for aiken/groth16).
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
OUT="${OUT:-/tmp/sd_step3_groth16}"
DEPTH="${DEPTH:-4}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"
echo "== Step 3 | Groth16 e2e (privacy pool, depth $DEPTH) =="

# 0. build the Rust CLIs
echo "[0/5] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. compile privacy_pool.circom
echo "[1/5] compiling privacy_pool.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate witness input (must run in-place for its Poseidon helper path)
echo "[2/5] generating witness input..."
( cd "$PP" && python3 gen_privacy_input.py "$DEPTH" )
cp "$PP/input.json" "$OUT/input.json"

# 3. witness
echo "[3/5] computing witness..."
snarkjs wtns calculate "$OUT/privacy_pool_js/privacy_pool.wasm" \
  "$OUT/input.json" "$OUT/witness.wtns"

# 4. dev ceremony (--sparse for this circuit's size) + prove (--sparse)
echo "[4/5] dev ceremony (--sparse) + prove (--sparse)..."
"$TS" ceremony-dev --sparse \
  --circuit "$OUT/privacy_pool.r1cs" \
  --proving-key "$OUT/pp.pk" --verifying-key "$OUT/pp.vk"
"$G16" prove --sparse \
  --circuit "$OUT/privacy_pool.r1cs" \
  --witness "$OUT/witness.wtns" \
  --proving-key "$OUT/pp.pk" --out "$OUT/pp.proof"

# 5. verify + export vk
echo "[5/5] verifying + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/pp.proof" --public "$OUT/pp.pub" --verifying-key "$OUT/pp.vk"
"$G16" export-vk --verifying-key "$OUT/pp.vk" --out "$OUT/pp_vk.ak"

echo
echo "== result: VALID =="
echo "   proof    : $OUT/pp.proof"
echo "   public   : $OUT/pp.pub"
echo "   aiken vk : $OUT/pp_vk.ak"
