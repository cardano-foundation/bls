#!/usr/bin/env bash
#
# Step 4 — Compliant shielded transfer (viewing-key auditor reveal):
# reproducible Groth16 end-to-end.
#
# Builds on Step 3's PrivacyPool (shielded 1-in / 2-out spend, reused verbatim
# via privacy_pool_lib.circom) and additionally encrypts the private input
# amount to a designated auditor's public key with Twisted ElGamal:
#
#   E = r * G,   C = in_amount * H + r * pk_audit
#
# Public   : merkle_root, nullifier_hash, out_commitment_1, out_commitment_2,
#            fee,  pk_audit[2]        (inputs)
#            E[2],  C[2]              (outputs — the auditor ciphertext)
# Private  : pool witness (step 3) + audit_blinding (ephemeral r)
#
# Only the auditor holding the viewing key sk_audit (pk_audit = sk_audit * G)
# can recover in_amount from the public ciphertext:  in_amount * H = C - sk_audit*E.
# gen_viewable_input.py runs this decrypt check and reports  in_amount.
#
# Emits on-chain artifacts: $OUT/pp.proof, pp.pub, pp_vk.ak (for aiken/groth16).
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
OUT="${OUT:-/tmp/sd_step4_groth16}"
DEPTH="${DEPTH:-4}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"
echo "== Step 4 | Groth16 e2e (compliant shielded transfer, depth $DEPTH) =="

# 0. build the Rust CLIs
echo "[0/6] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. compile privacy_pool_viewable.circom (Step 3 pool + auditor ElGamal)
echo "[1/6] compiling privacy_pool_viewable.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool_viewable.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate witness input (in-place) + auditor viewing-key reveal check
echo "[2/6] generating witness input (in-place) + auditor decrypt check..."
( cd "$PP" && python3 gen_viewable_input.py "$DEPTH" )
cp "$PP/input.json" "$OUT/input.json"
cp "$PP/auditor_meta.json" "$OUT/auditor_meta.json"

# 3. witness
echo "[3/6] computing witness..."
snarkjs wtns calculate "$OUT/privacy_pool_viewable_js/privacy_pool_viewable.wasm" \
  "$OUT/input.json" "$OUT/witness.wtns"

# 4. dev ceremony (--sparse) + prove (--sparse)
echo "[4/6] dev ceremony (--sparse) + prove (--sparse)..."
"$TS" ceremony-dev --sparse \
  --circuit "$OUT/privacy_pool_viewable.r1cs" \
  --proving-key "$OUT/pp.pk" --verifying-key "$OUT/pp.vk"
"$G16" prove --sparse \
  --circuit "$OUT/privacy_pool_viewable.r1cs" \
  --witness "$OUT/witness.wtns" \
  --proving-key "$OUT/pp.pk" --out "$OUT/pp.proof"

# 5. verify + export vk
echo "[5/6] verifying + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/pp.proof" --public "$OUT/pp.pub" --verifying-key "$OUT/pp.vk"
"$G16" export-vk --verifying-key "$OUT/pp.vk" --out "$OUT/pp_vk.ak"

# 6. auditor viewing-key reveal (off-chain decrypt) — recovered amount
echo "[6/6] auditor viewing-key reveal (off-chain decrypt)..."
python3 - "$OUT/auditor_meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
print(f"   auditor sk_audit  = {meta['sk_audit']}")
print(f"   pk_audit          = ({meta['pk_audit'][0][:16]}..., {meta['pk_audit'][1][:16]}...)")
print(f"   public E          = ({meta['E'][0][:16]}..., {meta['E'][1][:16]}...)")
print(f"   public C          = ({meta['C'][0][:16]}..., {meta['C'][1][:16]}...)")
print(f"   revealed amount   = {meta['amount']}  (C - sk_audit*E == amount*H)")
PY

echo
echo "== result: VALID =="
echo "   proof    : $OUT/pp.proof"
echo "   public   : $OUT/pp.pub"
echo "   aiken vk : $OUT/pp_vk.ak"
