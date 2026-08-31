#!/usr/bin/env bash
#
# Step 5 — Compliant shielded transfer with FULL auditor reveal (amount +
# recipient address): reproducible Groth16 end-to-end.
#
# Builds on Step 4's `PrivacyPoolViewable` (Step 3 `PrivacyPool` + a Twisted
# ElGamal encryption of the amount to an auditor, reused verbatim) and adds a
# multi-message Twisted ElGamal ciphertext that encrypts the recipient's
# address id to the SAME auditor public key with SHARED randomness r:
#
#   E     = r * G
#   C     = in_amount   * H + r * pk_audit     (amount)
#   C_a0  = addr_limb0  * H + r * pk_audit     (address low  u16 limb)
#   C_a1  = addr_limb1  * H + r * pk_audit     (address high u16 limb)
#
# Public   : merkle_root, nullifier_hash, out_commitment_1, out_commitment_2,
#            fee,  pk_audit[2],  addr_commitment   (inputs)
#            E[2], C[2], C_a0[2], C_a1[2]          (outputs — auditor ciphertexts)
# Private  : pool witness (step 3) + audit_blinding (ephemeral r) + recipient_addr
#
# Only the auditor holding the viewing key sk_audit (pk_audit = sk_audit * G)
# recovers BOTH the amount and the address (via  m*H = C_x - sk_audit*E and
# small discrete logs).  gen_viewable_addr_input.py runs these decrypt checks
# and reports the recovered amount + recipient_addr.
#
# Emits on-chain artifacts: $OUT/pp.proof, pp.pub, pp_vk.ak (for aiken/groth16).
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
OUT="${OUT:-/tmp/sd_step5_groth16}"
DEPTH="${DEPTH:-4}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"
echo "== Step 5 | Groth16 e2e (full auditor reveal: amount + address, depth $DEPTH) =="

# 0. build the Rust CLIs
echo "[0/6] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. compile privacy_pool_viewable_addr.circom (Step 3 pool + amount + 2x address-limb ElGamal)
echo "[1/6] compiling privacy_pool_viewable_addr.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool_viewable_addr.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate witness input (in-place) + auditor full decrypt check
echo "[2/6] generating witness input (in-place) + auditor decrypt checks..."
( cd "$PP" && python3 gen_viewable_addr_input.py "$DEPTH" )
cp "$PP/input.json" "$OUT/input.json"
cp "$PP/auditor_meta.json" "$OUT/auditor_meta.json"

# 3. witness
echo "[3/6] computing witness..."
snarkjs wtns calculate "$OUT/privacy_pool_viewable_addr_js/privacy_pool_viewable_addr.wasm" \
  "$OUT/input.json" "$OUT/witness.wtns"

# 4. dev ceremony (--sparse) + prove (--sparse)
echo "[4/6] dev ceremony (--sparse) + prove (--sparse)..."
"$TS" ceremony-dev --sparse \
  --circuit "$OUT/privacy_pool_viewable_addr.r1cs" \
  --proving-key "$OUT/pp.pk" --verifying-key "$OUT/pp.vk"
"$G16" prove --sparse \
  --circuit "$OUT/privacy_pool_viewable_addr.r1cs" \
  --witness "$OUT/witness.wtns" \
  --proving-key "$OUT/pp.pk" --out "$OUT/pp.proof"

# 5. verify + export vk
echo "[5/6] verifying + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/pp.proof" --public "$OUT/pp.pub" --verifying-key "$OUT/pp.vk"
"$G16" export-vk --verifying-key "$OUT/pp.vk" --out "$OUT/pp_vk.ak"

# 6. auditor viewing-key reveal (off-chain decrypt) — recovered amount + address
echo "[6/6] auditor viewing-key reveal (off-chain decrypt)..."
python3 - "$OUT/auditor_meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
print(f"   auditor sk_audit    = {meta['sk_audit']}")
print(f"   pk_audit            = ({meta['pk_audit'][0][:16]}..., {meta['pk_audit'][1][:16]}...)")
print(f"   public E            = ({meta['E'][0][:16]}..., {meta['E'][1][:16]}...)")
print(f"   public C  (amount)  = ({meta['C'][0][:16]}..., {meta['C'][1][:16]}...)")
print(f"   public C_a0 (addr0) = ({meta['C_a0'][0][:16]}..., {meta['C_a0'][1][:16]}...)")
print(f"   public C_a1 (addr1) = ({meta['C_a1'][0][:16]}..., {meta['C_a1'][1][:16]}...)")
print(f"   revealed amount     = {meta['amount']}      (C  - sk_audit*E == amount*H)")
print(f"   revealed address    = 0x{int(meta['recipient_addr']):x} "
      f"(limbs {meta['addr_limb0']}/{meta['addr_limb1']}, Poseidon(addr,nullifier)==addr_commitment)")
PY

echo
echo "== result: VALID =="
echo "   proof    : $OUT/pp.proof"
echo "   public   : $OUT/pp.pub"
echo "   aiken vk : $OUT/pp_vk.ak"
