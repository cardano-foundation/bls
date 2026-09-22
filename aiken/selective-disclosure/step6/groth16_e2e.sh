#!/usr/bin/env bash
#
# Step 6 — Multi-User Batch Privacy Pool with Full Auditor Reveal
#
# Marries F5 (multi-user batch verification, N proofs → 1 check) with Step 5
# (full auditor reveal: amount + recipient address encrypted to pk_audit).
#
# N distinct users each deposit a note into the shared pool, then submit a
# shielded 1-in/2-out spend whose private amount AND recipient address are
# encrypted to a designated auditor's public key.  All N proofs are verified
# in a single batch multi-pairing product.  The auditor — holding sk_audit —
# decrypts every amount and address off-chain from the public ciphertexts.
#
#   E     = r * G
#   C     = in_amount   * H + r * pk_audit
#   C_a0  = addr_limb0  * H + r * pk_audit
#   C_a1  = addr_limb1  * H + r * pk_audit
#
# Public inputs per proof: merkle_root, nullifier_hash, out_commitment_1,
#   out_commitment_2, fee, pk_audit[2], addr_commitment
# Public outputs per proof: E[2], C[2], C_a0[2], C_a1[2]
#
# On-chain artifacts per user: $OUT/user_NNN.proof, user_NNN.pub
# Shared:                       $OUT/pp_vk.ak
# Scenario:                     $OUT/scenario.json
# Auditor decrypt data:         $OUT/auditor_meta.json
# Timings:                      $OUT/timings.tsv
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
DEMO="$ROOT/aiken/f5/demo"
OUT="${OUT:-/tmp/sd_step6_groth16}"
DEPTH="${DEPTH:-4}"
USERS="${USERS:-4}"
SPENDS="${SPENDS:-$USERS}"
SEED="${SEED:-42}"

CAPACITY=$(( 2 ** DEPTH ))
if [ $(( USERS + 2 * SPENDS )) -gt "$CAPACITY" ]; then
  echo "error: tree capacity is $CAPACITY leaves (depth $DEPTH) but"
  echo "       USERS + 2*SPENDS = $(( USERS + 2 * SPENDS )). Reduce USERS/SPENDS or raise DEPTH."
  exit 2
fi

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"
TIME="/usr/bin/time"

# timed <phase> <who> <cmd...>
timed() {
  local phase="$1" who="$2"; shift 2
  local tf="$OUT/.t.$$"; : > "$tf"
  "$TIME" -f "%e %M" -o "$tf" "$@"
  awk -v u="$who" -v s="$phase" '{print u, s, $1, $2}' "$tf" >> "$OUT/timings.tsv"
  rm -f "$tf"
}

mkdir -p "$OUT"
echo "== Step 6 | Multi-User Batch Pool + Full Auditor Reveal (depth $DEPTH, $USERS users, $SPENDS spends, seed $SEED) =="

# 0. build the Rust CLIs
echo "[0/9] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. compile privacy_pool_viewable_addr.circom
echo "[1/9] compiling privacy_pool_viewable_addr.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool_viewable_addr.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l "$PP" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"
CONSTRAINTS="$(snarkjs info -r "$OUT/privacy_pool_viewable_addr.r1cs" 2>/dev/null \
  | grep -o '# of Constraints: [0-9]*' | grep -o '[0-9]*')"
[ -z "$CONSTRAINTS" ] && CONSTRAINTS="?"

# 2. generate multi-user scenario with auditor fields
echo "[2/9] generating multi-user scenario with auditor reveal..."
python3 "$DEMO/gen_multi_viewable_addr_input.py" \
  --depth "$DEPTH" --users "$USERS" --spends "$SPENDS" --seed "$SEED" --out "$OUT"

# 3. witnesses (one per user)
echo "[3/9] computing witnesses (one per user)..."
: > "$OUT/timings.tsv"
for f in "$OUT"/user_*.json; do
  u="$(basename "$f" .json)"
  rm -f "$OUT/$u.wtns"
  timed witness "$u" snarkjs wtns calculate \
    "$OUT/privacy_pool_viewable_addr_js/privacy_pool_viewable_addr.wasm" "$f" "$OUT/$u.wtns"
done

# 4. dev ceremony (once, shared)
echo "[4/9] dev ceremony (--sparse)..."
timed ceremony all "$TS" ceremony-dev --sparse \
  --circuit "$OUT/privacy_pool_viewable_addr.r1cs" \
  --proving-key "$OUT/pp.pk" --verifying-key "$OUT/pp.vk"

# 5. prove — one proof per user
echo "[5/9] proving (one proof per user)..."
for f in "$OUT"/user_*.json; do
  u="$(basename "$f" .json)"
  rm -f "$OUT/$u.proof" "$OUT/$u.pub"
  timed prove "$u" "$G16" prove --sparse \
    --circuit "$OUT/privacy_pool_viewable_addr.r1cs" \
    --witness "$OUT/$u.wtns" \
    --proving-key "$OUT/pp.pk" --out "$OUT/$u.proof"
done

# 6. verify individually (linear baseline)
echo "[6/9] verifying each proof individually..."
for f in "$OUT"/user_*.proof; do
  u="$(basename "$f" .proof)"
  timed verify "$u" "$G16" verify \
    --proof "$f" --public "$OUT/$u.pub" --verifying-key "$OUT/pp.vk"
done

# 7. batch verify — one multi-pairing product for ALL proofs
echo "[7/9] batch verifying all proofs (Impl 11)..."
BATCH_ARGS=()
for f in "$OUT"/user_*.proof; do
  u="$(basename "$f" .proof)"
  BATCH_ARGS+=(--proof "$f" --public "$OUT/$u.pub")
done
timed batch-verify all "$G16" verify-batch \
  --verifying-key "$OUT/pp.vk" \
  "${BATCH_ARGS[@]}"

"$G16" export-vk --verifying-key "$OUT/pp.vk" --out "$OUT/pp_vk.ak"

# 8. auditor viewing-key reveal (off-chain decrypt all users)
echo "[8/9] auditor viewing-key reveal (all users)..."
python3 - "$OUT/auditor_meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
aud = meta["auditor"]
print(f"auditor sk_audit = {aud['sk_audit']}")
print(f"auditor pk_audit = ({aud['pk_audit'][0][:16]}..., {aud['pk_audit'][1][:16]}...)")
print("")
for s in meta["spends"]:
    u = s["user"]
    print(f"  {u}:")
    print(f"    amount          = {s['amount']}")
    print(f"    recipient_addr  = 0x{int(s['recipient_addr']):x}  (limbs {s['addr_limb0']}/{s['addr_limb1']})")
    print(f"    addr_commitment = {s['addr_commitment'][:16]}...")
    print(f"    E               = ({s['E'][0][:16]}..., {s['E'][1][:16]}...)")
    print(f"    C  (amount)     = ({s['C'][0][:16]}..., {s['C'][1][:16]}...)")
PY

# 9. summary
echo
echo "[9/9] summary"
PROOF_BYTES="$(wc -c < "$OUT/user_000.proof")"
echo "  constraints   : $CONSTRAINTS"
echo "  spend proofs  : $(ls "$OUT"/user_*.proof | wc -l)  ($PROOF_BYTES bytes each)"
echo "  aiken vk      : $OUT/pp_vk.ak"
echo "  scenario      : $OUT/scenario.json"
echo "  auditor meta  : $OUT/auditor_meta.json"
echo
echo "  per-user breakdown (wall seconds / Max RSS KiB):"
awk '{printf "  %-12s %-8s %9.3f  %12d\n", $1, $2, $3, $4}' "$OUT/timings.tsv"
echo
echo "  phase totals (wall seconds):"
awk '{t[$2]+=$3; n[$2]++} END {for (p in t) printf "  %-8s %7.3f  (%d runs)\n", p, t[p], n[p]}' "$OUT/timings.tsv"

# batch speedup
VERIFY_TOTAL=$(awk '$2=="verify" {t+=$3} END {printf "%.3f", t}' "$OUT/timings.tsv")
BATCH_TOTAL=$(awk '$2=="batch-verify" {t+=$3} END {printf "%.3f", t}' "$OUT/timings.tsv")
if [ -n "$VERIFY_TOTAL" ] && [ -n "$BATCH_TOTAL" ] && [ "$VERIFY_TOTAL" != "0.000" ]; then
  RATIO=$(awk -v v="$VERIFY_TOTAL" -v b="$BATCH_TOTAL" 'BEGIN {printf "%.1f", v/b}')
  echo
echo "  batch speedup : ${VERIFY_TOTAL}s (individual) → ${BATCH_TOTAL}s (batch) = ${RATIO}×"
fi

echo
echo "== result: ALL $((SPENDS)) PROOFS VALID =="
echo "   Every user's amount and recipient address are encrypted to the auditor."
echo "   Only sk_audit can decrypt; the batch check verified all proofs in one go."
