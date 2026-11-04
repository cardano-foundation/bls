#!/usr/bin/env bash
#
# Step 11 — Private Token Lifecycle inside a Selective-Disclosure Vehicle
#
# Extends Step 10 by binding every shielded pool spend to real Pedersen token
# commitments.  For each spend the circuit proves:
#
#   1. A valid privacy-pool note spend (Merkle membership, nullifier, conservation).
#   2. The chosen auditor is in the current active-set Merkle tree.
#   3. Input and output token commitments open to the pool amounts.
#   4. Token value is conserved: token_in = token_out1 + token_out2 + fee.
#   5. Amount and recipient address are encrypted to the chosen auditor.
#
# This models a CIP-113-style private token moving through the pool: the ledger
# sees token UTxOs and commitments, while the real value stays hidden and is
# auditable only by the active auditor holding the viewing key.
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
OUT="${OUT:-/tmp/sd_step11_groth16}"
DEPTH="${DEPTH:-4}"
AUDITOR_DEPTH="${AUDITOR_DEPTH:-4}"
USERS="${USERS:-4}"
SPENDS="${SPENDS:-$USERS}"
AUDITORS="${AUDITORS:-4}"
SEED="${SEED:-42}"

CAPACITY=$(( 2 ** DEPTH ))
if [ $(( USERS + 2 * SPENDS )) -gt "$CAPACITY" ]; then
  echo "error: tree capacity is $CAPACITY leaves (depth $DEPTH) but"
  echo "       USERS + 2*SPENDS = $(( USERS + 2 * SPENDS )). Reduce USERS/SPENDS or raise DEPTH."
  exit 2
fi

AUDITOR_CAPACITY=$(( 2 ** AUDITOR_DEPTH ))
if [ "$AUDITORS" -gt "$AUDITOR_CAPACITY" ]; then
  echo "error: auditor tree capacity is $AUDITOR_CAPACITY leaves (auditor-depth $AUDITOR_DEPTH)"
  echo "       but AUDITORS = $AUDITORS. Reduce AUDITORS or raise AUDITOR_DEPTH."
  exit 2
fi

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"
TIME="/usr/bin/time"

timed() {
  local phase="$1" who="$2"; shift 2
  local tf="$OUT/.t.$$"; : > "$tf"
  "$TIME" -f "%e %M" -o "$tf" "$@"
  awk -v u="$who" -v s="$phase" '{print u, s, $1, $2}' "$tf" >> "$OUT/timings.tsv"
  rm -f "$tf"
}

mkdir -p "$OUT"
echo "== Step 11 | Private Token Lifecycle (depth $DEPTH, auditor-depth $AUDITOR_DEPTH, $USERS users, $SPENDS spends, $AUDITORS auditors, seed $SEED) =="

# 0. build the Rust CLIs
echo "[0/9] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. compile privacy_pool_token_lifecycle.circom
echo "[1/9] compiling privacy_pool_token_lifecycle.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool_token_lifecycle.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l "$PP" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"
CONSTRAINTS="$(snarkjs info -r "$OUT/privacy_pool_token_lifecycle.r1cs" 2>/dev/null \
  | grep -o '# of Constraints: [0-9]*' | grep -o '[0-9]*')"
[ -z "$CONSTRAINTS" ] && CONSTRAINTS="?"

# 2. generate multi-user scenario with token lifecycle fields
echo "[2/9] generating multi-user scenario with token lifecycle..."
python3 "$PP/gen_token_lifecycle_input.py" \
  --depth "$DEPTH" --auditor-depth "$AUDITOR_DEPTH" \
  --users "$USERS" --spends "$SPENDS" --auditors "$AUDITORS" --seed "$SEED" --out "$OUT"

# 3. witnesses (one per user)
echo "[3/9] computing witnesses (one per user)..."
: > "$OUT/timings.tsv"
for f in "$OUT"/user_*.json; do
  u="$(basename "$f" .json)"
  rm -f "$OUT/$u.wtns"
  timed witness "$u" snarkjs wtns calculate \
    "$OUT/privacy_pool_token_lifecycle_js/privacy_pool_token_lifecycle.wasm" "$f" "$OUT/$u.wtns"
done

# 4. dev ceremony (once, shared)
echo "[4/9] dev ceremony (--sparse)..."
timed ceremony all "$TS" ceremony-dev --sparse \
  --circuit "$OUT/privacy_pool_token_lifecycle.r1cs" \
  --proving-key "$OUT/pp.pk" --verifying-key "$OUT/pp.vk"

# 5. prove — one proof per user
echo "[5/9] proving (one proof per user)..."
for f in "$OUT"/user_*.json; do
  u="$(basename "$f" .json)"
  rm -f "$OUT/$u.proof" "$OUT/$u.pub"
  timed prove "$u" "$G16" prove --sparse \
    --circuit "$OUT/privacy_pool_token_lifecycle.r1cs" \
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

# 8. token conservation + auditor reveal checks
echo "[8/9] token conservation + auditor viewing-key reveal (all users)..."
python3 - "$OUT/auditor_meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
print(f"auditor_root = {meta['auditor_root']}")
print(f"active auditors = {len(meta['auditor_set'])}")
print("")
for s in meta["spends"]:
    u = s["user"]
    tin = int(s["token_in_value"])
    t1 = int(s["token_out1_value"])
    t2 = int(s["token_out2_value"])
    fee = int(s["fee"])
    conserved = (tin == t1 + t2 + fee)
    print(f"  {u}:")
    print(f"    auditor_index   = {s['auditor_index']}")
    print(f"    token values    = {tin} -> {t1} + {t2} + fee {fee}  ({'CONSERVED' if conserved else 'BROKEN'})")
    print(f"    amount          = {s['amount']}")
    print(f"    recipient_addr  = 0x{int(s['recipient_addr']):x}  (limbs {s['addr_limb0']}/{s['addr_limb1']})")
    print(f"    token_in_commitment  = ({s['token_in_commitment'][0][:16]}..., {s['token_in_commitment'][1][:16]}...)")
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

VERIFY_TOTAL=$(awk '$2=="verify" {t+=$3} END {printf "%.3f", t}' "$OUT/timings.tsv")
BATCH_TOTAL=$(awk '$2=="batch-verify" {t+=$3} END {printf "%.3f", t}' "$OUT/timings.tsv")
if [ -n "$VERIFY_TOTAL" ] && [ -n "$BATCH_TOTAL" ] && [ "$VERIFY_TOTAL" != "0.000" ]; then
  RATIO=$(awk -v v="$VERIFY_TOTAL" -v b="$BATCH_TOTAL" 'BEGIN {printf "%.1f", v/b}')
  echo
  echo "  batch speedup : ${VERIFY_TOTAL}s (individual) → ${BATCH_TOTAL}s (batch) = ${RATIO}×"
fi

echo
echo "== result: ALL $((SPENDS)) PROOFS VALID =="
echo "   Each spend proves token-value conservation inside the privacy pool."
echo "   Amount + address are encrypted to a dynamically chosen active auditor."
