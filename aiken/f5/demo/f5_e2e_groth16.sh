#!/usr/bin/env bash
#
# F5 — Multi-User Private Pools: reproducible Groth16 end-to-end.
#
# N distinct users each deposit a note into the shared pool, then submit their
# 1-in / 2-out spend (one Groth16 proof per user) against the pool root at the
# time of their transaction.  All proofs are verified individually — this is
# the *current* Groth16 implementation (Impl 7, single-proof verify); later the
# pool is upgraded to batched/aggregated verification.
#
# On-chain artifacts per user:  $OUT/user_NNN.proof, user_NNN.pub
# Shared:                        $OUT/pp_vk.ak (for aiken/groth16)
# Scenario bookkeeping:          $OUT/scenario.json
# Timings (wall + Max RSS):      $OUT/timings.tsv
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
OUT="${OUT:-/tmp/f5_groth16}"
DEPTH="${DEPTH:-4}"
USERS="${USERS:-4}"
SPENDS="${SPENDS:-$USERS}"
SEED="${SEED:-42}"

# 2^DEPTH leaves: deposits + 2 outputs per spend must fit.
CAPACITY=$(( 2 ** DEPTH ))
if [ $(( USERS + 2 * SPENDS )) -gt "$CAPACITY" ]; then
  echo "error: tree capacity is $CAPACITY leaves (depth $DEPTH) but"
  echo "       USERS + 2*SPENDS = $(( USERS + 2 * SPENDS )). Reduce USERS/SPENDS or raise DEPTH."
  exit 2
fi

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"
TIME="/usr/bin/time"

# timed <phase> <who> <cmd...> -- runs cmd, logs "who phase wall rss" to timings.tsv
timed() {
  local phase="$1" who="$2"; shift 2
  local tf="$OUT/.t.$$"; : > "$tf"
  "$TIME" -f "%e %M" -o "$tf" "$@"
  awk -v u="$who" -v s="$phase" '{print u, s, $1, $2}' "$tf" >> "$OUT/timings.tsv"
  rm -f "$tf"
}

mkdir -p "$OUT"
echo "== F5 | multi-user Groth16 e2e (privacy pool, depth $DEPTH, $USERS users, $SPENDS spends, seed $SEED) =="

# 0. build the Rust CLIs
echo "[0/7] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. compile privacy_pool.circom
echo "[1/7] compiling privacy_pool.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"
CONSTRAINTS="$(snarkjs info -r "$OUT/privacy_pool.r1cs" 2>/dev/null \
  | grep -o '# of Constraints: [0-9]*' | grep -o '[0-9]*')"
[ -z "$CONSTRAINTS" ] && CONSTRAINTS="?"

# 2. generate the multi-user scenario via the pool simulation
echo "[2/7] generating multi-user scenario (pool simulation)..."
python3 "$SDIR/gen_multi_input.py" \
  --depth "$DEPTH" --users "$USERS" --spends "$SPENDS" --seed "$SEED" --out "$OUT"

# 3. witnesses
echo "[3/7] computing witnesses (one per user)..."
: > "$OUT/timings.tsv"
for f in "$OUT"/user_*.json; do
  u="$(basename "$f" .json)"
  rm -f "$OUT/$u.wtns"
  timed witness "$u" snarkjs wtns calculate \
    "$OUT/privacy_pool_js/privacy_pool.wasm" "$f" "$OUT/$u.wtns"
done

# 4. dev ceremony (once, shared across all users)
echo "[4/7] dev ceremony (--sparse)..."
timed ceremony all "$TS" ceremony-dev --sparse \
  --circuit "$OUT/privacy_pool.r1cs" \
  --proving-key "$OUT/pp.pk" --verifying-key "$OUT/pp.vk"

# 5. prove — one proof per user
echo "[5/7] proving (one proof per user)..."
for f in "$OUT"/user_*.json; do
  u="$(basename "$f" .json)"
  rm -f "$OUT/$u.proof" "$OUT/$u.pub"
  timed prove "$u" "$G16" prove --sparse \
    --circuit "$OUT/privacy_pool.r1cs" \
    --witness "$OUT/$u.wtns" \
    --proving-key "$OUT/pp.pk" --out "$OUT/$u.proof"
done

# 6. verify all proofs individually (current impl — linear) + export vk
echo "[6/7] verifying each proof (current impl, N x single verify)..."
for f in "$OUT"/user_*.proof; do
  u="$(basename "$f" .proof)"
  timed verify "$u" "$G16" verify \
    --proof "$f" --public "$OUT/$u.pub" --verifying-key "$OUT/pp.vk"
done
"$G16" export-vk --verifying-key "$OUT/pp.vk" --out "$OUT/pp_vk.ak"

# 7. summary
echo
echo "[7/7] summary"
PROOF_BYTES="$(wc -c < "$OUT/user_000.proof")"
echo "  constraints   : $CONSTRAINTS"
echo "  spend proofs  : $(ls "$OUT"/user_*.proof | wc -l)  ($PROOF_BYTES bytes each)"
echo "  aiken vk      : $OUT/pp_vk.ak"
echo
echo "  per-user breakdown (wall seconds / Max RSS KiB):"
awk '{printf "  %-12s %-8s %9.3f  %12d\n", $1, $2, $3, $4}' "$OUT/timings.tsv"
echo
echo "  phase totals (wall seconds):"
awk '{t[$2]+=$3; n[$2]++} END {for (p in t) printf "  %-8s %7.3f  (%d runs)\n", p, t[p], n[p]}' "$OUT/timings.tsv"

echo
echo "== result: ALL $((SPENDS)) PROOFS VALID =="
echo "   scenario : $OUT/scenario.json"
echo "   timings  : $OUT/timings.tsv"