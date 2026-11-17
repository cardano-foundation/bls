#!/usr/bin/env bash
#
# Step 11 — Private Token Lifecycle with Dynamic Auditor: NovaSlim e2e.
#
# NovaSlim path for the Step 11 circuit.  Each user folds a single step that
# proves the full token-lifecycle spend:
#
#   * valid privacy-pool note spend (Merkle membership, nullifier, conservation),
#   * dynamic-auditor membership of pk_audit,
#   * Twisted-ElGamal encryption of amount + address to the auditor,
#   * Pedersen token commitments conserving value (in = out1 + out2 + fee).
#
# NovaSlim requires exactly one public input (state_in) and one public output
# (state_out).  All per-step public data is committed into state_out by the
# circuit; the witness generator reproduces that commitment off-chain so the
# e2e script can sanity-check it after witness calculation.
#
# No trusted setup is required.
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step11_novaslim}"
USERS="${USERS:-1}"
SPENDS="${SPENDS:-$USERS}"
AUDITORS="${AUDITORS:-4}"
DEPTH="${DEPTH:-4}"
AUDITOR_DEPTH="${AUDITOR_DEPTH:-4}"
SEED="${SEED:-42}"
# The 63k-constraint step circuit folds in ~3-4 min per user on this machine.
# Increase USERS/SPENDS only if you have the wall-clock time.

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi

mkdir -p "$OUT"
echo "== Step 11 | NovaSlim e2e (token lifecycle, $USERS users, $SPENDS spends, $AUDITORS auditors, seed $SEED) =="

# 1. compile the Nova step circuit
echo "[1/5] compiling privacy_pool_token_lifecycle_nova.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool_token_lifecycle_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate multi-user scenario with token lifecycle fields
echo "[2/5] generating multi-user scenario with token lifecycle fields..."
python3 "$PP/gen_token_lifecycle_input.py" \
  --depth "$DEPTH" --auditor-depth "$AUDITOR_DEPTH" \
  --users "$USERS" --spends "$SPENDS" --auditors "$AUDITORS" --seed "$SEED" --out "$OUT"

# 3. build per-user Nova step witnesses and expected state_out values
echo "[3/5] building per-user Nova step witnesses..."
python3 "$PP/gen_token_lifecycle_nova_steps.py" "$OUT/scenario.json" "$OUT/steps"

# 4. fold + compress per user
echo "[4/5] folding + compressing per user..."
: > "$OUT/timings.tsv"
for i in $(seq 0 $((SPENDS - 1))); do
  u="user_$(printf "%03d" $i)"
  usteps="$OUT/steps/$u"

  # calculate snarkjs witness from the Nova step input
  snarkjs wtns calculate \
    "$OUT/privacy_pool_token_lifecycle_nova_js/privacy_pool_token_lifecycle_nova.wasm" \
    "$usteps/input_0000.json" "$usteps/step_0000.wtns"

  # sanity-check state_out (witness element 1 is the only public output).
  expected="$(python3 - "$OUT/steps/expected_state_out.json" "$u" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[sys.argv[2]])
PY
  )"
  snarkjs wtns export json "$usteps/step_0000.wtns" "$usteps/witness.json" >/dev/null
  actual="$(python3 - "$usteps/witness.json" <<'PY'
import json, sys
w = json.load(open(sys.argv[1]))
print(w[1])
PY
  )"
  if [ "$expected" != "$actual" ]; then
    echo "error: $u state_out mismatch (expected $expected, actual $actual)"
    exit 2
  fi
  rm -f "$usteps/witness.json"

  # fold
  t0=$(date +%s.%N)
  "$NOVA" fold --curve bls12-381 \
    --circuit "$OUT/privacy_pool_token_lifecycle_nova.r1cs" \
    --steps "$usteps" --out "$OUT/${u}.ivc.cbor" 2>/dev/null
  t1=$(date +%s.%N)

  # compress
  t2=$(date +%s.%N)
  "$NOVA" compress --slim --curve bls12-381 \
    --circuit "$OUT/privacy_pool_token_lifecycle_nova.r1cs" \
    --steps "$usteps" --out "$OUT/${u}_slim.proof.cbor" 2>/dev/null
  t3=$(date +%s.%N)

  fold_t=$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.3f", b-a}')
  comp_t=$(awk -v a="$t2" -v b="$t3" 'BEGIN {printf "%.3f", b-a}')
  echo "$u fold $fold_t 0" >> "$OUT/timings.tsv"
  echo "$u compress $comp_t 0" >> "$OUT/timings.tsv"
done

# 5. verify per user
echo "[5/5] verifying per user..."
for i in $(seq 0 $((SPENDS - 1))); do
  u="user_$(printf "%03d" $i)"
  t0=$(date +%s.%N)
  "$NOVA" verify --curve bls12-381 \
    --ivc "$OUT/${u}.ivc.cbor" --slim-proof "$OUT/${u}_slim.proof.cbor"
  t1=$(date +%s.%N)
  verify_t=$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.3f", b-a}')
  echo "$u verify $verify_t 0" >> "$OUT/timings.tsv"
done

# token conservation + auditor reveal (same metadata as Groth16 path)
echo
echo "token conservation + auditor viewing-key reveal (all users)..."
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
    print(f"    recipient_addr  = 0x{int(s['recipient_addr']):x}")
    print(f"    token_in_commitment  = ({s['token_in_commitment'][0][:16]}..., {s['token_in_commitment'][1][:16]}...)")
PY

echo
echo "== result: ALL $SPENDS USERS VERIFIED =="
echo "  NovaSlim path: no trusted setup, one folded step per spend."
echo "  Per-user slim proof size: $(stat -c%s "$OUT/user_000_slim.proof.cbor") bytes"
echo "  Circuit constraints (step): $(snarkjs info -r "$OUT/privacy_pool_token_lifecycle_nova.r1cs" 2>/dev/null | grep -o '# of Constraints: [0-9]*' | grep -o '[0-9]*' || echo '?')"
echo "  Total timings:"
awk '{printf "  %-12s %-8s %9.3f\n", $1, $2, $3}' "$OUT/timings.tsv"
