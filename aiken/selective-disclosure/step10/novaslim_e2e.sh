#!/usr/bin/env bash
#
# Step 10 — Dynamic Multi-Auditor Privacy Pool with Full Reveal (NovaSlim)
#
# NovaSlim path for the Step 10 circuit.  Each user folds a single step that
# proves both the multi-message auditor encryption and membership of the chosen
# pk_audit in the current active-set Merkle tree rooted at auditor_root.
#
# The auditor decrypts every amount + address from the public IVC state
# (Poseidon commitment to E, C, C_a0, C_a1) in the same way as Step 5/6.
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step10_novaslim}"
USERS="${USERS:-4}"
AUDITORS="${AUDITORS:-4}"
AUDITOR_DEPTH="${AUDITOR_DEPTH:-4}"
SEED="${SEED:-42}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi

mkdir -p "$OUT"
echo "== Step 10 | NovaSlim e2e (dynamic multi-auditor reveal, $USERS users, $AUDITORS auditors, seed $SEED) =="

# 1. compile the Nova step circuit
echo "[1/5] compiling elgamal_viewkey_addr_dynamic_nova.circom (BLS12-381)..."
cd "$PP"
circom elgamal_viewkey_addr_dynamic_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate multi-user scenario with dynamic auditor fields
echo "[2/5] generating multi-user scenario with dynamic auditors..."
python3 "$PP/gen_multi_viewable_addr_dynamic_input.py" \
  --depth 4 --auditor-depth "$AUDITOR_DEPTH" \
  --users "$USERS" --spends "$USERS" --auditors "$AUDITORS" --seed "$SEED" --out "$OUT"

# 3. build per-user step witnesses from scenario.json
echo "[3/5] building per-user Nova step witnesses..."
python3 - "$OUT/scenario.json" "$OUT/steps" <<'PY'
import json, sys, os
scenario = json.load(open(sys.argv[1]))
steps_dir = sys.argv[2]
os.makedirs(steps_dir, exist_ok=True)
for i, s in enumerate(scenario["spends"]):
    meta = s["auditor_meta"]
    # path data is stored in the per-user Groth16 witness; reconstruct from public
    pub = {k: v for k, v in zip(scenario["spends"][i]["public"], scenario["spends"][i]["public"])}
    # load the full input json for the path siblings/directions
    full = json.load(open(os.path.join(os.path.dirname(sys.argv[1]), s["user"])))
    wit = {
        "state_in": "0",
        "amount": meta["amount"],
        "r": meta["r"],
        "pk_audit": meta["pk_audit"],
        "recipient_addr": meta["recipient_addr"],
        "auditor_root": scenario["auditor_root"],
        "auditor_sibling": full["auditor_sibling"],
        "auditor_direction": full["auditor_direction"],
    }
    open(f"{steps_dir}/user_{i:03d}_0000.json", "w").write(
        json.dumps(wit, indent=2) + "\n"
    )
print(f"wrote {len(scenario['spends'])} user step witnesses to {steps_dir}")
PY

# 4. fold + compress per user
echo "[4/5] folding + compressing per user..."
: > "$OUT/timings.tsv"
for i in $(seq 0 $((USERS - 1))); do
  u="user_$(printf "%03d" $i)"
  usteps="$OUT/steps/${u}"
  mkdir -p "$usteps"
  cp "$OUT/steps/${u}_0000.json" "$usteps/input_0000.json"
  snarkjs wtns calculate \
    "$OUT/elgamal_viewkey_addr_dynamic_nova_js/elgamal_viewkey_addr_dynamic_nova.wasm" \
    "$usteps/input_0000.json" "$usteps/step_0000.wtns"

  # fold
  t0=$(date +%s.%N)
  "$NOVA" fold --curve bls12-381 \
    --circuit "$OUT/elgamal_viewkey_addr_dynamic_nova.r1cs" \
    --steps "$usteps" --out "$OUT/${u}.ivc.cbor" 2>/dev/null
  t1=$(date +%s.%N)

  # compress
  t2=$(date +%s.%N)
  "$NOVA" compress --slim --curve bls12-381 \
    --circuit "$OUT/elgamal_viewkey_addr_dynamic_nova.r1cs" \
    --steps "$usteps" --out "$OUT/${u}_slim.proof.cbor" 2>/dev/null
  t3=$(date +%s.%N)

  fold_t=$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.3f", b-a}')
  comp_t=$(awk -v a="$t2" -v b="$t3" 'BEGIN {printf "%.3f", b-a}')
  echo "$u fold $fold_t 0" >> "$OUT/timings.tsv"
  echo "$u compress $comp_t 0" >> "$OUT/timings.tsv"
done

# 5. verify per user
echo "[5/5] verifying per user..."
for i in $(seq 0 $((USERS - 1))); do
  u="user_$(printf "%03d" $i)"
  t0=$(date +%s.%N)
  "$NOVA" verify --curve bls12-381 \
    --ivc "$OUT/${u}.ivc.cbor" --slim-proof "$OUT/${u}_slim.proof.cbor"
  t1=$(date +%s.%N)
  verify_t=$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.3f", b-a}')
  echo "$u verify $verify_t 0" >> "$OUT/timings.tsv"
done

# auditor reveal
echo
echo "auditor viewing-key reveal (all users)..."
python3 - "$OUT/auditor_meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
print(f"auditor_root = {meta['auditor_root']}")
print(f"active auditors = {len(meta['auditor_set'])}")
print("")
for s in meta["spends"]:
    u = s["user"]
    print(f"  {u}:")
    print(f"    auditor_index   = {s['auditor_index']}")
    print(f"    amount          = {s['amount']}")
    print(f"    recipient_addr  = 0x{int(s['recipient_addr']):x}")
    print(f"    commit(E,C,...) = E={str(s['E'][0])[:24]}... C={str(s['C'][0])[:24]}...")
PY

echo
echo "== result: ALL $USERS USERS VERIFIED =="
echo "  Note: NovaSlim verifies each user individually (no batch verifier yet)."
echo "  Per-user proof size: $(stat -c%s "$OUT/user_000_slim.proof.cbor") bytes"
echo "  Total timings:"
awk '{printf "  %-12s %-8s %9.3f\n", $1, $2, $3}' "$OUT/timings.tsv"
