#!/usr/bin/env bash
#
# Step 8 — Anonymous Delegation: NovaSlim end-to-end.
#
# NovaSlim path for the delegatable predicate.  Each step enforces the full
# PredicateDelegatable and chains the public state unchanged.
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
DEL="$ROOT/circom/Delegation"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step8_novaslim}"
DEPTH="${DEPTH:-2}"
SEED="${SEED:-1}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi

mkdir -p "$OUT"
echo "== Step 8 | NovaSlim e2e (anonymous delegation, 1 fold step) =="

# 1. compile the Nova step circuit
echo "[1/4] compiling predicate_delegatable_nova.circom (BLS12-381)..."
cd "$DEL"
circom predicate_delegatable_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ../PoseidonMerkle
cd "$ROOT"

# 2. generate step witness
echo "[2/4] generating step witness..."
cd "$DEL"
python3 gen_delegation_input.py --depth "$DEPTH" --seed "$SEED" --output "$OUT/input.json"
cd "$ROOT"

mkdir -p "$OUT/steps"
cp "$OUT/input.json" "$OUT/steps/input_0000.json"

snarkjs wtns calculate \
  "$OUT/predicate_delegatable_nova_js/predicate_delegatable_nova.wasm" \
  "$OUT/steps/input_0000.json" "$OUT/steps/step_0000.wtns"

# 3. fold + compress
echo "[3/4] folding (NIFS) + compressing (--slim)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/predicate_delegatable_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/delegation.ivc.cbor"
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/predicate_delegatable_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/delegation_slim.proof.cbor"

# 4. verify
echo "[4/4] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/delegation.ivc.cbor" --slim-proof "$OUT/delegation_slim.proof.cbor"

echo
echo "== result: state chain OK =="
echo "   ivc bundle : $OUT/delegation.ivc.cbor"
echo "   slim proof : $OUT/delegation_slim.proof.cbor ($(stat -c%s "$OUT/delegation_slim.proof.cbor") bytes)"
