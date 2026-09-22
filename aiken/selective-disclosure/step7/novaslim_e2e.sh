#!/usr/bin/env bash
#
# Step 7 — Revocable Predicate Proofs: NovaSlim end-to-end.
#
# NovaSlim path for the revocable predicate.  Each step enforces the full
# PredicateRevocable (expiry + revocation non-membership) and chains the
# public state unchanged.
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
REV="$ROOT/circom/Revocation"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step7_novaslim}"
DEPTH="${DEPTH:-2}"
REV_DEPTH="${REV_DEPTH:-2}"
SEED="${SEED:-1}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi

mkdir -p "$OUT"
echo "== Step 7 | NovaSlim e2e (revocable predicate, 1 fold step) =="

# 1. compile the Nova step circuit
echo "[1/4] compiling predicate_revocable_nova.circom (BLS12-381)..."
cd "$REV"
circom predicate_revocable_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ../PoseidonMerkle
cd "$ROOT"

# 2. generate step witness
echo "[2/4] generating step witness..."
cd "$REV"
python3 gen_revocable_input.py --depth "$DEPTH" --revocation-depth "$REV_DEPTH" \
  --seed "$SEED" --output "$OUT/input.json"
cd "$ROOT"

mkdir -p "$OUT/steps"
cp "$OUT/input.json" "$OUT/steps/input_0000.json"

snarkjs wtns calculate \
  "$OUT/predicate_revocable_nova_js/predicate_revocable_nova.wasm" \
  "$OUT/steps/input_0000.json" "$OUT/steps/step_0000.wtns"

# 3. fold + compress
echo "[3/4] folding (NIFS) + compressing (--slim)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/predicate_revocable_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/revocable.ivc.cbor"
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/predicate_revocable_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/revocable_slim.proof.cbor"

# 4. verify
echo "[4/4] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/revocable.ivc.cbor" --slim-proof "$OUT/revocable_slim.proof.cbor"

echo
echo "== result: state chain OK =="
echo "   ivc bundle : $OUT/revocable.ivc.cbor"
echo "   slim proof : $OUT/revocable_slim.proof.cbor ($(stat -c%s "$OUT/revocable_slim.proof.cbor") bytes)"
