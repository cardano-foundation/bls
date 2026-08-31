#!/usr/bin/env bash
#
# Step 2 — Twisted ElGamal: reproducible NovaSlim end-to-end (mention-only
# amounts).  A transfer is decomposed into u16 limbs and folded one limb per
# step with Nova; `state_out = state_in + (new_limb - old_limb)` accumulates
# to exactly `-amount`, proving value conservation with no trusted setup.
#
#   Step circuit : twisted_elgamal_nova.circom (1 u16 limb per step)
#   Witness      : 8 limb steps via gen_teg_steps.py
#   Output       : $OUT/teg.ivc.cbor + $OUT/teg_slim.proof.cbor, consumed by
#                  ../nova-slim/cardano/nova-slim-verifier on-chain validator.
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
TEG="$ROOT/circom/TwistedElGamal"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step2_novaslim}"
OLD="${OLD:-100000}"
NEW="${NEW:-99750}"
NLIMBS="${NLIMBS:-8}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi
mkdir -p "$OUT"
echo "== Step 2 | NovaSlim e2e (transfer $OLD -> $NEW, $NLIMBS limbs) =="

# 1. compile the Nova step circuit
echo "[1/4] compiling twisted_elgamal_nova.circom (BLS12-381)..."
cd "$TEG"
circom twisted_elgamal_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate the chained limb witnesses
echo "[2/4] generating $NLIMBS limb step witnesses..."
python3 "$TEG/gen_teg_steps.py" \
  --wasm "$OUT/twisted_elgamal_nova_js/twisted_elgamal_nova.wasm" \
  --old-balance "$OLD" --new-balance "$NEW" --nlimbs "$NLIMBS" \
  --dir "$OUT/steps/"

# 3. fold + compress to a slim proof
echo "[3/4] folding (NIFS) + compressing (--slim)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/twisted_elgamal_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/teg.ivc.cbor"
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/twisted_elgamal_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/teg_slim.proof.cbor"

# 4. verify off-chain
echo "[4/4] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/teg.ivc.cbor" --slim-proof "$OUT/teg_slim.proof.cbor"

echo
echo "== result: state chain OK (final state = -amount) =="
echo "   ivc bundle : $OUT/teg.ivc.cbor"
echo "   slim proof : $OUT/teg_slim.proof.cbor"
echo "   on-chain   : nova-slim-verifier validator (sumcheck only, no openings)"
