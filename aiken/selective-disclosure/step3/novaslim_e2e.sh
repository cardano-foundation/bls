#!/usr/bin/env bash
#
# Step 3 — Privacy Pool: reproducible NovaSlim end-to-end (shielded transfer).
# The input note's commitment is walked through the Merkle tree one level per
# Nova step (`state_out = Poseidon(switch(state_in, sibling, direction))`),
# folding the leaf commitment into the pool's public root.  No trusted setup.
#
#   Step circuit : privacy_pool_nova.circom (1 Merkle level per step)
#   Witness      : depth step witnesses via gen_nova_privpool_steps.py
#   Output       : $OUT/pp.ivc.cbor + $OUT/pp_slim.proof.cbor, consumed by
#                  ../nova-slim/cardano/nova-slim-verifier on-chain validator.
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step3_novaslim}"
DEPTH="${DEPTH:-4}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi
mkdir -p "$OUT"
echo "== Step 3 | NovaSlim e2e (privacy pool, depth $DEPTH) =="

# 1. compile the Nova step circuit
echo "[1/4] compiling privacy_pool_nova.circom (BLS12-381)..."
cd "$PP"
circom privacy_pool_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate the chained Merkle step witnesses (must run in-place for helpers)
echo "[2/4] generating $DEPTH Merkle-level step witnesses..."
( cd "$PP" && python3 gen_nova_privpool_steps.py \
    --wasm "$OUT/privacy_pool_nova_js/privacy_pool_nova.wasm" \
    --depth "$DEPTH" --dir "$OUT/steps/" )

# 3. fold + compress to a slim proof
echo "[3/4] folding (NIFS) + compressing (--slim)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/privacy_pool_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/pp.ivc.cbor"
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/privacy_pool_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/pp_slim.proof.cbor"

# 4. verify off-chain
echo "[4/4] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/pp.ivc.cbor" --slim-proof "$OUT/pp_slim.proof.cbor"

echo
echo "== result: state chain OK (leaf -> merkle root) =="
echo "   ivc bundle : $OUT/pp.ivc.cbor"
echo "   slim proof : $OUT/pp_slim.proof.cbor"
echo "   on-chain   : nova-slim-verifier validator (sumcheck only, no openings)"
