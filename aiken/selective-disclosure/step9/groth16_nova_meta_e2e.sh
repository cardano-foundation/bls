#!/usr/bin/env bash
#
# Step 9 — Recursive Proof Aggregation: NovaSlim meta-batch end-to-end.
#
# This script demonstrates the full pipeline:
#   1. Run Step 6 (F5 multi-user batch pool) to generate epoch proofs.
#   2. Build a MetaBatchStep witness from the epoch data.
#   3. Compile the MetaBatch Nova step circuit.
#   4. Fold + compress + verify with nova-slim.
#
# NOTE: The MetaBatchStep circuit is a scaffold. The embedded Groth16 batch
# pairing check is marked TODO (~500K–2M constraints). The current circuit
# proves the correct state transition (Merkle root + nullifier accumulator)
# and commits to the batch data via Poseidon hashing.
#
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
MB="$ROOT/circom/MetaBatch"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step9_novaslim}"
# NOTE: Step 6's privacy_pool_viewable_addr.circom hardcodes depth=4.
# Tree capacity = 16.  We need USERS + 2*SPENDS ≤ 16.
# With SPENDS=USERS, max USERS = 5 (5+10=15).  Default to 4 for safety.
EPOCH_SIZE="${EPOCH_SIZE:-4}"
DEPTH="${DEPTH:-4}"
SEED="${SEED:-42}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi

mkdir -p "$OUT"
echo "== Step 9 | NovaSlim meta-batch e2e (recursive aggregation) =="
echo "   epoch size: $EPOCH_SIZE  |  depth: $DEPTH  |  seed: $SEED"

# ---------------------------------------------------------------------------
# 1. Generate epoch proofs via Step 6 (F5 multi-user batch pool)
# ---------------------------------------------------------------------------
echo "[1/6] generating epoch proofs (Step 6 pipeline)..."
EPOCH_OUT="$OUT/epoch"
mkdir -p "$EPOCH_OUT"
OUT="$EPOCH_OUT" USERS="$EPOCH_SIZE" DEPTH="$DEPTH" SEED="$SEED" \
  bash "$ROOT/aiken/selective-disclosure/step6/groth16_e2e.sh" \
  >/dev/null 2>&1 || {
  echo "   Step 6 epoch generation failed — check $EPOCH_OUT"
  exit 1
}

# Derive vk_hash from the proving key (simplified: hash the first 32 bytes)
VK_HASH_HEX=$(xxd -l 32 -p "$EPOCH_OUT/pp.pk" | tr -d '\n')
VK_HASH=$(python3 -c "print(int('$VK_HASH_HEX', 16))")
echo "   vk_hash (from pk): ${VK_HASH:0:16}..."

# ---------------------------------------------------------------------------
# 2. Build MetaBatch step witness from epoch data
echo "[2/6] building MetaBatch step witness..."
cd "$MB"
python3 gen_meta_batch_input.py \
  --epoch-dir "$EPOCH_OUT" \
  --epoch-size "$EPOCH_SIZE" \
  --prev-root "0" \
  --nullifier-acc "0" \
  --vk-hash "$VK_HASH" \
  --output "$OUT/input.json"
cd "$ROOT"

mkdir -p "$OUT/steps"
cp "$OUT/input.json" "$OUT/steps/input_0000.json"

# ---------------------------------------------------------------------------
# 3. Compile the MetaBatch Nova step circuit
echo "[3/6] compiling groth16_batch_verifier_nova.circom (BLS12-381)..."
cd "$MB"
circom groth16_batch_verifier_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../PoseidonMerkle \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits
cd "$ROOT"

# ---------------------------------------------------------------------------
# 4. Compute step witness with snarkjs
echo "[4/6] computing step witness..."
snarkjs wtns calculate \
  "$OUT/groth16_batch_verifier_nova_js/groth16_batch_verifier_nova.wasm" \
  "$OUT/steps/input_0000.json" \
  "$OUT/steps/step_0000.wtns"

# ---------------------------------------------------------------------------
# 5. Fold + compress
echo "[5/6] folding (NIFS) + compressing (--slim)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/groth16_batch_verifier_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/meta_batch.ivc.cbor"
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/groth16_batch_verifier_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/meta_batch_slim.proof.cbor"

# ---------------------------------------------------------------------------
# 6. Verify
echo "[6/6] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/meta_batch.ivc.cbor" --slim-proof "$OUT/meta_batch_slim.proof.cbor"

echo
echo "== result: state chain OK =="
echo "   ivc bundle : $OUT/meta_batch.ivc.cbor"
echo "   slim proof : $OUT/meta_batch_slim.proof.cbor ($(stat -c%s "$OUT/meta_batch_slim.proof.cbor") bytes)"
echo "   epoch dir  : $EPOCH_OUT"
echo ""
echo "NOTE: The MetaBatchStep circuit is a scaffold."
echo "  - Embedded Groth16 pairing check: TODO (~500K–2M constraints)"
echo "  - State transition (Merkle + nullifier): implemented"
echo "  - Batch commitment (Poseidon hash chain): implemented"
