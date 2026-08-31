#!/usr/bin/env bash
#
# Step 1 — Predicate Proofs: reproducible NovaSlim end-to-end.
#
# Reproduces the same predicate flow (age >= 21 AND country in approved set)
# with Nova IVC + slim-sumcheck compression instead of a large monotonic
# Groth16 proof.  No trusted setup (transparent).  `nova-slim` must be a
# sibling of this repo (build: nova-slim/cli → `cargo build --release`).
#
#   Step circuit : predicate_nova.circom (monolithic, chains 5 public scalars)
#   Witness      : 1 step (N=1 fold) from gen_predicate_input.py
#   Output       : $OUT/pred.ivc.cbor + $OUT/pred_slim.proof.cbor, consumed by
#                  ../nova-slim/cardano/nova-slim-verifier on-chain validator.
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PRED="$ROOT/circom/Predicate"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step1_novaslim}"
SEED="${SEED:-1}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first:"
  echo "  cd $NOVA_DIR && cargo build --release --manifest-path cli/Cargo.toml"
  exit 1
fi

mkdir -p "$OUT"
echo "== Step 1 | NovaSlim e2e =="
echo "   repo : $ROOT"
echo "   out  : $OUT"

# 1. deterministic off-chain scenario (same as Groth16 path)
echo "[1/5] generating witness input (seed=$SEED)..."
python3 "$PRED/gen_predicate_input.py" --depth 2 --seed "$SEED" --output "$OUT/input.json"

# 2. compile the Nova step circuit
echo "[2/5] compiling predicate_nova.circom (BLS12-381)..."
cd "$PRED"
circom predicate_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub \
  -l ../PoseidonPreimage \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits
cd "$ROOT"

# 3. generate the (single) fold step witness, chaining the 5 public scalars
echo "[3/5] generating 1 step witness..."
python3 "$NOVA_DIR/benchmarks/gen_step_witnesses.py" \
  --wasm "$OUT/predicate_nova_js/predicate_nova.wasm" \
  --initial "$OUT/input.json" \
  --outputs pku=pk_u_out,pkv=pk_v_out,current_year=current_year_out,country_root=country_root_out,eligible=eligible_out \
  --steps 1 --dir "$OUT/steps/"

# 4. fold + compress to a slim (on-chain) proof
echo "[4/5] folding (NIFS)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/predicate_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/pred.ivc.cbor"
echo "[4/5] compressing (--slim)..."
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/predicate_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/pred_slim.proof.cbor"

# 5. verify off-chain
echo "[5/5] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/pred.ivc.cbor" --slim-proof "$OUT/pred_slim.proof.cbor"

echo
echo "== result: state chain OK =="
echo "   ivc bundle : $OUT/pred.ivc.cbor"
echo "   slim proof : $OUT/pred_slim.proof.cbor"
echo "   on-chain   : nova-slim-verifier validator (sumcheck only, no openings)"
