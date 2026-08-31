#!/usr/bin/env bash
#
# Step 5 — Compliant shielded transfer with FULL auditor reveal (amount +
# recipient address): reproducible NovaSlim end-to-end.
#
# A single Nova step folds a multi-message Twisted ElGamal encryption to an
# auditor's public key using SHARED ephemeral randomness r:
#
#   E = r*G ;  C = amount*H + r*pk ;  C_a0 = addr_limb0*H + r*pk ;  C_a1 = addr_limb1*H + r*pk
#
# The public IVC state (wit[1]) is a Poseidon commitment to the shared E and
# the three C points, so the slim proof binds the exact ciphertexts the prover
# reveals off-chain; only the auditor (viewing key sk_audit) can decrypt the
# amount AND the recipient address.  No trusted setup.
#
#   Step circuit : elgamal_viewkey_addr_nova.circom (1 step, N=1)
#   Witness      : single step via gen_viewable_addr_input.py (nova_input.json)
#   Output       : $OUT/vk.ivc.cbor + $OUT/vk_slim.proof.cbor, consumed by
#                  ../nova-slim/cardano/nova-slim-verifier on-chain validator.
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
PP="$ROOT/circom/PrivacyPool"
NOVA_DIR="$ROOT/../nova-slim"
NOVA="$NOVA_DIR/cli/target/release/nova-slim"
OUT="${OUT:-/tmp/sd_step5_novaslim}"

if [ ! -x "$NOVA" ]; then
  echo "nova-slim CLI not found at $NOVA — build it first (see nova-slim README)."
  exit 1
fi
mkdir -p "$OUT"
echo "== Step 5 | NovaSlim e2e (full auditor reveal: amount + address, 1 fold step) =="

# 1. compile the Nova step circuit
echo "[1/4] compiling elgamal_viewkey_addr_nova.circom (BLS12-381)..."
cd "$PP"
circom elgamal_viewkey_addr_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 2. generate the single step witness (in-place) + auditor viewing-key check
echo "[2/4] generating step witness (in-place) + auditor decrypt checks..."
( cd "$PP" && python3 gen_viewable_addr_input.py )
mkdir -p "$OUT/steps"
cp "$PP/nova_input.json" "$OUT/steps/input_0000.json"
cp "$PP/auditor_meta.json" "$OUT/auditor_meta.json"
snarkjs wtns calculate \
  "$OUT/elgamal_viewkey_addr_nova_js/elgamal_viewkey_addr_nova.wasm" \
  "$OUT/steps/input_0000.json" "$OUT/steps/step_0000.wtns"

# 3. fold + compress to a slim proof
echo "[3/4] folding (NIFS) + compressing (--slim)..."
"$NOVA" fold --curve bls12-381 \
  --circuit "$OUT/elgamal_viewkey_addr_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/vk.ivc.cbor"
"$NOVA" compress --slim --curve bls12-381 \
  --circuit "$OUT/elgamal_viewkey_addr_nova.r1cs" \
  --steps "$OUT/steps/" --out "$OUT/vk_slim.proof.cbor"

# 4. verify off-chain
echo "[4/4] verifying..."
"$NOVA" verify --curve bls12-381 \
  --ivc "$OUT/vk.ivc.cbor" --slim-proof "$OUT/vk_slim.proof.cbor"

echo
echo "== result: state chain OK (public state = ciphertext commitment) =="
echo "   ivc bundle : $OUT/vk.ivc.cbor"
echo "   slim proof : $OUT/vk_slim.proof.cbor ($(stat -c%s "$OUT/vk_slim.proof.cbor") bytes)"
echo "   on-chain   : nova-slim-verifier validator (sumcheck only, no openings)"
echo "   auditor    : revealed amount + address from auditor_meta.json"
python3 - "$OUT/auditor_meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
print(f"      pk_audit        = ({meta['pk_audit'][0][:16]}..., {meta['pk_audit'][1][:16]}...)")
print(f"      commit(E,C,C_a0,C_a1) = {meta['commitment'][:24]}...  (public Nova state)")
print(f"      revealed amount = {meta['amount']}")
print(f"      revealed address= 0x{int(meta['recipient_addr']):x} "
      f"(limbs {meta['addr_limb0']}/{meta['addr_limb1']})")
PY
