#!/usr/bin/env bash
#
# Step 2 — Twisted ElGamal: reproducible Groth16 end-to-end (mention-only
# amounts).  Single monolithic `transfer.circom` proof that
#   newBalance == oldBalance - amount,  amount in [0, 2^16),  newBalance >= 0.
#
#   Public : oldBalance, newBalance
#   Private: amount
#   Example: 100 -> 70  (amount = 30), valid
#
# Emits the on-chain artifacts: $OUT/transfer.proof, transfer.pub and
# transfer_vk.ak (paste into the aiken/groth16 gate validator).
set -euo pipefail

SDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SDIR/../../.." && pwd)"
TEG="$ROOT/circom/TwistedElGamal"
OUT="${OUT:-/tmp/sd_step2_groth16}"
OLD="${OLD:-100}"
NEW="${NEW:-70}"

TS="$ROOT/clis/trusted-setup/target/release/trusted-setup"
G16="$ROOT/clis/groth16/target/release/groth16"

mkdir -p "$OUT"
echo "== Step 2 | Groth16 e2e (transfer $OLD -> $NEW) =="

# 0. build the Rust CLIs
echo "[0/5] building Rust CLIs..."
cargo build --release --manifest-path "$ROOT/clis/trusted-setup/Cargo.toml"
cargo build --release --manifest-path "$ROOT/clis/groth16/Cargo.toml"

# 1. witness input (no generator — a small, auditable JSON)
echo "[1/5] writing witness input..."
python3 - "$OLD" "$NEW" "$OUT" <<'PY'
import json, sys
old, new, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
amount = old - new
assert 0 <= amount < 2**16 and 0 <= new < 2**16, "amount / newBalance must fit in u16"
json.dump({"oldBalance": old, "newBalance": new, "amount": amount},
          open(f"{out}/input_transfer.json", "w"))
print(f"   oldBalance={old} newBalance={new} amount={amount}")
PY

# 2. compile transfer.circom
echo "[2/5] compiling transfer.circom (BLS12-381)..."
cd "$TEG"
circom transfer.circom --r1cs --wasm --sym --prime bls12381 \
  -o "$OUT" \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
cd "$ROOT"

# 3. witness
echo "[3/5] computing witness..."
snarkjs wtns calculate "$OUT/transfer_js/transfer.wasm" \
  "$OUT/input_transfer.json" "$OUT/witness.wtns"

# 4. dev ceremony (tiny circuit — dense is fine) + prove
echo "[4/5] dev ceremony + prove..."
"$TS" ceremony-dev \
  --circuit "$OUT/transfer.r1cs" \
  --proving-key "$OUT/transfer.pk" --verifying-key "$OUT/transfer.vk"
"$G16" prove \
  --circuit "$OUT/transfer.r1cs" \
  --witness "$OUT/witness.wtns" \
  --proving-key "$OUT/transfer.pk" --out "$OUT/transfer.proof"

# 5. verify + export vk
echo "[5/5] verifying + exporting Aiken vk..."
"$G16" verify \
  --proof "$OUT/transfer.proof" --public "$OUT/transfer.pub" \
  --verifying-key "$OUT/transfer.vk"
"$G16" export-vk --verifying-key "$OUT/transfer.vk" --out "$OUT/transfer_vk.ak"

echo
echo "== result: VALID =="
echo "   proof    : $OUT/transfer.proof"
echo "   public   : $OUT/transfer.pub"
echo "   aiken vk : $OUT/transfer_vk.ak"
