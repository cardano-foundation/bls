#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ONCHAIN_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(cd "$ONCHAIN_DIR/../.." && pwd)"

echo "=== zkVM On-Chain E2E: BN254 → BLS12-381 Wrapping ==="
echo ""

# Create dummy proof files for testing
DUMMY_OPENVM="$ROOT_DIR/target/dummy_openvm.proof"
DUMMY_JOLT="$ROOT_DIR/target/dummy_jolt.proof"
mkdir -p "$ROOT_DIR/target"
echo -n "OPENVM_PROOF_DATA" > "$DUMMY_OPENVM"
echo -n "JOLT_PROOF_DATA" > "$DUMMY_JOLT"

cd "$ONCHAIN_DIR"
echo "Building zkvm-onchain..."
cargo build --release 2>&1 | tail -5

echo ""
echo "Wrapping OpenVM proof..."
./target/release/wrap-openvm --proof "$DUMMY_OPENVM" --out /tmp/wrapped_openvm.json
echo "  $(cat /tmp/wrapped_openvm.json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("a:",len(d["a"]),"b:",len(d["b"]),"c:",len(d["c"]),"vk:",d["vk_id"])' 2>/dev/null || echo "ok")"

echo ""
echo "Wrapping Jolt proof..."
./target/release/wrap-jolt --proof "$DUMMY_JOLT" --out /tmp/wrapped_jolt.json
echo "  done"

echo ""
echo "=== Done ==="
