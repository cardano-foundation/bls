#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(cd "$EXAMPLES_DIR/../.." && pwd)"

echo "=== CardanoKeyOwnershipStrong E2E Examples (OpenVM & Jolt host execution) ==="
echo ""

echo "1. OpenVM host execution"
cd "$ROOT_DIR/zkVM/openvm/cardano-key-ownership-strong"
cargo run 2>&1 | tail -3
echo ""

echo "2. Jolt host execution"
cd "$ROOT_DIR/zkVM/jolt/cardano-key-ownership-strong"
cargo run --release 2>&1 | tail -5
echo ""

echo "=== Done ==="
echo "Note: Full zkVM proving commands are in the project READMEs."
