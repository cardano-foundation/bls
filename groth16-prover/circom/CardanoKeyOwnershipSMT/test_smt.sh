#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="${SCRIPT_DIR}"
WASM="${CIRCUIT_DIR}/cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm"
R1CS="${CIRCUIT_DIR}/cardano_key_ownership_smt.r1cs"
INPUT="${CIRCUIT_DIR}/test_smt_input.json"
WITNESS="${CIRCUIT_DIR}/test_smt_witness.wtns"

echo "========================================"
echo "CardanoKeyOwnershipSMT Test"
echo "========================================"
echo ""

if ! command -v snarkjs &> /dev/null; then
    echo "ERROR: snarkjs not found in PATH"
    exit 1
fi

if [ ! -f "$WASM" ]; then
    echo "ERROR: WASM file not found: $WASM"
    echo "  Run: circom --prime bls12381 cardano_key_ownership_smt.circom --r1cs --wasm"
    exit 1
fi

echo "=== Step 1: Generate test input ==="
python3 "${CIRCUIT_DIR}/test_e2e.py" --depth 4 --index 0 --output "$INPUT"
echo "   Input generated: $INPUT"

echo ""
echo "=== Step 2: Generate witness ==="
snarkjs wc "$WASM" "$INPUT" "$WITNESS" 2>&1 | tail -1
echo "   Witness generated: $WITNESS"

echo ""
echo "=== Step 3: Check witness ==="
snarkjs wchk "$R1CS" "$WITNESS" 2>&1 | tail -3
echo "   Witness check passed!"

echo ""
echo "=== Test passed ==="
