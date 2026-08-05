#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="${SCRIPT_DIR}"
WASM="${CIRCUIT_DIR}/cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm"
R1CS="${CIRCUIT_DIR}/cardano_key_ownership_smt.r1cs"
INPUT="${CIRCUIT_DIR}/test_smt_input.json"
WITNESS="${CIRCUIT_DIR}/test_smt_witness.wtns"
PROOF="${CIRCUIT_DIR}/test_smt_proof.json"
PUBLIC="${CIRCUIT_DIR}/test_smt_public.json"

echo "========================================"
echo "CardanoKeyOwnershipSMT End-to-End Demo"
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
python3 "${CIRCUIT_DIR}/test_e2e.py"
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
echo "=== Step 4: Generate proof ==="
snarkjs groth16 prove "${CIRCUIT_DIR}/cardano_key_ownership_smt_final.zkey" "$INPUT" "$PROOF" "$PUBLIC" 2>&1 | tail -3
echo "   Proof generated: $PROOF"

echo ""
echo "=== Step 5: Verify proof ==="
snarkjs groth16 verify "${CIRCUIT_DIR}/cardano_key_ownership_smt_verification_key.json" "$PUBLIC" "$PROOF" 2>&1 | tail -3
echo "   Proof verified!"

echo ""
echo "=== Demo complete ==="