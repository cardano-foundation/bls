#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="${SCRIPT_DIR}"
WASM="${CIRCUIT_DIR}/cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm"
R1CS="${CIRCUIT_DIR}/cardano_key_ownership_smt.r1cs"
INPUT="${CIRCUIT_DIR}/test_smt_input.json"
WITNESS="${CIRCUIT_DIR}/test_smt_witness.wtns"

# Path to the groth16-prover binary used to build the SMT (must expose the
# 'smt' subcommand). Defaults to the release binary if present, else PATH.
if [ -z "${SMT_CLI:-}" ] && [ -x "${SCRIPT_DIR}/../../cli/target/release/groth16-prover" ]; then
    SMT_CLI="${SCRIPT_DIR}/../../cli/target/release/groth16-prover"
fi
SMT_CLI="${SMT_CLI:-groth16-prover}"

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
"${CIRCUIT_DIR}/gen_input.sh" --fixed --depth 4 --index 0 \
    --leaves "12345 67890 11111 22222 33333 44444 55555 66666 77777 88888 99999 10101 20202 30303 40404" \
    --output "$INPUT" --smt-cli "$SMT_CLI"
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
