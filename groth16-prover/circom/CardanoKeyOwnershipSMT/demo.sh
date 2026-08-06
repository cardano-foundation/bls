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

# Path to the groth16-prover binary used to build the SMT (must expose the
# 'smt' subcommand). Defaults to the release binary if present, else PATH.
if [ -z "${SMT_CLI:-}" ] && [ -x "${SCRIPT_DIR}/../../cli/target/release/groth16-prover" ]; then
    SMT_CLI="${SCRIPT_DIR}/../../cli/target/release/groth16-prover"
fi
SMT_CLI="${SMT_CLI:-groth16-prover}"

echo "========================================"
echo "CardanoKeyOwnershipSMT End-to-End Demo"
echo "========================================"
echo ""

if ! command -v snarkjs &> /dev/null; then
    echo "ERROR: snarkjs not found in PATH"
    exit 1
fi

if ! command -v cardano-address &> /dev/null || ! command -v bech32 &> /dev/null; then
    echo "ERROR: 'cardano-address' and 'bech32' CLIs are required for the demo."
    echo "  cardano-address: https://github.com/IntersectMBO/cardano-addresses"
    echo "  bech32:          https://github.com/IntersectMBO/bech32"
    echo "  (For a self-contained run without them, use: bash test_smt.sh)"
    exit 1
fi

if [ ! -f "$WASM" ]; then
    echo "ERROR: WASM file not found: $WASM"
    echo "  Run: circom --prime bls12381 cardano_key_ownership_smt.circom --r1cs --wasm"
    exit 1
fi

echo "=== Step 1: Derive a Cardano payment key ==="
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cardano-address recovery-phrase generate --size 15 > "$WORK/phrase.prv"
cardano-address key from-recovery-phrase Shelley < "$WORK/phrase.prv" > "$WORK/root.xsk"
cardano-address key child 1852H/1815H/0H/0/0 < "$WORK/root.xsk" > "$WORK/pay.xsk"
cardano-address key public --without-chain-code < "$WORK/pay.xsk" > "$WORK/pay.vk"
echo "   Key derived (temporary)"

echo ""
echo "=== Step 2: Generate test input ==="
"${CIRCUIT_DIR}/gen_input.sh" --xsk "$WORK/pay.xsk" --vk "$WORK/pay.vk" \
    --depth 4 --index 0 \
    --leaves "12345 67890 11111 22222 33333 44444 55555 66666 77777 88888 99999 10101 20202 30303 40404" \
    --output "$INPUT" --smt-cli "$SMT_CLI"
echo "   Input generated: $INPUT"

echo ""
echo "=== Step 3: Generate witness ==="
snarkjs wc "$WASM" "$INPUT" "$WITNESS" 2>&1 | tail -1
echo "   Witness generated: $WITNESS"

echo ""
echo "=== Step 4: Check witness ==="
snarkjs wchk "$R1CS" "$WITNESS" 2>&1 | tail -3
echo "   Witness check passed!"

echo ""
echo "=== Step 5: Generate proof ==="
ZKEY="${CIRCUIT_DIR}/cardano_key_ownership_smt_final.zkey"
VK="${CIRCUIT_DIR}/cardano_key_ownership_smt_verification_key.json"
if [ ! -f "$ZKEY" ] || [ ! -f "$VK" ]; then
    echo "   Skipped: trusted setup artifacts not present."
    echo "   To enable proof generation/verification, run a trusted setup for"
    echo "   ${R1CS} (e.g. snarkjs powersoftau + groth16 setup) and place:"
    echo "     - cardano_key_ownership_smt_final.zkey"
    echo "     - cardano_key_ownership_smt_verification_key.json"
else
    snarkjs groth16 prove "$ZKEY" "$INPUT" "$PROOF" "$PUBLIC" 2>&1 | tail -3
    echo "   Proof generated: $PROOF"

    echo ""
    echo "=== Step 6: Verify proof ==="
    snarkjs groth16 verify "$VK" "$PUBLIC" "$PROOF" 2>&1 | tail -3
    echo "   Proof verified!"
fi

echo ""
echo "=== Demo complete ==="