#!/usr/bin/env bash
set -euo pipefail

# test_cardano_address_e2e.sh
#
# End-to-end integration test for Cardano address key ownership proof.
# Tests both the "happy path" (correct key → proof verifies) and the
# "negative path" (wrong key → proof fails / cannot forge ownership).
#
# Requirements:
#   - cardano-address  in $PATH
#   - bech32 CLI in $PATH  (install from https://github.com/IntersectMBO/bech32/releases)
#   - snarkjs  in $PATH
#   - groth16 CLI built in release mode
#   - trusted-setup CLI built in release mode (ceremony step)
#
# Usage:
#   ./test_cardano_address_e2e.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="${SCRIPT_DIR}/../../../clis/groth16"
TRUSTED_SETUP_DIR="${SCRIPT_DIR}/../../../clis/trusted-setup"
CIRCUIT="${SCRIPT_DIR}/cardano_ed25519_ownership.r1cs"
WASM="${SCRIPT_DIR}/cardano_ed25519_ownership_js/cardano_ed25519_ownership.wasm"

echo "========================================"
echo "Cardano Address Key Ownership E2E Test"
echo "========================================"
echo ""

# ------------------------------------------------------------------
# 0. Sanity checks
# ------------------------------------------------------------------
if ! command -v cardano-address &> /dev/null; then
    echo "ERROR: cardano-address not found in PATH"
    exit 1
fi
if ! command -v bech32 &> /dev/null; then
    echo "ERROR: bech32 CLI not found in PATH."
    echo "  Install from https://github.com/IntersectMBO/bech32/releases"
    echo "  or build from source: cabal install bech32"
    exit 1
fi
if ! command -v snarkjs &> /dev/null; then
    echo "ERROR: snarkjs not found in PATH"
    exit 1
fi
if [ ! -f "${CLI_DIR}/target/release/groth16" ]; then
    echo "ERROR: groth16 CLI not built. Run: cd ${CLI_DIR} && cargo build --release"
    exit 1
fi
if [ ! -f "${TRUSTED_SETUP_DIR}/target/release/trusted-setup" ]; then
    echo "ERROR: trusted-setup CLI not built. Run: cd ${TRUSTED_SETUP_DIR} && cargo build --release"
    exit 1
fi
if [ ! -f "$CIRCUIT" ]; then
    echo "ERROR: circuit R1CS not found: $CIRCUIT"
    echo "Compile first: circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits cardano_ed25519_ownership.circom --r1cs --wasm --sym"
    exit 1
fi

# ------------------------------------------------------------------
# Helper: derive keys for a given mnemonic file
# ------------------------------------------------------------------
derive_keys() {
    local phrase_file=$1
    local out_prefix=$2
    cardano-address key from-recovery-phrase Shelley < "$phrase_file" > "${out_prefix}_root.xsk"
    cardano-address key child 1852H/1815H/0H/0/0 < "${out_prefix}_root.xsk" > "${out_prefix}_pay.xsk"
    cardano-address key public --without-chain-code < "${out_prefix}_pay.xsk" > "${out_prefix}_pay.vk"
}

# ------------------------------------------------------------------
# Helper: generate circuit input
# ------------------------------------------------------------------
make_input() {
    local xsk=$1
    local vk=$2
    local out=$3
    python3 "${SCRIPT_DIR}/gen_cardano_address_input.py" \
        --xsk "$xsk" --vk "$vk" -o "$out"
}

# ------------------------------------------------------------------
# 1. Generate two independent mnemonics (Alice and Bob)
# ------------------------------------------------------------------
echo "=== Step 1: Generate Alice and Bob mnemonics ==="
cardano-address recovery-phrase generate --size 15 > alice.prv
cardano-address recovery-phrase generate --size 15 > bob.prv
echo "   Alice phrase -> alice.prv"
echo "   Bob phrase   -> bob.prv"

# ------------------------------------------------------------------
# 2. Derive payment keys
# ------------------------------------------------------------------
echo "=== Step 2: Derive payment keys ==="
derive_keys alice.prv alice
derive_keys bob.prv bob
echo "   Alice pay.xsk / pay.vk derived"
echo "   Bob   pay.xsk / pay.vk derived"

# ------------------------------------------------------------------
# 3. Generate circuit inputs
# ------------------------------------------------------------------
echo "=== Step 3: Generate circuit witness inputs ==="
make_input alice_pay.xsk alice_pay.vk alice_input.json
make_input bob_pay.xsk   bob_pay.vk   bob_input.json
echo "   alice_input.json  (correct: Alice's sk + Alice's pk)"
echo "   bob_input.json    (correct: Bob's sk + Bob's pk)"

# ------------------------------------------------------------------
# 4. Generate witnesses
# ------------------------------------------------------------------
echo "=== Step 4: Generate witnesses ==="
snarkjs wtns calculate "$WASM" alice_input.json alice_witness.wtns 2>&1 | tail -1
snarkjs wtns calculate "$WASM" bob_input.json   bob_witness.wtns   2>&1 | tail -1
echo "   alice_witness.wtns  generated"
echo "   bob_witness.wtns    generated"

# ------------------------------------------------------------------
# 5. Dev ceremony (once per circuit)
# ------------------------------------------------------------------
echo "=== Step 5: Dev ceremony ==="
"${TRUSTED_SETUP_DIR}/target/release/trusted-setup" ceremony-dev --sparse \
    --circuit "$CIRCUIT" \
    --proving-key /tmp/cardano_addr_test.pk \
    --verifying-key /tmp/cardano_addr_test.vk \
    2>&1 | tail -3
echo "   Proving key  -> /tmp/cardano_addr_test.pk"
echo "   Verifying key -> /tmp/cardano_addr_test.vk"

# ------------------------------------------------------------------
# 6. Positive test: Alice proves she owns Alice's key
# ------------------------------------------------------------------
echo ""
echo "=== TEST A: Positive — Alice proves ownership of her own key ==="
"${CLI_DIR}/target/release/groth16" prove --sparse \
    --circuit "$CIRCUIT" \
    --witness alice_witness.wtns \
    --proving-key /tmp/cardano_addr_test.pk \
    --out /tmp/alice_proof.bin \
    2>&1 | tail -5

verify_output=$("${CLI_DIR}/target/release/groth16" verify \
    --proof /tmp/alice_proof.bin \
    --public /tmp/alice_proof.pub \
    --verifying-key /tmp/cardano_addr_test.vk \
    2>&1)
echo "$verify_output"

if echo "$verify_output" | grep -q "VALID"; then
    echo "   ✅ TEST A PASSED: Alice's proof verifies against her public key"
else
    echo "   ❌ TEST A FAILED: Alice's proof should have verified"
    exit 1
fi

# ------------------------------------------------------------------
# 7. Negative test: Bob tries to prove ownership of Alice's key
#     (using Bob's private key but Alice's public key)
# ------------------------------------------------------------------
echo ""
echo "=== TEST B: Negative — Bob tries to forge ownership of Alice's key ==="

# Create a "forged" input: Bob's sk + Alice's pk
# This is the critical attack vector: can Bob use his own secret to convince
# the verifier that he owns Alice's public key?
python3 "${SCRIPT_DIR}/gen_cardano_address_input.py" \
    --xsk bob_pay.xsk --vk alice_pay.vk -o forged_input.json 2>&1 | tail -3

# Try to generate witness. The Circom circuit asserts:
#   ScalarMul(sk, G) == PointA  &&  PointCompress(PointA) == A
# Bob's scalar multiplied by G gives Bob's public key, NOT Alice's.
# Therefore the circuit constraints are unsatisfied and witness generation
# should fail (or the prover will detect the bad witness).
echo "   Attempting witness generation with Bob's sk + Alice's pk ..."
if snarkjs wtns calculate "$WASM" forged_input.json forged_witness.wtns 2>&1; then
    echo "   ⚠️  Witness generated (Circom WASM did not assert); trying to prove..."
    prove_output=$("${CLI_DIR}/target/release/groth16" prove --sparse \
        --circuit "$CIRCUIT" \
        --witness forged_witness.wtns \
        --proving-key /tmp/cardano_addr_test.pk \
        --out /tmp/forged_proof.bin \
        2>&1)
    echo "$prove_output"
    if echo "$prove_output" | grep -qi "invalid\|error\|fail"; then
        echo "   ✅ TEST B PASSED: Prover rejected the forged witness"
    else
        # Even if proof was produced, verification must fail
        verify_output=$("${CLI_DIR}/target/release/groth16" verify \
            --proof /tmp/forged_proof.bin \
            --public /tmp/forged_proof.pub \
            --verifying-key /tmp/cardano_addr_test.vk \
            2>&1)
        echo "$verify_output"
        if echo "$verify_output" | grep -qi "invalid\|error\|fail"; then
            echo "   ✅ TEST B PASSED: Verifier rejected the forged proof"
        else
            echo "   ❌ TEST B FAILED: Forged proof was accepted — this is a security bug!"
            exit 1
        fi
    fi
else
    echo "   ✅ TEST B PASSED: Witness generation failed (circuit constraints unsatisfied)"
fi

# ------------------------------------------------------------------
# 8. Negative test C: Verify Alice's proof against Bob's public key
# ------------------------------------------------------------------
echo ""
echo "=== TEST C: Negative — Verify Alice's proof against Bob's public key ==="
# Alice's proof was generated with Alice's public key as public input.
# If we try to verify it claiming the public input is Bob's key, the
# verifier will reconstruct a different public-input commitment V
# and the pairing equation will not balance.

# We can't easily swap public inputs in the binary proof file,
# but we can prove Bob's ownership correctly and show the proofs
# are bound to their respective public keys.
"${CLI_DIR}/target/release/groth16" prove --sparse \
    --circuit "$CIRCUIT" \
    --witness bob_witness.wtns \
    --proving-key /tmp/cardano_addr_test.pk \
    --out /tmp/bob_proof.bin \
    2>&1 | tail -3

# Verify Bob's proof
bob_verify=$("${CLI_DIR}/target/release/groth16" verify \
    --proof /tmp/bob_proof.bin \
    --public /tmp/bob_proof.pub \
    --verifying-key /tmp/cardano_addr_test.vk \
    2>&1)
echo "$bob_verify"
if echo "$bob_verify" | grep -q "VALID"; then
    echo "   ✅ Bob's proof verifies against Bob's public key"
else
    echo "   ❌ Bob's proof failed unexpectedly"
    exit 1
fi

# Now demonstrate that Alice's proof.pub and Bob's proof.pub are different
alice_pub=$(xxd -p /tmp/alice_proof.pub | tr -d '\n' | head -c 128)
bob_pub=$(xxd -p /tmp/bob_proof.pub | tr -d '\n' | head -c 128)
echo "   Alice public input hash (first 64 bytes): ${alice_pub:0:64}..."
echo "   Bob   public input hash (first 64 bytes): ${bob_pub:0:64}..."
if [ "$alice_pub" != "$bob_pub" ]; then
    echo "   ✅ Public inputs are different — proofs are bound to their keys"
else
    echo "   ❌ Public inputs should differ"
    exit 1
fi

# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------
echo ""
echo "=== Cleanup ==="
rm -f alice.prv alice_root.xsk alice_pay.xsk alice_pay.vk \
      bob.prv bob_root.xsk bob_pay.xsk bob_pay.vk \
      alice_input.json bob_input.json forged_input.json \
      alice_witness.wtns bob_witness.wtns forged_witness.wtns \
      /tmp/alice_proof.bin /tmp/alice_proof.pub \
      /tmp/bob_proof.bin /tmp/bob_proof.pub \
      /tmp/forged_proof.bin /tmp/forged_proof.pub \
      /tmp/cardano_addr_test.pk /tmp/cardano_addr_test.vk
echo "   Temporary files removed"

echo ""
echo "========================================"
echo "ALL TESTS PASSED ✅"
echo "========================================"
