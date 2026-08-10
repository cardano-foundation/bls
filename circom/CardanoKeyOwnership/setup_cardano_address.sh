#!/usr/bin/env bash
set -euo pipefail

# setup_cardano_address.sh
#
# Full workflow to derive a Cardano payment key from a fresh mnemonic using
# cardano-addresses (https://github.com/IntersectMBO/cardano-addresses) and
# generate the corresponding Ed25519 ownership circuit input.
#
# Usage:
#   ./setup_cardano_address.sh
#
# Produces in the current directory:
#   phrase.prv          — 15-word recovery phrase
#   root.xsk            — extended root signing key (bech32)
#   pay.xsk             — payment signing key 1852H/1815H/0H/0/0 (bech32)
#   pay.vk              — payment public key without chain code (bech32)
#   input.json          — circuit witness input for cardano_ed25519_ownership.circom
#
# Requirements:
#   - cardano-address  in $PATH
#   - bech32 CLI in $PATH  (install from https://github.com/IntersectMBO/bech32/releases)
#   - gen_cardano_address_input.py  in the same directory

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check prerequisites
if ! command -v cardano-address &> /dev/null; then
    echo "ERROR: cardano-address not found in PATH."
    echo "  Install from https://github.com/IntersectMBO/cardano-addresses"
    exit 1
fi

if ! command -v bech32 &> /dev/null; then
    echo "ERROR: bech32 CLI not found in PATH."
    echo "  Install from https://github.com/IntersectMBO/bech32/releases"
    echo "  or build from source: cabal install bech32"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/gen_cardano_address_input.py" ]; then
    echo "ERROR: gen_cardano_address_input.py not found in $SCRIPT_DIR"
    exit 1
fi

echo "=== 1. Generate 15-word recovery phrase ==="
cardano-address recovery-phrase generate --size 15 > phrase.prv
echo "   phrase.prv  written"

echo "=== 2. Derive extended root signing key ==="
cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
echo "   root.xsk    written"

echo "=== 3. Derive payment signing key (1852H/1815H/0H/0/0) ==="
cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
echo "   pay.xsk     written"

echo "=== 4. Extract public payment key (no chain code) ==="
cardano-address key public --without-chain-code < pay.xsk > pay.vk
echo "   pay.vk      written"

echo "=== 5. Generate circuit witness input ==="
python3 "$SCRIPT_DIR/gen_cardano_address_input.py" \
    --xsk pay.xsk \
    --vk pay.vk \
    -o input.json
echo "   input.json   written"

echo ""
echo "=== Done. Files in $(pwd) ==="
ls -la phrase.prv root.xsk pay.xsk pay.vk input.json
echo ""
echo "Next steps:"
echo "  snarkjs wtns calculate cardano_ed25519_ownership_js/cardano_ed25519_ownership.wasm input.json witness.wtns"
