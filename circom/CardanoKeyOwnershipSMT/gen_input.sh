#!/bin/bash
# gen_input.sh — pure-shell circuit-input generator for CardanoKeyOwnershipSMT.
#
# All cryptography is performed by the `smt` CLI (`smt key`, `smt insert`,
# `smt cardano-input`); this script only chooses the key source and
# orchestrates those commands. No Python, PyNaCl, or in-script crypto.
#
# Two key sources:
#   --fixed                 fixed deterministic test key (no external deps)
#   --xsk FILE --vk FILE    real cardano-address keys, decoded via `bech32`
#
# Usage:
#   gen_input.sh --fixed --depth 4 --index 0 --output input.json \
#                [--leaves "11111 22222 33333"] [--smt-cli smt]
#   gen_input.sh --xsk pay.xsk --vk pay.vk --depth 4 --output input.json \
#                [--leaves "11111 22222 33333"] [--smt-cli smt]
#
# With `--index 0` the leaves are inserted sequentially (leaf first); with a
# non-zero `--index` a single leaf is placed at that index (zero-padded tree).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fixed deterministic test key (seed a54554e8...): the compressed public key
# and the Ed25519 scalar SHA512(seed)[:32]. Same values as test_smt_simple.py.
FIXED_PK_HEX="6f1aefc3c897385b1f65d663ab3bddc449ed2c47221c6b6c8a0650eb9791fd15"
FIXED_XSK_HEX="07ac47da43d59cdb54f1478e9b4423017a50ee1b9395abc485f6fb503e636c76"

DEPTH=4
INDEX=0
OUTPUT="input.json"
SMT_CLI="smt"
LEAVES=""
MODE=""

usage() {
    echo "Usage: $0 --fixed | --xsk <file> --vk <file> [--depth N] [--index N] [--output FILE] [--leaves \"a b c\"] [--smt-cli PATH]"
    echo "  --fixed       use a fixed deterministic test key"
    echo "  --xsk/--vk    decode real bech32 key files via the 'bech32' CLI"
    echo "  --leaves      extra leaves to insert (space-separated integers)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixed) MODE="fixed"; shift ;;
        --xsk) MODE="real"; XSK_FILE="$2"; shift 2 ;;
        --vk) VK_FILE="$2"; shift 2 ;;
        --depth) DEPTH="$2"; shift 2 ;;
        --index) INDEX="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --leaves) LEAVES="$2"; shift 2 ;;
        --smt-cli) SMT_CLI="$2"; shift 2 ;;
        *) echo "ERROR: unknown argument: $1"; usage ;;
    esac
done

# --- key source -----------------------------------------------------------
case "$MODE" in
    fixed)
        PK_HEX="$FIXED_PK_HEX"
        XSK_HEX="$FIXED_XSK_HEX"
        ;;
    real)
        if ! command -v bech32 &> /dev/null; then
            echo "ERROR: 'bech32' CLI not found in PATH."
            echo "  Install from https://github.com/IntersectMBO/bech32/releases"
            echo "  or build from source: cabal install bech32"
            exit 1
        fi
        PK_HEX=$(cat "$VK_FILE" | bech32 | tr -d '\n')
        # The first 32 bytes of the extended signing key are the Ed25519 scalar.
        XSK_HEX=$(cat "$XSK_FILE" | bech32 | tr -d '\n')
        XSK_HEX="${XSK_HEX:0:64}"
        ;;
    *)
        echo "ERROR: choose a key source: --fixed or --xsk <file> --vk <file>"
        usage
        ;;
esac

# --- run the CLI pipeline -------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
KEY_FILE="$TMP/key.json"
STATE="$TMP/smt.json"

"$SMT_CLI" key --vk "$PK_HEX" --xsk "$XSK_HEX" --json > "$KEY_FILE"
LEAF=$(grep -oP '"leaf":\s*"\K[0-9]+' "$KEY_FILE")

if [[ "$INDEX" == "0" ]]; then
    ITEMS="$LEAF"
    if [[ -n "$LEAVES" ]]; then
        ITEMS="$LEAF,$(echo "$LEAVES" | tr ' ' ',' | tr -d '\n')"
    fi
    "$SMT_CLI" insert --depth "$DEPTH" --items "$ITEMS" --state "$STATE" > /dev/null
else
    "$SMT_CLI" insert --depth "$DEPTH" --items "$LEAF" --index "$INDEX" --state "$STATE" > /dev/null
fi

"$SMT_CLI" cardano-input --state "$STATE" --key "$KEY_FILE" --out "$OUTPUT"

echo "Generated $OUTPUT"
echo "  Public key:     $PK_HEX"
echo "  Scalar (hex):   $XSK_HEX"
echo "  SMT depth:      $DEPTH"
echo "  SMT leaf index: $INDEX"
echo "  SMT builder:    smt CLI (--smt-cli $SMT_CLI)"
echo "  SMT root:       $(grep -oP '"smt_root":\s*"\K[0-9]+' "$OUTPUT")"
echo "  MiMC leaf:      $LEAF (smt key CLI)"
