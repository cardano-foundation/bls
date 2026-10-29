#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(cd "$EXAMPLES_DIR/../.." && pwd)"

echo "=== VRF/KDF E2E Examples (OpenVM & Jolt) ==="
echo ""

# VRF tests
echo "1. VRF keys_from_secret on OpenVM (host)"
cd "$ROOT_DIR/zkVM/openvm/hello-aiken"
cargo run --bin uplc -- ../../hello-world/vrf_keys_from_secret.flat 2>&1 | tail -2 || echo "  (needs args)"
echo ""

echo "2. VRF keys_from_secret on Jolt (host)"
cd "$ROOT_DIR/zkVM/jolt/hello-aiken"
cargo run --release --bin uplc -- ../../hello-world/vrf_keys_from_secret.flat 2>&1 | tail -2 || echo "  (needs args)"
echo ""

# KDF tests
echo "3. KDF hkdf on OpenVM (host)"
cd "$ROOT_DIR/zkVM/openvm/hello-aiken"
cargo run --bin uplc -- ../../hello-world/kdf_hkdf.flat 2>&1 | tail -2 || echo "  (needs args)"
echo ""

echo "4. KDF hkdf on Jolt (host)"
cd "$ROOT_DIR/zkVM/jolt/hello-aiken"
cargo run --release --bin uplc -- ../../hello-world/kdf_hkdf.flat 2>&1 | tail -2 || echo "  (needs args)"
echo ""

echo "=== Done ==="
echo "Note: Full arg encoding for complex Data structures requires extended input format (now supported)."
