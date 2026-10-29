#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "=== zkVM CI ==="

echo "1. uplc-guest tests"
cd "$ROOT/zkVM/uplc-guest"
cargo test --lib 2>&1 | tail -2
cargo test 2>&1 | tail -2

echo "2. uplc-guest riscv32im build"
rustup target add riscv32im-unknown-none-elf 2>/dev/null || true
cargo build --no-default-features --target riscv32im-unknown-none-elf 2>&1 | tail -3

echo "3. zkvm-onchain tests"
cd "$ROOT/zkVM/onchain"
cargo test 2>&1 | tail -2

echo "4. artifact-gen tests"
cd "$ROOT/zkVM/tools/artifact-gen"
cargo test 2>&1 | tail -2

echo "5. e2e-examples tests"
cd "$ROOT/zkVM/e2e-examples"
cargo test 2>&1 | tail -2

echo "=== All zkVM tests passed ==="
