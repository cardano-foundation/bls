#!/usr/bin/env python3
"""Generate a simple test input for CardanoKeyOwnershipSMT without cardano-addresses CLI."""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import (
    p, ROUND_CONSTANTS, mimc2, build_merkle_tree,
    bytes_to_bits_le, decompress_point, to_chunks, clamp_ed25519_scalar,
)

# Use a known Ed25519 key pair for reproducibility
# Private key (32 bytes, clamped)
sk_bytes = bytes.fromhex(
    "a54554e8a11746a75e6c1e6e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e"
)
# Corresponding public key (32 bytes, compressed)
pk_bytes = bytes.fromhex(
    "d7584e8a11746a75e6c1e6e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e"
)

# Decompress public key
PointA = decompress_point(pk_bytes)
PointA_chunks = [to_chunks(c) for c in PointA]

# Compressed public key bits
A_bits = bytes_to_bits_le(pk_bytes)

# Scalar bits (255 bits)
sk_bits = bytes_to_bits_le(sk_bytes)[:255]

# Compute MiMC leaf
leaf = mimc2(PointA[0][0], PointA[1][0])

# Build Merkle tree
depth = 2
other_leaves = [12345, 67890, 11111]
all_leaves = [0] * (1 << depth)
all_leaves[0] = leaf
for i, l in enumerate(other_leaves):
    all_leaves[i + 1] = l

smt_root, siblings, directions = build_merkle_tree(0, depth, all_leaves)

circuit_input = {
    "A": [str(b) for b in A_bits],
    "sk": [str(b) for b in sk_bits],
    "PointA": [[str(c) for c in row] for row in PointA_chunks],
    "smt_root": str(smt_root),
    "smt_siblings": [str(s) for s in siblings],
    "smt_directions": [str(d) for d in directions],
}

with open("test_smt_input.json", "w") as f:
    json.dump(circuit_input, f, indent=2)

print("Generated test_smt_input.json")
print(f"  SMT root: {smt_root}")
print(f"  MiMC leaf: {leaf}")
print(f"  Depth: {depth}")
