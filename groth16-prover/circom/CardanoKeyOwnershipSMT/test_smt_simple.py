#!/usr/bin/env python3
"""Generate a simple test input for CardanoKeyOwnershipSMT without cardano-addresses CLI."""

import json
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import (
    P_BLS, P_ED, ROUND_CONSTANTS, mimc2, multi_mimc7, build_merkle_tree,
    bytes_to_bits_le, decompress_point, to_chunks, clamp_ed25519_scalar,
)

import nacl.signing

# Fixed seed for reproducibility (32 bytes)
seed = bytes.fromhex("a54554e8a11746a75e6c1e6e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e")
sk = nacl.signing.SigningKey(seed)
pk_bytes = sk.verify_key.encode()

# Ed25519 scalar from the seed (as in test_e2e)
scalar = clamp_ed25519_scalar(hashlib.sha512(seed).digest()[:32])

# Decompress public key
PointA = decompress_point(pk_bytes)
PointA_chunks = [to_chunks(c) for c in PointA]

# Compressed public key bits
A_bits = bytes_to_bits_le(pk_bytes)

# Scalar bits (255 bits)
sk_bits = bytes_to_bits_le(scalar)[:255]

# Compute MiMC leaf over the full (x, y) coordinates
leaf = multi_mimc7(PointA_chunks[0] + PointA_chunks[1])

# Build Merkle tree (empty leaves default to 0, matching the Rust SMT)
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
print(f"  Public key: {pk_bytes.hex()}")
print(f"  SMT root: {smt_root}")
print(f"  MiMC leaf: {leaf}")
print(f"  Depth: {depth}")
