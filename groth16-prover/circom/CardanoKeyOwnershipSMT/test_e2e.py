#!/usr/bin/env python3
"""End-to-end test for CardanoKeyOwnershipSMT circuit with valid Ed25519 keys."""

import json
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import (
    p, ROUND_CONSTANTS, mimc2, build_merkle_tree,
    bytes_to_bits_le, decompress_point, to_chunks, clamp_ed25519_scalar,
)

import nacl.signing


def generate_test_input(depth=4, index=0, output_file="test_smt_input.json"):
    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key

    seed = bytes(sk)
    pk_bytes = pk.encode()

    scalar_bytes = hashlib.sha512(seed).digest()[:32]
    scalar = clamp_ed25519_scalar(scalar_bytes)

    A_bits = bytes_to_bits_le(pk_bytes)
    sk_bits = bytes_to_bits_le(scalar)[:255]

    PointA = decompress_point(pk_bytes)
    PointA_chunks = [to_chunks(c) for c in PointA]

    leaf = mimc2(PointA[0], PointA[1])

    other_leaves = [12345, 67890, 11111, 22222, 33333, 44444, 55555, 66666, 77777, 88888, 99999, 10101, 20202, 30303, 40404]
    all_leaves = [0] * (1 << depth)
    all_leaves[index] = leaf
    for i, l in enumerate(other_leaves):
        all_leaves[i + 1] = l

    smt_root, siblings, directions = build_merkle_tree(index, depth, all_leaves)

    circuit_input = {
        "A": [str(b) for b in A_bits],
        "sk": [str(b) for b in sk_bits],
        "PointA": [[str(c) for c in row] for row in PointA_chunks],
        "smt_root": str(smt_root),
        "smt_siblings": [str(s) for s in siblings],
        "smt_directions": [str(d) for d in directions],
    }

    with open(output_file, "w") as f:
        json.dump(circuit_input, f, indent=2)

    print(f"Generated {output_file}")
    print(f"  Public key: {pk_bytes.hex()}")
    print(f"  Scalar (hex): {scalar.hex()}")
    print(f"  SMT depth: {depth}")
    print(f"  SMT leaf index: {index}")
    print(f"  SMT root: {smt_root}")
    print(f"  MiMC leaf: {leaf}")

    return circuit_input


if __name__ == "__main__":
    generate_test_input()