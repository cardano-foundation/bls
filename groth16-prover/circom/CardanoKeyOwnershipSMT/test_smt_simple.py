#!/usr/bin/env python3
"""Generate a simple test input for CardanoKeyOwnershipSMT without cardano-addresses CLI."""

import argparse
import json
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import (
    P_BLS, P_ED, ROUND_CONSTANTS, mimc2, multi_mimc7, compute_leaf_cli,
    build_merkle_tree_cli_multi,
    bytes_to_bits_le, decompress_point, to_chunks, clamp_ed25519_scalar,
)

import nacl.signing


def generate_simple_input(depth=2, index=0, output_file="test_smt_input.json", smt_cli="groth16-prover"):
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

    # Compute the MiMC leaf over the full (x, y) coordinates via the CLI
    leaf, used_leaf_cli = compute_leaf_cli(PointA_chunks, smt_cli)

    # Build the SMT via the groth16-prover smt CLI (Python fallback if missing)
    other_leaves = [12345, 67890, 11111]
    smt_root, siblings, directions, used_cli = build_merkle_tree_cli_multi(
        [leaf] + other_leaves, index, depth, smt_cli)

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
    print(f"  SMT root: {smt_root}")
    if used_leaf_cli:
        print(f"  MiMC leaf: {leaf} (smt leaf CLI)")
    else:
        print(f"  MiMC leaf: {leaf} (PYTHON FALLBACK)")
    print(f"  Depth: {depth}")
    if used_cli:
        print(f"  SMT builder: groth16-prover smt CLI (--smt-cli {smt_cli})")
    else:
        print(f"  SMT builder: PYTHON FALLBACK (smt CLI '{smt_cli}' unavailable)")

    return circuit_input


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple input generator for CardanoKeyOwnershipSMT.")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--output", default="test_smt_input.json")
    parser.add_argument(
        "--smt-cli",
        default="groth16-prover",
        help="Path to the 'groth16-prover' binary used to build the SMT "
             "(must expose the 'smt' subcommand, i.e. be built with the "
             "'privacy' feature). Default: 'groth16-prover' (looked up on PATH).",
    )
    args = parser.parse_args()
    generate_simple_input(depth=args.depth, index=args.index,
                          output_file=args.output, smt_cli=args.smt_cli)
