#!/usr/bin/env python3
"""End-to-end test for CardanoKeyOwnershipSMT circuit with valid Ed25519 keys."""

import json
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import (
    P_BLS, P_ED, ROUND_CONSTANTS, mimc2, multi_mimc7,
    build_merkle_tree_cli_multi, build_merkle_tree_cli,
    bytes_to_bits_le, decompress_point, to_chunks, clamp_ed25519_scalar,
)

import nacl.signing


def generate_test_input(depth=4, index=0, output_file="test_smt_input.json", smt_cli="groth16-prover"):
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

    leaf = multi_mimc7(PointA_chunks[0] + PointA_chunks[1])

    other_leaves = [12345, 67890, 11111, 22222, 33333, 44444, 55555, 66666, 77777, 88888, 99999, 10101, 20202, 30303, 40404]
    if index == 0:
        smt_root, siblings, directions, used_cli = build_merkle_tree_cli_multi(
            [leaf] + other_leaves, index, depth, smt_cli)
    else:
        smt_root, siblings, directions, used_cli = build_merkle_tree_cli(
            leaf, index, depth, smt_cli)

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
    if used_cli:
        print(f"  SMT builder: groth16-prover smt CLI (--smt-cli {smt_cli})")
    else:
        print(f"  SMT builder: PYTHON FALLBACK (smt CLI '{smt_cli}' unavailable)")
    print(f"  SMT root: {smt_root}")
    print(f"  MiMC leaf: {leaf}")

    return circuit_input


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="End-to-end test input for CardanoKeyOwnershipSMT.")
    parser.add_argument("--depth", type=int, default=4)
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
    generate_test_input(depth=args.depth, index=args.index,
                        output_file=args.output, smt_cli=args.smt_cli)
