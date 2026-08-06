#!/usr/bin/env python3
"""End-to-end test for CardanoKeyOwnershipSMT circuit with valid Ed25519 keys.

All cryptography is delegated to the `groth16-prover smt` CLI (`smt key` for
the Ed25519 decompression / MiMC leaf / bit decomposition, `smt insert` for
the tree, `smt cardano-input` for the final circuit input). Python only
generates a fresh Ed25519 key pair with PyNaCl and orchestrates the CLI.
"""

import json
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import key_record_cli, build_smt_and_input_cli

import nacl.signing


def generate_test_input(depth=4, index=0, output_file="test_smt_input.json", smt_cli="groth16-prover"):
    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key

    seed = bytes(sk)
    pk_bytes = pk.encode()
    scalar_bytes = hashlib.sha512(seed).digest()[:32]

    key_record = key_record_cli(pk_bytes.hex(), scalar_bytes.hex(), smt_cli)

    other_leaves = [12345, 67890, 11111, 22222, 33333, 44444, 55555, 66666, 77777, 88888, 99999, 10101, 20202, 30303, 40404]
    leaves = [int(key_record["leaf"])] + other_leaves
    circuit_input = build_smt_and_input_cli(
        leaves, index, depth, key_record, output_file, smt_cli
    )

    print(f"Generated {output_file}")
    print(f"  Public key: {pk_bytes.hex()}")
    print(f"  Scalar (hex): {scalar_bytes.hex()}")
    print(f"  SMT depth: {depth}")
    print(f"  SMT leaf index: {index}")
    print(f"  SMT builder: groth16-prover smt CLI (--smt-cli {smt_cli})")
    print(f"  SMT root: {circuit_input['smt_root']}")
    print(f"  MiMC leaf: {key_record['leaf']} (smt key CLI)")

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
        help="Path to the 'groth16-prover' binary used for all crypto "
             "(must expose the 'smt' subcommand, i.e. be built with the "
             "'privacy' feature). Default: 'groth16-prover' (looked up on PATH).",
    )
    args = parser.parse_args()
    generate_test_input(depth=args.depth, index=args.index,
                        output_file=args.output, smt_cli=args.smt_cli)
