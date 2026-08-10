#!/usr/bin/env python3
"""Generate a simple test input for CardanoKeyOwnershipSMT without cardano-addresses CLI.

All cryptography is delegated to the standalone `smt` CLI (see
gen_smt_input.py); Python only derives a fixed-seed Ed25519 key pair with
PyNaCl and orchestrates the CLI commands.
"""

import argparse
import json
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_smt_input import key_record_cli, build_smt_and_input_cli

import nacl.signing


def generate_simple_input(depth=2, index=0, output_file="test_smt_input.json", smt_cli="smt"):
    # Fixed seed for reproducibility (32 bytes)
    seed = bytes.fromhex("a54554e8a11746a75e6c1e6e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e8e0e")
    sk = nacl.signing.SigningKey(seed)
    pk_bytes = sk.verify_key.encode()

    # Ed25519 scalar from the seed (as in test_e2e)
    scalar_bytes = hashlib.sha512(seed).digest()[:32]

    key_record = key_record_cli(pk_bytes.hex(), scalar_bytes.hex(), smt_cli)

    other_leaves = [12345, 67890, 11111]
    leaves = [int(key_record["leaf"])] + other_leaves
    circuit_input = build_smt_and_input_cli(
        leaves, index, depth, key_record, output_file, smt_cli
    )

    print(f"Generated {output_file}")
    print(f"  Public key: {pk_bytes.hex()}")
    print(f"  SMT root: {circuit_input['smt_root']}")
    print(f"  MiMC leaf: {key_record['leaf']} (smt key CLI)")
    print(f"  Depth: {depth}")
    print(f"  SMT builder: smt CLI (--smt-cli {smt_cli})")

    return circuit_input


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple input generator for CardanoKeyOwnershipSMT.")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--output", default="test_smt_input.json")
    parser.add_argument(
        "--smt-cli",
        default="smt",
        help="Path to the standalone 'smt' CLI binary (clis/smt) used for all "
             "crypto. Default: 'smt' (looked up on PATH).",
    )
    args = parser.parse_args()
    generate_simple_input(depth=args.depth, index=args.index,
                          output_file=args.output, smt_cli=args.smt_cli)
