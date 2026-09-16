#!/usr/bin/env python3
"""
Generate a depth-varied PrivacyPool circuit.

privacy_pool.circom hardcodes `PrivacyPool(4, 32)`.  For benchmarks that sweep
tree depth (which changes both capacity and constraint count) we materialize a
sibling circuit with the requested depth, keeping everything else identical:

    include "privacy_pool_lib.circom";
    component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee]} = PrivacyPool(D, 32);

Usage:
    python3 gen_circuit_depth.py --depth 6 --out /tmp/f5_bench/privacy_pool_d6.circom

The e2e script is then pointed at it with  CIRCUIT=...  (it adds `-l $PP` so
the `include "privacy_pool_lib.circom"` still resolves).
"""

import argparse
import re
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--source", type=Path, default=Path("circom/PrivacyPool/privacy_pool.circom"))
    args = ap.parse_args()

    src = args.source
    text = src.read_text()
    m = re.search(r"PrivacyPool\(\d+,\s*\d+\)", text)
    if not m:
        raise SystemExit(f"could not find 'PrivacyPool(D, R)' in {src}")

    circuit = (
        "pragma circom 2.0.0;\n"
        "\n"
        'include "privacy_pool_lib.circom";\n'
        "\n"
        f"component main {{public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee]}} = PrivacyPool({args.depth}, 32);\n"
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(circuit)
    print(f"wrote {args.out}  (depth {args.depth}, template {src.name})")


if __name__ == "__main__":
    main()