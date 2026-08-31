#!/usr/bin/env python3
"""Per-step witness generator for the privacy-pool Nova Merkle chain.

Each Nova step walks one level of the input note's Merkle path.  Unlike the
generic gen_nova_steps.py (which keeps private inputs fixed), this script
feeds sibling[i] / direction[i] for level i on step i, so the chained IVC
transforms the leaf commitment into the tree root.

    step i:  state_out = Poseidon(switch(state_in, sibling[i], direction[i]))
    initial state_in = input note commitment
    final   state_out = merkle_root

Usage:
    python3 gen_nova_privpool_steps.py --wasm <step.wasm> \
        --depth N --dir <output-dir>
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PoseidonMerkle" / "helpers_py"))
from poseidon_merkle import SparseMerkleTree  # noqa: E402
from gen_privacy_input import note_commitment  # noqa: E402


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}\n{r.stderr[-500:]}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--depth", type=int, required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)

    # Reuse the exact same note/lure from gen_privacy_input so the input note
    # (nullifier=0x1234, amount=100, blinding) is a committed leaf.
    nullifier = 0x1234
    in_amount = 100
    in_blinding = 0xABCD0000 + 1
    leaf = note_commitment(nullifier, in_amount, in_blinding)

    # Build the same tree as gen_privacy_input: unrelated deposits + input leaf.
    tree = SparseMerkleTree(args.depth)
    for i in range(5):
        tree.insert(note_commitment(0xDEAD + i, 10 + i, 0xBEEF0000 + i))
    tree.insert(leaf)
    path = tree.path(leaf)  # list of (sibling, direction) leaf->root

    t0 = __import__("time").perf_counter()
    state_in = leaf
    for i in range(args.depth):
        sibling, direction = path[i]
        inputs = {
            "state_in": str(state_in),
            "sibling": str(sibling),
            "direction": "1" if direction else "0",
        }
        in_file = os.path.join(args.dir, f"input_{i:04}.json")
        wtns = os.path.join(args.dir, f"step_{i:04}.wtns")
        json.dump(inputs, open(in_file, "w"))
        run([args.snarkjs, "wtns", "calculate", args.wasm, in_file, wtns])

        # public outputs at indices 1..1+len(outputs) in main order
        wit_json = os.path.join(args.dir, f"wit_{i:04}.json")
        run([args.snarkjs, "wtns", "export", "json", wtns, wit_json])
        with open(wit_json) as f:
            wit = json.load(f)
        os.remove(wit_json)
        state_in = wit[1]

    root = tree.digest()
    print(f"wrote {args.depth} step witnesses to {args.dir}")
    print(f"leaf            = {leaf}")
    print(f"final state_out = {state_in}")
    print(f"expected root   = {root}")
    assert str(state_in) == str(root), "IVC chain did not reach the tree root"
    print("OK: folded chain reaches the merkle root")


if __name__ == "__main__":
    main()
