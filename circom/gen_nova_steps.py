#!/usr/bin/env python3
"""Iteratively generate chained step witnesses for a Nova step circuit.

Drives the step circuit's wasm one step at a time, feeding each step's public
outputs back as the next step's public inputs so the IVC state chain invariant
(state_in[i+1] == state_out[i]) holds by construction:

    inputs[0] --wasm--> step_0000.wtns --outputs--> inputs[1] --> step_0001.wtns ...

Private inputs stay fixed across steps (passed once in the initial input JSON,
which therefore contains BOTH the public state signals and the private ones).

Usage:
    python3 gen_nova_steps.py --wasm <circuit.wasm> \
        --initial <input.json> --outputs <out_a,out_b,...> \
        --steps N --dir <output-dir> [--snarkjs snarkjs]
"""

import argparse
import json
import os
import subprocess
import sys

sys.setrecursionlimit(10000)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    FAILED: {' '.join(cmd)}\n{r.stderr[-800:]}", file=sys.stderr)
        sys.exit(1)
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--initial", required=True,
                    help="JSON with the first step's inputs (public state + private)")
    ap.add_argument("--outputs", required=True,
                    help="comma-separated 'input_signal=output_signal' pairs, e.g. "
                         "'dbl_in_0=dbl_out_0,dbl_in_1=dbl_out_1' (outputs in main-order)")
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    if os.path.exists(os.path.join(args.dir, "step_0000.wtns")):
        print(f"{args.dir} already has step witnesses; delete it to regenerate")
        sys.exit(1)
    os.makedirs(args.dir, exist_ok=True)

    inputs = json.load(open(args.initial))
    pairs = []
    for tok in args.outputs.split(","):
        if not tok.strip():
            continue
        in_sig, _, out_sig = tok.strip().partition("=")
        if not out_sig:
            sys.exit(f"expected 'input=output', got '{tok.strip()}'")
        pairs.append((in_sig.strip(), out_sig.strip()))
    if not pairs:
        sys.exit("no output mappings given")
    for in_sig, _ in pairs:
        if in_sig not in inputs:
            sys.exit(f"input signal '{in_sig}' is not in the initial input JSON")

    t0 = __import__("time").perf_counter()
    for i in range(args.steps):
        in_file = os.path.join(args.dir, f"input_{i:04}.json")
        wtns = os.path.join(args.dir, f"step_{i:04}.wtns")
        json.dump(inputs, open(in_file, "w"))
        run([args.snarkjs, "wtns", "calculate", args.wasm, in_file, wtns])
        # circom witness layout: signal 0 = constant 1, then main's public
        # outputs in declaration order at indices 1..1+len(outputs).
        wit_json = os.path.join(args.dir, f"wit_{i:04}.json")
        run([args.snarkjs, "wtns", "export", "json", wtns, wit_json])
        with open(wit_json) as f:
            wit = json.load(f)
        os.remove(wit_json)
        for (in_sig, _), val in zip(pairs, wit[1 : 1 + len(pairs)]):
            inputs[in_sig] = val
        if (i + 1) % 25 == 0 or i + 1 == args.steps:
            dt = __import__("time").perf_counter() - t0
            print(f"  step {i + 1}/{args.steps} ({dt:.1f}s elapsed)")

    print(f"wrote {args.steps} step witnesses to {args.dir}")


if __name__ == "__main__":
    main()
