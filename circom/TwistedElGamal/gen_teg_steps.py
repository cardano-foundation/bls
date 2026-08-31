#!/usr/bin/env python3
"""Per-step witness generator for the Twisted-ElGamal Nova transfer chain.

Each Nova step processes one u16 limb of the (old, new) balance pair and
accumulates the net change:

    step i:  state_out = state_in + (new_limb[i] - old_limb[i])
    initial  state_in = 0
    final    state_out = newBalance - oldBalance == -amount

Because the high limbs are shared between the old and new balances, the
accumulated raw sum collapses exactly to the transfer amount, so the IVC
state chain proves value conservation.  This mirrors
`circom/PrivacyPool/gen_nova_privpool_steps.py` (which does the same chained
witness generation for the Merkle walk).

Usage:
    python3 gen_teg_steps.py --wasm <step.wasm> \
        [--old-balance 100000] [--new-balance 99750] [--nlimbs 8] --dir <out-dir>
"""
import argparse
import json
import os
import subprocess
import sys


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAILED: {' '.join(map(str, cmd))}\n{r.stderr[-500:]}", file=sys.stderr)
        sys.exit(1)


def to_limbs(value: int, nlimbs: int):
    """Little-endian base-2^16 decomposition, zero-padded to nlimbs."""
    limbs = []
    for _ in range(nlimbs):
        limbs.append(value & 0xFFFF)
        value >>= 16
    return limbs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--old-balance", type=int, default=100000)
    ap.add_argument("--new-balance", type=int, default=99750)
    ap.add_argument("--nlimbs", type=int, default=8)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    amount = args.old_balance - args.new_balance
    old_limbs = to_limbs(args.old_balance, args.nlimbs)
    new_limbs = to_limbs(args.new_balance, args.nlimbs)

    # High limbs are shared, so the raw accumulated sum (new-old) collapses
    # exactly to -amount, giving clean value-conservation semantics.
    state_in = 0
    os.makedirs(args.dir, exist_ok=True)
    for i in range(args.nlimbs):
        inputs = {
            "state_in": str(state_in),
            "old_limb": str(old_limbs[i]),
            "new_limb": str(new_limbs[i]),
        }
        in_file = os.path.join(args.dir, f"input_{i:04}.json")
        wtns = os.path.join(args.dir, f"step_{i:04}.wtns")
        json.dump(inputs, open(in_file, "w"))
        run([args.snarkjs, "wtns", "calculate", args.wasm, in_file, wtns])

        wit_json = os.path.join(args.dir, f"wit_{i:04}.json")
        run([args.snarkjs, "wtns", "export", "json", wtns, wit_json])
        with open(wit_json) as f:
            wit = json.load(f)
        os.remove(wit_json)
        state_in = int(wit[1])  # 0-index 1 == state_out

    # BLS12-381 scalar field prime (matches --prime bls12381).
    field_prime = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    print(f"wrote {args.nlimbs} step witnesses to {args.dir}")
    print(f"old balance = {args.old_balance}  new balance = {args.new_balance}  amount = {amount}")
    print(f"final state_out (field) = {state_in}")
    print(f"expected (-amount mod field) = {(-amount) % field_prime}")
    assert state_in == (-amount) % field_prime, "IVC chain final state != -amount"
    print("OK: folded chain state equals -amount (value conservation)")


if __name__ == "__main__":
    main()
