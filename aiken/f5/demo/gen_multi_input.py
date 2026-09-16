#!/usr/bin/env python3
"""
Generate a multi-user F5 witness scenario for privacy_pool.circom.

Lays out `users` deposits (one per user) and then `spends` 1-in/2-out spends,
each submitted by a distinct user against the *shared* pool root at that point
in time.  The pool state (Poseidon Merkle tree + nullifier log) is the same
aiken/f5/pool module validated by the unit/golden/property tests, so every
generated input.json:

  * mirrors gen_privacy_input.py key-for-key (decimal strings, sibling path),
  * satisfies conservation and no-double-spend by construction,
  * references a Merkle root that equals the live pool root at spend time.

Each user's witness is written to $OUT/user_NNN.json.  scenario.json holds the
ordering, the final pool root, and the public inputs of every spend in the exact
order the circuit exposes them:
  [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee]

Usage:
    python3 gen_multi_input.py --depth 5 --users 4 --spends 4 --seed 42 --out DIR
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pool"))

from pool import Note, PoolState, note_commitment, write_input_json  # noqa: E402


def build_scenario(depth: int, users: int, spends: int, seed: int) -> tuple:
    """Generate the deposit/spend walk; returns (pool, list-of-witnesses)."""
    rng = random.Random(seed)
    pool = PoolState(depth=depth)

    deposited = []
    for u in range(users):
        amt = rng.randint(50, 200)
        note = pool.new_note(amt, rng.randint(1, 10**9))
        pool.deposit(note)
        deposited.append(note)

    witnesses = []
    for _ in range(spends):
        spendable = pool.unspent_notes()
        if not spendable:
            break
        src = rng.choice(spendable)
        fee = rng.randint(0, src.amount)
        out1_amt = rng.randint(0, src.amount - fee)
        out2_amt = src.amount - out1_amt - fee
        out1 = pool.new_note(out1_amt, rng.randint(1, 10**9))
        out2 = pool.new_note(out2_amt, rng.randint(1, 10**9))
        witnesses.append(pool.apply_spend(src, out1, out2, fee))
    return pool, witnesses


PUBLIC_KEYS = ["merkle_root", "nullifier_hash", "out_commitment_1", "out_commitment_2", "fee"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--users", type=int, default=4)
    ap.add_argument("--spends", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    spends = args.spends if args.spends is not None else args.users

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    pool, witnesses = build_scenario(args.depth, args.users, spends, args.seed)

    scenario = {
        "depth": args.depth,
        "users": args.users,
        "spends": len(witnesses),
        "seed": args.seed,
        "final_root": str(pool.root()),
        "spent_nullifier_hashes": sorted(str(h) for h in pool.spent),
        "spends": [],
    }
    for i, w in enumerate(witnesses):
        dest = out / f"user_{i:03d}.json"
        write_input_json(w, dest)
        scenario["spends"].append(
            {
                "user": f"user_{i:03d}.json",
                "public": [w[k] for k in PUBLIC_KEYS],
                "input_note_amount": int(w["in_amount"]),
                "output_commitment_leaves": [int(w["out_commitment_1"]), int(w["out_commitment_2"])],
            }
        )

    scenario_path = out / "scenario.json"
    scenario_path.write_text(json.dumps(scenario, indent=2) + "\n")

    print(f"wrote {len(witnesses)} user witnesses under {out}")
    print(f"final pool root       : {scenario['final_root']}")
    print(f"spent nullifiers      : {len(pool.spent)}")
    for s in scenario["spends"]:
        print(f"  {s['user']}  input={s['input_note_amount']}  "
              f"fee={s['public'][4]}")


if __name__ == "__main__":
    main()