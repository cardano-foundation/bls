#!/usr/bin/env python3
"""Property-style tests for the F5 pool simulation.

Deterministic (seeded) random walks over deposits/spends asserting the core
pool invariants that the privacy_pool.circom circuit relies on:

  * conservation      -- value never leaks or is created
  * mass balance      -- value held + fees spent == value originally deposited
  * no double spend   -- every nullifier hash is spent at most once
  * path correctness  -- every witness's merkle path re-derives its root
"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pool import Note, PoolState, nullifier_hash  # noqa: E402
from pool import _poseidon_bls12_381 as poseidon_bls12_381  # noqa: E402


def run_walk(seed, depth=5, users=5, spends=8):
    """Simulate `users` users doing up to `spends` spends on a shared pool."""
    rng = random.Random(seed)
    pool = PoolState(depth=depth)

    initial_value = 0
    for _ in range(users):
        amt = rng.randint(50, 200)
        initial_value += amt
        pool.deposit(pool.new_note(amt, rng.randint(1, 10**9)))

    events = []
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
        events.append(pool.apply_spend(src, out1, out2, fee))
    return initial_value, pool, events


def _leaf_of(witness):
    """Reconstruct the input-note commitment from a spend witness's private inputs."""
    h1 = poseidon_bls12_381(int(witness["nullifier"]), int(witness["in_amount"]))
    return poseidon_bls12_381(h1, int(witness["in_blinding"]))


def _rehash_from_path(witness):
    """Walk the witness's sibling/direction arrays leaf -> root by hand."""
    current = _leaf_of(witness)
    # All integers in the witness are stored as decimal strings,
    # exactly like gen_privacy_input.py does.
    for sibling, direction in zip(
        (int(s) for s in witness["sibling"]),
        (d == "1" for d in witness["direction"]),
    ):
        left, right = (sibling, current) if direction else (current, sibling)
        current = poseidon_bls12_381(left, right)
    return current


class TestPoolInvariants(unittest.TestCase):
    def test_conservation_per_spend(self):
        # value in (input note) == value out (two outputs + fee)
        for seed in range(8):
            initial_value, pool, events = run_walk(seed)
            for e in events:
                self.assertEqual(
                    int(e["in_amount"]),
                    int(e["out_amount_1"]) + int(e["out_amount_2"]) + int(e["fee"]),
                    f"seed={seed}",
                )

    def test_mass_balance(self):
        # value held in unspent notes == deposits minus fees paid out
        for seed in range(8):
            initial_value, pool, events = run_walk(seed)
            unspent_value = sum(n.amount for n in pool.unspent_notes())
            total_fees = sum(int(e["fee"]) for e in events)
            self.assertEqual(
                unspent_value + total_fees, initial_value, f"seed={seed}"
            )

    def test_no_double_spend(self):
        for seed in range(8):
            initial_value, pool, events = run_walk(seed)
            all_nh = [e["nullifier_hash"] for e in events]
            self.assertEqual(len(all_nh), len(set(all_nh)), f"seed={seed}")
            self.assertEqual(len(pool.spent), len(all_nh), f"seed={seed}")

    def test_path_rehashes_to_recorded_root(self):
        for seed in range(8):
            initial_value, pool, events = run_walk(seed)
            for e in events:
                self.assertEqual(
                    _rehash_from_path(e), int(e["merkle_root"]), f"seed={seed}"
                )

    def test_every_event_spends_a_real_pool_note(self):
        # Spent notes remain leaves in the insert-only tree, so the input
        # commitment of every spend must be a live leaf at walk end.
        for seed in range(8):
            initial_value, pool, events = run_walk(seed)
            for e in events:
                self.assertIn(_leaf_of(e), pool.tree.leaf_indices, f"seed={seed}")


class TestWalkDeterminism(unittest.TestCase):
    def test_same_seed_same_state(self):
        v1, p1, e1 = run_walk(7)
        v2, p2, e2 = run_walk(7)
        self.assertEqual(p1.snapshot(), p2.snapshot())
        self.assertEqual(v1, v2)
        self.assertEqual(len(e1), len(e2))

    def test_different_seed_different_root(self):
        _, p1, _ = run_walk(7)
        _, p2, _ = run_walk(8)
        self.assertNotEqual(p1.root(), p2.root())


if __name__ == "__main__":
    unittest.main()