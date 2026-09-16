#!/usr/bin/env python3
"""Unit tests for the F5 pool simulation (aiken/f5/pool/pool.py)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pool import Note, PoolState, note_commitment, nullifier_hash  # noqa: E402


class TestNoteAlgebra(unittest.TestCase):
    def test_note_commitment_determinism(self):
        n = Note(nullifier=0x1234, amount=100, blinding=0xABCD0000)
        self.assertEqual(note_commitment(n), note_commitment(n))

    def test_note_commitment_unique(self):
        a = Note(nullifier=1, amount=100, blinding=7)
        b = Note(nullifier=2, amount=100, blinding=7)
        self.assertNotEqual(note_commitment(a), note_commitment(b))

    def test_nullifier_hash_determinism(self):
        self.assertEqual(nullifier_hash(0x1234), nullifier_hash(0x1234))

    def test_note_commitment_differs_from_nullifier_hash(self):
        n = Note(nullifier=0x1234, amount=100, blinding=0xABCD0000)
        self.assertNotEqual(note_commitment(n), nullifier_hash(n.nullifier))


class TestPoolState(unittest.TestCase):
    def test_deposit_changes_root(self):
        pool = PoolState(depth=4)
        r0 = pool.root()
        pool.deposit(pool.new_note(100, 1))
        self.assertNotEqual(pool.root(), r0)

    def test_spend_conservation_enforced(self):
        pool = PoolState(depth=4)
        u = pool.new_note(100, 1)
        pool.deposit(u)
        r1 = pool.new_note(45, 2)
        ch = pool.new_note(40, 3)
        with self.assertRaises(ValueError):
            pool.spend(u, r1, ch, fee=5)  # 45 + 40 + 5 != 100

    def test_spend_input_must_be_deposited(self):
        pool = PoolState(depth=4)
        ghost = pool.new_note(100, 1)
        r1 = pool.new_note(45, 2)
        ch = pool.new_note(50, 3)
        with self.assertRaises(ValueError):
            pool.spend(ghost, r1, ch, fee=5)

    def test_double_spend_rejected(self):
        pool = PoolState(depth=4)
        u = pool.new_note(100, 1)
        pool.deposit(u)
        r1 = pool.new_note(45, 2)
        ch1 = pool.new_note(50, 3)
        pool.apply_spend(u, r1, ch1, fee=5)

        # Reuse of the input nullifier (same note, same outputs) must raise.
        with self.assertRaises(ValueError):
            pool.spend(u, r1, ch1, fee=5)
        self.assertIn(nullifier_hash(u.nullifier), pool.spent)

    def test_spent_note_cannot_be_respent_after_reinsertion(self):
        pool = PoolState(depth=4)
        u = pool.new_note(100, 1)
        pool.deposit(u)
        r1 = pool.new_note(45, 2)
        ch1 = pool.new_note(50, 3)
        pool.apply_spend(u, r1, ch1, fee=5)

        # Even if the exact same commitment leaf reappeared, the nullifier
        # hash being already spent must block the spend.
        self.assertIn(nullifier_hash(u.nullifier), pool.spent)
        with self.assertRaises(ValueError):
            pool.spend(Note(u.nullifier, u.amount, u.blinding), r1, ch1, fee=5)

    def test_merkle_path_direction_semantics(self):
        # A note committed to index 0 (leftmost leaf) must have direction=0
        # for every level, i.e. the sibling is always to the right.
        pool = PoolState(depth=3)
        a = pool.new_note(10, 1)
        pool.deposit(a)  # first note -> leaf index 0
        w = pool.spend(a, pool.new_note(4, 2), pool.new_note(4, 3), fee=2)
        self.assertEqual(w["direction"], ["0", "0", "0"])

    def test_spend_outputs_become_spendable(self):
        pool = PoolState(depth=5)
        u = pool.new_note(100, 1)
        pool.deposit(u)
        r1 = pool.new_note(45, 2)
        ch1 = pool.new_note(50, 3)
        pool.apply_spend(u, r1, ch1, fee=5)

        # r1 and ch1 were inserted into the tree by apply_spend, so they
        # should appear among the pool's unspent notes.
        r1_in = any(n.nullifier == r1.nullifier for n in pool.unspent_notes())
        ch1_in = any(n.nullifier == ch1.nullifier for n in pool.unspent_notes())
        self.assertTrue(r1_in)
        self.assertTrue(ch1_in)

        # And we can spend r1 in a subsequent transaction.
        r2 = pool.new_note(20, 4)
        ch2 = pool.new_note(25, 5)
        w2 = pool.apply_spend(r1, r2, ch2, fee=0)
        self.assertEqual(45, 20 + 25 + 0)
        self.assertEqual(w2["nullifier_hash"], str(nullifier_hash(r1.nullifier)))

    def test_snapshot_roundtrip(self):
        pool = PoolState(depth=4)
        u1 = pool.new_note(100, 1)
        pool.deposit(u1)
        r1 = pool.new_note(45, 2)
        ch1 = pool.new_note(50, 3)
        pool.apply_spend(u1, r1, ch1, fee=5)

        clone = PoolState.from_snapshot(pool.snapshot())
        self.assertEqual(clone.root(), pool.root())
        self.assertEqual(clone.spent, pool.spent)
        self.assertEqual(len(clone.notes), len(pool.notes))


class TestWitnessCompatibility(unittest.TestCase):
    def test_witness_keys_match_gen_privacy_input(self):
        """The witness dict must contain exactly the keys gen_privacy_input.py emits."""
        import json

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "circom" / "PrivacyPool"))
        import gen_privacy_input  # noqa: E402

        expected = set(gen_privacy_input.generate(depth=5, seed=2).keys())
        pool = PoolState(depth=5)
        u = pool.new_note(100, 0xABCD0000 + 2)
        pool.deposit(u)
        r1 = pool.new_note(45, 0xC0DE0001)
        ch1 = pool.new_note(50, 0xC0DE0002)
        w = pool.spend(u, r1, ch1, fee=5)

        self.assertEqual(set(w.keys()), expected)
        # spot-check the public inputs
        self.assertEqual(w["nullifier_hash"], str(nullifier_hash(u.nullifier)))
        self.assertEqual(w["out_commitment_1"], str(note_commitment(r1)))
        self.assertEqual(w["out_commitment_2"], str(note_commitment(ch1)))


if __name__ == "__main__":
    unittest.main()