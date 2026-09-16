#!/usr/bin/env python3
"""Golden regression tests for the F5 pool simulation.

A fully deterministic multi-user scenario produces fixed roots, commitments,
nullifier hashes and witness public inputs. The expected values recorded here
were produced by this simulation and are hard assertions on the exact BLS12-381
scalar-field arithmetic -- any change to the hashing/tree bookkeeping breaks
them, which protects the e2e pipeline from silent drift.
"""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pool import Note, PoolState, note_commitment, nullifier_hash  # noqa: E402
from pool import _poseidon_bls12_381 as poseidon_bls12_381  # noqa: E402


class TestGoldenScenario(unittest.TestCase):
    """The same 4-user / 3-spend scenario aiken/f5/demo runs end-to-end."""

    def _build(self):
        pool = PoolState(depth=4)

        # -- deposits: 4 users each drop one note -------------------------
        alice = Note(0x1111, 100, 0xA1110000)
        bob = Note(0x2222, 50, 0xA2220000)
        carol = Note(0x3333, 90, 0xA3330000)
        dana = Note(0x4444, 200, 0xA4440000)
        for n in (alice, bob, carol, dana):
            pool.deposit(n)

        # -- spend #1: bob -> dana + change -------------------------------
        to_dana = Note(0x5151, 20, 0xB1510000)
        change = Note(0x5252, 25, 0xB2520000)
        w1 = pool.apply_spend(bob, to_dana, change, fee=5)

        # -- spend #2: alice -> carol + change ----------------------------
        to_carol = Note(0x6161, 40, 0xB1610000)
        change2 = Note(0x6262, 55, 0xB2620000)
        w2 = pool.apply_spend(alice, to_carol, change2, fee=5)

        # -- spend #3: dana spends the note she received ------------------
        to_earl = Note(0x7171, 10, 0xB1710000)
        change3 = Note(0x7272, 5, 0xB2720000)
        w3 = pool.apply_spend(to_dana, to_earl, change3, fee=5)

        return pool, (w1, w2, w3)

    def test_golden_roots(self):
        pool, witnesses = self._build()

        self.assertEqual(
            pool.root(),
            0x11916FEB307DB209EBD63FEF56EE79E6DC5218B552ACB89F64B6FA311081E545,
        )
        # each spend witness froze a root that differs from the live pool root
        for w in witnesses:
            self.assertNotEqual(int(w["merkle_root"]), pool.root())

    def test_golden_spent_nullifiers(self):
        pool, _ = self._build()
        expected = {nullifier_hash(0x1111), nullifier_hash(0x2222), nullifier_hash(0x5151)}
        self.assertEqual(pool.spent, expected)
        # and the exact hashes, pinned:
        self.assertEqual(
            {hex(h) for h in pool.spent},
            {
                hex(0x4FCF342B941314527CB03F0E7AC469D316DA2E4BDA745E5B0897D66991D6321E),
                hex(0x1133311C78676EEF82BE2FCD3FD6AB8EE128DBB1D204765C4F7B923E1F99D76D),
                hex(0x72AA16765D953DD6C5D6EA7D073C90CD05105AFF47C83AA66CD3D3C9FA70FCE8),
            },
        )

    def test_golden_commitments(self):
        # The two output commitments of spend #1, frozen.
        to_dana = Note(0x5151, 20, 0xB1510000)
        change = Note(0x5252, 25, 0xB2520000)
        self.assertEqual(
            note_commitment(to_dana),
            0x560A0E75012BBEF57AB4A90DF9F34218A2AC8FB24D3E26672670A1E6D1A58C23,
        )
        self.assertEqual(
            note_commitment(change),
            0x1DCAB223ADF7A6ECB90D1FDA9DEB24DE5CB427DB0158116376D096C96BBBB04A,
        )

    def test_golden_witness_public_inputs(self):
        pool, (w1, _, _) = self._build()

        # public inputs of spend #1 in circuit order:
        # [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee]
        pub = [
            int(w1["merkle_root"]),
            int(w1["nullifier_hash"]),
            int(w1["out_commitment_1"]),
            int(w1["out_commitment_2"]),
            int(w1["fee"]),
        ]
        digest = hashlib.sha256("".join(f"{x:x}" for x in pub).encode()).hexdigest()
        self.assertEqual(
            digest,
            "f29d092e985dfcd213415294ca3cbebea2d1c43d62c6f0f2783f29878d3a32d5",
        )

    def test_golden_sibling_path(self):
        """The witness merkle path must re-derive the recorded root by hand."""
        pool, (w1, _, _) = self._build()
        leaf = note_commitment(Note(0x2222, 50, 0xA2220000))  # bob, index 1
        current = leaf
        for sibling, direction in zip(
            (int(s) for s in w1["sibling"]),
            (d == "1" for d in w1["direction"]),
        ):
            left, right = (sibling, current) if direction else (current, sibling)
            current = poseidon_bls12_381(left, right)
        self.assertEqual(current, int(w1["merkle_root"]))


if __name__ == "__main__":
    unittest.main()