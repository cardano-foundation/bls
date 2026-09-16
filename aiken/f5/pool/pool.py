#!/usr/bin/env python3
"""
Faithful off-chain simulation of the F5 multi-user privacy pool.

It reuses the exact same building blocks as circom/PrivacyPool:

* PoseidonBLS12_381 (t=3, alpha=5, RF=8, RP=57) from
  circom/PoseidonMerkle/helpers_py/poseidon_merkle.py, which is verified to
  match the Circom template.
* SparseMerkleTree from the same module, using the same compression function
  as circom/PrivacyPool/merkle.circom.

The note algebra mirrors circom/PrivacyPool/note.circom::

    commitment    = Poseidon(Poseidon(nullifier, amount), blinding)
    nullifier_hash = Poseidon(0, nullifier)

Both the tree and the witness inputs produced here are byte-for-byte compatible
with gen_privacy_input.py, so the output of PoolState.spend() can be fed
directly to snarkjs as a Circom input.json for privacy_pool.circom.

Run the tests with:

    python3 -m unittest discover -s aiken/f5/pool -v
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path

_HELPER_DIR = Path(__file__).resolve().parent.parent.parent.parent / "circom" / "PoseidonMerkle" / "helpers_py"
sys.path.insert(0, str(_HELPER_DIR))

from poseidon_merkle import poseidon_bls12_381 as _poseidon_bls12_381  # noqa: E402
from poseidon_merkle import SparseMerkleTree  # noqa: E402


@dataclass(frozen=True)
class Note:
    """A confidential value record: a nullifier, an amount, and blinding."""

    nullifier: int
    amount: int
    blinding: int


def note_commitment(note: Note) -> int:
    """Poseidon(Poseidon(nullifier, amount), blinding) -- the Merkle leaf."""
    h1 = _poseidon_bls12_381(note.nullifier, note.amount)
    return _poseidon_bls12_381(h1, note.blinding)


def nullifier_hash(nullifier: int) -> int:
    """Poseidon(0, nullifier) -- the public value marking a note spent."""
    return _poseidon_bls12_381(0, nullifier)


class PoolState:
    """Insert-only pool tracking the Merkle root and the set of spent nullifier hashes."""

    def __init__(self, depth: int = 4):
        self.depth = depth
        self.tree = SparseMerkleTree(depth)
        self.spent = set()          # nullifier hashes already spent
        self.notes = {}             # nullifier -> Note, keeps the record of every deposited note
        self.insertions = 0         # total inserted leaves (per user flows)
        self._next_nullifier = 1

    # --- deposits -------------------------------------------------------

    def new_note(self, amount: int, blinding: int | None = None) -> Note:
        """Mint a fresh note with a unique, simulation-generated nullifier."""
        if blinding is None:
            blinding = 0xC0FFEE0000 + self.insertions
        note = Note(nullifier=self._next_nullifier, amount=amount, blinding=blinding)
        self._next_nullifier += 1
        return note

    def deposit(self, note: Note) -> int:
        """Insert a note commitment into the tree; returns the new root."""
        leaf = note_commitment(note)
        self.tree.insert(leaf)
        self.notes[note.nullifier] = note
        self.insertions += 1
        return self.tree.digest()

    # --- spends ---------------------------------------------------------

    def spend(self, input_note: Note, out1: Note, out2: Note, fee: int) -> dict:
        """
        Build the full Circom witness input for a 1-in / 2-out spend.

        Mirrors the key/value structure of gen_privacy_input.generate(depth)
        exactly, so the result is a drop-in input.json for privacy_pool.circom.

        Enforces the same invariants the circuit relies on:
          * conservation: in_amount == out1.amount + out2.amount + fee
          * the input note already lives in the tree
          * the input note has not been spent yet
        """
        if input_note.amount != out1.amount + out2.amount + fee:
            raise ValueError(
                f"conservation violated: {input_note.amount} != "
                f"{out1.amount} + {out2.amount} + {fee}"
            )

        leaf = note_commitment(input_note)
        if leaf not in self.tree.leaf_indices:
            raise ValueError("input note is not in the tree (not deposited yet)")

        nh = nullifier_hash(input_note.nullifier)
        if nh in self.spent:
            raise ValueError("input note was already spent")

        # Merkle path for the input note, leaf -> root.
        path = self.tree.path(leaf)
        siblings = [str(s) for s, _ in path]
        dirs = ["1" if d else "0" for _, d in path]

        return {
            # public
            "merkle_root": str(self.tree.digest()),
            "nullifier_hash": str(nh),
            "out_commitment_1": str(note_commitment(out1)),
            "out_commitment_2": str(note_commitment(out2)),
            "fee": str(fee),
            # private
            "nullifier": str(input_note.nullifier),
            "in_amount": str(input_note.amount),
            "in_blinding": str(input_note.blinding),
            "out_nullifier_1": str(out1.nullifier),
            "out_amount_1": str(out1.amount),
            "out_blinding_1": str(out1.blinding),
            "out_nullifier_2": str(out2.nullifier),
            "out_amount_2": str(out2.amount),
            "out_blinding_2": str(out2.blinding),
            "sibling": siblings,
            "direction": dirs,
        }

    def apply_spend(self, input_note: Note, out1: Note, out2: Note, fee: int) -> dict:
        """
        Run spend() and, on success, advance the pool state: mark the input
        note's nullifier hash as spent and insert the two output commitments
        as fresh leaves (they become spendable by later users).
        """
        witness = self.spend(input_note, out1, out2, fee)

        self.spent.add(nullifier_hash(input_note.nullifier))
        self.deposit(out1)
        self.deposit(out2)
        self.notes[input_note.nullifier] = input_note
        return witness

    # --- queries --------------------------------------------------------

    def root(self) -> int:
        return self.tree.digest()

    def unspent_notes(self) -> list:
        """Notes that are in the tree and not yet spent."""
        return [
            n
            for n in self.notes.values()
            if nullifier_hash(n.nullifier) not in self.spent
        ]

    # --- JSON / reproducibility ----------------------------------------

    def snapshot(self) -> dict:
        """Serialisable state, including the full tree node table."""
        return {
            "depth": self.depth,
            "root": str(self.tree.digest()),
            "next_index": self.tree.next_index,
            "spent": sorted(str(h) for h in self.spent),
            "notes": [
                [note.nullifier, note.amount, note.blinding]
                for note in sorted(self.notes.values(), key=lambda n: n.nullifier)
            ],
        }

    @classmethod
    def from_snapshot(cls, snap: dict) -> "PoolState":
        pool = cls(snap["depth"])
        for nf, amt, bl in snap["notes"]:
            pool.deposit(Note(int(nf), int(amt), int(bl)))
        for h in snap["spent"]:
            pool.spent.add(int(h))
        return pool


def write_input_json(witness: dict, dest) -> None:
    """Persist a witness dict in the same format gen_privacy_input.py writes."""
    if isinstance(dest, (str, Path)):
        dest = Path(dest)
        dest.write_text(json.dumps(witness, indent=2) + "\n")
        return str(dest)
    json.dump(witness, dest, indent=2)
    dest.write("\n")
    return None


if __name__ == "__main__":
    # Default multi-user walk-through: 3 users, 6 notes, 2 spends.
    pool = PoolState(depth=4)
    u1 = pool.new_note(100, 0xABCD0000)
    u2 = pool.new_note(50, 0xABCD0001)
    u3 = pool.new_note(90, 0xABCD0002)

    pool.deposit(u1)
    pool.deposit(u2)
    pool.deposit(u3)
    print(f"after deposits        root = {pool.root()}")

    r1 = pool.new_note(45, 0xDEAD0001)
    ch1 = pool.new_note(0, 0xDEAD0002)

    w1 = pool.apply_spend(u2, r1, ch1, 5)
    print(f"after spend #1        root = {pool.root()}  spent={len(pool.spent)}")

    r2 = pool.new_note(40, 0xDEAD0003)
    ch2 = pool.new_note(5, 0xDEAD0004)
    w2 = pool.apply_spend(r1, r2, ch2, 0)
    print(f"after spend #2        root = {pool.root()}  spent={len(pool.spent)}")

    print("witness root (recorded before outputs inserted):", w2["merkle_root"])
    print("live root   (pool after spend #2):              ", pool.root())