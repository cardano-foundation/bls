#!/usr/bin/env python3
"""
Generate a valid witness input for circom/PrivacyPool/privacy_pool.circom.

Reuses the off-chain PoseidonBLS12_381 (t=3) from
circom/PoseidonMerkle/helpers_py/poseidon_merkle.py, which is verified to
match the Circom template.

A note commitment is  Poseidon(Poseidon(nullifier, amount), blinding).
The input note's commitment is inserted into a sparse Merkle tree (depth D);
gen_privacy_input.py outputs the tree root, the nullifier hash, the two output
commitments, the fee, and the Merkle path for the input note.

Run directly for a default depth-4 / 1-in-2-out example:

    python3 gen_privacy_input.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PoseidonMerkle" / "helpers_py"))
from poseidon_merkle import poseidon_bls12_381, SparseMerkleTree  # noqa: E402


def note_commitment(nullifier: int, amount: int, blinding: int) -> int:
    """Poseidon(Poseidon(nullifier, amount), blinding)."""
    h1 = poseidon_bls12_381(nullifier, amount)
    return poseidon_bls12_381(h1, blinding)


def nullifier_hash(nullifier: int) -> int:
    """Poseidon(0, nullifier)."""
    return poseidon_bls12_381(0, nullifier)


def generate(depth: int, seed: int = 1):
    # --- Input note (the one being spent) ---
    nullifier = 0x1234
    in_amount = 100
    in_blinding = 0xABCD0000 + seed
    in_commitment = note_commitment(nullifier, in_amount, in_blinding)

    # --- A few unrelated notes already in the pool ---
    deposits = []
    for i in range(5):
        nf = 0xDEAD + i
        amt = 10 + i
        bl = 0xBEEF0000 + i
        deposits.append((nf, amt, bl))

    # --- Output notes: change + fresh recipient note ---
    fee = 5
    out_amount_1 = 40            # to Bob
    out_amount_2 = in_amount - out_amount_1 - fee  # 55 change
    out_nullifier_1 = 0x7771
    out_blinding_1 = 0xC0DE0001
    out_nullifier_2 = 0x7772
    out_blinding_2 = 0xC0DE0002

    assert out_amount_2 >= 0, "conservation violated"

    out_commitment_1 = note_commitment(out_nullifier_1, out_amount_1, out_blinding_1)
    out_commitment_2 = note_commitment(out_nullifier_2, out_amount_2, out_blinding_2)

    # --- Build the Merkle tree of all committed notes ---
    tree = SparseMerkleTree(depth)
    for (nf, amt, bl) in deposits:
        tree.insert(note_commitment(nf, amt, bl))
    # the input note must be present as a leaf
    tree.insert(in_commitment)

    path = tree.path(in_commitment)
    siblings = [str(s) for s, _ in path]
    dirs = ["1" if d else "0" for _, d in path]

    return {
        # public
        "merkle_root": str(tree.digest()),
        "nullifier_hash": str(nullifier_hash(nullifier)),
        "out_commitment_1": str(out_commitment_1),
        "out_commitment_2": str(out_commitment_2),
        "fee": str(fee),
        # private
        "nullifier": str(nullifier),
        "in_amount": str(in_amount),
        "in_blinding": str(in_blinding),
        "out_nullifier_1": str(out_nullifier_1),
        "out_amount_1": str(out_amount_1),
        "out_blinding_1": str(out_blinding_1),
        "out_nullifier_2": str(out_nullifier_2),
        "out_amount_2": str(out_amount_2),
        "out_blinding_2": str(out_blinding_2),
        "sibling": siblings,
        "direction": dirs,
    }


def main():
    depth = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    out = Path(__file__).resolve().parent / "input.json"
    data = generate(depth)
    out.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {out}")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
