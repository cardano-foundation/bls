#!/usr/bin/env python3
"""
Generate witness inputs for the PredicateRevocable circuit (Step 7).

Extends the Step 1 predicate with:
  - expiry_year (public) — credential expiration year
  - revocation_root (public) — root of the issuer's revocation SMT
  - revocation_sibling[depth], revocation_direction[depth] (private) —
    non-membership proof that the credential is NOT revoked

The issuer maintains a Sparse Merkle Tree of revoked credentials.
A revoked credential is inserted at position  claims_msg % 2^depth
with leaf value Poseidon(claims_msg, 0).  The holder proves non-revocation
by showing the path from the default empty leaf (0) at their position.

Usage:
    python3 gen_revocable_input.py --depth 2 --revocation-depth 2 --seed 1
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Predicate"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PoseidonMerkle" / "helpers_py"))

from gen_predicate_input import generate_predicate_input as _gen_predicate  # noqa: E402
from poseidon_merkle import poseidon_bls12_381  # noqa: E402

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


class KeyedSMT:
    """Sparse Merkle Tree with explicit position-based insertion."""

    def __init__(self, depth: int):
        self.depth = depth
        self.nodes = {}
        self.defaults = [0]
        for _ in range(depth):
            self.defaults.append(poseidon_bls12_381(self.defaults[-1], self.defaults[-1]))
        self.defaults.reverse()

    def _node(self, level: int, index: int) -> int:
        return self.nodes.get((level, index), self.defaults[level])

    def set(self, index: int, value: int):
        self.nodes[(self.depth, index)] = value % P
        level = self.depth
        idx = index
        while level > 0:
            level -= 1
            idx //= 2
            left = self._node(level + 1, 2 * idx)
            right = self._node(level + 1, 2 * idx + 1)
            self.nodes[(level, idx)] = poseidon_bls12_381(left, right)

    def root(self) -> int:
        return self._node(0, 0)

    def path(self, index: int):
        path = []
        idx = index
        for level in range(self.depth, 0, -1):
            direction = bool(idx & 1)
            sibling_idx = idx ^ 1
            sibling = self._node(level, sibling_idx)
            path.append((sibling, direction))
            idx //= 2
        return path


def generate(depth: int = 2, revocation_depth: int = 2, seed: int = 1):
    rng = random.Random(seed)

    # 1. Generate base predicate input
    pred, _ = _gen_predicate(depth, seed)

    # 2. Add expiry (e.g., 2030)
    expiry_year = 2030

    # 3. Compute claims_msg
    dob_year = int(pred["dob_year"])
    country = int(pred["country"])
    claims_msg = poseidon_bls12_381(dob_year, country)

    # 4. Build revocation SMT
    revocation_smt = KeyedSMT(revocation_depth)

    # Insert a few revoked credentials (different from ours)
    for _ in range(3):
        revoked_claims = rng.randint(1, P - 1)
        # avoid collision with our credential
        if revoked_claims == claims_msg:
            continue
        idx = revoked_claims % (1 << revocation_depth)
        leaf = poseidon_bls12_381(revoked_claims, 0)
        revocation_smt.set(idx, leaf)

    # 5. Compute non-membership proof for our credential
    our_idx = claims_msg % (1 << revocation_depth)
    rev_path = revocation_smt.path(our_idx)

    rev_siblings = [str(s) for s, _ in rev_path]
    rev_directions = ["1" if d else "0" for _, d in rev_path]

    result = dict(pred)
    result.update({
        "expiry_year": str(expiry_year),
        "revocation_root": str(revocation_smt.root()),
        "revocation_sibling": rev_siblings,
        "revocation_direction": rev_directions,
    })

    meta = {
        "claims_msg": str(claims_msg),
        "revocation_index": str(our_idx),
        "revocation_siblings": rev_siblings,
        "revocation_directions": rev_directions,
        "revoked_count": 3,
    }

    return result, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--revocation-depth", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--output", type=Path, default=Path("input.json"))
    args = ap.parse_args()

    inp, meta = generate(args.depth, args.revocation_depth, args.seed)
    args.output.write_text(json.dumps(inp, indent=2) + "\n")
    print(f"wrote {args.output}")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
