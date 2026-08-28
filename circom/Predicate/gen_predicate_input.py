#!/usr/bin/env python3
"""
Generate the witness input for the composite Predicate circuit.

Builds a complete selective-disclosure scenario:

  1. Issuer generates an issuer keypair (sk -> JubJub pk).
  2. Issuer defines an approved-countries set (a Merkle tree of depth 2 whose
     leaves are  poseidon(country, 0) ) and publishes its root.
  3. Issuer issues a credential (dob_year, country) to a holder: signs
     claims_msg = poseidon(dob_year, country) with EdDSA-JubJub.
  4. The holder's witness bundles the private fields, the issuer signature,
     and the Merkle membership proof, so the Predicate circuit accepts.

The Poseidon / JubJub / EdDSA primitives are reused from the validated
`../EdDSAJubJub/gen_test_vectors.py`.

Usage:
    python3 gen_predicate_input.py [--depth 2] [--output input.json]
"""
import argparse
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'EdDSAJubJub'))

from gen_test_vectors import (  # noqa: E402
    p,
    L,
    poseidon_hash,
    poseidon_hash_t6,
    ed_add,
    ed_mul,
    SUBGROUP_GENERATOR,
    eddsa_sign,
)

COUNTRY_ROOT_DOMAIN = 0  # leaf = poseidon(country, 0)


def poseidon_leaf(country):
    return poseidon_hash(country, COUNTRY_ROOT_DOMAIN)


def build_merkle_tree(countries, depth):
    """Deterministic Merkle tree of the given countries (depth levels, leaves keyed by index)."""
    leaves = [poseidon_leaf(c) for c in countries]
    # pad to a power of two
    n = 1 << depth
    assert len(leaves) <= n, "too many countries for depth"
    leaves += [0] * (n - len(leaves))
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(poseidon_hash(level[i], level[i + 1]))
        level = nxt
    root = level[0]
    return root, leaves


def merkle_proof(leaves, index, depth):
    """Membership witness for leaves[index]: sibling[] + direction[] ordered leaf->root.

    direction[i] = 0 if the current node is the left child (sibling on right),
                   1 if it is the right child (sibling on left).
    """
    idx = index
    cur = list(leaves)
    siblings = []
    directions = []
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            nxt.append(poseidon_hash(cur[i], cur[i + 1]))
        sib_idx = idx ^ 1
        siblings.append(cur[sib_idx])
        directions.append(0 if idx % 2 == 0 else 1)
        idx //= 2
        cur = nxt
    return siblings, directions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--depth', type=int, default=2)
    parser.add_argument('--output', type=str, default='input.json')
    parser.add_argument('--seed', type=int, default=None)
    parser.add_argument('--dob-year', type=int, default=1990)
    parser.add_argument('--country', type=int, default=276)
    args = parser.parse_args()

    rng = random.Random(args.seed) if args.seed is not None else random

    # ---- Issuer keypair ----
    issuer_sk = rng.randint(1, L - 1)
    issuer_pk = ed_mul(issuer_sk, SUBGROUP_GENERATOR[0], SUBGROUP_GENERATOR[1])

    # ---- Credential fields ----
    dob_year = args.dob_year
    country = args.country
    current_year = 2026    # age = current_year - dob_year

    # ---- Approved countries set (leaf = poseidon(country, 0)) ----
    approved = [276, 250, 756, 40]  # DEU, FRA, CHE, AT
    assert country in approved
    assert len(approved) <= (1 << args.depth)
    country_root, leaves = build_merkle_tree(approved, args.depth)
    country_index = approved.index(country)
    siblings, directions = merkle_proof(leaves, country_index, args.depth)

    # ---- Issuer signs claims_msg ----
    claims_msg = poseidon_hash(dob_year, country)
    pk, R, S, r, k, r_raw, k_raw = eddsa_sign(issuer_sk, claims_msg)
    assert pk == issuer_pk

    eligible = 1

    inp = {
        # public
        "pku": str(issuer_pk[0]),
        "pkv": str(issuer_pk[1]),
        "current_year": str(current_year),
        "country_root": str(country_root),
        "eligible": str(eligible),
        # private
        "dob_year": str(dob_year),
        "country": str(country),
        "Ru": str(R[0]),
        "Rv": str(R[1]),
        "S": str(S),
        "sibling": [str(s) for s in siblings],
        "direction": [str(d) for d in directions],
    }

    with open(args.output, 'w') as f:
        json.dump(inp, f, indent=2)

    print(f"issuer_sk    = {issuer_sk}")
    print(f"issuer_pk    = ({issuer_pk[0]}, {issuer_pk[1]})")
    print(f"claims_msg   = poseidon({dob_year}, {country}) = {claims_msg}")
    print(f"R            = ({R[0]}, {R[1]})")
    print(f"S            = {S}")
    print(f"country_root = {country_root}")
    print(f"merkle sibling = {siblings}")
    print(f"merkle direction = {directions}")
    print(f"eligible     = {eligible}")
    print()
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
