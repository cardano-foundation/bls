#!/usr/bin/env python3
"""
Generate a multi-user witness scenario for privacy_pool_viewable_addr_dynamic.circom
(Step 10 — dynamic multi-auditor privacy pool).

Extends Step 6's full-auditor-reveal scenario so that each spend encrypts its
amount and recipient address to one auditor chosen from an active-set Merkle
tree.  The circuit proves the chosen pk_audit is a leaf of the tree rooted at
auditor_root, so:

  * multiple auditors can coexist,
  * new auditors can join after setup (admin inserts a new leaf → new root),
  * an auditor can be removed (admin rebuilds the tree without it → new root).

The encryption math is unchanged from Step 5/6:
    E     = r * G
    C     = in_amount   * H + r * pk_audit
    C_a0  = addr_limb0  * H + r * pk_audit
    C_a1  = addr_limb1  * H + r * pk_audit

Usage:
    python3 gen_multi_viewable_addr_dynamic_input.py \
        --depth 4 --auditor-depth 4 --users 4 --spends 4 --auditors 4 --seed 42 --out DIR
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PoseidonMerkle" / "helpers_py"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "EdDSAJubJub"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "aiken" / "f5" / "pool"))

from poseidon_merkle import poseidon_bls12_381, SparseMerkleTree  # noqa: E402
from helpers_jubjub import ed_add, ed_mul, SUBGROUP_GENERATOR  # noqa: E402
from pool import Note, PoolState, note_commitment, write_input_json  # noqa: E402

# BLS12-381 scalar field prime
_P = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# Second generator H = 2*G, matching the ElGamal circuit's doubling.
_H = ed_mul(2, SUBGROUP_GENERATOR[0], SUBGROUP_GENERATOR[1])


def elgamal_encrypt(message: int, r: int, pk_audit):
    """(E, C) = ElGamal-encrypt `message` to pk_audit with randomness r."""
    Gx, Gy = SUBGROUP_GENERATOR
    E = ed_mul(r, Gx, Gy)
    mH = msg_times_H(message)
    rPK = ed_mul(r, pk_audit[0], pk_audit[1])
    C = ed_add(mH[0], mH[1], rPK[0], rPK[1])
    return E, C


def msg_times_H(m):
    """m * H, treating m == 0 as the identity."""
    if m == 0:
        return (0, 1)
    return ed_mul(m, _H[0], _H[1])


def dlog_small(P, base, limit=1 << 17):
    """Recover small m with P == m*base by incremental addition."""
    if P == (0, 1):
        return 0
    cur = base
    for m in range(1, limit):
        if cur == P:
            return m
        cur = ed_add(cur[0], cur[1], base[0], base[1])
    raise ValueError("small-DL recovery failed (message too large)")


def build_auditor_set(auditor_depth: int, auditors: int, rng: random.Random):
    """Generate `auditors` keypairs and build an active-set Merkle tree."""
    if auditors > 2 ** auditor_depth:
        raise ValueError(f"auditors={auditors} exceeds tree capacity {2**auditor_depth}")

    keys = []
    for _ in range(auditors):
        sk = rng.randint(1, _P - 1)
        pk = ed_mul(sk, SUBGROUP_GENERATOR[0], SUBGROUP_GENERATOR[1])
        keys.append({"sk": sk, "pk": pk})

    tree = SparseMerkleTree(auditor_depth)
    for k in keys:
        leaf = poseidon_bls12_381(k["pk"][0], k["pk"][1])
        tree.insert(leaf)

    return keys, tree


def auditor_path_for_pk(pk, tree: SparseMerkleTree, auditor_depth: int):
    """Return siblings and directions proving pk is in the active-set tree."""
    leaf = poseidon_bls12_381(pk[0], pk[1])
    path = tree.path(leaf)
    siblings = [str(sibling) for sibling, _ in path]
    directions = ["1" if direction else "0" for _, direction in path]
    # pad to full depth (tree.path already returns depth entries, but keep safe)
    while len(siblings) < auditor_depth:
        siblings.append("0")
        directions.append("0")
    return siblings, directions


def build_auditor_meta(pool_witness, sk_audit, pk_audit, r, recipient_addr):
    """Run auditor decrypt checks and return metadata dict."""
    in_amount = int(pool_witness["in_amount"])
    nullifier = int(pool_witness["nullifier"])
    addr_limb0 = recipient_addr & 0xFFFF
    addr_limb1 = recipient_addr >> 16

    E, C = elgamal_encrypt(in_amount, r, pk_audit)
    E_a0, C_a0 = elgamal_encrypt(addr_limb0, r, pk_audit)
    E_a1, C_a1 = elgamal_encrypt(addr_limb1, r, pk_audit)
    assert E_a0 == E and E_a1 == E

    skE = ed_mul(sk_audit, E[0], E[1])
    for name, Cpt, expected_m in (("amount", C, in_amount),
                                   ("addr_limb0", C_a0, addr_limb0),
                                   ("addr_limb1", C_a1, addr_limb1)):
        mH = (ed_add(Cpt[0], Cpt[1], (-skE[0]) % _P, skE[1]))
        assert mH == msg_times_H(expected_m), f"{name} decrypt failed"
        recovered = dlog_small(mH, _H)
        assert recovered == expected_m, f"{name} recovery mismatch"

    addr_commitment = poseidon_bls12_381(recipient_addr, nullifier)

    return {
        "sk_audit": str(sk_audit),
        "pk_audit": [str(pk_audit[0]), str(pk_audit[1])],
        "E": [str(E[0]), str(E[1])],
        "C": [str(C[0]), str(C[1])],
        "C_a0": [str(C_a0[0]), str(C_a0[1])],
        "C_a1": [str(C_a1[0]), str(C_a1[1])],
        "amount": str(in_amount),
        "recipient_addr": str(recipient_addr),
        "addr_limb0": str(addr_limb0),
        "addr_limb1": str(addr_limb1),
        "addr_commitment": str(addr_commitment),
        "r": str(r),
    }


def build_scenario(depth: int, auditor_depth: int, users: int, spends: int,
                   auditors: int, seed: int) -> tuple:
    """Generate the deposit/spend walk with dynamic-auditor fields per spend."""
    rng = random.Random(seed)
    pool = PoolState(depth=depth)

    auditor_keys, auditor_tree = build_auditor_set(auditor_depth, auditors, rng)
    auditor_root = auditor_tree.digest()

    deposited = []
    for u in range(users):
        amt = rng.randint(50, 200)
        note = pool.new_note(amt, rng.randint(1, 10**9))
        pool.deposit(note)
        deposited.append(note)

    witnesses = []
    auditor_metas = []
    for i in range(spends):
        spendable = pool.unspent_notes()
        if not spendable:
            break
        src = rng.choice(spendable)
        fee = rng.randint(0, src.amount)
        out1_amt = rng.randint(0, src.amount - fee)
        out2_amt = src.amount - out1_amt - fee
        out1 = pool.new_note(out1_amt, rng.randint(1, 10**9))
        out2 = pool.new_note(out2_amt, rng.randint(1, 10**9))

        recipient_addr = rng.randint(1, 0xFFFFFFFF)
        r = rng.randint(1, (1 << 253) - 1)

        # choose one active auditor for this spend
        auditor_idx = rng.randrange(len(auditor_keys))
        aud = auditor_keys[auditor_idx]

        pool_witness = pool.apply_spend(src, out1, out2, fee)

        addr_commitment = poseidon_bls12_381(recipient_addr, int(pool_witness["nullifier"]))
        auditor_siblings, auditor_directions = auditor_path_for_pk(
            aud["pk"], auditor_tree, auditor_depth
        )

        pool_witness.update({
            "pk_audit": [str(aud["pk"][0]), str(aud["pk"][1])],
            "addr_commitment": str(addr_commitment),
            "audit_blinding": str(r),
            "recipient_addr": str(recipient_addr),
            "auditor_root": str(auditor_root),
            "auditor_sibling": auditor_siblings,
            "auditor_direction": auditor_directions,
        })

        meta = build_auditor_meta(pool_witness, aud["sk"], aud["pk"], r, recipient_addr)
        meta["auditor_index"] = auditor_idx
        witnesses.append(pool_witness)
        auditor_metas.append(meta)

    return pool, witnesses, auditor_metas, auditor_keys, auditor_root


PUBLIC_KEYS = [
    "merkle_root", "nullifier_hash", "out_commitment_1",
    "out_commitment_2", "fee", "pk_audit", "addr_commitment", "auditor_root",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--auditor-depth", type=int, default=4)
    ap.add_argument("--users", type=int, default=4)
    ap.add_argument("--spends", type=int, default=None)
    ap.add_argument("--auditors", type=int, default=4)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    spends = args.spends if args.spends is not None else args.users

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    pool, witnesses, auditor_metas, auditor_keys, auditor_root = build_scenario(
        args.depth, args.auditor_depth, args.users, spends, args.auditors, args.seed
    )

    scenario = {
        "depth": args.depth,
        "auditor_depth": args.auditor_depth,
        "users": args.users,
        "spends": len(witnesses),
        "auditors": args.auditors,
        "seed": args.seed,
        "final_root": str(pool.root()),
        "spent_nullifier_hashes": sorted(str(h) for h in pool.spent),
        "auditor_root": str(auditor_root),
        "auditor_set": [
            {"index": i, "sk": str(k["sk"]), "pk": [str(k["pk"][0]), str(k["pk"][1])]}
            for i, k in enumerate(auditor_keys)
        ],
        "spends": [],
    }

    for i, w in enumerate(witnesses):
        dest = out / f"user_{i:03d}.json"
        write_input_json(w, dest)
        scenario["spends"].append({
            "user": f"user_{i:03d}.json",
            "public": [w[k] for k in PUBLIC_KEYS],
            "input_note_amount": int(w["in_amount"]),
            "output_commitment_leaves": [int(w["out_commitment_1"]), int(w["out_commitment_2"])],
            "recipient_addr": hex(int(w["recipient_addr"])),
            "auditor_index": auditor_metas[i]["auditor_index"],
            "auditor_meta": auditor_metas[i],
        })

    (out / "scenario.json").write_text(json.dumps(scenario, indent=2) + "\n")
    (out / "auditor_meta.json").write_text(json.dumps({
        "auditor_root": str(auditor_root),
        "auditor_set": scenario["auditor_set"],
        "spends": [{"user": s["user"], **s["auditor_meta"]} for s in scenario["spends"]],
    }, indent=2) + "\n")

    print(f"wrote {len(witnesses)} user witnesses under {out}")
    print(f"final pool root       : {scenario['final_root']}")
    print(f"spent nullifiers      : {len(pool.spent)}")
    print(f"auditor root          : {auditor_root}")
    print(f"active auditors       : {args.auditors}")
    for s in scenario["spends"]:
        print(f"  {s['user']}  input={s['input_note_amount']}  fee={s['public'][4]}  "
              f"addr={s['recipient_addr']}  auditor_idx={s['auditor_index']}")


if __name__ == "__main__":
    main()
