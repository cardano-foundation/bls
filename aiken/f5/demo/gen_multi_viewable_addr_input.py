#!/usr/bin/env python3
"""
Generate a multi-user F5 witness scenario for privacy_pool_viewable_addr.circom.

Extends gen_multi_input.py (Step 3/F5 pool) with Step 5's full auditor reveal:
each spend additionally encrypts the private input amount AND the recipient's
address id to a designated auditor's public key with a multi-message Twisted
ElGamal ciphertext (shared ephemeral randomness r).

  E     = r * G
  C     = in_amount   * H + r * pk_audit     (amount)
  C_a0  = addr_limb0  * H + r * pk_audit     (address low  u16 limb)
  C_a1  = addr_limb1  * H + r * pk_audit     (address high u16 limb)

Each user gets a unique recipient address. All users share the same auditor
(pk_audit) so the on-chain gate whitelists a single key.

Outputs per-user witness: $OUT/user_NNN.json (compatible with snarkjs)
Shared metadata:           $OUT/auditor_meta.json (sk_audit, per-user decrypt data)
Scenario:                  $OUT/scenario.json

Usage:
    python3 gen_multi_viewable_addr_input.py \
        --depth 4 --users 4 --spends 4 --seed 42 --out DIR
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pool"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent
                       / "circom" / "PoseidonMerkle" / "helpers_py"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent
                       / "circom" / "EdDSAJubJub"))

from pool import Note, PoolState, note_commitment, write_input_json  # noqa: E402
from poseidon_merkle import poseidon_bls12_381  # noqa: E402
from helpers_jubjub import ed_add, ed_mul, SUBGROUP_GENERATOR  # noqa: E402

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


def build_scenario(depth: int, users: int, spends: int, seed: int) -> tuple:
    """Generate the deposit/spend walk with auditor fields per spend."""
    rng = random.Random(seed)
    pool = PoolState(depth=depth)

    # --- auditor keypair (shared across all users) ---
    sk_audit = 0x51DE
    pk_audit = ed_mul(sk_audit, SUBGROUP_GENERATOR[0], SUBGROUP_GENERATOR[1])

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

        # unique recipient address per spend (32-bit)
        recipient_addr = rng.randint(1, 0xFFFFFFFF)
        # unique ephemeral randomness per spend
        # must fit in scalarBits=253 (the bit-width of TwistedElGamalEncrypt)
        r = rng.randint(1, (1 << 253) - 1)

        pool_witness = pool.apply_spend(src, out1, out2, fee)

        addr_commitment = poseidon_bls12_381(recipient_addr, int(pool_witness["nullifier"]))
        pool_witness.update({
            "pk_audit": [str(pk_audit[0]), str(pk_audit[1])],
            "addr_commitment": str(addr_commitment),
            "audit_blinding": str(r),
            "recipient_addr": str(recipient_addr),
        })

        meta = build_auditor_meta(pool_witness, sk_audit, pk_audit, r, recipient_addr)
        witnesses.append(pool_witness)
        auditor_metas.append(meta)

    return pool, witnesses, auditor_metas, sk_audit, pk_audit


PUBLIC_KEYS = [
    "merkle_root", "nullifier_hash", "out_commitment_1",
    "out_commitment_2", "fee", "pk_audit", "addr_commitment",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--users", type=int, default=4)
    ap.add_argument("--spends", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    spends = args.spends if args.spends is not None else args.users

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    pool, witnesses, auditor_metas, sk_audit, pk_audit = build_scenario(
        args.depth, args.users, spends, args.seed
    )

    scenario = {
        "depth": args.depth,
        "users": args.users,
        "spends": len(witnesses),
        "seed": args.seed,
        "final_root": str(pool.root()),
        "spent_nullifier_hashes": sorted(str(h) for h in pool.spent),
        "auditor": {
            "sk_audit": str(sk_audit),
            "pk_audit": [str(pk_audit[0]), str(pk_audit[1])],
        },
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
            "auditor_meta": auditor_metas[i],
        })

    (out / "scenario.json").write_text(json.dumps(scenario, indent=2) + "\n")
    (out / "auditor_meta.json").write_text(json.dumps({
        "auditor": scenario["auditor"],
        "spends": [{"user": s["user"], **s["auditor_meta"]} for s in scenario["spends"]],
    }, indent=2) + "\n")

    print(f"wrote {len(witnesses)} user witnesses under {out}")
    print(f"final pool root       : {scenario['final_root']}")
    print(f"spent nullifiers      : {len(pool.spent)}")
    print(f"auditor pk            : ({str(pk_audit[0])[:16]}..., {str(pk_audit[1])[:16]}...)")
    for s in scenario["spends"]:
        print(f"  {s['user']}  input={s['input_note_amount']}  fee={s['public'][4]}  "
              f"addr={s['recipient_addr']}")


if __name__ == "__main__":
    main()
