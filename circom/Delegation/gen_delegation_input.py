#!/usr/bin/env python3
"""
Generate witness inputs for the PredicateDelegatable circuit (Step 8).

Extends the Step 1 predicate with anonymous delegation:
  - holder_sk (private) — holder's secret key
  - proxy_pku, proxy_pkv (public) — proxy's public key
  - delegation_expiry (public) — delegation expiration year
  - delegation_sig_ru, delegation_sig_rv, delegation_sig_s (private) —
    EdDSA-JubJub signature by holder on  PoseidonT6(proxy_pk, expiry, 0,0,0,0)

Usage:
    python3 gen_delegation_input.py --depth 2 --seed 1
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Predicate"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "EdDSAJubJub"))

from gen_predicate_input import generate_predicate_input  # noqa: E402
from gen_test_vectors import (  # noqa: E402
    p,
    L,
    poseidon_hash_t6,
    ed_mul,
    SUBGROUP_GENERATOR,
    eddsa_sign,
)


def generate_delegation_input(depth: int = 2, seed: int = 1):
    pred, meta = generate_predicate_input(depth, seed)

    rng = random.Random(seed + 1000)

    # ---- Holder keypair (for delegation) ----
    holder_sk = rng.randint(1, L - 1)
    holder_pk = ed_mul(holder_sk, SUBGROUP_GENERATOR[0], SUBGROUP_GENERATOR[1])

    # ---- Proxy keypair ----
    proxy_sk = rng.randint(1, L - 1)
    proxy_pk = ed_mul(proxy_sk, SUBGROUP_GENERATOR[0], SUBGROUP_GENERATOR[1])

    # ---- Delegation expiry (e.g., 2030) ----
    delegation_expiry = 2030

    # ---- Delegation message ----
    delegation_msg = poseidon_hash_t6(proxy_pk[0], proxy_pk[1], delegation_expiry, 0, 0, 0)

    # ---- Holder signs delegation_msg ----
    pk, R, S, r, k, r_raw, k_raw = eddsa_sign(holder_sk, delegation_msg)
    assert pk == holder_pk

    result = dict(pred)
    result.update({
        "proxy_pku": str(proxy_pk[0]),
        "proxy_pkv": str(proxy_pk[1]),
        "delegation_expiry": str(delegation_expiry),
        "holder_sk": str(holder_sk),
        "delegation_sig_ru": str(R[0]),
        "delegation_sig_rv": str(R[1]),
        "delegation_sig_s": str(S),
    })

    meta.update({
        "holder_sk": holder_sk,
        "holder_pk": holder_pk,
        "proxy_sk": proxy_sk,
        "proxy_pk": proxy_pk,
        "delegation_msg": delegation_msg,
        "delegation_sig": (R, S),
    })

    return result, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--output", type=Path, default=Path("input.json"))
    args = ap.parse_args()

    inp, meta = generate_delegation_input(args.depth, args.seed)
    args.output.write_text(json.dumps(inp, indent=2) + "\n")
    print(f"wrote {args.output}")
    print(f"holder_pk = {meta['holder_pk']}")
    print(f"proxy_pk  = {meta['proxy_pk']}")
    print(f"delegation_msg = {meta['delegation_msg']}")


if __name__ == "__main__":
    main()
