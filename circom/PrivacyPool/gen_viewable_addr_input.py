#!/usr/bin/env python3
"""
Generate witness inputs for Step 5 (full auditor reveal) circuits.

Builds directly on Step 3's gen_privacy_input.generate(depth): the shielded
1-in/2-out privacy-pool spend is reused verbatim.  On top of it, Step 5 uses a
multi-message Twisted ElGamal ciphertext that encrypts BOTH the private input
amount AND the recipient's address id to a designated auditor's public key,
with SHARED ephemeral randomness r:

    pk_audit = sk_audit * G
    E     = r * G
    C     = in_amount   * H + r * pk_audit     (amount)
    C_a0  = addr_limb0  * H + r * pk_audit     (address low  u16 limb)
    C_a1  = addr_limb1  * H + r * pk_audit     (address high u16 limb)

Auditor (viewing key sk_audit) recovers each message via small DLog:
    m * H == C_x - sk_audit * E
recovering in_amount and the two address limbs, then reassembling the
recipient address id.  The address is bound to the spend via a public
commitment  addr_commitment = Poseidon(recipient_addr, nullifier).

Outputs used by:
  * Groth16  : privacy_pool_viewable_addr.circom -> input.json
  * NovaSlim : elgamal_viewkey_addr_nova.circom  -> nova_input.json + commitment

Run in-place (as gen_viewable_input.py) so the Poseidon/JubJub helper paths
resolve relative to this file.

Usage:
    python3 gen_viewable_addr_input.py [depth]
"""
import json
import sys
from pathlib import Path

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PoseidonMerkle" / "helpers_py"))
from poseidon_merkle import poseidon_bls12_381  # noqa: E402

_sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "EdDSAJubJub"))
from helpers_jubjub import ed_add, ed_mul, SUBGROUP_GENERATOR  # noqa: E402

from gen_privacy_input import generate as gen_pool  # noqa: E402

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


def point_sub(a, b):
    """a - b on twisted Edwards (negation is (-x, y))."""
    return ed_add(a[0], a[1], (-b[0]) % _P, b[1])


# Twisted Edwards identity point (not on the affine (0,0), which is off-curve).
_IDENTITY = (0, 1)


def msg_times_H(m):
    """m * H, treating m == 0 as the identity (ed_mul(0, ...) is not reliable)."""
    if m == 0:
        return _IDENTITY
    return ed_mul(m, _H[0], _H[1])


def dlog_small(P, base, limit=1 << 17):
    """Recover small m with P == m*base by incrementally adding base (fast)."""
    if P == _IDENTITY:
        return 0
    cur = base
    for m in range(1, limit):
        if cur == P:
            return m
        cur = ed_add(cur[0], cur[1], base[0], base[1])
    raise ValueError("small-DL recovery failed (message too large)")


def generate(depth: int = 4, seed: int = 1, audit_sk: int = 0x51DE,
             r: int = 0xBAD0C0DE, recipient_addr: int = 0x1234):
    pool = gen_pool(depth, seed)
    in_amount = int(pool["in_amount"])
    nullifier = int(pool["nullifier"])

    # --- auditor key pair (viewing key) ---
    sk_audit = audit_sk
    Gx, Gy = SUBGROUP_GENERATOR
    pk_audit = ed_mul(sk_audit, Gx, Gy)

    # --- split the 32-bit recipient address into two u16 limbs ---
    addr_limb0 = recipient_addr & 0xFFFF
    addr_limb1 = recipient_addr >> 16
    assert addr_limb0 < (1 << 16) and addr_limb1 < (1 << 16)

    # --- multi-message ElGamal to the auditor, SHARED randomness r ---
    r_red = r % _P
    E, C = elgamal_encrypt(in_amount, r_red, pk_audit)
    E_a0, C_a0 = elgamal_encrypt(addr_limb0, r_red, pk_audit)
    E_a1, C_a1 = elgamal_encrypt(addr_limb1, r_red, pk_audit)
    assert E_a0 == E and E_a1 == E, "shared-ephemeral E consistency broken"

    # --- auditor viewing-key reveal (off-chain decrypt) ---
    skE = ed_mul(sk_audit, E[0], E[1])
    for name, Cpt, expected_m in (("amount", C, in_amount),
                                  ("addr_limb0", C_a0, addr_limb0),
                                  ("addr_limb1", C_a1, addr_limb1)):
        mH = point_sub(Cpt, skE)                    # C_x - sk_audit*E == m*H
        assert mH == msg_times_H(expected_m), f"{name} decrypt failed: m*H mismatch"
        recovered = dlog_small(mH, _H)
        assert recovered == expected_m, f"{name} recovery mismatch"
        print(f"   auditor revealed {name:<10} = {recovered}")

    # --- reassemble the recipient address id ---
    recovered_addr = dlog_small(point_sub(C_a0, skE), _H) + \
                     (dlog_small(point_sub(C_a1, skE), _H) << 16)
    assert recovered_addr == recipient_addr, "address reassembly mismatch"
    print(f"   auditor revealed recipient_addr = {hex(recovered_addr)} ({recovered_addr})")

    # --- bind the address to the spend: Poseidon(recipient_addr, nullifier) ---
    addr_commitment = poseidon_bls12_381(recipient_addr, nullifier)

    # --- witness input for the Groth16 PrivacyPoolViewableAddr circuit ---
    # E/C/C_a0/C_a1 are circuit OUTPUTS (computed by the witness), so they are
    # NOT passed as inputs here; they instead appear in the public list.
    view = dict(pool)
    view.update({
        "pk_audit": [str(pk_audit[0]), str(pk_audit[1])],
        "addr_commitment": str(addr_commitment),
        "audit_blinding": str(r_red),
        "recipient_addr": str(recipient_addr),
    })
    return view, {
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
        "r": str(r_red),
        "commitment": str(ciphertext_commitment(E, C, C_a0, C_a1)),
    }


def ciphertext_commitment(E, C, C_a0, C_a1):
    """Poseidon commitment of the shared E + three C points == Nova state_out."""
    c = poseidon_bls12_381(E[0], E[1])
    c = poseidon_bls12_381(c, C[0])
    c = poseidon_bls12_381(c, C[1])
    c = poseidon_bls12_381(c, C_a0[0])
    c = poseidon_bls12_381(c, C_a0[1])
    c = poseidon_bls12_381(c, C_a1[0])
    c = poseidon_bls12_381(c, C_a1[1])
    return c


def main():
    depth = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    base = Path(__file__).resolve().parent
    view, meta = generate(depth)

    (base / "input.json").write_text(json.dumps(view, indent=2) + "\n")
    (base / "nova_input.json").write_text(json.dumps({
        "state_in": "0",
        "amount": meta["amount"],
        "r": meta["r"],
        "pk_audit": meta["pk_audit"],
        "recipient_addr": meta["recipient_addr"],
    }, indent=2) + "\n")
    (base / "auditor_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print("wrote input.json (Groth16) + nova_input.json + auditor_meta.json")
    print("Nova public state_out (commit) =", meta["commitment"])


if __name__ == "__main__":
    main()
