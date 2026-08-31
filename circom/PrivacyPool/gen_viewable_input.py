#!/usr/bin/env python3
"""
Generate witness inputs for Step 4 (viewing-key / auditor-reveal) circuits.

Builds directly on Step 3's gen_privacy_input.generate(depth): the shielded
1-in/2-out privacy-pool spend is reused verbatim.  On top of it, Step 4
additionally encrypts the (private) input amount to a designated auditor's
public key with Twisted ElGamal:

    pk_audit = sk_audit * G
    E = r * G
    C = amount * H + r * pk_audit

and demonstrates the viewing-key reveal off-chain:
    amount * H == C - sk_audit * E     (auditor decrypts the amount)

Outputs used by:
  * Groth16  : privacy_pool_viewable.circom  -> input.json
  * NovaSlim : elgamal_viewkey_nova.circom   -> nova_input.json + commitment

Run in-place (as gen_privacy_input.py) so the Poseidon/JubJub helper paths
resolve relative to this file.

Usage:
    python3 gen_viewable_input.py [depth]
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


def elgamal_encrypt(amount: int, r: int, pk_audit):
    """(E, C) = ElGamal-encrypt `amount` to pk_audit with randomness r."""
    Gx, Gy = SUBGROUP_GENERATOR
    E = ed_mul(r, Gx, Gy)
    mH = ed_mul(amount, _H[0], _H[1])
    rPK = ed_mul(r, pk_audit[0], pk_audit[1])
    C = ed_add(mH[0], mH[1], rPK[0], rPK[1])
    return E, C


def point_sub(a, b):
    """a - b on twisted Edwards (negation is (-x, y))."""
    return ed_add(a[0], a[1], (-b[0]) % _P, b[1])


def generate(depth: int = 4, seed: int = 1, audit_sk: int = 0x51DE,
             r: int = 0xBAD0C0DE):
    pool = gen_pool(depth, seed)
    in_amount = int(pool["in_amount"])
    nullifier = pool["nullifier"]

    # --- auditor key pair (viewing key) ---
    sk_audit = audit_sk
    Gx, Gy = SUBGROUP_GENERATOR
    pk_audit = ed_mul(sk_audit, Gx, Gy)

    # --- encrypt the pooled in_amount to the auditor ---
    E, C = elgamal_encrypt(in_amount, r % _P, pk_audit)

    # --- auditor viewing-key reveal (off-chain decrypt) ---
    skE = ed_mul(sk_audit, E[0], E[1])
    mH = point_sub(C, skE)          # C - sk_audit*E == amount*H
    expected_mH = ed_mul(in_amount, _H[0], _H[1])
    assert mH == expected_mH, "auditor decryption failed: m*H mismatch"
    # small discrete-log recovery of the amount (u32 range-checked)
    recovered = None
    probe = (0, 0)
    # walk amount*H by adding H until we match mH (amount is small)
    # H is not the subgroup generator; instead brute-force over the scalar
    for m in range(1 << 24):
        if ed_mul(m, _H[0], _H[1]) == mH:
            recovered = m
            break
    assert recovered == in_amount, "auditor amount recovery mismatch"
    print(f"auditor viewing-key reveal OK: recovered in_amount = {recovered}")

    # --- witness input for the Groth16 PrivacyPoolViewable circuit ---
    # E[2]/C[2] are circuit OUTPUTS (computed by the witness), so they are NOT
    # passed as inputs here; they instead appear in the verification public list.
    view = dict(pool)
    view.update({
        "pk_audit": [str(pk_audit[0]), str(pk_audit[1])],
        "audit_blinding": str(r % _P),
    })
    return view, {
        "sk_audit": str(sk_audit),
        "pk_audit": [str(pk_audit[0]), str(pk_audit[1])],
        "E": [str(E[0]), str(E[1])],
        "C": [str(C[0]), str(C[1])],
        "amount": str(in_amount),
        "r": str(r % _P),
        "commitment": str(ciphertext_commitment(E, C)),
    }


def ciphertext_commitment(E, C):
    """Poseidon commitment of the ciphertext == Nova step state_out."""
    c1 = poseidon_bls12_381(E[0], E[1])
    c2 = poseidon_bls12_381(c1, C[0])
    return poseidon_bls12_381(c2, C[1])


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
    }, indent=2) + "\n")
    (base / "auditor_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print("wrote input.json (Groth16) + nova_input.json + auditor_meta.json")
    print("Nova public state_out (commit) =", meta["commitment"])


if __name__ == "__main__":
    main()
