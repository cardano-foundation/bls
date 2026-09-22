#!/usr/bin/env python3
"""
Generate witness inputs for the MetaBatchStep circuit (Step 9).

This script consumes the outputs of the F5 multi-user pipeline (step6) and
builds a Nova step witness for the MetaBatchStep circuit. Each "step" is one
epoch of N Groth16 batch proofs.

Usage:
    python3 gen_meta_batch_input.py \
        --epoch-dir /tmp/sd_step6_groth16/step3 \
        --epoch-size 8 \
        --prev-root 123456... \
        --nullifier-acc 0 \
        --vk-hash 789012... \
        --output input.json
"""

import argparse
import json
import struct
from pathlib import Path


def decode_groth16_proof(proof_path: Path) -> dict:
    """Decode a binary Groth16 proof into affine coordinates."""
    data = proof_path.read_bytes()
    # Groth16 proof format: pi_a (G1, 96 B), pi_b (G2, 192 B), pi_c (G1, 96 B)
    # = 384 bytes total. We extract only the x coordinates as scalars.
    if len(data) < 384:
        raise ValueError(f"Proof file too small: {len(data)} bytes")

    # Unpack as little-endian u256 (simplified — actual decoding needs Fr parsing)
    # For the scaffold we use the first 32 bytes of each component as a scalar.
    pi_a_x = int.from_bytes(data[0:32], "little")
    pi_a_y = int.from_bytes(data[32:64], "little")
    pi_b_x0 = int.from_bytes(data[96:128], "little")
    pi_b_x1 = int.from_bytes(data[128:160], "little")
    pi_c_x = int.from_bytes(data[288:320], "little")
    pi_c_y = int.from_bytes(data[320:352], "little")

    return {
        "pi_a_x": str(pi_a_x),
        "pi_a_y": str(pi_a_y),
        "pi_b_x0": str(pi_b_x0),
        "pi_b_x1": str(pi_b_x1),
        "pi_c_x": str(pi_c_x),
        "pi_c_y": str(pi_c_y),
    }


def decode_public_inputs(pub_path: Path) -> list:
    """Read public inputs from a .pub file (one scalar per line)."""
    lines = pub_path.read_text().strip().splitlines()
    return [line.strip() for line in lines if line.strip()]


def build_epoch_witness(epoch_dir: Path, epoch_size: int, prev_root: str,
                        nullifier_acc: str, vk_hash: str) -> dict:
    """Build one MetaBatchStep witness from an epoch directory."""
    proof_files = sorted(epoch_dir.glob("user_*.proof"))[:epoch_size]
    pub_files = sorted(epoch_dir.glob("user_*.pub"))[:epoch_size]

    if len(proof_files) < epoch_size or len(pub_files) < epoch_size:
        raise ValueError(
            f"Epoch dir {epoch_dir} has only {len(proof_files)} proofs, "
            f"need {epoch_size}"
        )

    pi_a_x = []
    pi_a_y = []
    pi_c_x = []
    pi_c_y = []
    pub_merkle_root = []
    pub_nullifier_hash = []
    pub_out_commitment_1 = []
    pub_out_commitment_2 = []
    pub_fee = []
    pub_pk_audit_x = []
    pub_pk_audit_y = []
    pub_addr_commitment = []

    for proof_path, pub_path in zip(proof_files, pub_files):
        proof = decode_groth16_proof(proof_path)
        pub = decode_public_inputs(pub_path)

        # Public input order for privacy_pool_viewable_addr:
        # 0: merkle_root, 1: nullifier_hash, 2: out_commitment_1,
        # 3: out_commitment_2, 4: fee, 5: pk_audit_x, 6: pk_audit_y,
        # 7: addr_commitment
        if len(pub) < 8:
            raise ValueError(f"Public inputs too short: {len(pub)} < 8")

        pi_a_x.append(proof["pi_a_x"])
        pi_a_y.append(proof["pi_a_y"])
        pi_c_x.append(proof["pi_c_x"])
        pi_c_y.append(proof["pi_c_y"])
        pub_merkle_root.append(pub[0])
        pub_nullifier_hash.append(pub[1])
        pub_out_commitment_1.append(pub[2])
        pub_out_commitment_2.append(pub[3])
        pub_fee.append(pub[4])
        pub_pk_audit_x.append(pub[5])
        pub_pk_audit_y.append(pub[6])
        pub_addr_commitment.append(pub[7])

    return {
        "prev_root": prev_root,
        "nullifier_acc": nullifier_acc,
        "vk_hash": vk_hash,
        "pi_a_x": pi_a_x,
        "pi_a_y": pi_a_y,
        "pi_c_x": pi_c_x,
        "pi_c_y": pi_c_y,
        "pub_merkle_root": pub_merkle_root,
        "pub_nullifier_hash": pub_nullifier_hash,
        "pub_out_commitment_1": pub_out_commitment_1,
        "pub_out_commitment_2": pub_out_commitment_2,
        "pub_fee": pub_fee,
        "pub_pk_audit_x": pub_pk_audit_x,
        "pub_pk_audit_y": pub_pk_audit_y,
        "pub_addr_commitment": pub_addr_commitment,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epoch-dir", type=Path, required=True)
    ap.add_argument("--epoch-size", type=int, default=8)
    ap.add_argument("--prev-root", type=str, default="0")
    ap.add_argument("--nullifier-acc", type=str, default="0")
    ap.add_argument("--vk-hash", type=str, default="0")
    ap.add_argument("--output", type=Path, default=Path("input.json"))
    args = ap.parse_args()

    witness = build_epoch_witness(
        args.epoch_dir, args.epoch_size,
        args.prev_root, args.nullifier_acc, args.vk_hash
    )
    args.output.write_text(json.dumps(witness, indent=2) + "\n")
    print(f"wrote {args.output}")
    print(f"  epoch dir : {args.epoch_dir}")
    print(f"  epoch size: {args.epoch_size}")
    print(f"  prev root : {args.prev_root}")
    print(f"  nullifier : {args.nullifier_acc}")


if __name__ == "__main__":
    main()
