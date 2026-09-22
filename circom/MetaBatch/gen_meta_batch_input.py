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
    """Decode a binary Groth16 proof into scalars for the batch commitment.

    The proof is in BLS12-381 compressed format (192 bytes):
      pi_a (G1 compressed): 48 bytes
      pi_b (G2 compressed): 96 bytes
      pi_c (G1 compressed): 48 bytes

    For the scaffold we hash the raw bytes into representative scalars.
    """
    data = proof_path.read_bytes()
    if len(data) < 192:
        raise ValueError(f"Proof file too small: {len(data)} bytes")

    # Split the 192-byte compressed proof into four 48-byte chunks
    # and interpret each as a little-endian scalar.
    chunks = [data[i:i+48] for i in range(0, 192, 48)]
    scalars = [int.from_bytes(c, "little") for c in chunks]

    return {
        "pi_a_x": str(scalars[0]),
        "pi_a_y": str(scalars[1]),
        "pi_c_x": str(scalars[2]),
        "pi_c_y": str(scalars[3]),
    }


def decode_public_inputs(json_path: Path) -> list:
    """Extract public inputs from a user witness JSON file.

    Order matches privacy_pool_viewable_addr.circom public inputs:
      merkle_root, nullifier_hash, out_commitment_1, out_commitment_2,
      fee, pk_audit_x, pk_audit_y, addr_commitment
    """
    data = json.loads(json_path.read_text())
    return [
        data["merkle_root"],
        data["nullifier_hash"],
        data["out_commitment_1"],
        data["out_commitment_2"],
        data["fee"],
        data["pk_audit"][0],
        data["pk_audit"][1],
        data["addr_commitment"],
    ]


def build_epoch_witness(epoch_dir: Path, epoch_size: int, prev_root: str,
                        nullifier_acc: str, vk_hash: str) -> dict:
    """Build one MetaBatchStep witness from an epoch directory."""
    proof_files = sorted(epoch_dir.glob("user_*.proof"))[:epoch_size]
    json_files = sorted(epoch_dir.glob("user_*.json"))[:epoch_size]

    if len(proof_files) < epoch_size or len(json_files) < epoch_size:
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

    for proof_path, json_path in zip(proof_files, json_files):
        proof = decode_groth16_proof(proof_path)
        pub = decode_public_inputs(json_path)

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

    # Use first user's merkle_root as prev_root so the consistency check passes.
    first_json = sorted(args.epoch_dir.glob("user_*.json"))[0]
    first_data = json.loads(first_json.read_text())
    prev_root = args.prev_root if args.prev_root != "0" else first_data["merkle_root"]

    witness = build_epoch_witness(
        args.epoch_dir, args.epoch_size,
        prev_root, args.nullifier_acc, args.vk_hash
    )
    args.output.write_text(json.dumps(witness, indent=2) + "\n")
    print(f"wrote {args.output}")
    print(f"  epoch dir : {args.epoch_dir}")
    print(f"  epoch size: {args.epoch_size}")
    print(f"  prev root : {args.prev_root}")
    print(f"  nullifier : {args.nullifier_acc}")


if __name__ == "__main__":
    main()
