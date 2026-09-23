#!/usr/bin/env python3
"""
Generate K chained MetaBatch step witnesses from one epoch directory.

Each step i uses the output state of step i-1 as its input state,
so that Nova can fold them into a single recursive proof.

Usage:
    python3 gen_multi_step_witnesses.py \
        --epoch-dir EPOCH \
        --epoch-size 4 \
        --steps 3 \
        --out-dir STEPS
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                       / "PoseidonMerkle" / "helpers_py"))
from poseidon_merkle import poseidon_bls12_381  # noqa: E402


def decode_groth16_proof(proof_path: Path) -> dict:
    data = proof_path.read_bytes()
    if len(data) < 192:
        raise ValueError(f"Proof file too small: {len(data)} bytes")
    chunks = [data[i:i+48] for i in range(0, 192, 48)]
    scalars = [int.from_bytes(c, "little") for c in chunks]
    return {
        "pi_a_x": str(scalars[0]),
        "pi_a_y": str(scalars[1]),
        "pi_c_x": str(scalars[2]),
        "pi_c_y": str(scalars[3]),
    }


def decode_public_inputs(json_path: Path) -> list:
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


def build_step_witness(epoch_dir: Path, epoch_size: int,
                       prev_root: int, nullifier_acc: int, vk_hash: int) -> dict:
    proof_files = sorted(epoch_dir.glob("user_*.proof"))[:epoch_size]
    json_files = sorted(epoch_dir.glob("user_*.json"))[:epoch_size]

    if len(proof_files) < epoch_size or len(json_files) < epoch_size:
        raise ValueError(
            f"Epoch dir {epoch_dir} has only {len(proof_files)} proofs, need {epoch_size}"
        )

    pi_a_x, pi_a_y, pi_c_x, pi_c_y = [], [], [], []
    pub_merkle_root, pub_nullifier_hash = [], []
    pub_out_commitment_1, pub_out_commitment_2 = [], []
    pub_fee, pub_pk_audit_x, pub_pk_audit_y, pub_addr_commitment = [], [], [], []

    for proof_path, jpath in zip(proof_files, json_files):
        proof = decode_groth16_proof(proof_path)
        pub = decode_public_inputs(jpath)

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

    # Set first merkle root to prev_root so the circuit constraint passes.
    pub_merkle_root[0] = str(prev_root)

    return {
        "prev_root": str(prev_root),
        "nullifier_acc": str(nullifier_acc),
        "vk_hash": str(vk_hash),
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


def compute_next_state(witness: dict) -> tuple:
    """Compute (next_root, nullifier_acc_next) using the same logic as the circuit."""
    prev_root = int(witness["prev_root"])
    nullifier_acc = int(witness["nullifier_acc"])
    epoch_size = len(witness["pub_nullifier_hash"])

    # Nullifier accumulator: chain Poseidon(nullifier_acc, nf_i)
    running_nf = nullifier_acc
    for i in range(epoch_size):
        running_nf = poseidon_bls12_381(running_nf, int(witness["pub_nullifier_hash"][i]))

    # Merkle root: chain Poseidon(runningRoot, leafVal)
    # leafVal = out1 + out2
    running_root = prev_root
    for i in range(epoch_size):
        leaf_val = int(witness["pub_out_commitment_1"][i]) + int(witness["pub_out_commitment_2"][i])
        running_root = poseidon_bls12_381(running_root, leaf_val)
        running_root = poseidon_bls12_381(running_root, leaf_val)

    return running_root, running_nf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epoch-dir", type=Path, required=True)
    ap.add_argument("--epoch-size", type=int, default=4)
    ap.add_argument("--steps", type=int, default=3)
    ap.add_argument("--vk-hash", type=str, default="0")
    ap.add_argument("--out-dir", type=Path, default=Path("steps"))
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    # Determine initial prev_root from first user's merkle_root
    first_json = sorted(args.epoch_dir.glob("user_*.json"))[0]
    first_data = json.loads(first_json.read_text())
    prev_root = int(first_data["merkle_root"])
    nullifier_acc = 0
    vk_hash = int(args.vk_hash)

    for step in range(args.steps):
        witness = build_step_witness(
            args.epoch_dir, args.epoch_size,
            prev_root, nullifier_acc, vk_hash
        )
        out_path = args.out_dir / f"input_{step:04d}.json"
        out_path.write_text(json.dumps(witness, indent=2) + "\n")
        print(f"step {step}: prev_root={prev_root} nullifier_acc={nullifier_acc}")

        next_root, next_nf = compute_next_state(witness)
        prev_root = next_root
        nullifier_acc = next_nf

    print(f"wrote {args.steps} step witnesses to {args.out_dir}")
    print(f"final next_root={prev_root} final nullifier_acc={nullifier_acc}")


if __name__ == "__main__":
    main()
