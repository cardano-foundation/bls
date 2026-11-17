#!/usr/bin/env python3
"""
Build per-user NovaSlim step witnesses for privacy_pool_token_lifecycle_nova.circom
(Step 11 — private token lifecycle with dynamic auditor).

Reads the scenario produced by gen_token_lifecycle_input.py and emits one
Nova step input per spend under STEPS_DIR/user_NNN/input_0000.json.  The only
extra field vs. the Groth16 witness is `state_in`, which is the 0 sentinel for
a singleton Nova step.

Also writes expected_state_out.json containing the Poseidon chain the circuit
computes over the per-step public data (pool public inputs, auditor data, token
commitments, auditor ciphertexts).  The e2e script can compare this against the
state_out reported by `nova-slim verify`.

Usage:
    python3 gen_token_lifecycle_nova_steps.py SCENARIO_JSON STEPS_DIR
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PoseidonMerkle" / "helpers_py"))

from poseidon_merkle import poseidon_bls12_381  # noqa: E402


def chain_state_out(public, meta):
    """
    Reproduce the Poseidon chain computed by the Nova step circuit.

    `public` is the ordered list stored in scenario["spends"][i]["public"].
    `meta` is the corresponding scenario["spends"][i]["auditor_meta"].
    """
    # Unpack public list (matches PUBLIC_KEYS in gen_token_lifecycle_input.py)
    (
        merkle_root,
        nullifier_hash,
        out_commitment_1,
        out_commitment_2,
        fee,
        pk_audit,
        addr_commitment,
        auditor_root,
        token_in_commitment,
        token_out_commitment_1,
        token_out_commitment_2,
    ) = public

    def h(a, b):
        return poseidon_bls12_381(int(a), int(b))

    x = h(merkle_root, nullifier_hash)
    x = h(x, out_commitment_1)
    x = h(x, out_commitment_2)
    x = h(x, fee)
    x = h(x, pk_audit[0])
    x = h(x, pk_audit[1])
    x = h(x, addr_commitment)
    x = h(x, auditor_root)
    x = h(x, token_in_commitment[0])
    x = h(x, token_in_commitment[1])
    x = h(x, token_out_commitment_1[0])
    x = h(x, token_out_commitment_1[1])
    x = h(x, token_out_commitment_2[0])
    x = h(x, token_out_commitment_2[1])
    x = h(x, meta["E"][0])
    x = h(x, meta["E"][1])
    x = h(x, meta["C"][0])
    x = h(x, meta["C"][1])
    x = h(x, meta["C_a0"][0])
    x = h(x, meta["C_a0"][1])
    x = h(x, meta["C_a1"][0])
    x = h(x, meta["C_a1"][1])
    return str(x)


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} SCENARIO_JSON STEPS_DIR", file=sys.stderr)
        sys.exit(1)

    scenario_path = Path(sys.argv[1])
    steps_dir = Path(sys.argv[2])
    scenario_dir = scenario_path.parent

    scenario = json.loads(scenario_path.read_text())
    steps_dir.mkdir(parents=True, exist_ok=True)

    expected = {}
    for i, s in enumerate(scenario["spends"]):
        user_file = scenario_dir / s["user"]
        witness = json.loads(user_file.read_text())
        witness["state_in"] = "0"

        user_dir = steps_dir / f"user_{i:03d}"
        user_dir.mkdir(parents=True, exist_ok=True)
        out_file = user_dir / "input_0000.json"
        out_file.write_text(json.dumps(witness, indent=2) + "\n")

        expected[f"user_{i:03d}"] = chain_state_out(s["public"], s["auditor_meta"])

    (steps_dir / "expected_state_out.json").write_text(
        json.dumps(expected, indent=2) + "\n"
    )

    print(f"wrote {len(scenario['spends'])} Nova step inputs under {steps_dir}")
    print(f"expected state_out values written to {steps_dir / 'expected_state_out.json'}")


if __name__ == "__main__":
    main()
