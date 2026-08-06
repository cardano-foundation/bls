#!/usr/bin/env python3
"""
gen_smt_input.py

Generate circuit witness input for CardanoKeyOwnershipSMT from a Cardano
address derived via cardano-addresses (https://github.com/IntersectMBO/cardano-addresses).

Workflow:
  1. cardano-address recovery-phrase generate --size 15 > phrase.prv
  2. cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
  3. cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
  4. cardano-address key public --without-chain-code < pay.xsk > pay.vk
  5. python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o input.json

The script is a **thin orchestration layer**. All cryptography is performed
by external CLIs, never in Python:

  1. `bech32` decodes the extended signing key and public key files
  2. `groth16-prover smt key`   decompresses the Ed25519 public key, splits it
     into base-2^85 limbs, computes the MiMC leaf commitment, and
     bit-decomposes `A` / `sk` (see groth16-prover/src/ed25519.rs)
  3. `groth16-prover smt insert` builds the zero-padded Merkle tree
  4. `groth16-prover smt cardano-input` assembles the full circuit input JSON
     (Merkle root + proof + key witness data)

Python only parses the key files (byte slicing of the bech32-decoded blobs)
and drives the CLI commands. The `groth16-prover` binary must be built with
the `privacy` feature so the `smt` subcommand is available.

Usage:
  python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o input.json [--depth 4] [--index 0] [--smt-cli groth16-prover]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile


def decode_bech32_file(path):
    """Decode a bech32 key file to raw bytes via the `bech32` CLI."""
    with open(path, "r") as f:
        encoded = f.read().strip()
    try:
        result = subprocess.run(
            ["bech32"],
            input=encoded,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"bech32 CLI failed for {path}: {e.stderr}") from e
    except FileNotFoundError:
        print(
            "ERROR: 'bech32' CLI not found in PATH.\n"
            "  Install from https://github.com/IntersectMBO/bech32/releases\n"
            "  or build from source: cabal install bech32"
        )
        sys.exit(1)
    hex_str = result.stdout.strip()
    raw = bytes.fromhex(hex_str)
    hrp = encoded.split("1")[0] if "1" in encoded else ""
    return raw, hrp


def run_smt_cli(smt_cli, subcommand, *args):
    """Run `groth16-prover smt <subcommand> [args]` and return stdout.

    All cryptography lives in the CLI, so there is no Python fallback: a
    missing or failing binary is a hard error.
    """
    cmd = [smt_cli, "smt", subcommand, *args]
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        print(
            f"ERROR: smt CLI '{smt_cli}' not found.\n"
            "  All cryptography is handled by the groth16-prover CLI.\n"
            "  Build it with:  cargo build --release  (in groth16-prover/cli)\n"
            "  and pass its path via --smt-cli if it is not on PATH.",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: `{' '.join(cmd)}` failed:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout


def key_record_cli(pk_hex, xsk_hex, smt_cli):
    """Run `smt key --vk <hex> --xsk <hex> --json`.

    Returns the record dict: {"vk", "PointA", "leaf", "A", "sk"}.
    """
    out = run_smt_cli(smt_cli, "key", "--vk", pk_hex, "--xsk", xsk_hex, "--json")
    return json.loads(out)


def build_smt_and_input_cli(leaves, index, depth, key_record, out_file, smt_cli):
    """Run `smt insert` + `smt cardano-input` to produce the circuit input.

    `leaves` is the full list of leaves (the key's MiMC leaf first). With
    `index == 0` the leaves are inserted sequentially; otherwise a single
    leaf is placed at `index` (zero-padded tree). `key_record` comes from
    `key_record_cli`. Writes the full circuit input to `out_file` and returns
    the parsed circuit input dict.
    """
    with tempfile.TemporaryDirectory(prefix="smt_cli_") as tmp:
        state = os.path.join(tmp, "smt.json")
        key_file = os.path.join(tmp, "key.json")
        with open(key_file, "w") as f:
            json.dump(key_record, f)
        if index == 0:
            items = ",".join(str(l) for l in leaves)
            run_smt_cli(smt_cli, "insert", "--depth", str(depth), "--items", items, "--state", state)
        else:
            run_smt_cli(smt_cli, "insert", "--depth", str(depth), "--items", str(leaves[0]), "--index", str(index), "--state", state)
        run_smt_cli(smt_cli, "cardano-input", "--state", state, "--key", key_file, "--out", out_file)
    with open(out_file) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Generate CardanoKeyOwnershipSMT circuit input from cardano-address keys."
    )
    parser.add_argument("--xsk", required=True, help="Path to payment extended signing key (pay.xsk)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--vk", help="Path to payment public key without chain code (pay.vk, 32 bytes)")
    group.add_argument("--xvk", help="Path to payment extended public key with chain code (pay.xvk, 64 bytes)")
    parser.add_argument("-o", "--output", default="input.json", help="Output JSON file (default: input.json)")
    parser.add_argument("--depth", type=int, default=4, help="SMT depth (default: 4)")
    parser.add_argument("--index", type=int, default=0, help="Leaf index in the SMT (default: 0)")
    parser.add_argument(
        "--smt-cli",
        default="groth16-prover",
        help="Path to the 'groth16-prover' binary used for all crypto "
             "(must expose the 'smt' subcommand, i.e. be built with the "
             "'privacy' feature). Default: 'groth16-prover' (looked up on PATH).",
    )
    args = parser.parse_args()

    xsk_bytes, xsk_hrp = decode_bech32_file(args.xsk)
    if not xsk_hrp.endswith("_xsk"):
        print(f"WARNING: xsk HRP is '{xsk_hrp}', expected something ending in '_xsk'")
    if len(xsk_bytes) != 96:
        print(f"WARNING: xsk length is {len(xsk_bytes)}, expected 96 bytes")

    if args.vk:
        vk_bytes, vk_hrp = decode_bech32_file(args.vk)
        if not vk_hrp.endswith("_vk"):
            print(f"WARNING: vk HRP is '{vk_hrp}', expected something ending in '_vk'")
        if len(vk_bytes) != 32:
            print(f"WARNING: vk length is {len(vk_bytes)}, expected 32 bytes")
        pk_bytes = vk_bytes
    else:
        xvk_bytes, vk_hrp = decode_bech32_file(args.xvk)
        if not vk_hrp.endswith("_xvk"):
            print(f"WARNING: xvk HRP is '{vk_hrp}', expected something ending in '_xvk'")
        if len(xvk_bytes) != 64:
            print(f"WARNING: xvk length is {len(xvk_bytes)}, expected 64 bytes")
        pk_bytes = xvk_bytes[:32]

    # Raw material for `smt key`: the compressed public key and the first
    # 32 bytes of the extended signing key (the Ed25519 scalar).
    key_record = key_record_cli(pk_bytes.hex(), xsk_bytes[:32].hex(), args.smt_cli)

    # The key's MiMC leaf is inserted into the (zero-padded) tree.
    leaves = [int(key_record["leaf"])]
    circuit_input = build_smt_and_input_cli(
        leaves, args.index, args.depth, key_record, args.output, args.smt_cli
    )

    print(f"Generated {args.output}")
    print(f"  xsk HRP:        {xsk_hrp}")
    print(f"  vk HRP:         {vk_hrp}")
    print(f"  Public key:     {pk_bytes.hex()}")
    print(f"  Scalar (hex):   {xsk_bytes[:32].hex()}")
    print(f"  SMT depth:      {args.depth}")
    print(f"  SMT leaf index: {args.index}")
    print(f"  SMT builder:    groth16-prover smt CLI (--smt-cli {args.smt_cli})")
    print(f"  SMT root:       {circuit_input['smt_root']}")
    print(f"  MiMC leaf:      {key_record['leaf']} (smt key CLI)")
    print("Input generated successfully for CardanoKeyOwnershipSMT circuit.")


if __name__ == "__main__":
    main()
