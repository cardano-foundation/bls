#!/usr/bin/env python3
"""
gen_cardano_address_input.py

Generate circuit witness input from a Cardano address derived via
cardano-addresses (https://github.com/IntersectMBO/cardano-addresses).

Workflow:
  1. cardano-address recovery-phrase generate --size 15 > phrase.prv
  2. cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
  3. cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
  4. cardano-address key public --without-chain-code < pay.xsk > pay.vk
  5. python3 gen_cardano_address_input.py --xsk pay.xsk --vk pay.vk -o input.json

The script decodes the bech32 extended signing key (pay.xsk) and the
bech32 public key (pay.vk), extracts the Ed25519 scalar and public key,
decompresses the point, and emits the JSON input expected by the
CardanoEd25519Ownership circuit.

Usage:
  python3 gen_cardano_address_input.py --xsk pay.xsk --vk pay.vk -o input.json
  python3 gen_cardano_address_input.py --xsk pay.xsk --xvk pay.xvk -o input.json
"""

import argparse
import json
import hashlib
import subprocess
import sys


def decode_bech32_file(path):
    """Decode a bech32-encoded file to raw bytes using the bech32 CLI."""
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
    # HRP is the prefix before the '1' in the bech32 string
    hrp = encoded.split("1")[0] if "1" in encoded else ""
    return raw, hrp


# Ed25519 prime
p = 2**255 - 19
# Curve constant d = -121665 / 121666  (mod p)
d = -121665 * pow(121666, p - 2, p) % p


def clamp_ed25519_scalar(kL):
    """
    Apply Ed25519 clamping to the first 32 bytes of an extended key.
    In Cardano BIP32-Ed25519 (CIP-1852), kL is already stored clamped,
    but we apply clamping idempotently to be safe.
    """
    a = bytearray(kL[:32])
    a[0] &= 0xF8     # clear bottom 3 bits
    a[31] &= 0x7F    # clear top bit
    a[31] |= 0x40    # set second-top bit
    return bytes(a)


def bytes_to_bits_le(data):
    """Convert bytes to little-endian bit array (LSB first per byte)."""
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def decompress_point(y_bytes):
    """
    Decompress an Ed25519 public key from 32 bytes to extended coordinates
    [X, Y, Z, T] (integers modulo p).
    """
    y_int = int.from_bytes(y_bytes, "little")
    sign_x = y_int >> 255
    y_int &= (1 << 255) - 1

    y2 = (y_int * y_int) % p
    u = (y2 - 1) % p
    v = (d * y2 + 1) % p
    v_inv = pow(v, p - 2, p)
    x2 = (u * v_inv) % p

    x = pow(x2, (p + 3) // 8, p)
    if (x * x) % p != x2:
        x = (x * pow(2, (p - 1) // 4, p)) % p

    if x & 1 != sign_x:
        x = (-x) % p

    return [x, y_int, 1, (x * y_int) % p]


def to_chunks(val, bits=85, n=3):
    """Split integer into n chunks of 'bits' bits each (little-endian chunks)."""
    chunks = []
    for i in range(n):
        chunk = (val >> (i * bits)) & ((1 << bits) - 1)
        chunks.append(chunk)
    return chunks


def main():
    parser = argparse.ArgumentParser(
        description="Generate CardanoEd25519Ownership circuit input from cardano-address keys."
    )
    parser.add_argument("--xsk", required=True, help="Path to payment extended signing key (pay.xsk)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--vk", help="Path to payment public key without chain code (pay.vk, 32 bytes)")
    group.add_argument("--xvk", help="Path to payment extended public key with chain code (pay.xvk, 64 bytes)")
    parser.add_argument("-o", "--output", default="input.json", help="Output JSON file (default: input.json)")
    args = parser.parse_args()

    # Decode extended signing key
    xsk_bytes, xsk_hrp = decode_bech32_file(args.xsk)
    if not xsk_hrp.endswith("_xsk"):
        print(f"WARNING: xsk HRP is '{xsk_hrp}', expected something ending in '_xsk'")
    if len(xsk_bytes) != 96:
        print(f"WARNING: xsk length is {len(xsk_bytes)}, expected 96 bytes")

    # Decode public key
    if args.vk:
        vk_bytes, vk_hrp = decode_bech32_file(args.vk)
        if not vk_hrp.endswith("_vk"):
            print(f"WARNING: vk HRP is '{vk_hrp}', expected something ending in '_vk'")
        if len(vk_bytes) != 32:
            print(f"WARNING: vk length is {len(vk_bytes)}, expected 32 bytes")
        pk_bytes = vk_bytes
    else:
        xvk_bytes, xvk_hrp = decode_bech32_file(args.xvk)
        if not xvk_hrp.endswith("_xvk"):
            print(f"WARNING: xvk HRP is '{xvk_hrp}', expected something ending in '_xvk'")
        if len(xvk_bytes) != 64:
            print(f"WARNING: xvk length is {len(xvk_bytes)}, expected 64 bytes")
        pk_bytes = xvk_bytes[:32]  # first 32 bytes are the public key

    # Extract scalar from xsk (first 32 bytes = kL, clamped)
    kL = xsk_bytes[:32]
    scalar = clamp_ed25519_scalar(kL)

    # Compressed public key bits (256 bits)
    A_bits = bytes_to_bits_le(pk_bytes)

    # Scalar bits (255 bits — top bit is always 0 after clamping)
    sk_bits = bytes_to_bits_le(scalar)[:255]

    # Decompress public key and chunk into base-2^85
    PointA = decompress_point(pk_bytes)
    PointA_chunks = [to_chunks(c) for c in PointA]

    circuit_input = {
        "A": [str(b) for b in A_bits],
        "sk": [str(b) for b in sk_bits],
        "PointA": [[str(c) for c in row] for row in PointA_chunks],
    }

    with open(args.output, "w") as f:
        json.dump(circuit_input, f, indent=2)

    print(f"Generated {args.output}")
    print(f"  xsk HRP:        {xsk_hrp}")
    print(f"  vk HRP:         {vk_hrp if args.vk else xvk_hrp}")
    print(f"  Public key:     {pk_bytes.hex()}")
    print(f"  Scalar (hex):   {scalar.hex()}")
    print(f"  Scalar bits:    {len(sk_bits)} (255 expected)")
    print(f"  A bits:         {len(A_bits)} (256 expected)")
    print(f"  PointA chunks:  {[row for row in PointA_chunks]}")
    print("Input generated successfully for Cardano Ed25519 ownership circuit.")
    print("Note: sk is the clamped Ed25519 scalar derived from the cardano-address extended key.")


if __name__ == "__main__":
    main()
