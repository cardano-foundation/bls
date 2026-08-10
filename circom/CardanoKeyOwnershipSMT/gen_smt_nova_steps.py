#!/usr/bin/env python3
"""Generate the 255 step witnesses for the Nova (Implementation 8) step-chain.

Consumes the monolithic circuit input produced by `gen_smt_input.py` (which
contains the clamped scalar bits `sk[255]`), then runs the step circuit's
wasm once per scalar bit, feeding each step's outputs forward so the state
chain invariant holds by construction:

    dblIn = extended(G)          # circuit base point, [4][3] x base-2^85 limbs
    addIn = extended(O)          # identity
    for i in 0..254:
        inputs = (dblIn, addIn, sel := sk[i])   # sel = scalar bit, LSB-first
        run wasm -> step_%04d.wtns
        read outputs (dblOut, addOut) -> next (dblIn, addIn)

After 255 steps `addOut = 2 * [sk] * G`; the script asserts this equals
`2 * PointA` (the decompressed public key) as a final sanity check.

Usage:
    python3 gen_smt_nova_steps.py --input smt_input.json \
        --wasm cardano_key_ownership_smt_nova_js/cardano_key_ownership_smt_nova.wasm \
        --dir steps
"""

import argparse
import json
import os
import struct
import subprocess
import sys

P_ED = 2 ** 255 - 19
B = 2 ** 85
D_ED = (-121665 * pow(121666, P_ED - 2, P_ED)) % P_ED

# The circuit base point G in extended Edwards coordinates, base-2^85 limbs
# (identical to the constants in cardano_key_ownership_smt.circom).
G_LIMBS = [
    [6836562328990639286768922, 21231440843933962135602345, 10097852978535018773096760],
    [7737125245533626718119512, 23211375736600880154358579, 30948500982134506872478105],
    [1, 0, 0],
    [20943500354259764865654179, 24722277920680796426601402, 31289658119428895172835987],
]
O_LIMBS = [[0, 0, 0], [1, 0, 0], [1, 0, 0], [0, 0, 0]]


def limbs_to_int(limbs):
    return sum(int(v) * (B ** i) for i, v in enumerate(limbs)) % P_ED


def ext_add(p1, p2):
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P_ED
    B_ = (Y1 + X1) * (Y2 + X2) % P_ED
    C = (T1 * 2 * D_ED % P_ED) * T2 % P_ED
    D = Z1 * 2 * Z2 % P_ED
    E = (B_ - A) % P_ED
    F = (D - C) % P_ED
    G2 = (D + C) % P_ED
    H = (B_ + A) % P_ED
    return (E * F % P_ED, G2 * H % P_ED, F * G2 % P_ED, E * H % P_ED)


def projective_eq(p, q):
    return all((p[i] * q[3] - q[i] * p[3]) % P_ED == 0 for i in range(4))


def read_wtns(path):
    """Parse a circom-2 .wtns binary and return (n8, prime, witness list).

    Layout (from circom_runtime `calculateWTNSBin`):
      [magic 'wtns'][version u32][nSections u32]
      [s1 id u32][s1 size u64][n8 u32][prime n8 bytes][nWires u32]
      [s2 id u32][s2 size u64][witness data: nWires x n8 bytes LE]
    Byte offsets: magic 0, version 4, nSections 8, s1 id 12, s1 size 16,
    n8 24, prime 28, nWires 28 + n8, s2 id 28 + n8 + 4, s2 size 28 + n8 + 8,
    data 28 + n8 + 16.
    """
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"wtns", "not a wtns file"
    n8, = struct.unpack_from("<I", data, 24)
    n_wires, = struct.unpack_from("<I", data, 28 + n8)
    off = 28 + n8 + 16
    values = []
    for _ in range(n_wires):
        values.append(int.from_bytes(data[off:off + n8], "little"))
        off += n8
    return n8, values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="monolithic input JSON (from gen_smt_input.py)")
    ap.add_argument("--wasm", required=True, help="step circuit wasm (cardano_key_ownership_smt_nova.wasm)")
    ap.add_argument("--dir", required=True, help="output directory for step_%04d.wtns")
    ap.add_argument("--steps", type=int, default=255, help="number of steps (default 255)")
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    d = json.load(open(args.input))
    sk = [int(b) for b in d["sk"]]
    point_a = [[int(v) for v in limb] for limb in d["PointA"]]

    os.makedirs(args.dir, exist_ok=True)
    # R1CS signal layout: [1][dbl_out: 12][add_out: 12][dbl_in: 12][add_in: 12][sel]
    # (verified against cardano_ed25519_ownership_nova.sym / nova params)
    n_dbl_out = 12
    n_pub_out = 24  # 12 dbl_out + 12 add_out

    dbl_in, add_in = G_LIMBS, O_LIMBS
    for i in range(args.steps):
        inp = {"sel": str(sk[i])}
        for c in range(4):
            for l in range(3):
                inp[f"dbl_in_{c}_{l}"] = str(dbl_in[c][l])
                inp[f"add_in_{c}_{l}"] = str(add_in[c][l])
        inp_path = os.path.join(args.dir, f"input_{i:04d}.json")
        wtns_path = os.path.join(args.dir, f"step_{i:04d}.wtns")
        with open(inp_path, "w") as f:
            json.dump(inp, f)
        subprocess.run(
            [args.snarkjs, "wc", args.wasm, inp_path, wtns_path],
            check=True,
            capture_output=True,
        )
        _, w = read_wtns(wtns_path)
        assert w[0] == 1, "wtns[0] != 1"
        dbl_out = [[w[1 + c * 3 + l] for l in range(3)] for c in range(4)]
        add_out = [[w[1 + n_dbl_out + c * 3 + l] for l in range(3)] for c in range(4)]
        # Sanity check against the pure-Python model (catches feed-forward bugs).
        dbl_m = ext_add(tuple(limbs_to_int(dbl_in[c]) for c in range(4)),
                        tuple(limbs_to_int(dbl_in[c]) for c in range(4)))
        add_m = ext_add(tuple(limbs_to_int(add_in[c]) for c in range(4)),
                        dbl_m if sk[i] else tuple((0, 1, 1, 0)))
        if not (projective_eq(tuple(limbs_to_int(dbl_out[c]) for c in range(4)), dbl_m)
                and projective_eq(tuple(limbs_to_int(add_out[c]) for c in range(4)), add_m)):
            print(f"step {i}: model/actual mismatch — aborting", file=sys.stderr)
            sys.exit(1)
        dbl_in, add_in = dbl_out, add_out
        if i % 50 == 0 or i == args.steps - 1:
            print(f"step {i:4d}/{args.steps - 1}: sel={sk[i]}")

    final = tuple(limbs_to_int(add_in[c]) for c in range(4))
    two_point_a = ext_add(tuple(limbs_to_int(point_a[c]) for c in range(4)),
                          tuple(limbs_to_int(point_a[c]) for c in range(4)))
    ok = projective_eq(final, two_point_a)
    print("final addOut == 2*PointA:", ok)
    if not ok:
        sys.exit(1)
    print(f"wrote {args.steps} step witnesses to {args.dir}/")


if __name__ == "__main__":
    main()
