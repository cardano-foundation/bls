#!/usr/bin/env python3
"""Generate the 6 step witnesses for the Strong Key Ownership Nova chain.

Proves knowledge of a 96-byte master XPrv that derives a payment extended
public key along CIP-1852 path m/purposeH/coinTypeH/accountH/role/index, by
folding the identical step circuit `cardano_ed25519_ownership_strong_nova`:

    step  op=?  transition                                public in / out
    0     seed  CKD_hard(master, purposeH)  -> key1       (zeros)/ (key1, pub(key1))
    1     hard  CKD_hard(key1, coinTypeH)   -> key2
    2     hard  CKD_hard(key2, accountH)    -> key3
    3     soft  CKD_soft(key3, role, pub(key3))  -> key4
    4     soft  CKD_soft(key4, index, pub(key4)) -> key5
    5     final passthrough pub(key5), zero keys         ((0,0,0,key5))/ (0,0,0,pub(key5))

op bits: seed=[0,0], hard=[1,0], soft=[0,1], final=[1,1].

The (kL,kR,cc,apk) public state chain is derived with reference V2 CKD
arithmetic (identical to `gen_cardano_address_input.py`), each step is run
through the step circuit's wasm, and the outputs are sanity-checked against
the pure-Python model.  The final step's apk output equals the target A.

Usage:
    python3 gen_strong_nova_steps.py --wasm <step.wasm> --dir steps
        [--master-hex <96-byte hex>] [--path 1852H/1815H/0H/0/0] [--snarkjs snarkjs]
"""

import argparse
import json
import os
import struct
import subprocess
import sys

from gen_cardano_address_input import ckd_hardened, ckd_soft, compress_point, point_mul

P_ED = 2 ** 255 - 19
N_ED = 2 ** 252 + 27742317777372353535851937790883648493
GY = (4 * pow(5, P_ED - 2, P_ED)) % P_ED
G_BYTES = (GY & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(32, "little")

# wtns signal offsets for the strong step circuit (from the compiled .sym):
# wires are 1-based; outK@1, outR@257, outc@513, outAp@769.
OFF_OUTK = 1
OFF_OUTR = 257
OFF_OUTC = 513
OFF_OUTAP = 769

OP_SEED = [0, 0]
OP_HARD = [1, 0]
OP_SOFT = [0, 1]
OP_FINAL = [1, 1]

MASTER_DEFAULT = ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")


def bytes_to_bits_le(data):
    return [int(b) for byte in data for b in ((byte >> i) & 1 for i in range(8))]


def index_word(value, hardened):
    idx = value + (0x80000000 if hardened else 0)
    return bytes_to_bits_le(idx.to_bytes(4, "little"))


def pubkey_bits(scalar_bytes):
    pt = compress_point(point_mul(int.from_bytes(scalar_bytes, "little") % N_ED, G_BYTES))
    return bytes_to_bits_le(pt.to_bytes(32, "little"))


def read_wtns(path):
    data = open(path, "rb").read()
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
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wasm", required=True, help="step circuit wasm")
    ap.add_argument("--dir", required=True, help="output dir for step_%04d.wtns")
    ap.add_argument("--master-hex", default=MASTER_DEFAULT, help="96-byte master XPrv hex")
    ap.add_argument("--path", default="1852H/1815H/0H/0/0", help="CIP-1852 derivation path")
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    master_bytes = bytes.fromhex(args.master_hex)
    assert len(master_bytes) == 96
    master_bits = bytes_to_bits_le(master_bytes)

    segs = []
    for t in args.path.split("/"):
        if not t:
            continue
        hardened = t.upper().endswith("H")
        segs.append((int(t[:-1]) if hardened else int(t), hardened))
    assert len(segs) == 5, "expected 5 path segments (3 hardened + 2 soft)"

    # --- derive the (kL,kR,cc,apk) chain with reference V2 CKD arithmetic ---
    ext = (master_bytes[:32], master_bytes[32:64], master_bytes[64:96])
    chain = []          # (op, idx_bits, state_in_bits, state_out_bits)
    state_in = ([0] * 256, [0] * 256, [0] * 256, [0] * 256)

    for step, (value, hardened) in enumerate(segs):
        idx_bits = index_word(value, hardened)
        if step == 0:
            op = OP_SEED
            ext = ckd_hardened(ext, value + 0x80000000)
        elif step < 3:
            op = OP_HARD
            ext = ckd_hardened(ext, value + 0x80000000)
        else:
            op = OP_SOFT
            parent_pk = compress_point(point_mul(int.from_bytes(ext[0], "little"), G_BYTES))
            ext = ckd_soft(ext, parent_pk.to_bytes(32, "little"), value)
        state_out = (bytes_to_bits_le(ext[0]), bytes_to_bits_le(ext[1]),
                     bytes_to_bits_le(ext[2]), pubkey_bits(ext[0]))
        chain.append((op, idx_bits, state_in, state_out))
        state_in = state_out

    # final step: passthrough apk, zero the keys
    chain.append((OP_FINAL, [0] * 32, state_in,
                  ([0] * 256, [0] * 256, [0] * 256, state_in[3])))
    A_bits = state_in[3]

    # --- run each step through the wasm, feed forward, sanity-check ---------
    os.makedirs(args.dir, exist_ok=True)
    for step, (op, idx_bits, _, state_out) in enumerate(chain):
        prev_out = chain[step - 1][3] if step > 0 else ([0] * 256,) * 4
        kLIn, kRIn, ccIn, apkIn = prev_out
        inp = {
            "kLIn": [str(b) for b in kLIn],
            "kRIn": [str(b) for b in kRIn],
            "ccIn": [str(b) for b in ccIn],
            "apkIn": [str(b) for b in apkIn],
            "master": [str(b) for b in (master_bits if step == 0 else [0] * 768)],
            "op": [str(b) for b in op],
            "idx": [str(b) for b in idx_bits],
        }
        name = {0: "seed", 1: "hard", 2: "hard", 3: "soft", 4: "soft", 5: "final"}[step]
        inp_path = os.path.join(args.dir, f"input_{step:04d}.json")
        wtns_path = os.path.join(args.dir, f"step_{step:04d}.wtns")
        with open(inp_path, "w") as f:
            json.dump(inp, f)
        subprocess.run([args.snarkjs, "wc", args.wasm, inp_path, wtns_path],
                       check=True, capture_output=True)
        _, w = read_wtns(wtns_path)
        assert w[0] == 1
        got = ([int(w[OFF_OUTK + i]) for i in range(256)],
               [int(w[OFF_OUTR + i]) for i in range(256)],
               [int(w[OFF_OUTC + i]) for i in range(256)],
               [int(w[OFF_OUTAP + i]) for i in range(256)])
        for i, (g, e) in enumerate(zip(got, state_out)):
            if g != e:
                print(f"step {step} ({name}): output block {i} mismatch vs model", file=sys.stderr)
                sys.exit(1)
        print(f"step {step:1d} ({name}): OK, idx={int(''.join(map(str, idx_bits[::-1])), 2):>10}")

    if got[3] != A_bits:
        print("final apk != A", file=sys.stderr)
        sys.exit(1)
    print(f"wrote {len(chain)} step witnesses to {args.dir}/ (final apk == A)")


if __name__ == "__main__":
    main()