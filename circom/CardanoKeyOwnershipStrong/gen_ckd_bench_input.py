#!/usr/bin/env python3
"""Generate the deterministic hardened-CKD benchmark fixture without external keys.

Fixed parent (bytes range 0x00..0x1f), index = 1852H. Child expected from
hashlib HMAC-SHA512 per CIP-1852 DerivationScheme2 (via Cardano V2 scheme):

    nkL = (8 * LE(Z[0:28]) + kL) mod 2^256
    nkR = (LE(Z[32:64]) + kR) mod 2^256
    ncc = HMAC-SHA512(cc, 0x01 || kL || kR || idxLE)[32:64]
"""
import hmac, hashlib, json, os


def le28(h): return int.from_bytes(h[:28], "little")
def le256(h): return int.from_bytes(h[:32], "little")
def bits_le(data): return [(b >> i) & 1 for b in data for i in range(8)]

kL = bytes(range(32))
kR = bytes(range(32, 64))
cc = bytes(range(64, 96))
idx = 1852 + 0x80000000
idxLE = idx.to_bytes(4, "little")
z = hmac.new(cc, b"\x00" + kL + kR + idxLE, hashlib.sha512).digest()
h2 = hmac.new(cc, b"\x01" + kL + kR + idxLE, hashlib.sha512).digest()
nkL = ((8 * le28(z) + le256(kL)) % (1 << 256)).to_bytes(32, "little")
nkR = ((le256(z[32:]) + le256(kR)) % (1 << 256)).to_bytes(32, "little")
ncc = h2[32:]
inp = {"kL": bits_le(kL), "kR": bits_le(kR), "cc": bits_le(cc), "idx": bits_le(idxLE),
       "oK": bits_le(nkL), "oR": bits_le(nkR), "oC": bits_le(ncc)}
out = os.path.join(os.path.dirname(__file__), "benchmarks", "ckd_hardened_input.json")
json.dump({k: [str(v) for v in var] for k, var in inp.items()}, open(out, "w"))
print("wrote", out)
print("nkL", nkL.hex())
print("nkR", nkR.hex())
print("ncc", ncc.hex())
