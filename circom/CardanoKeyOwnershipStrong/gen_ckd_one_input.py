#!/usr/bin/env python3
"""Generate ckd_one_test witness input from golden root + purpose 1852H."""
import hmac, hashlib, json, sys
sys.path.insert(0, "/home/pawel/Work/cardano-foundation/bls/circom/CardanoKeyOwnershipStrong")


def le28(h): return int.from_bytes(h[:28], "little")
def le256(h): return int.from_bytes(h[:32], "little")
def bits_le(data):
    return [(b >> i) & 1 for b in data for i in range(8)]


def load(path):
    with open(path) as f:
        return bytes.fromhex(f.read().strip().split("1")[-1]) if "1" not in open(path).read().strip() else read_bech32(path)


def read_bech32(path):
    import subprocess
    with open(path) as f:
        enc = f.read().strip()
    out = subprocess.run(["bech32"], input=enc, capture_output=True, text=True, check=True).stdout.strip()
    return bytes.fromhex(out)


root = read_bech32("/tmp/opencode/cko_strong_probe/root2.xsk")
kL, kR, cc = root[:32], root[32:64], root[64:96]

idx = 1852 + 0x80000000
idxLE = idx.to_bytes(4, "little")
hmac1 = hmac.new(cc, b"\x00" + kL + kR + idxLE, hashlib.sha512)
z = hmac1.digest()
hmac2 = hmac.new(cc, b"\x01" + kL + kR + idxLE, hashlib.sha512)
nkL = ((8 * le28(z) + le256(kL)) % (1 << 256)).to_bytes(32, "little")
nkR = ((le256(z[32:]) + le256(kR)) % (1 << 256)).to_bytes(32, "little")
ncc = hmac2.digest()[32:]

inp = {
    "kL": bits_le(kL), "kR": bits_le(kR), "cc": bits_le(cc),
    "idx": bits_le(idxLE),
    "oK": bits_le(nkL), "oR": bits_le(nkR), "oC": bits_le(ncc),
}
json.dump({k: [str(v) for v in var] for k, var in inp.items()}, open("/tmp/opencode/cko_strong_probe/onestep_input.json", "w"))

print("child kL:", nkL.hex())
print("child kR:", nkR.hex())
print("child cc:", ncc.hex())
# cross-check against binary oracle
c1 = read_bech32("/tmp/opencode/cko_strong_probe/ora/c1.txt") if False else None