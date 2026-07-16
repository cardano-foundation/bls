#!/usr/bin/env sage
"""
JubJub golden test vectors over BLS12-381 scalar field.

Independent verification of circom EdDSA-JubJub circuit parameters.
Run with: sage jubjub.sage
"""

# ─── Curve setup (from zkcrypto/jubjub, via Weierstrass birational equivalence) ───

p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
K = GF(p)

# Twisted Edwards parameters: -x^2 + y^2 = 1 + d*x^2*y^2
a = K(-1)
d = K(0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1)

# Weierstrass form (Sage does not support TwistedEdwards curves)
E = EllipticCurve(K, (
    K(-1/48) * (a^2 + 14*a*d + d^2),
    K(1/864) * (a + d) * (-a^2 + 34*a*d - d^2)
))

def to_weierstrass(a, d, x, y):
    return (
        (5*a + a*y - 5*d*y - d) / (12 - 12*y),
        (a + a*y - d*y - d) / (4*x - 4*x*y)
    )

def to_twistededwards(a, d, u, v):
    y = (5*a - 12*u - d) / (-12*u - a + 5*d)
    x = (a + a*y - d*y - d) / (4*v - 4*v*y)
    return (x, y)

# Full generator (cofactor 8)
G_full = E(*to_weierstrass(a, d,
    K(0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b),
    K(0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa)
))

# Subgroup order and cofactor
l = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
cofactor = 8
E.set_order(l * cofactor)

# Subgroup generator = [8] * G_full
G_sub = cofactor * G_full

print("=" * 70)
print("JubJub golden test vectors (SageMath)")
print("=" * 70)

# ─── Test 1: Curve parameters ───
print("\n[1] Curve parameters")
assert a == -1, f"a = {a}, expected -1"
assert d == 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1
print(f"  a = {int(a)}")
print(f"  d = {hex(int(d))}")
print("  OK")

# ─── Test 2: Cofactor and subgroup order ───
print("\n[2] Subgroup order l")
assert E.order() == l * cofactor
assert cofactor == 8
print(f"  l      = {hex(l)}")
print(f"  cofactor = {cofactor}")
print(f"  #E      = l * 8 = {hex(l * 8)}")
print("  OK")

# ─── Test 3: Subgroup generator [8]·G = identity ───
print("\n[3] [l]·G_sub = identity")
identity = l * G_sub
assert identity.is_zero()
print(f"  [l]·G_sub = O (identity)")
print("  OK")

# ─── Test 4: Montgomery constants ───
print("\n[4] Montgomery constants A, B")
A_mont = 2 * (a + d) / (a - d)
B_mont = 4 / (a - d)
A_int = int(A_mont)
B_int = int(B_mont)
B_small = B_int - p   # B mod p as negative representative
print(f"  A = {A_int}")
print(f"  B = {B_small}  (≡ {hex(B_int)} mod p)")
assert A_int == 40962
assert B_small == -40964
print("  OK")

# ─── Test 5: Subgroup generator coordinates ───
print("\n[5] Subgroup generator G_sub in twisted Edwards")
gx, gy = to_twistededwards(a, d, G_sub.xy()[0], G_sub.xy()[1])
gx_int, gy_int = int(gx), int(gy)
print(f"  G_sub.x = {gx_int}")
print(f"  G_sub.y = {gy_int}")

# Expected from our circuit
EXPECTED_Gx = 28336281903124990867587793011069573392383982287722241916350956173377953689573
EXPECTED_Gy = 39385640392217313770878525135509063452020585410343666726093009378539878503883
assert gx_int == EXPECTED_Gx, f"x mismatch: {gx_int} vs {EXPECTED_Gx}"
assert gy_int == EXPECTED_Gy, f"y mismatch: {gy_int} vs {EXPECTED_Gy}"
print("  matches circuit BASE8")
print("  OK")

# ─── Test 6: Scalar multiplication sk=12345 ───
print("\n[6] Scalar multiplication: pk = [sk]·G, sk = 12345")
sk = 12345
pk = sk * G_sub
pkx, pky = to_twistededwards(a, d, pk.xy()[0], pk.xy()[1])
pkx_int, pky_int = int(pkx), int(pky)
print(f"  pk.x = {pkx_int}")
print(f"  pk.y = {pky_int}")

EXPECTED_pkx = 1914743222257478407163814202117263020858704688091498094144911655627470604937
EXPECTED_pky = 37092003077164576870713451654441773931184159294480200812903353189095900507621
assert pkx_int == EXPECTED_pkx, f"pk.x mismatch"
assert pky_int == EXPECTED_pky, f"pk.y mismatch"
print("  matches gen_test_vectors.py output")
print("  OK")

# ─── Test 7: [2]·G ───
print("\n[7] [2]·G_sub")
p2 = 2 * G_sub
p2x, p2y = to_twistededwards(a, d, p2.xy()[0], p2.xy()[1])
print(f"  [2]·G = ({int(p2x)}, {int(p2y)})")
EXPECTED_2G = (
    28470720865600895264575250048565445848783776096727055802752773414594395577565,
    22436823168302830732060329876357833227584559018655015131868680653136578255473,
)
assert int(p2x) == EXPECTED_2G[0]
assert int(p2y) == EXPECTED_2G[1]
print("  OK")

# ─── Test 8: Point encoding (y + sign of x) ───
print("\n[8] Point encoding (256-bit)")
# Encoding: bits 0-254 = y (little-endian), bit 255 = 1 iff x is odd
assert gx_int % 2 == 1, "G_sub.x should be odd (sign bit = 1)"
print(f"  G_sub sign bit (x odd): {gx_int % 2}")
print(f"  G_sub.y = {hex(gy_int)}")
print("  OK")

# ─── Test 9: EdDSA test vectors (sk=12345, msg=42) ───
print("\n[9] EdDSA test vectors (sk=12345, msg=42)")
print("  (Computed by gen_test_vectors.py, verified here in Sage)")

msg = 42
# Poseidon hash (inline from gen_test_vectors.py output)
r_raw = 20303835410256128589556963184759188245269459717105879955320172142444332706945
r = r_raw % l
R = r * G_sub
Rx, Ry = to_twistededwards(a, d, R.xy()[0], R.xy()[1])
Rx_int, Ry_int = int(Rx), int(Ry)
print(f"  r       = {r}")
print(f"  R.x     = {Rx_int}")
print(f"  R.y     = {Ry_int}")

EXPECTED_Rx = 4384991668369057020734373506491933779920488003914251204678836161699924724732
EXPECTED_Ry = 3806805145546491246983319853986921198780697477686903231224756311112997686965
assert Rx_int == EXPECTED_Rx, f"R.x mismatch: {Rx_int}"
assert Ry_int == EXPECTED_Ry, f"R.y mismatch: {Ry_int}"
print("  R = [r]·G: matches")

k_raw = 5269530059424680588120358094301167190586107624602731153940316545601107115228
k = k_raw % l
S = (r + k * sk) % l
print(f"  k       = {k}")
print(f"  S       = {S}")

EXPECTED_S = 6285811073226377750662634237407797240087679123328323234607522520908505763132
assert S == EXPECTED_S, f"S mismatch: {S}"

# Verify EdDSA: [S]·G == R + [k]·pk
SG = S * G_sub
kpk = k * pk
Rkpk = R + kpk
assert SG == Rkpk, "EdDSA verification failed!"
print(f"  [S]·G  == R + [k]·pk: True")
print("  OK")

print("\n" + "=" * 70)
print("ALL TESTS PASSED")
print("=" * 70)
