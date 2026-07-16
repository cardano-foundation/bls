#!/usr/bin/env sage
"""
JubJub golden test vectors over BLS12-381 scalar field.

Independent verification of circom EdDSA-JubJub circuit parameters.
Works directly on the twisted Edwards curve (no Weierstrass conversion needed).

Curve: -x^2 + y^2 = 1 + d*x^2*y^2  over GF(p)
  p = 0x73eda753...ffffffff00000001  (BLS12-381 scalar field)
  a = -1
  d = 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1

Run:
    sage jubjub.sage
"""

# ─── Field and curve parameters ───

p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
K = GF(p)
a_ed = K(-1)
d_ed = K(0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1)

l = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7  # subgroup order
cofactor = 8

# Twisted Edwards point addition: matches JubJubAdd in jubjub_primitives.circom
def ed_add(P, Q):
    if is_identity(P):
        return Q
    if is_identity(Q):
        return P
    x1, y1 = P
    x2, y2 = Q
    beta  = x1 * y2
    gamma = y1 * x2
    tau   = beta * gamma
    x3 = (beta + gamma) / (1 + d_ed * tau)
    y3 = (x1 * x2 + y1 * y2) / (1 - d_ed * tau)
    return (x3, y3)

def ed_double(P):
    return ed_add(P, P)

def ed_mul(k, P):
    """Double-and-add scalar multiplication."""
    R = IDENTITY  # identity (0, 1)
    Q = P
    while k > 0:
        if k & 1:
            R = ed_add(R, Q)
        Q = ed_double(Q)
        k >>= 1
    return R

# ─── Known points ───

# Subgroup generator (zkcrypto/jubjub SUBGROUP_GENERATOR = [8]·FULL_GENERATOR)
Gx = K(28336281903124990867587793011069573392383982287722241916350956173377953689573)
Gy = K(39385640392217313770878525135509063452020585410343666726093009378539878503883)
G = (Gx, Gy)

# Identity (neutral element) for twisted Edwards: (0, 1)
IDENTITY = (K(0), K(1))

def is_identity(P):
    return P[0] == 0 and P[1] == 1

def ed_eq(P, Q):
    return P[0] == Q[0] and P[1] == Q[1]

def pt(P):
    """Pretty-print a point."""
    if P is None:
        return "O (identity)"
    return f"({int(P[0])}, {int(P[1])})"

print("=" * 70)
print("JubJub golden test vectors (SageMath)")
print("=" * 70)

# ─── Test 1: Curve parameters ───
print("\n[1] Curve parameters")
assert int(a_ed) == p - 1, f"a = {int(a_ed)}, expected p-1"
assert int(d_ed) == 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1
print(f"  p = {hex(p)}")
print(f"  a = {int(a_ed)}  (≡ -1 mod p)")
print(f"  d = {hex(int(d_ed))}")
print("  OK")

# ─── Test 2: Identity element ───
print("\n[2] Identity element (0, 1)")
lhs = (-a_ed * 0 + 1 * 1)   # -x^2 + y^2
rhs = 1 + d_ed * 0 * 0 * 1 * 1   # 1 + d*x^2*y^2
assert lhs == rhs
print("  (0, 1) is on curve: OK")
print(f"  [1]·(0,1) = {pt(ed_mul(1, (K(0), K(1))))}")
# (0,1) is the identity for twisted Edwards
assert ed_eq(ed_mul(1, IDENTITY), IDENTITY)
print("  OK")

# ─── Test 3: Generator is on curve ───
print("\n[3] Generator on curve")
lhs = (-Gx^2 + Gy^2)
rhs = 1 + d_ed * Gx^2 * Gy^2
assert lhs == rhs, f"Not on curve: LHS={int(lhs)}, RHS={int(rhs)}"
print(f"  G = {pt(G)}")
print("  -x^2 + y^2 = 1 + d*x^2*y^2  ✓")
print("  OK")

# ─── Test 4: Subgroup order: [l]·G = identity ───
print("\n[4] [l]·G = identity")
result = ed_mul(l, G)
assert is_identity(result), f"[l]·G = {pt(result)}, expected identity"
print(f"  [l]·G = O")
print("  OK")

# ─── Test 5: Montgomery constants A, B ───
print("\n[5] Montgomery constants")
A_mont = int(2 * (a_ed + d_ed) / (a_ed - d_ed))
B_mont = int(4 / (a_ed - d_ed))
B_small = B_mont - p
print(f"  A = {A_mont}")
print(f"  B = {B_small}  (≡ {hex(B_mont)} mod p)")
assert A_mont == 40962
assert B_small == -40964
print("  OK")

# ─── Test 6: [2]·G ───
print("\n[6] [2]·G")
p2 = ed_mul(2, G)
print(f"  [2]·G = {pt(p2)}")
EXPECTED_2G = (
    28470720865600895264575250048565445848783776096727055802752773414594395577565,
    22436823168302830732060329876357833227584559018655015131868680653136578255473,
)
assert int(p2[0]) == EXPECTED_2G[0], f"x: {int(p2[0])}"
assert int(p2[1]) == EXPECTED_2G[1], f"y: {int(p2[1])}"
print("  OK")

# ─── Test 7: [8]·G (cofactor) ───
print("\n[7] [8]·G (cofactor application)")
p8 = ed_mul(8, G)
print(f"  [8]·G = {pt(p8)}")
# [8]·G should be a non-identity point (G is already in the subgroup)
assert not is_identity(p8)
print("  OK")

# ─── Test 8: Scalar multiplication sk=12345 ───
print("\n[8] pk = [sk]·G, sk = 12345")
sk = 12345
pk = ed_mul(sk, G)
print(f"  pk = {pt(pk)}")
EXPECTED_pk = (
    1914743222257478407163814202117263020858704688091498094144911655627470604937,
    37092003077164576870713451654441773931184159294480200812903353189095900507621,
)
assert int(pk[0]) == EXPECTED_pk[0], f"pk.x: {int(pk[0])}"
assert int(pk[1]) == EXPECTED_pk[1], f"pk.y: {int(pk[1])}"
print("  matches gen_test_vectors.py")
print("  OK")

# ─── Test 9: Point encoding ───
print("\n[9] Point encoding (256-bit)")
# bits 0-254 = y (little-endian), bit 255 = 1 iff x is odd
sign_bit = int(Gx) % 2
print(f"  G.x odd (sign bit) = {sign_bit}")
assert sign_bit == 1, "G.x should be odd"
print(f"  G.y = {hex(int(Gy))}")
print("  OK")

# ─── Test 10: EdDSA test vectors (sk=12345, msg=42) ───
print("\n[10] EdDSA test vectors (sk=12345, msg=42)")

msg = 42
# Poseidon hash outputs (from gen_test_vectors.py — PoseidonBLS12_381)
r_raw = 20303835410256128589556963184759188245269459717105879955320172142444332706945
r = r_raw % l
R = ed_mul(r, G)
print(f"  r     = {r}")
print(f"  R     = {pt(R)}")

EXPECTED_R = (
    4384991668369057020734373506491933779920488003914251204678836161699924724732,
    3806805145546491246983319853986921198780697477686903231224756311112997686965,
)
assert int(R[0]) == EXPECTED_R[0], f"R.x: {int(R[0])}"
assert int(R[1]) == EXPECTED_R[1], f"R.y: {int(R[1])}"
print("  R = [r]·G  ✓")

k_raw = 5269530059424680588120358094301167190586107624602731153940316545601107115228
k = k_raw % l
S = (r + k * sk) % l
print(f"  k     = {k}")
print(f"  S     = {S}")

EXPECTED_S = 6285811073226377750662634237407797240087679123328323234607522520908505763132
assert S == EXPECTED_S, f"S: {S}"

# EdDSA verification: [S]·G == R + [k]·pk
SG = ed_mul(S, G)
kpk = ed_mul(k, pk)
Rkpk = ed_add(R, kpk)
assert ed_eq(SG, Rkpk), "EdDSA verification failed!"
print(f"  [S]·G == R + [k]·pk  ✓")
print("  OK")

print("\n" + "=" * 70)
print("ALL TESTS PASSED")
print("=" * 70)
