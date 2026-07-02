# groth16.sage
# ---------------------------------------------------------------------------
# Minimal Groth16 example over BLS12-381 using pure Sage.
#
# This script mirrors the logic from Coh22HW10.ipynb:
#   Circuit:
#     x1 * x2 == x5
#     x3 * x4 == x6
#     x5 * x6 == a
#
# It reuses BLS12-381 curve parameters, generators, and the ate pairing from
# bls13-381.sage (kept in the same directory).
# ---------------------------------------------------------------------------

load("bls13-381.sage")

import random

# q  = order of G1 / G2 (subgroup order), defined in bls13-381.sage
# p  = base field order
# g1 = G1 generator (point on E1)
# g2 = G2 generator (point on E2)
# atePairing(p1, p2) computes e(p1, p2) with p1 in G1 (E1) and p2 in G2 (E2)

# ---------------------------------------------------------------------------
# 1. R1CS
# ---------------------------------------------------------------------------

# Witness vector: [1, a, x1, x2, x3, x4, x5, x6]
a_vec = [1, 48, 2, 2, 3, 4, 4, 12]

L = matrix([[0,0,1,0,0,0,0,0],
            [0,0,0,0,1,0,0,0],
            [0,0,0,0,0,0,1,0]])

R = matrix([[0,0,0,1,0,0,0,0],
            [0,0,0,0,0,1,0,0],
            [0,0,0,0,0,0,0,1]])

O = matrix([[0,0,0,0,0,0,1,0],
            [0,0,0,0,0,0,0,1],
            [0,1,0,0,0,0,0,0]])

# Verify that (L*a) .* (R*a) == O*a
lhs = (L * vector(a_vec)).pairwise_product(R * vector(a_vec))
rhs = O * vector(a_vec)
assert lhs == rhs, "R1CS relation does not hold"

# ---------------------------------------------------------------------------
# Step 1.1 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("=== Step 1.1: R1CS Matrices and Witness ===\n")
print("Witness a =", a_vec)
print("\nL matrix:")
for row in L.rows():
    print(" ", list(row))
print("\nR matrix:")
for row in R.rows():
    print(" ", list(row))
print("\nO matrix:")
for row in O.rows():
    print(" ", list(row))

la = L * vector(a_vec)
ra = R * vector(a_vec)
oa = O * vector(a_vec)
print("\nL · a =", list(la))
print("R · a =", list(ra))
print("O · a =", list(oa))

print("\nElement-wise (L·a) * (R·a):")
for i in range(len(la)):
    constraint_prod = la[i] * ra[i]
    print("  constraint {}: {} * {} = {} (O·a = {})".format(i, la[i], ra[i], constraint_prod, oa[i]))

print("\n✓ R1CS relation verified.")

# ---------------------------------------------------------------------------
# 2. Finite field & polynomial ring over the BLS12-381 scalar field F_q
# ---------------------------------------------------------------------------

Fq = GF(q)

# ---------------------------------------------------------------------------
# Step 1.2 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.2: BLS12-381 Scalar Field F_q ===\n")
print("Field modulus q =", q)

a = Fq(5)
b = Fq(7)
print("\nSample operations:")
print("  a =", a)
print("  b =", b)
print("  a + b =", a + b)
print("  a * b =", a * b)
print("  a^-1  =", a^(-1))

c = Fq(123456789)
d = Fq(987654321)
print("\nLarger sample operations:")
print("  c =", c)
print("  d =", d)
print("  c + d =", c + d)
print("  c * d =", c * d)
print("  c^-1  =", c^(-1))

print("\n✓ Field arithmetic cross-check values printed.")

PR.<x> = PolynomialRing(Fq)

xs = [Fq(0), Fq(1), Fq(2)]   # one evaluation point per constraint

def interpolate(col):
    """Lagrange interpolation of a column over xs."""
    points = list(zip(xs, [Fq(v) for v in col.list()]))
    return PR.lagrange_polynomial(points)

# Interpolate each column of L, R, O -> u_i(x), v_i(x), w_i(x)
us = [interpolate(L[:, i]) for i in range(L.ncols())]
vs = [interpolate(R[:, i]) for i in range(R.ncols())]
ws = [interpolate(O[:, i]) for i in range(O.ncols())]

# ---------------------------------------------------------------------------
# Step 1.3 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.3: QAP Polynomial Interpolation ===\n")

for i in range(len(us)):
    print("u_{} coeffs =".format(i), list(us[i].coefficients(sparse=False)))
print()
for i in range(len(vs)):
    print("v_{} coeffs =".format(i), list(vs[i].coefficients(sparse=False)))
print()
for i in range(len(ws)):
    print("w_{} coeffs =".format(i), list(ws[i].coefficients(sparse=False)))

print("\n✓ Step 1.3 coefficient printouts complete.")

# ---------------------------------------------------------------------------
# Step 1.5 explicit verification: QAP polynomials reproduce R1CS columns
# ---------------------------------------------------------------------------
print("\n=== Step 1.5: QAP Verification at Constraint Points ===\n")
for j in range(len(xs)):
    xj = xs[j]
    for i in range(L.ncols()):
        assert us[i](xj) == Fq(L[j, i]), "u_{}({}) mismatch".format(i, j)
        assert vs[i](xj) == Fq(R[j, i]), "v_{}({}) mismatch".format(i, j)
        assert ws[i](xj) == Fq(O[j, i]), "w_{}({}) mismatch".format(i, j)
    print("  x = {}: all u_i, v_i, w_i match L, R, O columns".format(j))

print("\n✓ All 24 evaluations (8 variables × 3 points) pass.")

# Target polynomial T(x) = (x-0)(x-1)(x-2)
T = prod(x - xi for xi in xs)

# ---------------------------------------------------------------------------
# Step 1.4 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.4: Target Polynomial T(x) ===\n")
print("T coeffs =", list(T.coefficients(sparse=False)))

print("\nT(x) vanishes at all constraint points:")
for j in range(len(xs)):
    val = T(xs[j])
    print("  T({}) = {}".format(j, val))
    assert val == 0, "T({}) should be zero".format(j)

print("\n✓ Target polynomial verified.")

# ---------------------------------------------------------------------------
# 3. Trusted Setup
# ---------------------------------------------------------------------------

# Toxic waste – in a real deployment these must be discarded / destroyed!
tau   = Fq(random.randint(1, int(q) - 1))
alpha = Fq(random.randint(1, int(q) - 1))
beta  = Fq(random.randint(1, int(q) - 1))
gamma = Fq(random.randint(1, int(q) - 1))
delta = Fq(random.randint(1, int(q) - 1))

n = L.nrows()   # number of constraints == SRS length bound

# SRS1 : g1 * tau^i   (G1)
SRS1 = [ZZ(tau^i) * g1 for i in range(n)]
# SRS2 : g2 * tau^i   (G2)
SRS2 = [ZZ(tau^i) * g2 for i in range(n)]
# SRS3 : g1 * T(tau) * tau^i / delta   (G1)
SRS3 = [ZZ(T(tau) * (tau^i) / delta) * g1 for i in range(n - 1)]

# CRS points
alphaG1 = ZZ(alpha) * g1
betaG2  = ZZ(beta)  * g2
gammaG2 = ZZ(gamma) * g2
deltaG2 = ZZ(delta) * g2

# Psi for public inputs (variables 0 and 1, divided by gamma)
Psi_V_G1 = []
for i in range(2):
    term = (ZZ(vs[i](tau) * alpha) * g1
            + ZZ(us[i](tau) * beta) * g1
            + ZZ(ws[i](tau)) * g1)
    Psi_V_G1.append(ZZ(gamma^(-1)) * term)

# Psi for private inputs (variables 2..7, divided by delta)
Psi_P_G1 = []
for i in range(2, len(a_vec)):
    term = (ZZ(vs[i](tau) * alpha) * g1
            + ZZ(us[i](tau) * beta) * g1
            + ZZ(ws[i](tau)) * g1)
    Psi_P_G1.append(ZZ(delta^(-1)) * term)

print("Trusted setup complete.")

# ---------------------------------------------------------------------------
# 4. Prover
# ---------------------------------------------------------------------------

a_Fq = vector(Fq, a_vec)

# l(x) = sum a_i * u_i(x),   r(x) = sum a_i * v_i(x),   o(x) = sum a_i * w_i(x)
l = sum(a_Fq[i] * us[i] for i in range(len(a_vec)))
r = sum(a_Fq[i] * vs[i] for i in range(len(a_vec)))
o = sum(a_Fq[i] * ws[i] for i in range(len(a_vec)))

# Quotient polynomial h(x) = (l(x)*r(x) - o(x)) / T(x)
assert (l * r - o) % T == 0, "Polynomial division has non-zero remainder!"
h = (l * r - o) // T

print("l(x) =", l)
print("r(x) =", r)
print("o(x) =", o)
print("h(x) =", h)

def eval_in_exponent(poly_coeffs, srs):
    """
    Evaluate a polynomial in the exponent using the given SRS.
    poly_coeffs : list of coefficients [c0, c1, ...] (constant term first)
    srs         : list of elliptic-curve points [P0, P1, ...]
    Returns     : sum_i  ci * Pi
    """
    result = 0 * srs[0]          # identity element of the curve
    for i, c in enumerate(poly_coeffs):
        result = result + ZZ(c) * srs[i]
    return result

# Evaluate l(tau), r(tau), h(tau) in the exponent via the SRS
l_tau_G1 = eval_in_exponent(l.coefficients(sparse=False), SRS1)
r_tau_G2 = eval_in_exponent(r.coefficients(sparse=False), SRS2)
h_tau_G1 = eval_in_exponent(h.coefficients(sparse=False), SRS3)

# Private-witness accumulation: sum_{i=2}^{7} a_i * Psi_P_G1[i-2]
Psi_with_a = 0 * Psi_P_G1[0]
for i in range(len(a_vec) - 2):
    Psi_with_a = Psi_with_a + ZZ(a_vec[i + 2]) * Psi_P_G1[i]

# Assemble proof (A in G1, B in G2, C in G1)
A = l_tau_G1 + alphaG1
B = r_tau_G2 + betaG2
C = Psi_with_a + h_tau_G1

print("Proof generated.")

# ---------------------------------------------------------------------------
# 5. Verifier
# ---------------------------------------------------------------------------

# Public-input commitment V = sum_{i=0}^{1} a_i * Psi_V_G1[i]
V = 0 * Psi_V_G1[0]
for i in range(2):
    V = V + ZZ(a_vec[i]) * Psi_V_G1[i]

# Groth16 pairing check:
#   e(A, B) == e(alpha*G1, beta*G2) * e(C, delta*G2) * e(V, gamma*G2)
lhs = atePairing(A, B)
rhs = (atePairing(alphaG1, betaG2)
       * atePairing(C, deltaG2)
       * atePairing(V, gammaG2))

assert lhs == rhs, "Pairing check FAILED"
print("Pairing check PASSED.  The proof is valid.")
