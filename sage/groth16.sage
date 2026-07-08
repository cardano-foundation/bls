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

# ---------------------------------------------------------------------------
# Step 1.6 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
# Toxic waste – in a real deployment these must be discarded / destroyed!
# Here we hard-code the same small-prime values used in Rust so outputs match.
print("\n=== Step 1.6: Toxic Waste (Fixed Deterministic Values) ===\n")

tau   = Fq(3)
alpha = Fq(5)
beta  = Fq(7)
gamma = Fq(11)
delta = Fq(13)

print("Field modulus q =", q)
print()
print("tau   =", tau, "(decimal)")
print("alpha =", alpha, "(decimal)")
print("beta  =", beta, "(decimal)")
print("gamma =", gamma, "(decimal)")
print("delta =", delta, "(decimal)")
print()

assert tau != 0,   "tau must be non-zero"
assert alpha != 0, "alpha must be non-zero"
assert beta != 0,  "beta must be non-zero"
assert gamma != 0, "gamma must be non-zero"
assert delta != 0, "delta must be non-zero"

assert tau != alpha, "tau and alpha must be distinct"
assert beta != gamma, "beta and gamma must be distinct"
assert gamma != delta, "gamma and delta must be distinct"

print("✓ All five toxic-waste values are non-zero, distinct, and invertible.")
print("✓ Step 1.6 printouts complete.")

n = L.nrows()   # number of constraints == SRS length bound

# ---------------------------------------------------------------------------
# Step 1.7 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.7: SRS Points ===\n")

print("T(tau) =", T(tau), " (tau =", tau, ", T(x) = x^3 - 3x^2 + 2x)")

n = L.nrows()   # number of constraints == SRS length bound

# SRS1 : g1 * tau^i   (G1)
SRS1 = [ZZ(tau^i) * g1 for i in range(n)]
# SRS2 : g2 * tau^i   (G2)
SRS2 = [ZZ(tau^i) * g2 for i in range(n)]
# SRS3 : g1 * T(tau) * tau^i / delta   (G1)
SRS3 = [ZZ(T(tau) * (tau^i) / delta) * g1 for i in range(n - 1)]

print("\n--- SRS1 : G1 * tau^i ---")
for i in range(n):
    scalar = ZZ(tau^i)
    pt = SRS1[i]
    print("SRS1[{}] scalar = tau^{} = {}".format(i, i, scalar))
    print("         x =", pt[0])
    print("         y =", pt[1])

print("\n--- SRS2 : G2 * tau^i ---")
for i in range(n):
    scalar = ZZ(tau^i)
    pt = SRS2[i]
    print("SRS2[{}] scalar = tau^{} = {}".format(i, i, scalar))
    print("         x =", pt[0])
    print("         y =", pt[1])

print("\n--- SRS3 : G1 * T(tau) * tau^i / delta ---")
base_scalar = ZZ(T(tau) / delta)
print("Base scalar = T(tau)/delta =", base_scalar)
for i in range(n - 1):
    scalar = ZZ(T(tau) * (tau^i) / delta)
    pt = SRS3[i]
    print("SRS3[{}] scalar = T(tau)*tau^{}/delta = {}".format(i, i, scalar))
    print("         x =", pt[0])
    print("         y =", pt[1])

# Sanity checks
assert SRS1[0] == g1, "SRS1[0] must be the G1 generator"
assert SRS2[0] == g2, "SRS2[0] must be the G2 generator"
print("\n✓ SRS sanity checks passed.")
print("✓ Step 1.7 printouts complete.")

# CRS points
alphaG1 = ZZ(alpha) * g1
betaG2  = ZZ(beta)  * g2
gammaG2 = ZZ(gamma) * g2
deltaG2 = ZZ(delta) * g2

# ---------------------------------------------------------------------------
# Step 1.8 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.8: CRS Fixed Points ===\n")

print("--- alpha * G1 ---")
print("scalar = alpha =", alpha)
print("x =", alphaG1[0])
print("y =", alphaG1[1])

print("\n--- beta * G2 ---")
print("scalar = beta =", beta)
print("x =", betaG2[0])
print("y =", betaG2[1])

print("\n--- gamma * G2 ---")
print("scalar = gamma =", gamma)
print("x =", gammaG2[0])
print("y =", gammaG2[1])

print("\n--- delta * G2 ---")
print("scalar = delta =", delta)
print("x =", deltaG2[0])
print("y =", deltaG2[1])

# Sanity: scalar multiplication by a non-zero scalar always yields a valid point
assert alphaG1 != 0 * g1, "alpha*G1 must be non-zero"
assert betaG2  != 0 * g2, "beta*G2 must be non-zero"
assert gammaG2 != 0 * g2, "gamma*G2 must be non-zero"
assert deltaG2 != 0 * g2, "delta*G2 must be non-zero"
print("\n✓ CRS fixed-point sanity checks passed.")
print("✓ Step 1.8 printouts complete.")

# ---------------------------------------------------------------------------
# Step 1.9 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.9: Per-Variable CRS ===\n")
print("tau =", tau, ", alpha =", alpha, ", beta =", beta, ", gamma =", gamma, ", delta =", delta)

# Psi for public inputs (variables 0 and 1, divided by gamma)
Psi_V_G1 = []
print("\n--- Psi_V_G1 (public inputs, divided by gamma) ---")
for i in range(2):
    u_tau = us[i](tau)
    v_tau = vs[i](tau)
    w_tau = ws[i](tau)
    scalar = v_tau * alpha + u_tau * beta + w_tau
    psi_scalar = scalar / gamma
    term = (ZZ(v_tau * alpha) * g1
            + ZZ(u_tau * beta) * g1
            + ZZ(w_tau) * g1)
    pt = ZZ(gamma^(-1)) * term
    Psi_V_G1.append(pt)
    print("Variable {}: u_i(tau) = {}, v_i(tau) = {}, w_i(tau) = {}".format(i, u_tau, v_tau, w_tau))
    print("  combined scalar = v*alpha + u*beta + w =", scalar)
    print("  psi_scalar = combined / gamma =", psi_scalar)
    if pt == 0 * g1:
        print("  point = (point at infinity)")
    else:
        print("  x =", pt[0])
        print("  y =", pt[1])

# Psi for private inputs (variables 2..7, divided by delta)
Psi_P_G1 = []
print("\n--- Psi_P_G1 (private inputs, divided by delta) ---")
for i in range(2, len(a_vec)):
    u_tau = us[i](tau)
    v_tau = vs[i](tau)
    w_tau = ws[i](tau)
    scalar = v_tau * alpha + u_tau * beta + w_tau
    psi_scalar = scalar / delta
    term = (ZZ(v_tau * alpha) * g1
            + ZZ(u_tau * beta) * g1
            + ZZ(w_tau) * g1)
    pt = ZZ(delta^(-1)) * term
    Psi_P_G1.append(pt)
    print("Variable {}: u_i(tau) = {}, v_i(tau) = {}, w_i(tau) = {}".format(i, u_tau, v_tau, w_tau))
    print("  combined scalar = v*alpha + u*beta + w =", scalar)
    print("  psi_scalar = combined / delta =", psi_scalar)
    if pt == 0 * g1:
        print("  point = (point at infinity)")
    else:
        print("  x =", pt[0])
        print("  y =", pt[1])

assert us[0](tau) == 0, "u_0(tau) must be zero"
assert vs[0](tau) == 0, "v_0(tau) must be zero"
assert ws[0](tau) == 0, "w_0(tau) must be zero"
print("\n✓ Step 1.9 sanity checks passed.")
print("✓ Step 1.9 printouts complete.")

print("Trusted setup complete.")

# ---------------------------------------------------------------------------
# 4. Prover
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Step 1.10 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.10: Witness Polynomials l(x), r(x), o(x) ===\n")

a_Fq = vector(Fq, a_vec)

# l(x) = sum a_i * u_i(x),   r(x) = sum a_i * v_i(x),   o(x) = sum a_i * w_i(x)
l = sum(a_Fq[i] * us[i] for i in range(len(a_vec)))
r = sum(a_Fq[i] * vs[i] for i in range(len(a_vec)))
o = sum(a_Fq[i] * ws[i] for i in range(len(a_vec)))

print("Witness a =", a_vec)
print()
print("l(x) =", l)
print("r(x) =", r)
print("o(x) =", o)

# Sanity check: evaluate at constraint points x = 0, 1, 2
xs_check = [Fq(0), Fq(1), Fq(2)]
print("\nEvaluation at constraint points:")
for j, xj in enumerate(xs_check):
    l_val = l(xj)
    r_val = r(xj)
    o_val = o(xj)
    print("  x = {}: l(x) = {}, r(x) = {}, o(x) = {}".format(j, l_val, r_val, o_val))
    assert l_val * r_val == o_val, "l({}) * r({}) != o({})".format(j, j, j)

print("\n✓ l(x)*r(x) == o(x) at all constraint points.")
print("✓ Step 1.10 printouts complete.")

# ---------------------------------------------------------------------------
# Step 1.11: Quotient polynomial h(x)
# ---------------------------------------------------------------------------
print("\n=== Step 1.11: Quotient Polynomial h(x) ===\n")

print("l(x) =", l)
print("r(x) =", r)
print("o(x) =", o)
print("T(x) =", T)

p = l * r - o
print("\np(x) = l(x)*r(x) - o(x) =", p)

assert p % T == 0, "Polynomial division has non-zero remainder!"
h = p // T
print("h(x) = leading_coeff(p) / leading_coeff(T) =", p.leading_coefficient(), "/", T.leading_coefficient(), "=", h)
print("h(x) =", h)

# Verify: p(x) == T(x) * h(x)
assert p == T * h, "p(x) must equal T(x) * h(x)"
print("\n✓ p(x) == T(x) * h(x) — zero remainder confirmed.")
print("✓ Step 1.11 printouts complete.")

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

# ---------------------------------------------------------------------------
# Step 1.12 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.12: Proof Element A ===\n")

print("l(x) =", l)
print("l(tau) =", l(tau), " (tau =", tau, ")")
print("alpha =", alpha)

A = l_tau_G1 + alphaG1
print("\nA = l(tau)*G1 + alpha*G1")
print("  combined scalar = l(tau) + alpha =", l(tau) + alpha)
print("  x =", A[0])
print("  y =", A[1])

print("\n✓ Proof element A computed.")
print("✓ Step 1.12 printouts complete.")

# ---------------------------------------------------------------------------
# Step 1.13 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.13: Proof Element B ===\n")

print("r(x) =", r)
print("r(tau) =", r(tau), " (tau =", tau, ")")
print("beta =", beta)

B = r_tau_G2 + betaG2
print("\nB = r(tau)*G2 + beta*G2")
print("  combined scalar = r(tau) + beta =", r(tau) + beta)
print("  x =", B[0])
print("  y =", B[1])

print("\n✓ Proof element B computed.")
print("✓ Step 1.13 printouts complete.")

# ---------------------------------------------------------------------------
# Step 1.14 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.14: Proof Element C ===\n")

print("--- Psi_P_G1 accumulation ---")
for i in range(len(a_vec) - 2):
    psi_scalar = (vs[i+2](tau) * alpha + us[i+2](tau) * beta + ws[i+2](tau)) / delta
    contrib = a_vec[i+2] * psi_scalar
    print("Variable {}: a_i = {}, psi_scalar = {}, contribution scalar = {}".format(
        i+2, a_vec[i+2], psi_scalar, contrib))

print("\nT(tau) =", T(tau))
print("h(x) =", h)
h_tau_scalar = h(tau) * T(tau) / delta
print("h_tau_G1 scalar = h * T(tau) / delta =", h_tau_scalar)

C = Psi_with_a + h_tau_G1
print("\nC = sum(a_i * Psi_P_G1) + h_tau_G1")
print("  x =", C[0])
print("  y =", C[1])

# Sanity: compute total scalar directly
total_scalar = sum(
    a_vec[i] * (vs[i](tau) * alpha + us[i](tau) * beta + ws[i](tau)) / delta
    for i in range(2, len(a_vec))
) + h_tau_scalar
print("\nTotal combined scalar =", total_scalar)

print("\n✓ Proof element C computed.")
print("✓ Step 1.14 printouts complete.")

print("Proof generated.")

# ---------------------------------------------------------------------------
# Step 1.15 explicit printouts for cross-checking with Rust / arkworks
# ---------------------------------------------------------------------------
print("\n=== Step 1.15: Public-Input Commitment V ===\n")

# Public-input commitment V = sum_{i=0}^{1} a_i * Psi_V_G1[i]
print("--- Psi_V_G1 accumulation ---")
for i in range(2):
    psi_scalar = (vs[i](tau) * alpha + us[i](tau) * beta + ws[i](tau)) / gamma
    contrib = a_vec[i] * psi_scalar
    print("Variable {}: a_i = {}, psi_scalar = {}, contribution scalar = {}".format(
        i, a_vec[i], psi_scalar, contrib))

V = 0 * Psi_V_G1[0]
for i in range(2):
    V = V + ZZ(a_vec[i]) * Psi_V_G1[i]

print("\nV = sum(a_i * Psi_V_G1)")
print("  x =", V[0])
print("  y =", V[1])

# Sanity: compute total scalar directly
total_scalar = sum(
    a_vec[i] * (vs[i](tau) * alpha + us[i](tau) * beta + ws[i](tau)) / gamma
    for i in range(2)
)
print("\nTotal combined scalar =", total_scalar)

print("\n✓ Public-input commitment V computed.")
print("✓ Step 1.15 printouts complete.")

# ---------------------------------------------------------------------------
# 5. Verifier
# ---------------------------------------------------------------------------

# Groth16 pairing check:
#   e(A, B) == e(alpha*G1, beta*G2) * e(C, delta*G2) * e(V, gamma*G2)
lhs = atePairing(A, B)
rhs = (atePairing(alphaG1, betaG2)
       * atePairing(C, deltaG2)
       * atePairing(V, gammaG2))

assert lhs == rhs, "Pairing check FAILED"
print("Pairing check PASSED.  The proof is valid.")
