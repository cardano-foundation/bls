#!/usr/bin/env python3
"""
Compute JubJub Pedersen base points for circomlib-style Pedersen hash.

JubJub is a twisted Edwards curve over BLS12-381's scalar field:
  -u^2 + v^2 = 1 + d*u^2*v^2

The Pedersen hash uses 10 base points, each being [8 * 2^(200*i)] * FULL_GENERATOR.
BASE[0] = SUBGROUP_GENERATOR = [8] * FULL_GENERATOR
BASE[i] = [2^200] * BASE[i-1]  for i >= 1
"""

# BLS12-381 scalar field prime
P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# JubJub curve parameters
# -u^2 + v^2 = 1 + d*u^2*v^2
D = 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1

# Full generator (order 8*l)
FULL_GEN_U = 0x62edcbb8bf3787c88b0f03ddd60a8187caf55d1b29bf81afe4b3d35df1a7adfe
FULL_GEN_V = 11

def mod_inv(a, p):
    """Modular inverse using Fermat's little theorem."""
    return pow(a, p - 2, p)

def ed_add(p1, p2):
    """Twisted Edwards addition: -u^2 + v^2 = 1 + d*u^2*v^2"""
    u1, v1 = p1
    u2, v2 = p2
    beta = u1 * v2 % P
    gamma = v1 * u2 % P
    delta = (-u1 + v1) * (u2 + v2) % P
    tau = beta * gamma % P
    u3 = (beta + gamma) * mod_inv(1 + D * tau, P) % P
    v3 = (delta + (-1) * beta - gamma) * mod_inv(1 - D * tau, P) % P
    return (u3, v3)

def ed_double(pt):
    return ed_add(pt, pt)

def ed_mul(pt, n):
    """Scalar multiplication via double-and-add."""
    result = None  # identity
    addend = pt
    while n > 0:
        if n & 1:
            if result is None:
                result = addend
            else:
                result = ed_add(result, addend)
        addend = ed_double(addend)
        n >>= 1
    return result

def mul_by_cofactor(pt):
    """Multiply by cofactor 8 (three doublings)."""
    pt = ed_double(pt)
    pt = ed_double(pt)
    pt = ed_double(pt)
    return pt

# Compute subgroup generator
full_gen = (FULL_GEN_U, FULL_GEN_V)
subgroup_gen = mul_by_cofactor(full_gen)

print(f"FULL_GENERATOR = ({hex(FULL_GEN_U)}, {FULL_GEN_V})")
print(f"SUBGROUP_GENERATOR = ({hex(subgroup_gen[0])}, {hex(subgroup_gen[1])})")
print()

# Compute Pedersen base points: BASE[i] = [8 * 2^(200*i)] * FULL_GENERATOR
# BASE[0] = SUBGROUP_GENERATOR
# BASE[i] = [2^200] * BASE[i-1]

# Precompute [2^200] for repeated multiplication
SHIFT = 2**200

bases = []
current = subgroup_gen  # BASE[0] = [8] * FULL_GEN = SUBGROUP_GENERATOR
bases.append(current)

for i in range(1, 10):
    current = ed_mul(current, SHIFT)
    bases.append(current)

print("JubJub Pedersen BASE[10][2] (for circomlib pedersen.circom port):")
print("var BASE[10][2] = [")
for i, (u, v) in enumerate(bases):
    comma = "," if i < 9 else ""
    print(f"    [{u},{v}]{comma}")
print("];")
print()

# Also output the S < l CompConstant threshold
# CompConstant checks if a 256-bit number is < l
# The threshold constant is the first 8 bits of l (the comparison is done
# via a chain of inequalities on the bit decomposition)
l = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
print(f"JubJub subgroup order l = {hex(l)}")
print(f"l bit length = {l.bit_length()}")

# For CompConstant, we need the constant that compares the top bits
# circomlib's CompConstant checks if input < constant
# For S < l, we need CompConstant(l) which is l itself represented as a constant
# The actual circomlib CompConstant template works differently - it checks
# if the input is less than a constant by comparing bit by bit from MSB
print(f"\nFor S < l check, CompConstant needs the subgroup order.")
print(f"This will be handled in the EdDSA template directly.")
