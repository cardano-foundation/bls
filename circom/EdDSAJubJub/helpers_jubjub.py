#!/usr/bin/env python3
"""
JubJub decompression witness generator.

Computes the x-coordinate from (y, sign) for the Bits2Point_Strict_JubJub circuit.
The circuit verifies the result, so this script only needs to be correct (not trusted).

Usage:
    python3 gen_witness.py <y> <sign> <encoding_hex>
    python3 gen_witness.py --from-point <x> <y>

Examples:
    python3 gen_witness.py 1 0 ""
    python3 gen_witness.py 39385640392217313770878525135509063452020585410343666726093009378539878503883 1 ""
"""
import json
import sys

# BLS12-381 scalar field prime
p = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# JubJub curve parameters (twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2)
d = 19257038036680949359750312669786877991949435402254120286184196891950884077233
a = p - 1  # -1 mod p

# JubJub subgroup generator
SUBGROUP_GENERATOR = (
    28336281903124990867587793011069573392383982287722241916350956173377953689573,
    39385640392217313770878525135509063452020585410343666726093009378539878503883,
)


def ed_add(x1, y1, x2, y2):
    """Twisted Edwards point addition matching circomlib JubJubAdd formula.
    Formula: beta = x1*y2, gamma = y1*x2, tau = beta*gamma,
             x3 = (beta+gamma)/(1+d*tau), y3 = (x1*x2+y1*y2)/(1-d*tau)
    """
    beta = (x1 * y2) % p
    gamma = (y1 * x2) % p
    tau = (beta * gamma) % p
    x3 = ((beta + gamma) * pow((1 + d * tau) % p, -1, p)) % p
    y3 = (((x1 * x2 + y1 * y2) % p) * pow((1 - d * tau) % p, -1, p)) % p
    return x3, y3


def ed_mul(k, x, y):
    """Double-and-add scalar multiplication."""
    rx, ry = x, y
    kbits = bin(k)[3:]  # skip '0b1' (MSB is always 1)
    for b in kbits:
        rx, ry = ed_add(rx, ry, rx, ry)
        if b == '1':
            rx, ry = ed_add(rx, ry, x, y)
    return rx, ry


def tonelli_shanks(n):
    """Compute sqrt(n) mod p using Tonelli-Shanks. Returns None if no sqrt exists."""
    if n == 0:
        return 0
    # Check if n is a quadratic residue
    if pow(n, (p - 1) // 2, p) != 1:
        return None

    # Factor p - 1 = Q * 2^S
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # Find a non-residue
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)

    while True:
        if t == 1:
            return R
        # Find least i such that t^(2^i) = 1
        i = 0
        tt = t
        while tt != 1:
            tt = (tt * tt) % p
            i += 1
            if i == M:
                return None

        b = pow(c, 1 << (M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p


def decompress_y(y, sign):
    """Given y-coordinate and sign bit, compute x-coordinate on JubJub."""
    y2 = (y * y) % p
    # Curve: -x^2 + y^2 = 1 + d*x^2*y^2
    # => x^2 * (d*y^2 + 1) = y^2 - 1
    # => x^2 = (y^2 - 1) / (d*y^2 + 1)
    num = (y2 - 1) % p
    denom = (d * y2 + 1) % p
    x2 = (num * pow(denom, -1, p)) % p

    x = tonelli_shanks(x2)
    if x is None:
        raise ValueError(f"No square root exists for y={y}")

    # Apply sign: 1 iff x is odd
    if sign == 1:
        if x % 2 == 0:
            x = p - x
    else:
        if x % 2 == 1:
            x = p - x

    # Verify
    lhs = (-x * x + y * y) % p
    rhs = (1 + d * x * x * y * y) % p
    assert lhs == rhs, f"Point not on curve: LHS={lhs}, RHS={rhs}"
    assert (x % 2 == 1) == (sign == 1), f"Sign mismatch: x%2={x%2}, sign={sign}"

    return x


def point_to_encoding(x, y):
    """Compress a JubJub point to 256-bit encoding."""
    encoding = []
    # Bits 0-254: y in little-endian
    for i in range(255):
        encoding.append((y >> i) & 1)
    # Bit 255: sign of x (1 iff odd)
    encoding.append(x % 2)
    return encoding


def encoding_to_point(encoding):
    """Decode 256-bit encoding to (y, sign)."""
    y = 0
    for i in range(255):
        y += encoding[i] << i
    sign = encoding[255]
    return y, sign


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--from-point":
        x = int(sys.argv[2])
        y = int(sys.argv[3])
        encoding = point_to_encoding(x, y)
        print(json.dumps({"x": str(x), "y": str(y), "encoding": encoding}))
    else:
        y = int(sys.argv[1])
        sign = int(sys.argv[2])
        x = decompress_y(y, sign)
        encoding = point_to_encoding(x, y)
        print(json.dumps({
            "x": str(x),
            "y": str(y),
            "sign": sign,
            "encoding": encoding
        }))
