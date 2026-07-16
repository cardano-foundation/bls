/*
 * JubJub point compression/decompression — matches zkcrypto/jubjub encoding.
 *
 * Encoding (256 bits total):
 *   Bits 0-254: v-coordinate (y) in little-endian, 255 bits
 *   Bit 255:    sign of u-coordinate (1 iff u is odd)
 *
 * Curve: -u^2 + v^2 = 1 + d*u^2*v^2  (a = -1)
 * Field: BLS12-381 scalar field (255-bit prime)
 *
 * Decompression requires the x-coordinate as an additional input because
 * Circom `function` (including sqrt) is evaluated at constraint generation
 * time, NOT witness time. The prover computes x off-circuit (trivial with
 * Tonelli-Shanks) and provides it as a private input. The circuit verifies
 * correctness via the curve equation + sign bit.
 *
 * License: MIT (clean reimplementation).
 */
pragma circom 2.0.0;

include "bitify.circom";
include "jubjub_primitives.circom";


/*
 * Decompress: 256-bit encoding -> JubJub point (x, y).
 *
 * Inputs:
 *   in[256] — 256-bit encoding (bits 0-254 = y, bit 255 = sign of x)
 *   x       — x-coordinate (private input, computed by prover off-circuit)
 *
 * Outputs:
 *   out[0] = x
 *   out[1] = y
 *
 * Verification:
 *   1. y matches the bit decomposition
 *   2. (x, y) is on the curve: -x^2 + y^2 = 1 + d*x^2*y^2
 *   3. LSB(x) == in[255] (sign bit matches)
 */
template Bits2Point_Strict_JubJub() {
    signal input in[256];
    signal input x;
    signal output out[2];

    var i;

    component b2nY = Bits2Num(255);
    for (i = 0; i < 255; i++) {
        b2nY.in[i] <== in[i];
    }
    out[1] <== b2nY.out;

    var d = 19257038036680949359750312669786877991949435402254120286184196891950884077233;

    out[0] <== x;

    // Verify point is on curve: -x^2 + y^2 = 1 + d*x^2*y^2
    signal y2;
    y2 <== out[1] * out[1];

    signal x2;
    x2 <== out[0] * out[0];

    // Curve equation: x^2 * (d * y^2 + 1) == y^2 - 1
    signal check;
    check <== x2 * (d * y2 + 1) - y2 + 1;
    check === 0;

    // Verify sign bit: LSB(x) == in[255]
    component n2bX = Num2Bits(255);
    n2bX.in <== out[0];
    n2bX.out[0] === in[255];
}


/*
 * Compress: JubJub point (x, y) -> 256-bit encoding.
 *
 * Layout: bits 0-254 = v (y-coordinate), bit 255 = sign of u (x is odd).
 */
template Point2Bits_Strict_JubJub() {
    signal input in[2];
    signal output out[256];

    var i;

    component n2bX = Num2Bits(255);
    n2bX.in <== in[0];
    component n2bY = Num2Bits(255);
    n2bY.in <== in[1];

    for (i = 0; i < 255; i++) {
        out[i] <== n2bY.out[i];
    }
    out[255] <== n2bX.out[0];
}
