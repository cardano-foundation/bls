/*
 * Test JubJub variable-base scalar multiplication.
 * Verifies that [n]·P computed by the circuit matches the expected result.
 */
pragma circom 2.0.0;

include "scalarmul_jubjub.circom";

template TestScalarMul() {
    signal input n;
    signal input px;
    signal input py;
    signal output ox;
    signal output oy;

    // Convert scalar to 253-bit binary
    component n2b = Num2Bits(253);
    n2b.in <== n;

    component mul = EscalarMulAnyJubJub(253);
    for (var i = 0; i < 253; i++) {
        mul.e[i] <== n2b.out[i];
    }
    mul.p[0] <== px;
    mul.p[1] <== py;

    ox <== mul.out[0];
    oy <== mul.out[1];
}

component main = TestScalarMul();
