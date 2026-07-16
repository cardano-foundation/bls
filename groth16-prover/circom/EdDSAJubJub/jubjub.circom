/*
 * JubJub high-level templates — public key derivation.
 * Point primitives are in jubjub_primitives.circom (no circular includes).
 *
 * License: MIT (clean reimplementation with different constants).
 */
pragma circom 2.0.0;

include "bitify.circom";
include "jubjub_primitives.circom";
include "escalarmulfix_jubjub.circom";

template JubJubPbk() {
    signal input  in;
    signal output Ax;
    signal output Ay;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    component pvkBits = Num2Bits(253);
    pvkBits.in <== in;

    component mulFix = EscalarMulFixJubJub(253, BASE8);

    var i;
    for (i=0; i<253; i++) {
        mulFix.e[i] <== pvkBits.out[i];
    }
    Ax  <== mulFix.out[0];
    Ay  <== mulFix.out[1];
}
