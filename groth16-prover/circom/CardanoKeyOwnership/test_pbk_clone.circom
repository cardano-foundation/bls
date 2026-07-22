pragma circom 2.0.0;

include "bitify.circom";
include "../EdDSAJubJub/jubjub.circom";
include "../EdDSAJubJub/scalarmul_jubjub.circom";

template TestPbk() {
    signal input sk;
    signal input expected_x;
    signal input expected_y;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    component skBits = Num2Bits(254);
    skBits.in <== sk;

    component pkMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        pkMul.e[i] <== skBits.out[i];
    }

    pkMul.out[0] === expected_x;
    pkMul.out[1] === expected_y;
}

component main {public [expected_x, expected_y]} = TestPbk();
