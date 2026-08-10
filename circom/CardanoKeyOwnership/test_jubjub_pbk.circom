pragma circom 2.0.0;

include "../EdDSAJubJub/jubjub.circom";

template TestJubJubPbk() {
    signal input sk;
    signal input expected_x;
    signal input expected_y;

    component derive = JubJubPbk();
    derive.in <== sk;

    expected_x === derive.Ax;
    expected_y === derive.Ay;
}

component main {public [expected_x, expected_y]} = TestJubJubPbk();
