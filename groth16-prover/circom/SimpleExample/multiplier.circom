pragma circom 2.0.0;

// SimpleExample: 3-gate multiplication chain
//
//   x5 = x1 * x2
//   x6 = x3 * x4
//   a  = x5 * x6
//
// Witness ordering: [1, a, x1, x2, x3, x4, x5, x6]

template Multiplier3() {
    signal input x1;
    signal input x2;
    signal input x3;
    signal input x4;

    signal x5;
    signal x6;
    signal output a;

    x5 <== x1 * x2;
    x6 <== x3 * x4;
    a  <== x5 * x6;
}

component main = Multiplier3();
