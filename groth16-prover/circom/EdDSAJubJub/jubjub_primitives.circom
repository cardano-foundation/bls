/*
 * JubJub point arithmetic primitives — no external includes, no circular dependencies.
 * Used by both jubjub.circom (high-level templates) and
 * escalarmulfix_jubjub.circom (scalar multiplication).
 *
 * JubJub (Zcash/zkcrypto): twisted Edwards curve over BLS12-381 scalar field
 *   -u^2 + v^2 = 1 + d*u^2*v^2
 *
 * Parameters:
 *   a = -1
 *   d = 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1
 */
pragma circom 2.0.0;

template JubJubAdd() {
    signal input x1;
    signal input y1;
    signal input x2;
    signal input y2;
    signal output xout;
    signal output yout;

    signal beta;
    signal gamma;
    signal delta;
    signal tau;

    var a = -1;
    var d = 19257038036680949359750312669786877991949435402254120286184196891950884077233;

    beta <== x1*y2;
    gamma <== y1*x2;
    delta <== (-a*x1+y1)*(x2 + y2);
    tau <== beta * gamma;

    xout <-- (beta + gamma) / (1+ d*tau);
    (1+ d*tau) * xout === (beta + gamma);

    yout <-- (delta + a*beta - gamma) / (1-d*tau);
    (1-d*tau)*yout === (delta + a*beta - gamma);
}

template JubJubDbl() {
    signal input x;
    signal input y;
    signal output xout;
    signal output yout;

    component adder = JubJubAdd();
    adder.x1 <== x;
    adder.y1 <== y;
    adder.x2 <== x;
    adder.y2 <== y;

    adder.xout ==> xout;
    adder.yout ==> yout;
}

template JubJubCheck() {
    signal input x;
    signal input y;

    signal x2;
    signal y2;

    var a = -1;
    var d = 19257038036680949359750312669786877991949435402254120286184196891950884077233;

    x2 <== x*x;
    y2 <== y*y;

    a*x2 + y2 === 1 + d*x2*y2;
}

/*
 * JubJub Montgomery curve operations.
 * Montgomery form: B*v^2 = u^3 + A*u^2 + u
 *   A = 2*(a+d)/(a-d) = 40962
 *   B = 4/(a-d) = 52435875175126190479447740508185965837690552500527637822603658699938581143549
 */
template JubJubMontgomeryAdd() {
    signal input in1[2];
    signal input in2[2];
    signal output out[2];

    var A = 40962;
    var B = 52435875175126190479447740508185965837690552500527637822603658699938581143549;

    signal lamda;

    lamda <-- (in2[1] - in1[1]) / (in2[0] - in1[0]);
    lamda * (in2[0] - in1[0]) === (in2[1] - in1[1]);

    out[0] <== B*lamda*lamda - A - in1[0] - in2[0];
    out[1] <== lamda * (in1[0] - out[0]) - in1[1];
}

template JubJubMontgomeryDouble() {
    signal input in[2];
    signal output out[2];

    var A = 40962;
    var B = 52435875175126190479447740508185965837690552500527637822603658699938581143549;

    signal lamda;
    signal x1_2;

    x1_2 <== in[0] * in[0];

    lamda <-- (3*x1_2 + 2*A*in[0] + 1) / (2*B*in[1]);
    lamda * (2*B*in[1]) === (3*x1_2 + 2*A*in[0] + 1);

    out[0] <== B*lamda*lamda - A - 2*in[0];
    out[1] <== lamda * (in[0] - out[0]) - in[1];
}
