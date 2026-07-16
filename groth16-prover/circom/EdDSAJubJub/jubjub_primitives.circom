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
