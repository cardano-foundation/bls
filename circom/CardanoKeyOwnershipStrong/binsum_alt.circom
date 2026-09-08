/*
 * Precision-safe replacement for circomlib's BinSumAlt and Num2Bits.
 *
 * circomlib's BinSumAlt accumulates all operand bits into a single var
 * (`lin`) and then extracts bits with `<-- (lin >> k) & 1`. The witness
 * calculators evaluate that expression with 64-bit (i64) arithmetic, so any
 * sum that reaches >= 2^64 wraps and the `lin === lout` assertion fails.
 * Real SHA-512 messages with high-bit 64-bit words routinely exceed 2^64.
 *
 * This implementation computes the same sum with a chain of ripple-carry
 * full adders (one bit at a time, never overflowing) and constrains every
 * output bit, so it is exact under any witness calculator and imposes the
 * same `sum == out` relation as the original.
 *
 * License: MIT.
 */
pragma circom 2.0.0;

function nbitsAlt(a) {
    var n = 1;
    var r = 0;
    while (n - 1 < a) {
        r++;
        n *= 2;
    }
    return r;
}

// 3-bit binary decomposition (input is 0..3 for full-adder use).
template N2B3() {
    signal input in;
    signal output out[3];
    out[0] <-- (in >> 0) & 1;
    out[1] <-- (in >> 1) & 1;
    out[2] <-- (in >> 2) & 1;
    out[0] * (out[0] - 1) === 0;
    out[1] * (out[1] - 1) === 0;
    out[2] * (out[2] - 1) === 0;
    out[0] + 2 * out[1] + 4 * out[2] === in;
}

template FullAdder() {
    signal input a;
    signal input b;
    signal input cin;
    signal output s;
    signal output cout;
    signal sum3;
    sum3 <== a + b + cin;
    component db = N2B3();
    db.in <== sum3;
    s <== db.out[0];
    cout <== db.out[1];
}

// W-bit ripple adder: s = (a + b) plus final carry, all bits exact.
template RippleAdd(W) {
    signal input a[W];
    signal input b[W];
    signal output s[W + 1];
    component fa[W];
    for (var i = 0; i < W; i++) {
        fa[i] = FullAdder();
        fa[i].a <== a[i];
        fa[i].b <== b[i];
        if (i == 0) { fa[i].cin <== 0; }
        else { fa[i].cin <== fa[i - 1].cout; }
        s[i] <== fa[i].s;
    }
    s[W] <== fa[W - 1].cout;
}

// Sum of `ops` n-bit operands (exact, ripple) with the same interface as
// circomlib's BinSumAlt(n, ops). Every intermediate sum fits because the width
// grows by one per operand; NO value ever exceeds 64 bits during witness
// evaluation.
template BinSumAlt(n, ops) {
    var nout = nbitsAlt((2 ** n - 1) * ops);
    signal input in[ops][n];
    signal output out[nout];

    component adds[ops - 1];
    var k;
    var j;

    adds[0] = RippleAdd(n);
    for (k = 0; k < n; k++) {
        adds[0].a[k] <== in[0][k];
        adds[0].b[k] <== in[1][k];
    }

    for (j = 1; j < ops - 1; j++) {
        var W = n + j;
        adds[j] = RippleAdd(W);
        for (k = 0; k < W; k++) {
            adds[j].a[k] <== adds[j - 1].s[k];
            if (k < n) { adds[j].b[k] <== in[j + 1][k]; }
            else { adds[j].b[k] <== 0; }
        }
    }

    for (k = 0; k < nout; k++) {
        out[k] <== adds[ops - 2].s[k];
    }
}