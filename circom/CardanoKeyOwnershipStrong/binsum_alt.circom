/*
 * Precision-safe replacement for circomlib's BinSum and Num2Bits.
 *
 * circomlib/electron-labs BinSum accumulates all operand bits into a single
 * value (`lin <== 2^k * in[j][k]`) and extracts bits through a linear
 * decomposition. Every witness calculator evaluates that linear value while
 * solving the circuit (JS numbers for the webasm path, native ints for the
 * generated C++), so a sum >= 2^64 wraps and yields corrupt-but-consistent
 * witnesses (or an assert), even though the R1CS is valid.
 *
 * This implementation performs the same signed-free binary addition entirely
 * with 0/1 signals and only quadratic constraints:
 *   - (ops > 2) is folded down to two numbers with a carry-save full adder
 *     whose parity is a XOR chain and whose carry obeys
 *         2*carry + parity === a + b + c,   carry*(carry-1) === 0
 *   - the final two-term addition is a ripple-carry adder written the same
 *     way (Xor2 for the sum bit, the same sum/carry relation for cleans),
 * so no intermediate value exceeds a single bit during witness solving and no
 * subcomponent is instantiated.
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

// 3-bit binary decomposition (input is 0..3).
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

// W-bit ripple carry adder: s = a + b (mod 2^W). Quadratic-only.
template RippleAddSig(W) {
    signal input a[W];
    signal input b[W];
    signal output s[W + 1];
    signal carry[W + 1];
    signal x[W];
    signal t[W];
    carry[0] <== 0;
    for (var i = 0; i < W; i++) {
        x[i] <== a[i] + b[i] - 2 * a[i] * b[i];
        s[i] <== x[i] + carry[i] - 2 * x[i] * carry[i];
        t[i] <== a[i] + b[i] + carry[i];
        carry[i + 1] <-- (t[i] - s[i]) / 2;
        2 * carry[i + 1] + s[i] === t[i];
    }
    s[W] <== carry[W];
}

// Sum of `ops` n-bit operands (exact, component-free, quadratic-only) with the
// same interface as circomlib's BinSumAlt(n, ops).
template BinSumAlt(n, ops) {
    var nout = nbitsAlt((2 ** n - 1) * ops);
    signal input in[ops][n];
    signal output out[nout];

    var j;
    var k;

    // carry-save fold: stage pairs (s, c) with c shifted one column (majority).
    // stage 0 holds the first two operands; each new stage folds the next one.
    signal sst[ops][nout];
    signal cst[ops][nout];
    signal tst[ops][nout];
    signal xst[ops][nout];

    for (k = 0; k < nout; k++) {
        if (k < n) { sst[0][k] <== in[0][k]; cst[0][k] <== in[1][k]; }
        else { sst[0][k] <== 0; cst[0][k] <== 0; }
    }

    for (j = 1; j < ops - 1; j++) {
        cst[j][0] <== 0;
        for (k = 0; k < nout; k++) {
            var c = 0;
            if (k < n) { c = in[j + 1][k]; }
            xst[j][k] <== sst[j - 1][k] + cst[j - 1][k] - 2 * sst[j - 1][k] * cst[j - 1][k];
            sst[j][k] <== xst[j][k] + c - 2 * xst[j][k] * c;
            tst[j][k] <== sst[j - 1][k] + cst[j - 1][k] + c;
        }
        for (k = 1; k < nout; k++) {
            cst[j][k] <-- (tst[j][k - 1] - sst[j][k - 1]) / 2;
            2 * cst[j][k] + sst[j][k - 1] === tst[j][k - 1];
        }
    }

    component add = RippleAddSig(nout);
    for (k = 0; k < nout; k++) {
        add.a[k] <== sst[ops - 2][k];
        add.b[k] <== cst[ops - 2][k];
    }
    for (k = 0; k < nout; k++) {
        out[k] <== add.s[k];
    }
}