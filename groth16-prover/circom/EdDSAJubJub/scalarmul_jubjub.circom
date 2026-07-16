/*
 * JubJub variable-base scalar multiplication — port of circomlib's
 * scalarmulany.circom with BabyJubJub → JubJub curve constants.
 *
 * Montgomery form: A = 40962, B = 52435875175126190479447740508185965837690552500527637822603658699938581143549
 * Twisted Edwards: a = -1, d = 19257038036680949359750312669786877991949435402254120286184196891950884077233
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "bitify.circom";
include "jubjub_primitives.circom";

/* ---- Montgomery curve operations for JubJub ---- */

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

/* ---- Edwards ↔ Montgomery conversions (generic, no curve constants) ---- */

template Edwards2MontgomeryJubJub() {
    signal input in[2];
    signal output out[2];

    out[0] <-- (1 + in[1]) / (1 - in[1]);
    out[1] <-- out[0] / in[0];

    out[0] * (1 - in[1]) === (1 + in[1]);
    out[1] * in[0] === out[0];
}

template Montgomery2EdwardsJubJub() {
    signal input in[2];
    signal output out[2];

    out[0] <-- in[0] / in[1];
    out[1] <-- (in[0] - 1) / (in[0] + 1);

    out[0] * in[1] === in[0];
    out[1] * (in[0] + 1) === in[0] - 1;
}

/* ---- Scalar multiplication primitives ---- */

template Multiplexor2JubJub() {
    signal input sel;
    signal input in[2][2];
    signal output out[2];

    out[0] <== (in[1][0] - in[0][0])*sel + in[0][0];
    out[1] <== (in[1][1] - in[0][1])*sel + in[0][1];
}

template BitElementMulAnyJubJub() {
    signal input sel;
    signal input dblIn[2];
    signal input addIn[2];
    signal output dblOut[2];
    signal output addOut[2];

    component doubler = JubJubMontgomeryDouble();
    component adder = JubJubMontgomeryAdd();
    component selector = Multiplexor2JubJub();

    sel ==> selector.sel;

    dblIn[0] ==> doubler.in[0];
    dblIn[1] ==> doubler.in[1];
    doubler.out[0] ==> adder.in1[0];
    doubler.out[1] ==> adder.in1[1];
    addIn[0] ==> adder.in2[0];
    addIn[1] ==> adder.in2[1];
    addIn[0] ==> selector.in[0][0];
    addIn[1] ==> selector.in[0][1];
    adder.out[0] ==> selector.in[1][0];
    adder.out[1] ==> selector.in[1][1];

    doubler.out[0] ==> dblOut[0];
    doubler.out[1] ==> dblOut[1];
    selector.out[0] ==> addOut[0];
    selector.out[1] ==> addOut[1];
}

template SegmentMulAnyJubJub(n) {
    signal input e[n];
    signal input p[2];
    signal output out[2];
    signal output dbl[2];

    component bits[n-1];

    component e2m = Edwards2MontgomeryJubJub();

    p[0] ==> e2m.in[0];
    p[1] ==> e2m.in[1];

    var i;

    bits[0] = BitElementMulAnyJubJub();
    e2m.out[0] ==> bits[0].dblIn[0];
    e2m.out[1] ==> bits[0].dblIn[1];
    e2m.out[0] ==> bits[0].addIn[0];
    e2m.out[1] ==> bits[0].addIn[1];
    e[1] ==> bits[0].sel;

    for (i = 1; i < n-1; i++) {
        bits[i] = BitElementMulAnyJubJub();

        bits[i-1].dblOut[0] ==> bits[i].dblIn[0];
        bits[i-1].dblOut[1] ==> bits[i].dblIn[1];
        bits[i-1].addOut[0] ==> bits[i].addIn[0];
        bits[i-1].addOut[1] ==> bits[i].addIn[1];
        e[i+1] ==> bits[i].sel;
    }

    bits[n-2].dblOut[0] ==> dbl[0];
    bits[n-2].dblOut[1] ==> dbl[1];

    component m2e = Montgomery2EdwardsJubJub();

    bits[n-2].addOut[0] ==> m2e.in[0];
    bits[n-2].addOut[1] ==> m2e.in[1];

    component eadder = JubJubAdd();

    m2e.out[0] ==> eadder.x1;
    m2e.out[1] ==> eadder.y1;
    -p[0] ==> eadder.x2;
    p[1] ==> eadder.y2;

    component lastSel = Multiplexor2JubJub();

    e[0] ==> lastSel.sel;
    eadder.xout ==> lastSel.in[0][0];
    eadder.yout ==> lastSel.in[0][1];
    m2e.out[0] ==> lastSel.in[1][0];
    m2e.out[1] ==> lastSel.in[1][1];

    lastSel.out[0] ==> out[0];
    lastSel.out[1] ==> out[1];
}

template EscalarMulAnyJubJub(n) {
    signal input e[n];
    signal input p[2];
    signal output out[2];

    var nsegments = (n - 1) \ 148 + 1;
    var nlastsegment = n - (nsegments - 1) * 148;

    component segments[nsegments];
    component doublers[nsegments-1];
    component m2e[nsegments-1];
    component adders[nsegments-1];
    component zeropoint = IsZero();
    zeropoint.in <== p[0];

    var s;
    var i;
    var nseg;

    for (s = 0; s < nsegments; s++) {
        nseg = (s < nsegments - 1) ? 148 : nlastsegment;

        segments[s] = SegmentMulAnyJubJub(nseg);

        for (i = 0; i < nseg; i++) {
            e[s * 148 + i] ==> segments[s].e[i];
        }

        if (s == 0) {
            // Force a non-zero point if input is zero (to avoid Montgomery issues)
            segments[s].p[0] <== p[0] + (5299619240641551281634865583518297030282874472190772894086521144482721001553 - p[0]) * zeropoint.out;
            segments[s].p[1] <== p[1] + (16950150798460657717958625567821834550301663161624707787222815936182638968203 - p[1]) * zeropoint.out;
        } else {
            doublers[s-1] = JubJubMontgomeryDouble();
            m2e[s-1] = Montgomery2Edwards();
            adders[s-1] = JubJubAdd();

            segments[s-1].dbl[0] ==> doublers[s-1].in[0];
            segments[s-1].dbl[1] ==> doublers[s-1].in[1];

            doublers[s-1].out[0] ==> m2e[s-1].in[0];
            doublers[s-1].out[1] ==> m2e[s-1].in[1];

            m2e[s-1].out[0] ==> segments[s].p[0];
            m2e[s-1].out[1] ==> segments[s].p[1];

            if (s == 1) {
                segments[s-1].out[0] ==> adders[s-1].x1;
                segments[s-1].out[1] ==> adders[s-1].y1;
            } else {
                adders[s-2].xout ==> adders[s-1].x1;
                adders[s-2].yout ==> adders[s-1].y1;
            }
            segments[s].out[0] ==> adders[s-1].x2;
            segments[s].out[1] ==> adders[s-1].y2;
        }
    }

    if (nsegments == 1) {
        segments[0].out[0] * (1 - zeropoint.out) ==> out[0];
        segments[0].out[1] + (1 - segments[0].out[1]) * zeropoint.out ==> out[1];
    } else {
        adders[nsegments-2].xout * (1 - zeropoint.out) ==> out[0];
        adders[nsegments-2].yout + (1 - adders[nsegments-2].yout) * zeropoint.out ==> out[1];
    }
}
