/*
 * JubJub fixed-base scalar multiplication — ported from circomlib escalarmulfix.circom
 * Uses JubJubAdd instead of BabyAdd.
 *
 * The Montgomery operations (MontgomeryDouble, MontgomeryAdd, Edwards2Montgomery,
 * Montgomery2Edwards) are curve-agnostic and work for any Montgomery curve.
 * Only the final Edwards addition needs JubJub-specific constants.
 *
 * License: MIT (clean reimplementation).
 */
pragma circom 2.0.0;

include "mux3.circom";
include "montgomery.circom";
include "jubjub_primitives.circom";


template WindowMulFixJubJub() {
    signal input in[3];
    signal input base[2];
    signal output out[2];
    signal output out8[2];

    component mux = MultiMux3(2);

    mux.s[0] <== in[0];
    mux.s[1] <== in[1];
    mux.s[2] <== in[2];

    component dbl2 = MontgomeryDouble();
    component adr3 = MontgomeryAdd();
    component adr4 = MontgomeryAdd();
    component adr5 = MontgomeryAdd();
    component adr6 = MontgomeryAdd();
    component adr7 = MontgomeryAdd();
    component adr8 = MontgomeryAdd();

    mux.c[0][0] <== base[0];
    mux.c[1][0] <== base[1];

    dbl2.in[0] <== base[0];
    dbl2.in[1] <== base[1];
    mux.c[0][1] <== dbl2.out[0];
    mux.c[1][1] <== dbl2.out[1];

    adr3.in1[0] <== base[0];
    adr3.in1[1] <== base[1];
    adr3.in2[0] <== dbl2.out[0];
    adr3.in2[1] <== dbl2.out[1];
    mux.c[0][2] <== adr3.out[0];
    mux.c[1][2] <== adr3.out[1];

    adr4.in1[0] <== base[0];
    adr4.in1[1] <== base[1];
    adr4.in2[0] <== adr3.out[0];
    adr4.in2[1] <== adr3.out[1];
    mux.c[0][3] <== adr4.out[0];
    mux.c[1][3] <== adr4.out[1];

    adr5.in1[0] <== base[0];
    adr5.in1[1] <== base[1];
    adr5.in2[0] <== adr4.out[0];
    adr5.in2[1] <== adr4.out[1];
    mux.c[0][4] <== adr5.out[0];
    mux.c[1][4] <== adr5.out[1];

    adr6.in1[0] <== base[0];
    adr6.in1[1] <== base[1];
    adr6.in2[0] <== adr5.out[0];
    adr6.in2[1] <== adr5.out[1];
    mux.c[0][5] <== adr6.out[0];
    mux.c[1][5] <== adr6.out[1];

    adr7.in1[0] <== base[0];
    adr7.in1[1] <== base[1];
    adr7.in2[0] <== adr6.out[0];
    adr7.in2[1] <== adr6.out[1];
    mux.c[0][6] <== adr7.out[0];
    mux.c[1][6] <== adr7.out[1];

    adr8.in1[0] <== base[0];
    adr8.in1[1] <== base[1];
    adr8.in2[0] <== adr7.out[0];
    adr8.in2[1] <== adr7.out[1];
    mux.c[0][7] <== adr8.out[0];
    mux.c[1][7] <== adr8.out[1];

    out8[0] <== adr8.out[0];
    out8[1] <== adr8.out[1];

    out[0] <== mux.out[0];
    out[1] <== mux.out[1];
}


template SegmentMulFixJubJub(nWindows) {
    signal input e[nWindows*3];
    signal input base[2];
    signal output out[2];
    signal output dbl[2];

    var i;
    var j;

    component e2m = Edwards2Montgomery();
    e2m.in[0] <== base[0];
    e2m.in[1] <== base[1];

    component windows[nWindows];
    component adders[nWindows];
    component cadders[nWindows];

    component dblLast = MontgomeryDouble();

    for (i=0; i<nWindows; i++) {
        windows[i] = WindowMulFixJubJub();
        cadders[i] = MontgomeryAdd();
        if (i==0) {
            windows[i].base[0] <== e2m.out[0];
            windows[i].base[1] <== e2m.out[1];
            cadders[i].in1[0] <== e2m.out[0];
            cadders[i].in1[1] <== e2m.out[1];
        } else {
            windows[i].base[0] <== windows[i-1].out8[0];
            windows[i].base[1] <== windows[i-1].out8[1];
            cadders[i].in1[0] <== cadders[i-1].out[0];
            cadders[i].in1[1] <== cadders[i-1].out[1];
        }
        for (j=0; j<3; j++) {
            windows[i].in[j] <== e[3*i+j];
        }
        if (i<nWindows-1) {
            cadders[i].in2[0] <== windows[i].out8[0];
            cadders[i].in2[1] <== windows[i].out8[1];
        } else {
            dblLast.in[0] <== windows[i].out8[0];
            dblLast.in[1] <== windows[i].out8[1];
            cadders[i].in2[0] <== dblLast.out[0];
            cadders[i].in2[1] <== dblLast.out[1];
        }
    }

    for (i=0; i<nWindows; i++) {
        adders[i] = MontgomeryAdd();
        if (i==0) {
            adders[i].in1[0] <== dblLast.out[0];
            adders[i].in1[1] <== dblLast.out[1];
        } else {
            adders[i].in1[0] <== adders[i-1].out[0];
            adders[i].in1[1] <== adders[i-1].out[1];
        }
        adders[i].in2[0] <== windows[i].out[0];
        adders[i].in2[1] <== windows[i].out[1];
    }

    component m2e = Montgomery2Edwards();
    component cm2e = Montgomery2Edwards();

    m2e.in[0] <== adders[nWindows-1].out[0];
    m2e.in[1] <== adders[nWindows-1].out[1];
    cm2e.in[0] <== cadders[nWindows-1].out[0];
    cm2e.in[1] <== cadders[nWindows-1].out[1];

    component cAdd = JubJubAdd();
    cAdd.x1 <== m2e.out[0];
    cAdd.y1 <== m2e.out[1];
    cAdd.x2 <== -cm2e.out[0];
    cAdd.y2 <== cm2e.out[1];

    cAdd.xout ==> out[0];
    cAdd.yout ==> out[1];

    windows[nWindows-1].out8[0] ==> dbl[0];
    windows[nWindows-1].out8[1] ==> dbl[1];
}


template EscalarMulFixJubJub(n, BASE) {
    signal input e[n];
    signal output out[2];

    var nsegments = (n-1)\246 +1;
    var nlastsegment = n - (nsegments-1)*249;

    component segments[nsegments];

    component m2e[nsegments-1];
    component adders[nsegments-1];

    var s;
    var i;
    var nseg;
    var nWindows;

    for (s=0; s<nsegments; s++) {

        nseg = (s < nsegments-1) ? 249 : nlastsegment;
        nWindows = ((nseg - 1)\3)+1;

        segments[s] = SegmentMulFixJubJub(nWindows);

        for (i=0; i<nseg; i++) {
            segments[s].e[i] <== e[s*249+i];
        }

        for (i = nseg; i<nWindows*3; i++) {
            segments[s].e[i] <== 0;
        }

        if (s==0) {
            segments[s].base[0] <== BASE[0];
            segments[s].base[1] <== BASE[1];
        } else {
            m2e[s-1] = Montgomery2Edwards();
            adders[s-1] = JubJubAdd();

            segments[s-1].dbl[0] ==> m2e[s-1].in[0];
            segments[s-1].dbl[1] ==> m2e[s-1].in[1];

            m2e[s-1].out[0] ==> segments[s].base[0];
            m2e[s-1].out[1] ==> segments[s].base[1];

            if (s==1) {
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
        segments[0].out[0] ==> out[0];
        segments[0].out[1] ==> out[1];
    } else {
        adders[nsegments-2].xout ==> out[0];
        adders[nsegments-2].yout ==> out[1];
    }
}
