/*
 * Single hardened CKD step test. Asserts that a given child extended key
 * follows from its parent + index under the proven scheme.
 */
pragma circom 2.0.0;

include "ckd_cardano.circom";

template CkdOneH() {
    signal input kL[256];
    signal input kR[256];
    signal input cc[256];
    signal input idx[32];
    signal input oK[256];
    signal input oR[256];
    signal input oC[256];
    signal output out;
    var i;

    component h = CkdHardened();
    for (i = 0; i < 256; i++) { h.kL[i] <== kL[i]; }
    for (i = 0; i < 256; i++) { h.kR[i] <== kR[i]; }
    for (i = 0; i < 256; i++) { h.cc[i] <== cc[i]; }
    for (i = 0; i < 32; i++)  { h.idx[i] <== idx[i]; }

    for (i = 0; i < 256; i++) { h.nkL[i] === oK[i]; }
    for (i = 0; i < 256; i++) { h.nkR[i] === oR[i]; }
    for (i = 0; i < 256; i++) { h.ncc[i] === oC[i]; }

    out <== 1;
}

component main = CkdOneH();