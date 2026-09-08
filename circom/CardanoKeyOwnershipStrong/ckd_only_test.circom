/*
 * CKD-only test: 3 hardened steps from a master key. No Ed25519 — verifies
 * the core derivation scheme compiles and is satisfiable against golden state.
 */
pragma circom 2.0.0;

include "ckd_cardano.circom";

template CkdOnly3H() {
    signal input kL[256];
    signal input kR[256];
    signal input cc[256];
    signal input purpose[32];
    signal input coinType[32];
    signal input accountIx[32];
    signal output okL[256];
    signal output okR[256];
    signal output occ[256];
    var i;

    component h1 = CkdHardened();
    for (i = 0; i < 256; i++) { h1.kL[i] <== kL[i]; }
    for (i = 0; i < 256; i++) { h1.kR[i] <== kR[i]; }
    for (i = 0; i < 256; i++) { h1.cc[i] <== cc[i]; }
    for (i = 0; i < 32; i++)  { h1.idx[i] <== purpose[i]; }

    component h2 = CkdHardened();
    for (i = 0; i < 256; i++) { h2.kL[i] <== h1.nkL[i]; }
    for (i = 0; i < 256; i++) { h2.kR[i] <== h1.nkR[i]; }
    for (i = 0; i < 256; i++) { h2.cc[i] <== h1.ncc[i]; }
    for (i = 0; i < 32; i++)  { h2.idx[i] <== coinType[i]; }

    component h3 = CkdHardened();
    for (i = 0; i < 256; i++) { h3.kL[i] <== h2.nkL[i]; }
    for (i = 0; i < 256; i++) { h3.kR[i] <== h2.nkR[i]; }
    for (i = 0; i < 256; i++) { h3.cc[i] <== h2.ncc[i]; }
    for (i = 0; i < 32; i++)  { h3.idx[i] <== accountIx[i]; }

    for (i = 0; i < 256; i++) { okL[i] <== h3.nkL[i]; }
    for (i = 0; i < 256; i++) { okR[i] <== h3.nkR[i]; }
    for (i = 0; i < 256; i++) { occ[i]  <== h3.ncc[i]; }
}

component main {public [purpose, coinType, accountIx]} = CkdOnly3H();