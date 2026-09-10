/*
 * Cardano Strong Key Ownership — Nova step circuit (IVC chain).
 *
 * Proves knowledge of a 96-byte master XPrv that derives a payment extended
 * public key along CIP-1852 path m/purposeH/coinTypeH/accountH/role/index by
 * folding a chain of identical steps over a 1024-bit public state
 * (kL || kR || cc || apk).
 *
 * Chain layout (6 identical steps, private op per step):
 *     op=0 (seed-hard) : kL/kR/cc taken from private `master`, hardened CKD
 *     op=1 (hard)      : hardened CKD of the public state key
 *     op=2 (soft)      : soft CKD of the public state key (parent Ap = state apk)
 *     op=3 (final)     : pass through apk, zero kL/kR/cc (public bundle reveals
 *                        only the final public key apk)
 *
 * Both CKD branches are instantiated unconditionally so the circuit shape is
 * constant across all steps; op selects outputs via bit-muxes.  The parent
 * public key (needed by soft steps) is recomputed in-circuit every step as
 * Ed25519Pub256(nkL).  The final apk comparison against the target A is done
 * by the application after the fold, mirroring the Ed25519 ownership cases.
 *
 * The fold bundle (initial_state=zeros, final_instance=(0,0,0,apk), transcript)
 * never reveals intermediate derived keys.
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "ckd_cardano.circom";
include "ed25519_pub.circom";
include "modn.circom";

template CardanoKeyOwnershipStrongStep() {
    // public state in
    signal input kLIn[256];
    signal input kRIn[256];
    signal input ccIn[256];
    signal input apkIn[256];
    // private per-step inputs
    signal input master[768];
    signal input op[2];
    signal input idx[32];
    // public state out
    signal output outK[256];
    signal output outR[256];
    signal output outc[256];
    signal output outAp[256];

    var i;

    // op selectors (op is a private 2-bit value; enforce binary)
    op[0] * (1 - op[0]) === 0;
    op[1] * (1 - op[1]) === 0;
    signal seedSel;
    signal hardSel;
    signal softSel;
    signal finalSel;
    seedSel  <== (1 - op[0]) * (1 - op[1]);
    hardSel  <== op[0] * (1 - op[1]);
    softSel  <== (1 - op[0]) * op[1];
    finalSel <== op[0] * op[1];

    // branch inputs: seed step sources kL/kR/cc from the private master
    signal kLb[256];
    signal kRb[256];
    signal ccb[256];
    for (i = 0; i < 256; i++) {
        kLb[i] <== seedSel * (master[i] - kLIn[i]) + kLIn[i];
        kRb[i] <== seedSel * (master[256 + i] - kRIn[i]) + kRIn[i];
        ccb[i] <== seedSel * (master[512 + i] - ccIn[i]) + ccIn[i];
    }

    // both CKD branches, always instantiated (constant shape)
    component h = CkdHardened();
    for (i = 0; i < 256; i++) { h.kL[i] <== kLb[i]; h.kR[i] <== kRb[i]; h.cc[i] <== ccb[i]; }
    for (i = 0; i < 32; i++)  { h.idx[i] <== idx[i]; }

    component s = CkdSoft();
    for (i = 0; i < 256; i++) { s.kL[i] <== kLb[i]; s.kR[i] <== kRb[i]; s.cc[i] <== ccb[i]; s.Ap[i] <== apkIn[i]; }
    for (i = 0; i < 32; i++)  { s.idx[i] <== idx[i]; }

    // selected derived key (any value in final step; unused there)
    signal selK[256];
    signal selR[256];
    signal selC[256];
    signal softK[256];
    signal softR[256];
    signal softC[256];
    for (i = 0; i < 256; i++) {
        softK[i] <== softSel * (s.nkL[i] - h.nkL[i]);
        softR[i] <== softSel * (s.nkR[i] - h.nkR[i]);
        softC[i] <== softSel * (s.ncc[i] - h.ncc[i]);
        selK[i] <== h.nkL[i] + softK[i];
        selR[i] <== h.nkR[i] + softR[i];
        selC[i] <== h.ncc[i] + softC[i];
    }

    // parent public key of the derived key, recomputed every step
    // (scalar reduced mod the ed25519 subgroup order first, as [kL]G)
    component modn = ModN256();
    for (i = 0; i < 256; i++) { modn.s[i] <== selK[i]; }
    component e = Ed25519Pub256();
    for (i = 0; i < 256; i++) { e.s[i] <== modn.r[i]; }

    for (i = 0; i < 256; i++) {
        outK[i]  <== selK[i] - finalSel * selK[i];
        outR[i]  <== selR[i] - finalSel * selR[i];
        outc[i]  <== selC[i] - finalSel * selC[i];
        // non-final: apk = pub(derived key); final: pass through apkIn
        outAp[i] <== e.apk[i] - finalSel * (e.apk[i] - apkIn[i]);
    }
}

component main {public [kLIn, kRIn, ccIn, apkIn]} = CardanoKeyOwnershipStrongStep();