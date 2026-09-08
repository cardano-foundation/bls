/*
 * Cardano Ed25519 Strong Key Ownership — proves in-circuit knowledge of the
 * 96-byte master XPrv (root `Root_xsk`) that derives a payment credential
 * (extended public key `A`) at CIP-1852 path:
 *
 *     m / purposeH / coinTypeH / accountH / role / index
 *
 * Public inputs : A[256]              — target compressed public key bits
 *                 purpose[32]         — hardened purpose index word (LE, bit31 = hardened)
 *                 coinType[32]        — hardened coin-type index word (LE)
 *                 accountIx[32]       — hardened account index word (LE)
 *                 roleIdx[32]         — soft role index word (LE)
 *                 addrIdx[32]         — soft address index word (LE)
 * Private inputs: master[768]         — Root_xsk bits: kL(256) || kR(256) || cc(256)
 *
 * Output       : out == 1 iff A equals the public key derived in-circuit from
 *                 master[768] along the given path (CIP-1852, DerivationScheme2).
 *
 * Hardened steps use HMAC-SHA512(m=0x00||kL||kR||idx), soft steps use
 * HMAC-SHA512(m=0x02||A_parent||idx) with parent public keys recomputed
 * in-circuit as [kL]·G. See ckd_cardano.circom for the exact, validated scheme.
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "ckd_cardano.circom";
include "ed25519_pub.circom";

template CardanoEd25519OwnershipStrong() {
    signal input A[256];
    signal input purpose[32];
    signal input coinType[32];
    signal input accountIx[32];
    signal input roleIdx[32];
    signal input addrIdx[32];
    signal input master[768];
    signal output out;

    var i;

    // --- III. hardened steps: m/1852H/1815H/<account>H -----------------------
    component h1 = CkdHardened();
    for (i = 0; i < 256; i++) { h1.kL[i] <== master[i]; }
    for (i = 0; i < 256; i++) { h1.kR[i] <== master[256 + i]; }
    for (i = 0; i < 256; i++) { h1.cc[i]  <== master[512 + i]; }
    for (i = 0; i < 32; i++)  { h1.idx[i] <== purpose[i]; }

    component h2 = CkdHardened();
    for (i = 0; i < 256; i++) { h2.kL[i] <== h1.nkL[i]; }
    for (i = 0; i < 256; i++) { h2.kR[i] <== h1.nkR[i]; }
    for (i = 0; i < 256; i++) { h2.cc[i]  <== h1.ncc[i]; }
    for (i = 0; i < 32; i++)  { h2.idx[i] <== coinType[i]; }

    component h3 = CkdHardened();
    for (i = 0; i < 256; i++) { h3.kL[i] <== h2.nkL[i]; }
    for (i = 0; i < 256; i++) { h3.kR[i] <== h2.nkR[i]; }
    for (i = 0; i < 256; i++) { h3.cc[i]  <== h2.ncc[i]; }
    for (i = 0; i < 32; i++)  { h3.idx[i] <== accountIx[i]; }

    // --- parent public keys, recomputed in-circuit ---------------------------
    component e3 = Ed25519Pub256();
    for (i = 0; i < 256; i++) { e3.s[i] <== h3.nkL[i]; }

    // --- soft steps: /<role>/<index> ----------------------------------------
    component s1 = CkdSoft();
    for (i = 0; i < 256; i++) { s1.kL[i] <== h3.nkL[i]; }
    for (i = 0; i < 256; i++) { s1.kR[i] <== h3.nkR[i]; }
    for (i = 0; i < 256; i++) { s1.cc[i]  <== h3.ncc[i]; }
    for (i = 0; i < 256; i++) { s1.Ap[i] <== e3.apk[i]; }
    for (i = 0; i < 32; i++)  { s1.idx[i] <== roleIdx[i]; }

    component e4 = Ed25519Pub256();
    for (i = 0; i < 256; i++) { e4.s[i] <== s1.nkL[i]; }

    component s2 = CkdSoft();
    for (i = 0; i < 256; i++) { s2.kL[i] <== s1.nkL[i]; }
    for (i = 0; i < 256; i++) { s2.kR[i] <== s1.nkR[i]; }
    for (i = 0; i < 256; i++) { s2.cc[i]  <== s1.ncc[i]; }
    for (i = 0; i < 256; i++) { s2.Ap[i] <== e4.apk[i]; }
    for (i = 0; i < 32; i++)  { s2.idx[i] <== addrIdx[i]; }

    component e5 = Ed25519Pub256();
    for (i = 0; i < 256; i++) { e5.s[i] <== s2.nkL[i]; }

    for (i = 0; i < 256; i++) {
        e5.apk[i] === A[i];
    }

    out <== 1;
}

component main {public [A, purpose, coinType, accountIx, roleIdx, addrIdx]} = CardanoEd25519OwnershipStrong();