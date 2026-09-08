/*
 * Cardano CIP-1852 Child Key Derivation (CKD) — proven derivation scheme.
 *
 * Reverse-engineered and validated against `cardano-address key child`
 * (cardano-addresses 4.0.0 / cardano-crypto encrypted_sign.c):
 *
 *   V2 hardened:
 *     Z   = HMAC-SHA512(cc, 0x00 || kL || kR || idxLE32)
 *     kL' = (8 * LE(Z[0:28]) + kL)            mod 2^256
 *     kR' = (LE(Z[32:64])  + kR)              mod 2^256
 *     cc' = HMAC-SHA512(cc, 0x01 || kL || kR || idxLE32)[32:64]
 *
 *   V2 soft:
 *     Z   = HMAC-SHA512(cc, 0x02 || A_parent || idxLE32)
 *     kL' = (8 * LE(Z[0:28]) + kL)            mod 2^256
 *     kR' = (LE(Z[32:64])  + kR)              mod 2^256
 *     cc' = HMAC-SHA512(cc, 0x03 || A_parent || idxLE32)[32:64]
 *
 * All scalars are 256-bit little-endian integers; index words are 32-bit
 * little-endian (the hardened bit lives in bit 31 of the index word).
 *
 * Uses Sha512 from @electron-labs/sha512 and Num2Bits from circomlib (MIT).
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "../Ed25519Verify/node_modules/@electron-labs/sha512/circuits/sha512/sha512.circom";
include "../Ed25519Verify/node_modules/circomlib/circuits/bitify.circom";

// ---------------------------------------------------------------------------
// HMAC-SHA512(key[32 bytes] bits in, msg bits in) -> out[512] bits
// Standard HMAC: inner = SHA512((key ^ ipad || msg)), outer = SHA512((key ^ opad || inner))
// ipad = 0x36 * 64, opad = 0x5c * 64
// ---------------------------------------------------------------------------
template HmacSha512(nMsgBits) {
    signal input key[256];
    signal input msg[nMsgBits];
    signal output out[512];

    // inner input = 512 + nMsgBits
    signal inner[512 + nMsgBits];
    var i;
    var b;
    var bit;
    var padbit;

    for (i = 0; i < 512; i++) {
        b = i \ 8;
        bit = i % 8;
        if (b < 32) {
            padbit = (0x36 >> bit) & 1;
            inner[i] <== key[b * 8 + bit] + padbit - 2 * padbit * key[b * 8 + bit];
        } else {
            inner[i] <== (0x36 >> bit) & 1;
        }
    }
    for (i = 0; i < nMsgBits; i++) {
        inner[512 + i] <== msg[i];
    }

    component s1 = Sha512(512 + nMsgBits);
    for (i = 0; i < 512 + nMsgBits; i++) {
        s1.in[i] <== inner[i];
    }

    // outer input = 1024
    signal outer[1024];
    for (i = 0; i < 512; i++) {
        b = i \ 8;
        bit = i % 8;
        if (b < 32) {
            padbit = (0x5c >> bit) & 1;
            outer[i] <== key[b * 8 + bit] + padbit - 2 * padbit * key[b * 8 + bit];
        } else {
            outer[i] <== (0x5c >> bit) & 1;
        }
    }
    for (i = 0; i < 512; i++) {
        outer[512 + i] <== s1.out[i];
    }

    component s2 = Sha512(1024);
    for (i = 0; i < 1024; i++) {
        s2.in[i] <== outer[i];
    }
    for (i = 0; i < 512; i++) {
        out[i] <== s2.out[i];
    }
}

// ---------------------------------------------------------------------------
// 256-bit little-endian full adder (ripple carry). out = (a + b) mod 2^256.
// Uses Num2Bits(3) to decompose the 3-bit sum into sum-bit and carry.
// ---------------------------------------------------------------------------
template FullAdder() {
    signal input a;
    signal input b;
    signal input cin;
    signal output s;
    signal output cout;
    signal sum3;
    sum3 <== a + b + cin;
    component db = Num2Bits(3);
    db.in <== sum3;
    s <== db.out[0];
    cout <== db.out[1];
}

template LEAdd256() {
    signal input a[256];
    signal input b[256];
    signal output out[256];

    component add[256];
    for (var i = 0; i < 256; i++) {
        add[i] = FullAdder();
        add[i].a <== a[i];
        add[i].b <== b[i];
        if (i == 0) { add[i].cin <== 0; }
        else { add[i].cin <== add[i - 1].cout; }
        out[i] <== add[i].s;
    }
}

// ---------------------------------------------------------------------------
// 8 * LE(val[0:224]) as a 256-bit little-endian integer.
// i.e. out bit i = val[i-3] for 3 <= i <= 226, 0 elsewhere.
// ---------------------------------------------------------------------------
template Mul8L224() {
    signal input val[224];
    signal output out[256];
    var i;
    for (i = 0; i < 256; i++) {
        if (i >= 3 && i <= 226) {
            out[i] <== val[i - 3];
        } else {
            out[i] <== 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Proven 256-bit harden/derive step (DerivationScheme2 / V2).
//   input : kL[256] kR[256] cc[256] idx[32] (index word, LE bits incl. hardened bit31)
//   output: nkL[256] nkR[256] ncc[256]
// ---------------------------------------------------------------------------
template CkdHardened() {
    signal input kL[256];
    signal input kR[256];
    signal input cc[256];
    signal input idx[32];
    signal output nkL[256];
    signal output nkR[256];
    signal output ncc[256];

    // hmac(K=cc, msg = tag(8) || kL(256) || kR(256) || idx(32))   -> 552 bits
    signal mz[552];
    var i;
    for (i = 0; i < 8; i++) { mz[i] <== 0; }              // tag 0x00
    for (i = 0; i < 256; i++) { mz[8 + i] <== kL[i]; }
    for (i = 0; i < 256; i++) { mz[264 + i] <== kR[i]; }
    for (i = 0; i < 32; i++)  { mz[520 + i] <== idx[i]; }

    signal mc[552];
    for (i = 0; i < 8; i++) { mc[i] <== (i == 0) ? 1 : 0; }   // tag 0x01
    for (i = 0; i < 256; i++) { mc[8 + i] <== kL[i]; }
    for (i = 0; i < 256; i++) { mc[264 + i] <== kR[i]; }
    for (i = 0; i < 32; i++)  { mc[520 + i] <== idx[i]; }

    component hz = HmacSha512(552);
    for (i = 0; i < 256; i++) { hz.key[i] <== cc[i]; }
    for (i = 0; i < 552; i++) { hz.msg[i] <== mz[i]; }

    component hc = HmacSha512(552);
    for (i = 0; i < 256; i++) { hc.key[i] <== cc[i]; }
    for (i = 0; i < 552; i++) { hc.msg[i] <== mc[i]; }

    // z = hz.out;  nkL = 8*LE(z[0:28]) + kL  (mod 2^256)
    signal zl[224];
    for (i = 0; i < 224; i++) { zl[i] <== hz.out[i]; }
    component ml = Mul8L224();
    for (i = 0; i < 224; i++) { ml.val[i] <== zl[i]; }
    component al = LEAdd256();
    for (i = 0; i < 256; i++) { al.a[i] <== ml.out[i]; }
    for (i = 0; i < 256; i++) { al.b[i] <== kL[i]; }
    for (i = 0; i < 256; i++) { nkL[i] <== al.out[i]; }

    // nkR = LE(z[32:64]) + kR  (mod 2^256)
    signal zr[256];
    for (i = 0; i < 256; i++) { zr[i] <== hz.out[256 + i]; }
    component ar = LEAdd256();
    for (i = 0; i < 256; i++) { ar.a[i] <== zr[i]; }
    for (i = 0; i < 256; i++) { ar.b[i] <== kR[i]; }
    for (i = 0; i < 256; i++) { nkR[i] <== ar.out[i]; }

    // ncc = hc.out bytes 32..63
    for (i = 0; i < 256; i++) { ncc[i] <== hc.out[256 + i]; }
}

// ---------------------------------------------------------------------------
// Proven soft derive step (DerivationScheme2 / V2). Parent public key A_parent
// is a circuit input (computed by the caller via [kL]·G in Ed25519Pub).
// ---------------------------------------------------------------------------
template CkdSoft() {
    signal input kL[256];
    signal input kR[256];
    signal input cc[256];
    signal input Ap[256];
    signal input idx[32];
    signal output nkL[256];
    signal output nkR[256];
    signal output ncc[256];

    // hmac(K=cc, msg = tag(8) || Ap(256) || idx(32))   -> 296 bits
    signal mz[296];
    var i;
    for (i = 0; i < 8; i++) { mz[i] <== (i == 1) ? 1 : 0; }  // tag 0x02
    for (i = 0; i < 256; i++) { mz[8 + i] <== Ap[i]; }
    for (i = 0; i < 32; i++)  { mz[264 + i] <== idx[i]; }

    signal mc[296];
    for (i = 0; i < 8; i++) { mc[i] <== (i == 0 || i == 1) ? 1 : 0; }  // tag 0x03
    for (i = 0; i < 256; i++) { mc[8 + i] <== Ap[i]; }
    for (i = 0; i < 32; i++)  { mc[264 + i] <== idx[i]; }

    component hz = HmacSha512(296);
    for (i = 0; i < 256; i++) { hz.key[i] <== cc[i]; }
    for (i = 0; i < 296; i++) { hz.msg[i] <== mz[i]; }

    component hc = HmacSha512(296);
    for (i = 0; i < 256; i++) { hc.key[i] <== cc[i]; }
    for (i = 0; i < 296; i++) { hc.msg[i] <== mc[i]; }

    signal zl[224];
    for (i = 0; i < 224; i++) { zl[i] <== hz.out[i]; }
    component ml = Mul8L224();
    for (i = 0; i < 224; i++) { ml.val[i] <== zl[i]; }
    component al = LEAdd256();
    for (i = 0; i < 256; i++) { al.a[i] <== ml.out[i]; }
    for (i = 0; i < 256; i++) { al.b[i] <== kL[i]; }
    for (i = 0; i < 256; i++) { nkL[i] <== al.out[i]; }

    signal zr[256];
    for (i = 0; i < 256; i++) { zr[i] <== hz.out[256 + i]; }
    component ar = LEAdd256();
    for (i = 0; i < 256; i++) { ar.a[i] <== zr[i]; }
    for (i = 0; i < 256; i++) { ar.b[i] <== kR[i]; }
    for (i = 0; i < 256; i++) { nkR[i] <== ar.out[i]; }

    for (i = 0; i < 256; i++) { ncc[i] <== hc.out[256 + i]; }
}