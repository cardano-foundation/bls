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

include "sha512F.circom";
include "binsum_alt.circom";

// ---------------------------------------------------------------------------
// HMAC-SHA512(key[32 bytes] bits in, msg bits in) -> out[512] bits
// Standard HMAC: inner = SHA512((key ^ ipad || msg)), outer = SHA512((key ^ opad || inner))
// SHA-512 hashes have block_size 128 bytes, so ipad = 0x36 * 128, opad = 0x5c * 128
// and the 32-byte key is appended with 96 zero bytes before XOR.
// ---------------------------------------------------------------------------
template HmacSha512(nMsgBits) {
    signal input key[256];
    signal input msg[nMsgBits];
    signal output out[512];

    // inner input = 1024 + nMsgBits
    signal inner[1024 + nMsgBits];
    var i;
    var b;
    var bit;
    var padbit;

    for (i = 0; i < 1024; i++) {
        b = i \ 8;
        bit = i % 8;
        if (b < 32) {
            padbit = (0x36 >> (7 - bit)) & 1;
            inner[i] <== key[b * 8 + bit] + padbit - 2 * padbit * key[b * 8 + bit];
        } else {
            inner[i] <== (0x36 >> (7 - bit)) & 1;
        }
    }
    for (i = 0; i < nMsgBits; i++) {
        inner[1024 + i] <== msg[i];
    }

    component s1 = Sha512F(1024 + nMsgBits);
    for (i = 0; i < 1024 + nMsgBits; i++) {
        s1.in[i] <== inner[i];
    }

    // outer input = 1024 + 512
    signal outer[1536];
    for (i = 0; i < 1024; i++) {
        b = i \ 8;
        bit = i % 8;
        if (b < 32) {
            padbit = (0x5c >> (7 - bit)) & 1;
            outer[i] <== key[b * 8 + bit] + padbit - 2 * padbit * key[b * 8 + bit];
        } else {
            outer[i] <== (0x5c >> (7 - bit)) & 1;
        }
    }
    for (i = 0; i < 512; i++) {
        outer[1024 + i] <== s1.out[i];
    }

    component s2 = Sha512F(1536);
    for (i = 0; i < 1536; i++) {
        s2.in[i] <== outer[i];
    }
    for (i = 0; i < 512; i++) {
        out[i] <== s2.out[i];
    }
}

// ---------------------------------------------------------------------------
// 256-bit little-endian full adder (ripple carry). out = (a + b) mod 2^256.
// FullAdder is supplied by binsum_alt.circom (N2B3-based).
// ---------------------------------------------------------------------------
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
// @electron-labs/sha512 treats a bit array as a big-endian byte stream:
// bit i of the input = bit (7 - i%8) of byte (i/8). Our key/message bits are
// little-endian (bit i of byte i/8), so this swaps each byte's bit order.
// ---------------------------------------------------------------------------
template RevByteBits(n) {
    signal input in[n];
    signal output out[n];
    for (var i = 0; i < n; i++) {
        var b = i \ 8;
        var p = i % 8;
        out[i] <== in[b * 8 + (7 - p)];
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

    var i;

    // Reorder to SHA-512 big-endian byte-stream bit order.
    component rkL = RevByteBits(256);
    component rkR = RevByteBits(256);
    component rcc = RevByteBits(256);
    component ridx = RevByteBits(32);
    for (i = 0; i < 256; i++) { rkL.in[i] <== kL[i]; rkR.in[i] <== kR[i]; rcc.in[i] <== cc[i]; }
    for (i = 0; i < 32; i++)  { ridx.in[i] <== idx[i]; }

    // hmac(K=cc, msg = tag(8) || kL(256) || kR(256) || idx(32))   -> 552 bits
    signal mz[552];
    for (i = 0; i < 8; i++) { mz[i] <== 0; }              // tag 0x00 (big-endian byte)
    for (i = 0; i < 256; i++) { mz[8 + i] <== rkL.out[i]; }
    for (i = 0; i < 256; i++) { mz[264 + i] <== rkR.out[i]; }
    for (i = 0; i < 32; i++)  { mz[520 + i] <== ridx.out[i]; }

    signal mc[552];
    for (i = 0; i < 8; i++) { mc[i] <== (i == 7) ? 1 : 0; }   // tag 0x01
    for (i = 0; i < 256; i++) { mc[8 + i] <== rkL.out[i]; }
    for (i = 0; i < 256; i++) { mc[264 + i] <== rkR.out[i]; }
    for (i = 0; i < 32; i++)  { mc[520 + i] <== ridx.out[i]; }

    component hz = HmacSha512(552);
    for (i = 0; i < 256; i++) { hz.key[i] <== rcc.out[i]; }
    for (i = 0; i < 552; i++) { hz.msg[i] <== mz[i]; }

    component hc = HmacSha512(552);
    for (i = 0; i < 256; i++) { hc.key[i] <== rcc.out[i]; }
    for (i = 0; i < 552; i++) { hc.msg[i] <== mc[i]; }

    // z = hz.out (big-endian byte stream). nkL = 8*LE(z[0:28]) + kL (mod 2^256)
    // Reorder digest bytes back to little-endian bit arrays before the adder.
    component rzL = RevByteBits(224);
    for (i = 0; i < 224; i++) { rzL.in[i] <== hz.out[i]; }
    component ml = Mul8L224();
    for (i = 0; i < 224; i++) { ml.val[i] <== rzL.out[i]; }
    component al = LEAdd256();
    for (i = 0; i < 256; i++) { al.a[i] <== ml.out[i]; }
    for (i = 0; i < 256; i++) { al.b[i] <== kL[i]; }
    for (i = 0; i < 256; i++) { nkL[i] <== al.out[i]; }

    // nkR = LE(z[32:64]) + kR  (mod 2^256)
    component rzR = RevByteBits(256);
    for (i = 0; i < 256; i++) { rzR.in[i] <== hz.out[256 + i]; }
    component ar = LEAdd256();
    for (i = 0; i < 256; i++) { ar.a[i] <== rzR.out[i]; }
    for (i = 0; i < 256; i++) { ar.b[i] <== kR[i]; }
    for (i = 0; i < 256; i++) { nkR[i] <== ar.out[i]; }

    // ncc = hc.out bytes 32..63 (big-endian stream) -> LE bits
    component rcC = RevByteBits(256);
    for (i = 0; i < 256; i++) { rcC.in[i] <== hc.out[256 + i]; }
    for (i = 0; i < 256; i++) { ncc[i] <== rcC.out[i]; }
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

    var i;

    component rkL = RevByteBits(256);
    component rkR = RevByteBits(256);
    component rcc = RevByteBits(256);
    component ridx = RevByteBits(32);
    component rAp = RevByteBits(256);
    for (i = 0; i < 256; i++) { rkL.in[i] <== kL[i]; rkR.in[i] <== kR[i]; rcc.in[i] <== cc[i]; rAp.in[i] <== Ap[i]; }
    for (i = 0; i < 32; i++)  { ridx.in[i] <== idx[i]; }

    // hmac(K=cc, msg = tag(8) || Ap(256) || idx(32))   -> 296 bits
    signal mz[296];
    for (i = 0; i < 8; i++) { mz[i] <== (i == 6) ? 1 : 0; }  // tag 0x02 (big-endian byte)
    for (i = 0; i < 256; i++) { mz[8 + i] <== rAp.out[i]; }
    for (i = 0; i < 32; i++)  { mz[264 + i] <== ridx.out[i]; }

    signal mc[296];
    for (i = 0; i < 8; i++) { mc[i] <== (i == 6 || i == 7) ? 1 : 0; }  // tag 0x03
    for (i = 0; i < 256; i++) { mc[8 + i] <== rAp.out[i]; }
    for (i = 0; i < 32; i++)  { mc[264 + i] <== ridx.out[i]; }

    component hz = HmacSha512(296);
    for (i = 0; i < 256; i++) { hz.key[i] <== rcc.out[i]; }
    for (i = 0; i < 296; i++) { hz.msg[i] <== mz[i]; }

    component hc = HmacSha512(296);
    for (i = 0; i < 256; i++) { hc.key[i] <== rcc.out[i]; }
    for (i = 0; i < 296; i++) { hc.msg[i] <== mc[i]; }

    component rzL = RevByteBits(224);
    for (i = 0; i < 224; i++) { rzL.in[i] <== hz.out[i]; }
    component ml = Mul8L224();
    for (i = 0; i < 224; i++) { ml.val[i] <== rzL.out[i]; }
    component al = LEAdd256();
    for (i = 0; i < 256; i++) { al.a[i] <== ml.out[i]; }
    for (i = 0; i < 256; i++) { al.b[i] <== kL[i]; }
    for (i = 0; i < 256; i++) { nkL[i] <== al.out[i]; }

    component rzR = RevByteBits(256);
    for (i = 0; i < 256; i++) { rzR.in[i] <== hz.out[256 + i]; }
    component ar = LEAdd256();
    for (i = 0; i < 256; i++) { ar.a[i] <== rzR.out[i]; }
    for (i = 0; i < 256; i++) { ar.b[i] <== kR[i]; }
    for (i = 0; i < 256; i++) { nkR[i] <== ar.out[i]; }

    component rcC = RevByteBits(256);
    for (i = 0; i < 256; i++) { rcC.in[i] <== hc.out[256 + i]; }
    for (i = 0; i < 256; i++) { ncc[i] <== rcC.out[i]; }
}