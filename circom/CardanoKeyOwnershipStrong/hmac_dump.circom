/*
 * Diagnostic: dump the in-circuit HMAC digest for a hardened step and the
 * adder outputs, so the exact divergence from reference python can be seen.
 */
pragma circom 2.0.0;

include "ckd_cardano.circom";

template HmacDump() {
    signal input kL[256];
    signal input kR[256];
    signal input cc[256];
    signal input idx[32];
    signal output dzin[512];    // inner Sha512 digest
    signal output dz[512];      // Z  = HMAC(cc, 0x00||kL||kR||idx)
    signal output dout;

    component rkL = RevByteBits(256);
    component rkR = RevByteBits(256);
    component rcc = RevByteBits(256);
    component ridx = RevByteBits(32);
    var i;
    for (i = 0; i < 256; i++) { rkL.in[i] <== kL[i]; rkR.in[i] <== kR[i]; rcc.in[i] <== cc[i]; }
    for (i = 0; i < 32; i++)  { ridx.in[i] <== idx[i]; }

    signal mz[552];
    for (i = 0; i < 8; i++) { mz[i] <== 0; }
    for (i = 0; i < 256; i++) { mz[8 + i] <== rkL.out[i]; }
    for (i = 0; i < 256; i++) { mz[264 + i] <== rkR.out[i]; }
    for (i = 0; i < 32; i++)  { mz[520 + i] <== ridx.out[i]; }

    // inner = SHA512( (cc||0*96) ^ ipad || mz )   -- 128-byte key block + 69-byte msg
    signal inner[1576];
    for (i = 0; i < 1024; i++) {
        var b = i \ 8;
        var bit = i % 8;
        if (b < 32) {
            inner[i] <== rcc.out[i] + (0x36 >> bit) - 2 * (0x36 >> bit) * rcc.out[i];
        } else {
            inner[i] <== (0x36 >> bit) & 1;
        }
    }
    for (i = 0; i < 552; i++) { inner[1024 + i] <== mz[i]; }

    component s1 = Sha512(1576);
    for (i = 0; i < 1576; i++) { s1.in[i] <== inner[i]; }
    for (i = 0; i < 512; i++)  { dzin[i] <== s1.out[i]; }

    // outer = SHA512( (cc||0*96) ^ opad || inner_digest )
    signal outer[1536];
    for (i = 0; i < 1024; i++) {
        var b2 = i \ 8;
        var bit2 = i % 8;
        if (b2 < 32) {
            outer[i] <== rcc.out[i] + (0x5c >> bit2) - 2 * (0x5c >> bit2) * rcc.out[i];
        } else {
            outer[i] <== (0x5c >> bit2) & 1;
        }
    }
    for (i = 0; i < 512; i++) { outer[1024 + i] <== s1.out[i]; }

    component s2 = Sha512(1536);
    for (i = 0; i < 1536; i++) { s2.in[i] <== outer[i]; }
    for (i = 0; i < 512; i++)  { dz[i] <== s2.out[i]; }

    dout <== 1;
}

component main = HmacDump();