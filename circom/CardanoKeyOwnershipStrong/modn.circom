/*
 * Reduce a 256-bit little-endian signal to its residue modulo the Ed25519
 * subgroup order n = 2^252 + 27742317777372353535851937790883648493.
 *
 * Uses r = s - n when s >= n, else s.  The comparison is carried out as a
 * 256-bit addition of s with m = 2^256 - n (mod 2^256): the carry-out c is 1
 * exactly when s >= n, and the low 256 bits of the sum are s - n (mod 2^256).
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "./binsum_alt.circom";

template ModN256() {
    signal input s[256];
    signal output r[256];

    // m = (2^256 - n) mod 2^256, little-endian bits (fixed constant).
    var M[256] = [1, 1, 0, 0, 1, 0, 0, 0,
                  0, 0, 1, 1, 0, 1, 0, 0,
                  0, 1, 0, 1, 0, 0, 0, 0,
                  1, 1, 0, 0, 0, 1, 0, 1,
                  1, 0, 1, 0, 0, 1, 1, 1,
                  0, 0, 1, 1, 1, 0, 0, 1,
                  1, 0, 1, 1, 0, 1, 1, 1,
                  1, 1, 1, 0, 0, 1, 0, 1,
                  1, 0, 0, 1, 0, 1, 0, 0,
                  1, 1, 0, 0, 0, 1, 1, 0,
                  0, 0, 0, 1, 0, 0, 0, 0,
                  1, 0, 1, 1, 1, 0, 1, 0,
                  1, 0, 0, 0, 0, 1, 0, 0,
                  0, 1, 1, 0, 0, 0, 0, 0,
                  1, 0, 0, 0, 0, 1, 0, 0,
                  1, 1, 0, 1, 0, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1, 1, 1, 1,
                  1, 1, 1, 1, 0, 1, 1, 1];

    var i;

    // add s + m, capture the carry-out as the s >= n indicator
    signal sum[256];
    component fa[256];
    for (i = 0; i < 256; i++) {
        fa[i] = FullAdder();
        fa[i].a <== s[i];
        fa[i].b <== M[i];
        if (i == 0) { fa[i].cin <== 0; }
        else { fa[i].cin <== fa[i - 1].cout; }
        sum[i] <== fa[i].s;
    }
    signal c;
    c <== fa[255].cout;

    signal d[256];
    for (i = 0; i < 256; i++) {
        d[i] <== c * sum[i];
        r[i] <== d[i] + s[i] - c * s[i];
    }
}