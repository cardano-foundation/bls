/*
 * Fully inlined, component-free SHA-512 compression (replaces the
 * componentised sha512compression.circom with a signal-based equivalent
 * using the same bit conventions).
 *
 *   - each 64-bit word is stored LSB-first,
 *   - ROTR(r) feeds output bit i from input bit (i+r)%64,
 *   - schedule: w[t>=16] = sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16],
 *   - t1 = h + Sigma1(e) + ch(e,f,g) + K + w,
 *   - t2 = Maj(a,b,c) + Sigma0(a),
 *   - outgoing block is bit-reversed within each word (MSB-first).
 *
 * Summation strategy (quadratic-only constraints, no components, no
 * division hints):
 *   - every carry bit is computed DIRECTLY from its input bits:
 *       carry2(a,b) = a*b        (single AND)
 *       carry3(a,b,c) = ab + ac + bc - 2*abc   (majority)
 *   - a 3-operand carry-save fold is column-local: parity = xor3(a,b,c)
 *     (pinned by its own <== chain), carry = carry3 (pinned by inputs), so
 *        a+b+c = parity + 2*carryWord
 *   - folding N addends down to (parity, ...) accumulates carry streams, so a
 *     sum is finished as:  value = lastParity + 2*(sum of all carryWords);
 *   - 2-operand binary adds are plain ripples (majority carry chains).
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "sha512/constants.circom";

function K512w(x, bitLoc) {
    var c[80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ];
    return (c[x] >> bitLoc) & 1;
}

template Sha512compressionF() {
    signal input hin[512];
    signal input inp[1024];
    signal output out[512];

    var k;
    var r;

    // working state after r rounds: st[0] = hin
    signal st[81][8][64];
    for (k = 0; k < 64; k++) {
        st[0][0][k] <== hin[1 * 0 + k];
        st[0][1][k] <== hin[1 * 64 + k];
        st[0][2][k] <== hin[2 * 64 + k];
        st[0][3][k] <== hin[3 * 64 + k];
        st[0][4][k] <== hin[4 * 64 + k];
        st[0][5][k] <== hin[5 * 64 + k];
        st[0][6][k] <== hin[6 * 64 + k];
        st[0][7][k] <== hin[7 * 64 + k];
    }

    // message schedule words (LSB-first words, read reversed from the block)
    signal wAt[81][64];
    for (r = 0; r < 16; r++) {
        for (k = 0; k < 64; k++) {
            wAt[r][k] <== inp[r * 64 + 63 - k];
        }
    }

    // per-round scratch
    signal sg1[81][64];
    signal sg1b[81][64];
    signal chn[81][64];
    signal s0v[81][64];
    signal s0vb[81][64];
    signal mjv[81][64];
    signal mjmid[81][64];
    signal ws1[81][64];
    signal ws1b[81][64];
    signal ws0[81][64];
    signal ws0b[81][64];
    signal sw1sh[81][64];
    signal sw0sh[81][64];
    signal p1[81][64];
    signal p1b[81][64];
    signal c1c[81][65];
    signal cabA[81][64];
    signal caxA[81][64];
    signal cbyA[81][64];
    signal p2[81][64];
    signal p2b[81][64];
    signal c2c[81][65];
    signal cabB[81][64];
    signal caxB[81][64];
    signal cbyB[81][64];
    signal wp1[81][64];
    signal wp1b[81][64];
    signal wc1c[81][65];
    signal cabW[81][64];
    signal caxW[81][64];
    signal cbyW[81][64];

    // schedule shift-ripple (wp1b + 2*wc1c) then + w16
    signal wv[81][64];
    signal wvc[81][64];
    signal wvm[81][64];
    signal wvq[81][64];
    signal wdc[81][64];
    signal wdm[81][64];
    signal wdq[81][64];

    // t1: accumulate carry words then shift-ripple final
signal tcp[81][64];
    signal tch[81][64];
    signal tcu[81][64];
    signal tcw[81][64];
    signal tqm[81][64];
    signal tqk[81][64];
    signal t1s[81][64];
    signal t1c[81][64];
    signal t2p[81][64];
    signal t2c[81][64];
    signal t2u[81][64];
    signal t2g[81][64];
    signal t2x[81][64];
    signal t2s[81][64];
    signal ep[81][64];
    signal ec[81][64];
    signal teg[81][64];
    signal esx[81][64];
    signal eu[81][64];
    signal es[81][64];
    signal ap[81][64];
    signal ac[81][64];
    signal tag[81][64];
    signal asx[81][64];
    signal au[81][64];
    signal as[81][64];

    // feedforward additions
    signal f0s[64];
    signal f1s[64];
    signal f2s[64];
    signal f3s[64];
    signal f4s[64];
    signal f5s[64];
    signal f6s[64];
    signal f7s[64];
    signal f0p[64];
    signal f1p[64];
    signal f2p[64];
    signal f3p[64];
    signal f4p[64];
    signal f5p[64];
    signal f6p[64];
    signal f7p[64];
    signal f0c[64];
    signal f1c[64];
    signal f2c[64];
    signal f3c[64];
    signal f4c[64];
    signal f5c[64];
    signal f6c[64];
    signal f7c[64];
    signal f0u[64];
    signal f1u[64];
    signal f2u[64];
    signal f3u[64];
    signal f4u[64];
    signal f5u[64];
    signal f6u[64];
    signal f7u[64];
    signal f0g[64];
    signal f1g[64];
    signal f2g[64];
    signal f3g[64];
    signal f4g[64];
    signal f5g[64];
    signal f6g[64];
    signal f7g[64];
    signal f0x[64];
    signal f1x[64];
    signal f2x[64];
    signal f3x[64];
    signal f4x[64];
    signal f5x[64];
    signal f6x[64];
    signal f7x[64];

    for (r = 1; r < 81; r++) {
        // ---- Sigma1(e), ch(e,f,g); Sigma0(a), Maj(a,b,c) ----
        for (k = 0; k < 64; k++) {
            sg1[r][k] <== st[r - 1][4][(k + 14) % 64] + st[r - 1][4][(k + 18) % 64] - 2 * st[r - 1][4][(k + 14) % 64] * st[r - 1][4][(k + 18) % 64];
            sg1b[r][k] <== sg1[r][k] + st[r - 1][4][(k + 41) % 64] - 2 * sg1[r][k] * st[r - 1][4][(k + 41) % 64];
            chn[r][k] <== st[r - 1][4][k] * (st[r - 1][5][k] - st[r - 1][6][k]) + st[r - 1][6][k];
            s0v[r][k] <== st[r - 1][0][(k + 28) % 64] + st[r - 1][0][(k + 34) % 64] - 2 * st[r - 1][0][(k + 28) % 64] * st[r - 1][0][(k + 34) % 64];
            s0vb[r][k] <== s0v[r][k] + st[r - 1][0][(k + 39) % 64] - 2 * s0v[r][k] * st[r - 1][0][(k + 39) % 64];
            mjmid[r][k] <== st[r - 1][1][k] * st[r - 1][2][k];
            mjv[r][k] <== st[r - 1][0][k] * (st[r - 1][1][k] + st[r - 1][2][k] - 2 * mjmid[r][k]) + mjmid[r][k];
        }

        // ---- message schedule word wAt[r] ----
        if (r >= 16) {
            // fold 1: (sigma1(w-2), w-7, sigma0(w-15)) -> (wp1b, wc1c)
            wc1c[r][0] <== 0;
            for (k = 0; k < 64; k++) {
                if (k + 6 < 64) {
                    sw1sh[r][k] <== wAt[r - 2][k + 6];
                } else {
                    sw1sh[r][k] <== 0;
                }
                if (k + 7 < 64) {
                    sw0sh[r][k] <== wAt[r - 15][k + 7];
                } else {
                    sw0sh[r][k] <== 0;
                }
                ws1[r][k] <== wAt[r - 2][(k + 19) % 64] + wAt[r - 2][(k + 61) % 64] - 2 * wAt[r - 2][(k + 19) % 64] * wAt[r - 2][(k + 61) % 64];
                ws1b[r][k] <== ws1[r][k] + sw1sh[r][k] - 2 * ws1[r][k] * sw1sh[r][k];
                ws0[r][k] <== wAt[r - 15][(k + 1) % 64] + wAt[r - 15][(k + 8) % 64] - 2 * wAt[r - 15][(k + 1) % 64] * wAt[r - 15][(k + 8) % 64];
                ws0b[r][k] <== ws0[r][k] + sw0sh[r][k] - 2 * ws0[r][k] * sw0sh[r][k];
                wp1[r][k] <== ws1b[r][k] + wAt[r - 7][k] - 2 * ws1b[r][k] * wAt[r - 7][k];
                wp1b[r][k] <== wp1[r][k] + ws0b[r][k] - 2 * wp1[r][k] * ws0b[r][k];
                                wc1c[r][k + 1] <-- (ws1b[r][k] + wAt[r - 7][k] + ws0b[r][k] - wp1b[r][k]) / 2;
                2 * wc1c[r][k + 1] + wp1b[r][k] === ws1b[r][k] + wAt[r - 7][k] + ws0b[r][k];
            }
            // shift-ripple: wv = wp1b + wc1c  (wc1c already left-shifted by the fold)
            wv[r][0] <== wp1b[r][0];
            wvc[r][0] <== 0;
            for (k = 1; k < 64; k++) {
                wvm[r][k] <== wc1c[r][k] * wvc[r][k - 1];
                wvq[r][k] <== wp1b[r][k] * (wc1c[r][k] + wvc[r][k - 1] - 2 * wvm[r][k]) + wvm[r][k];
                wvc[r][k] <== wvq[r][k];
                wv[r][k] <== wp1b[r][k] + wc1c[r][k] + wvc[r][k - 1] - 2 * wvq[r][k];
            }
            // ripple: wAt[r] = wv + wAt[r-16]
            wAt[r][0] <== wv[r][0] + wAt[r - 16][0] - 2 * wv[r][0] * wAt[r - 16][0];
            wdc[r][0] <== wv[r][0] * wAt[r - 16][0];
            for (k = 1; k < 64; k++) {
                wdm[r][k] <== wAt[r - 16][k] * wdc[r][k - 1];
                wdq[r][k] <== wv[r][k] * (wAt[r - 16][k] + wdc[r][k - 1] - 2 * wdm[r][k]) + wdm[r][k];
                wdc[r][k] <== wdq[r][k];
                wAt[r][k] <== wv[r][k] + wAt[r - 16][k] + wdc[r][k - 1] - 2 * wdq[r][k];
            }
        }

        // ---- t1 = h + Sigma1(e) + ch + K + w ----
        // Fold A (h, Sigma1(e), ch) -> (p1b, c1c); carry computed from inputs
        c1c[r][0] <== 0;
        for (k = 0; k < 64; k++) {
            p1[r][k] <== st[r - 1][7][k] + sg1b[r][k] - 2 * st[r - 1][7][k] * sg1b[r][k];
            p1b[r][k] <== p1[r][k] + chn[r][k] - 2 * p1[r][k] * chn[r][k];
                        c1c[r][k + 1] <-- (st[r - 1][7][k] + sg1b[r][k] + chn[r][k] - p1b[r][k]) / 2;
            2 * c1c[r][k + 1] + p1b[r][k] === st[r - 1][7][k] + sg1b[r][k] + chn[r][k];
        }
        c2c[r][0] <== 0;
        for (k = 0; k < 64; k++) {
            p2[r][k] <== p1b[r][k] + K512w(r - 1, k) - 2 * p1b[r][k] * K512w(r - 1, k);
            p2b[r][k] <== p2[r][k] + wAt[r - 1][k] - 2 * p2[r][k] * wAt[r - 1][k];
                        c2c[r][k + 1] <-- (p1b[r][k] + K512w(r - 1, k) + wAt[r - 1][k] - p2b[r][k]) / 2;
            2 * c2c[r][k + 1] + p2b[r][k] === p1b[r][k] + K512w(r - 1, k) + wAt[r - 1][k];
        }
        // accumulate carry words: tcw = c1c + c2c (full ripple with carry chain)
        tcp[r][0] <== c1c[r][0] + c2c[r][0] - 2 * c1c[r][0] * c2c[r][0];
        tch[r][0] <== c1c[r][0] * c2c[r][0];
        tcw[r][0] <== tcp[r][0];
        tcu[r][0] <== 0;
        for (k = 1; k < 64; k++) {
            tcp[r][k] <== c1c[r][k] + c2c[r][k] - 2 * c1c[r][k] * c2c[r][k];
            tch[r][k] <== c1c[r][k] * c2c[r][k];
            tcu[r][k] <== tch[r][k - 1] + tcp[r][k - 1] * tcu[r][k - 1];
            tcw[r][k] <== tcp[r][k] + tcu[r][k] - 2 * tcp[r][k] * tcu[r][k];
        }
        // final shift-ripple: t1 = p2b + tcw  (tcw already left-shifted by accumulation of
        // pre-shifted carry words c1c/c2c)
        t1s[r][0] <== p2b[r][0];
        t1c[r][0] <== 0;
        for (k = 1; k < 64; k++) {
            tqk[r][k] <== tcw[r][k] * t1c[r][k - 1];
            tqm[r][k] <== p2b[r][k] * (tcw[r][k] + t1c[r][k - 1] - 2 * tqk[r][k]) + tqk[r][k];
            t1c[r][k] <== tqm[r][k];
            t1s[r][k] <== p2b[r][k] + tcw[r][k] + t1c[r][k - 1] - 2 * tqm[r][k];
        }

        // ---- t2 = Maj(a,b,c) + Sigma0(a) ----
        for (k = 0; k < 64; k++) {
            t2p[r][k] <== mjv[r][k] + s0vb[r][k] - 2 * mjv[r][k] * s0vb[r][k];
            t2c[r][k] <== mjv[r][k] * s0vb[r][k];
        }
        t2s[r][0] <== t2p[r][0];
        t2u[r][0] <== 0;
        for (k = 1; k < 64; k++) {
            t2x[r][k] <== t2p[r][k] + t2c[r][k - 1] - 2 * t2p[r][k] * t2c[r][k - 1];
            if (k >= 2) {
                t2g[r][k] <== t2p[r][k - 1] * t2c[r][k - 2];
                t2u[r][k] <== t2g[r][k] + t2x[r][k - 1] * t2u[r][k - 1];
            } else {
                t2u[r][k] <== 0;
            }
            t2s[r][k] <== t2x[r][k] + t2u[r][k] - 2 * t2x[r][k] * t2u[r][k];
        }

        // ---- e' = d + t1 (full ripple) ; a' = t1 + t2 (full ripple) ----
        for (k = 0; k < 64; k++) {
            ep[r][k] <== st[r - 1][3][k] + t1s[r][k] - 2 * st[r - 1][3][k] * t1s[r][k];
            ec[r][k] <== st[r - 1][3][k] * t1s[r][k];
            ap[r][k] <== t1s[r][k] + t2s[r][k] - 2 * t1s[r][k] * t2s[r][k];
            ac[r][k] <== t1s[r][k] * t2s[r][k];
        }
        es[r][0] <== ep[r][0];
        eu[r][0] <== 0;
        as[r][0] <== ap[r][0];
        au[r][0] <== 0;
        for (k = 1; k < 64; k++) {
            esx[r][k] <== ep[r][k] + ec[r][k - 1] - 2 * ep[r][k] * ec[r][k - 1];
            asx[r][k] <== ap[r][k] + ac[r][k - 1] - 2 * ap[r][k] * ac[r][k - 1];
            if (k >= 2) {
                teg[r][k] <== ep[r][k - 1] * ec[r][k - 2];
                tag[r][k] <== ap[r][k - 1] * ac[r][k - 2];
                eu[r][k] <== teg[r][k] + esx[r][k - 1] * eu[r][k - 1];
                au[r][k] <== tag[r][k] + asx[r][k - 1] * au[r][k - 1];
            } else {
                eu[r][k] <== 0;
                au[r][k] <== 0;
            }
            es[r][k] <== esx[r][k] + eu[r][k] - 2 * esx[r][k] * eu[r][k];
            as[r][k] <== asx[r][k] + au[r][k] - 2 * asx[r][k] * au[r][k];
        }

        // ---- register rotation ----
        for (k = 0; k < 64; k++) {
            st[r][0][k] <== as[r][k];
            st[r][1][k] <== st[r - 1][0][k];
            st[r][2][k] <== st[r - 1][1][k];
            st[r][3][k] <== st[r - 1][2][k];
            st[r][4][k] <== es[r][k];
            st[r][5][k] <== st[r - 1][4][k];
            st[r][6][k] <== st[r - 1][5][k];
            st[r][7][k] <== st[r - 1][6][k];
        }
    }

    // ---- feedforward hin + state, word-reversed output ----
    for (k = 0; k < 64; k++) {
        f0p[k] <== hin[0 * 64 + k] + st[80][0][k] - 2 * hin[0 * 64 + k] * st[80][0][k];
        f1p[k] <== hin[1 * 64 + k] + st[80][1][k] - 2 * hin[1 * 64 + k] * st[80][1][k];
        f2p[k] <== hin[2 * 64 + k] + st[80][2][k] - 2 * hin[2 * 64 + k] * st[80][2][k];
        f3p[k] <== hin[3 * 64 + k] + st[80][3][k] - 2 * hin[3 * 64 + k] * st[80][3][k];
        f4p[k] <== hin[4 * 64 + k] + st[80][4][k] - 2 * hin[4 * 64 + k] * st[80][4][k];
        f5p[k] <== hin[5 * 64 + k] + st[80][5][k] - 2 * hin[5 * 64 + k] * st[80][5][k];
        f6p[k] <== hin[6 * 64 + k] + st[80][6][k] - 2 * hin[6 * 64 + k] * st[80][6][k];
        f7p[k] <== hin[7 * 64 + k] + st[80][7][k] - 2 * hin[7 * 64 + k] * st[80][7][k];
        f0c[k] <== hin[0 * 64 + k] * st[80][0][k];
        f1c[k] <== hin[1 * 64 + k] * st[80][1][k];
        f2c[k] <== hin[2 * 64 + k] * st[80][2][k];
        f3c[k] <== hin[3 * 64 + k] * st[80][3][k];
        f4c[k] <== hin[4 * 64 + k] * st[80][4][k];
        f5c[k] <== hin[5 * 64 + k] * st[80][5][k];
        f6c[k] <== hin[6 * 64 + k] * st[80][6][k];
        f7c[k] <== hin[7 * 64 + k] * st[80][7][k];
    }
    f0s[0] <== f0p[0];
    f1s[0] <== f1p[0];
    f2s[0] <== f2p[0];
    f3s[0] <== f3p[0];
    f4s[0] <== f4p[0];
    f5s[0] <== f5p[0];
    f6s[0] <== f6p[0];
    f7s[0] <== f7p[0];
    f0u[0] <== 0;
    f1u[0] <== 0;
    f2u[0] <== 0;
    f3u[0] <== 0;
    f4u[0] <== 0;
    f5u[0] <== 0;
    f6u[0] <== 0;
    f7u[0] <== 0;
    for (k = 1; k < 64; k++) {
        f0x[k] <== f0p[k] + f0c[k - 1] - 2 * f0p[k] * f0c[k - 1];
        f1x[k] <== f1p[k] + f1c[k - 1] - 2 * f1p[k] * f1c[k - 1];
        f2x[k] <== f2p[k] + f2c[k - 1] - 2 * f2p[k] * f2c[k - 1];
        f3x[k] <== f3p[k] + f3c[k - 1] - 2 * f3p[k] * f3c[k - 1];
        f4x[k] <== f4p[k] + f4c[k - 1] - 2 * f4p[k] * f4c[k - 1];
        f5x[k] <== f5p[k] + f5c[k - 1] - 2 * f5p[k] * f5c[k - 1];
        f6x[k] <== f6p[k] + f6c[k - 1] - 2 * f6p[k] * f6c[k - 1];
        f7x[k] <== f7p[k] + f7c[k - 1] - 2 * f7p[k] * f7c[k - 1];
        if (k >= 2) {
            f0g[k] <== f0p[k - 1] * f0c[k - 2];
            f1g[k] <== f1p[k - 1] * f1c[k - 2];
            f2g[k] <== f2p[k - 1] * f2c[k - 2];
            f3g[k] <== f3p[k - 1] * f3c[k - 2];
            f4g[k] <== f4p[k - 1] * f4c[k - 2];
            f5g[k] <== f5p[k - 1] * f5c[k - 2];
            f6g[k] <== f6p[k - 1] * f6c[k - 2];
            f7g[k] <== f7p[k - 1] * f7c[k - 2];
            f0u[k] <== f0g[k] + f0x[k - 1] * f0u[k - 1];
            f1u[k] <== f1g[k] + f1x[k - 1] * f1u[k - 1];
            f2u[k] <== f2g[k] + f2x[k - 1] * f2u[k - 1];
            f3u[k] <== f3g[k] + f3x[k - 1] * f3u[k - 1];
            f4u[k] <== f4g[k] + f4x[k - 1] * f4u[k - 1];
            f5u[k] <== f5g[k] + f5x[k - 1] * f5u[k - 1];
            f6u[k] <== f6g[k] + f6x[k - 1] * f6u[k - 1];
            f7u[k] <== f7g[k] + f7x[k - 1] * f7u[k - 1];
        } else {
            f0u[k] <== 0;
            f1u[k] <== 0;
            f2u[k] <== 0;
            f3u[k] <== 0;
            f4u[k] <== 0;
            f5u[k] <== 0;
            f6u[k] <== 0;
            f7u[k] <== 0;
        }
        f0s[k] <== f0x[k] + f0u[k] - 2 * f0x[k] * f0u[k];
        f1s[k] <== f1x[k] + f1u[k] - 2 * f1x[k] * f1u[k];
        f2s[k] <== f2x[k] + f2u[k] - 2 * f2x[k] * f2u[k];
        f3s[k] <== f3x[k] + f3u[k] - 2 * f3x[k] * f3u[k];
        f4s[k] <== f4x[k] + f4u[k] - 2 * f4x[k] * f4u[k];
        f5s[k] <== f5x[k] + f5u[k] - 2 * f5x[k] * f5u[k];
        f6s[k] <== f6x[k] + f6u[k] - 2 * f6x[k] * f6u[k];
        f7s[k] <== f7x[k] + f7u[k] - 2 * f7x[k] * f7u[k];
    }
    for (k = 0; k < 64; k++) {
        out[0 * 64 + 63 - k] <== f0s[k];
        out[1 * 64 + 63 - k] <== f1s[k];
        out[2 * 64 + 63 - k] <== f2s[k];
        out[3 * 64 + 63 - k] <== f3s[k];
        out[4 * 64 + 63 - k] <== f4s[k];
        out[5 * 64 + 63 - k] <== f5s[k];
        out[6 * 64 + 63 - k] <== f6s[k];
        out[7 * 64 + 63 - k] <== f7s[k];
    }
}