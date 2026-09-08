/*
 * Cardano Ed25519 public key from a 256-bit little-endian scalar.
 *
 * ScalarMul (fixed base G, from Ed25519Verify) only accepts 255 bits, so a
 * 256-bit scalar s is handled as s = (s & 2^255-1) + b*2^255:
 *   [s]G = [(s mod 2^255)]G  +  b * [2^255]G
 * and the fixed point H2 = [2^255]G is conditionally added when bit 255 is
 * set. [2^255]G was computed with reference point arithmetic.
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "../Ed25519Verify/scalarmul.circom";
include "../Ed25519Verify/pointcompress.circom";

template Ed25519Pub256() {
    signal input s[256];
    signal output apk[256];
    signal output P[4][3];

    // Curve25519 base point G in extended coordinates [X, Y, Z, T]
    // with base-2^85 chunks (3 chunks of 85 bits each).
    var G[4][3] = [[6836562328990639286768922, 21231440843933962135602345, 10097852978535018773096760],
                   [7737125245533626718119512, 23211375736600880154358579, 30948500982134506872478105],
                   [1, 0, 0],
                   [20943500354259764865654179, 24722277920680796426601402, 31289658119428895172835987]
                  ];

    // Fixed point H2 = [2^255]G (computed beforehand with reference arithmetic).
    var H2[4][3] = [[29350205944995946125508871, 33737606821838887153209739, 10996217138619443686565997],
                    [35447127680470390673213308, 5130538174559635423766846, 5883621750166418855424256],
                    [29245779687662048857324109, 15119968157073566121245641, 34782622270892083339930079],
                    [6607081396515208725147512, 36167356812356090657982215, 25123133767894672193830853]
                   ];

    var i;
    var j;

    component pm = ScalarMul();
    for (i = 0; i < 255; i++) {
        pm.s[i] <== s[i];
    }
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 3; j++) {
            pm.P[i][j] <== G[i][j];
        }
    }

    // Add H2 if bit 255 is set.
    component addH2 = PointAdd();
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 3; j++) {
            addH2.P[i][j] <== pm.sP[i][j];
            addH2.Q[i][j] <== H2[i][j];
        }
    }

    component pick = Multiplexor2();
    pick.sel <== s[255];
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 3; j++) {
            pick.in[0][i][j] <== pm.sP[i][j];
            pick.in[1][i][j] <== addH2.R[i][j];
        }
    }

    component cp = PointCompress();
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 3; j++) {
            cp.P[i][j] <== pick.out[i][j];
        }
    }
    for (i = 0; i < 256; i++) {
        apk[i] <== cp.out[i];
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 3; j++) {
            P[i][j] <== pick.out[i][j];
        }
    }
}