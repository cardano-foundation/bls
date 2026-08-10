pragma circom 2.0.0;

// Cardano Ed25519 Key Ownership — proves knowledge of private scalar sk
// such that PointA = [sk]·G on Curve25519, and that PointA compresses to A.
//
// Public inputs:  A[256] — compressed Ed25519 public key bits
// Private inputs: sk[255] — private scalar bits
//                 PointA[4][3] — decompressed public key in extended coordinates
// Output:         out (1 = valid, 0 = invalid)
//
// This is a minimal subset of Ed25519Verify: only scalar multiplication
// on the base point G plus point compression check. No SHA-512, no signature.
//
// Uses templates from Ed25519Verify (Electron-Labs/ed25519-circom, MIT License)

include "../Ed25519Verify/scalarmul.circom";
include "../Ed25519Verify/pointcompress.circom";
include "../Ed25519Verify/verify.circom";  // for PointEqual template

template CardanoEd25519Ownership() {
    signal input A[256];
    signal input sk[255];
    signal input PointA[4][3];
    signal output out;

    // Curve25519 base point G in extended coordinates [X, Y, Z, T]
    // with base-2^85 chunks (3 chunks of 85 bits each)
    var G[4][3] = [[6836562328990639286768922, 21231440843933962135602345, 10097852978535018773096760],
                   [7737125245533626718119512, 23211375736600880154358579, 30948500982134506872478105],
                   [1, 0, 0],
                   [20943500354259764865654179, 24722277920680796426601402, 31289658119428895172835987]
                  ];

    var i;
    var j;

    // 1. Compute [sk]·G
    component pMul = ScalarMul();
    for(i=0; i<255; i++) {
        pMul.s[i] <== sk[i];
    }
    for(i=0; i<4; i++) {
        for(j=0; j<3; j++) {
            pMul.P[i][j] <== G[i][j];
        }
    }

    // 2. Assert [sk]·G == PointA using projective coordinate equality
    // (PointEqual compares X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1)
    component equal = PointEqual();
    for(i=0; i<3; i++) {
        for(j=0; j<3; j++) {
            equal.p[i][j] <== pMul.sP[i][j];   // X, Y, Z of computed point
            equal.q[i][j] <== PointA[i][j];     // X, Y, Z of provided point
        }
    }

    // 3. Compress PointA and assert it equals A
    component compressA = PointCompress();
    for(i=0; i<4; i++) {
        for(j=0; j<3; j++) {
            compressA.P[i][j] <== PointA[i][j];
        }
    }

    for(i=0; i<256; i++) {
        compressA.out[i] === A[i];
    }

    // 4. Output validity
    out <== equal.out;
}

component main {public [A]} = CardanoEd25519Ownership();
