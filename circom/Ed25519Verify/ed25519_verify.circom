pragma circom 2.0.0;

// Ed25519 signature verification — top-level circuit
//
// Public inputs:  A[256], R8[256], msg[n]
// Private inputs: S[255], PointA[4][3], PointR[4][3]
// Output:         out (1 = valid, 0 = invalid)
//
// This circuit proves that an Ed25519 signature (R8, S) on message msg
// is valid under public key A, without revealing S, PointA, or PointR.
//
// Reference: Electron-Labs/ed25519-circom (archived, MIT License)
// Adapted for BLS12-381.

include "verify.circom";

template Ed25519Verify(n) {
    signal input msg[n];
    signal input A[256];
    signal input R8[256];
    signal input S[255];
    signal input PointA[4][3];
    signal input PointR[4][3];
    signal output out;

    component verifier = Ed25519Verifier(n);
    verifier.msg <== msg;
    verifier.A <== A;
    verifier.R8 <== R8;
    verifier.S <== S;
    verifier.PointA <== PointA;
    verifier.PointR <== PointR;

    out <== verifier.out;
}

// Instantiate with n = 256 bits (32-byte message)
component main {public [msg, A, R8]} = Ed25519Verify(256);
