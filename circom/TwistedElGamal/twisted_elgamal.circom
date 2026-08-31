pragma circom 2.0.0;

// Twisted ElGamal over JubJub — encryption circuit.
//
// Proves knowledge of message and randomness such that:
//   E = r * G       (ephemeral)
//   C = m * H + r * PK   (commitment)
//
// Where G is the JubJub base point (BASE8) and H = 2*G is a second
// independent generator.  In production H should be derived via a
// hash-to-curve construction; here we use the doubled base point for
// determinism and testability.
//
// The message lives in the exponent, so it must be small enough for
// brute-force discrete-log recovery (or used as a symmetric key).
//
// Coordinate field: BLS12-381 scalar field (same as the R1CS field).

// Include paths are resolved via the `-l` compiler flag; see README.
include "bitify.circom";
include "../EdDSAJubJub/jubjub_primitives.circom";
include "../EdDSAJubJub/escalarmulfix_jubjub.circom";
include "../EdDSAJubJub/scalarmul_jubjub.circom";

template TwistedElGamalEncrypt(nBits) {
    signal input message;          // message scalar (must be small for DL recovery)
    signal input randomness;       // randomness r
    signal input pk[2];            // recipient public key (x, y)

    signal output E[2];            // ephemeral ciphertext component
    signal output C[2];            // committed ciphertext component

    // JubJub base point G = BASE8
    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    // Second generator H = 2*G  (deterministic, on-curve)
    // Production deployments should replace this with hash-to-curve(G).
    var H[2] = [
        28470720865600895264575250048565445848783776096727055802752773414594395577565,
        22436823168302830732060329876357833227584559018655015131868680653136578255473
    ];

    // Decompose scalars into bits
    component mBits = Num2Bits(nBits);
    mBits.in <== message;

    component rBits = Num2Bits(nBits);
    rBits.in <== randomness;

    // E = r * G  (fixed-base scalar multiplication)
    component eMul = EscalarMulFixJubJub(nBits, BASE8);
    for (var i = 0; i < nBits; i++) {
        eMul.e[i] <== rBits.out[i];
    }
    E[0] <== eMul.out[0];
    E[1] <== eMul.out[1];

    // mH = message * H  (fixed-base scalar multiplication)
    component mhMul = EscalarMulFixJubJub(nBits, H);
    for (var i = 0; i < nBits; i++) {
        mhMul.e[i] <== mBits.out[i];
    }

    // rPK = randomness * PK  (variable-base scalar multiplication)
    component rpkMul = EscalarMulAnyJubJub(nBits);
    for (var i = 0; i < nBits; i++) {
        rpkMul.e[i] <== rBits.out[i];
    }
    rpkMul.p[0] <== pk[0];
    rpkMul.p[1] <== pk[1];

    // C = mH + rPK  (point addition)
    component adder = JubJubAdd();
    adder.x1 <== mhMul.out[0];
    adder.y1 <== mhMul.out[1];
    adder.x2 <== rpkMul.out[0];
    adder.y2 <== rpkMul.out[1];
    C[0] <== adder.xout;
    C[1] <== adder.yout;
}

// Convenience wrapper that also proves the ciphertext decrypts correctly.
// Decryption check:  C - sk*E  ==  m*H
// The holder supplies sk; the verifier checks the equation.
template TwistedElGamalDecrypt(nBits) {
    signal input sk;               // secret key
    signal input E[2];             // ephemeral
    signal input C[2];             // commitment
    signal input message;          // claimed plaintext

    // Reconstruct m*H
    component mBits = Num2Bits(nBits);
    mBits.in <== message;

    var H[2] = [
        28470720865600895264575250048565445848783776096727055802752773414594395577565,
        22436823168302830732060329876357833227584559018655015131868680653136578255473
    ];

    component mhMul = EscalarMulFixJubJub(nBits, H);
    for (var i = 0; i < nBits; i++) {
        mhMul.e[i] <== mBits.out[i];
    }

    // Compute sk*E
    component skBits = Num2Bits(nBits);
    skBits.in <== sk;

    component skEMul = EscalarMulAnyJubJub(nBits);
    for (var i = 0; i < nBits; i++) {
        skEMul.e[i] <== skBits.out[i];
    }
    skEMul.p[0] <== E[0];
    skEMul.p[1] <== E[1];

    // Negate sk*E  (twisted Edwards negation: (-x, y))
    component adder = JubJubAdd();
    adder.x1 <== C[0];
    adder.y1 <== C[1];
    adder.x2 <== -skEMul.out[0];
    adder.y2 <== skEMul.out[1];

    // Verify C - sk*E == m*H
    adder.xout === mhMul.out[0];
    adder.yout === mhMul.out[1];
}

// Main: encrypt a 32-bit message with a random 254-bit randomness.
component main {public [pk]} = TwistedElGamalEncrypt(254);
