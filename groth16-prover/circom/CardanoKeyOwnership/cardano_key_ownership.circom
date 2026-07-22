/*
 * Cardano Key Ownership Proof — JubJub variant.
 *
 * Proves knowledge of a private scalar `sk` such that:
 *   pk = [sk] · G_JubJub
 * where G_JubJub is the standard JubJub base point embedded in BLS12-381.
 *
 * Public inputs:  pk_x, pk_y (the JubJub public key coordinates)
 * Private input: sk (the scalar)
 *
 * This is NOT a proof of ownership of a standard Cardano Ed25519 key
 * (Curve25519 arithmetic is incompatible with BLS12-381). Instead,
 * it proves ownership of a JubJub key that can be linked to a Cardano
 * identity via an off-chain commitment.
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "bitify.circom";
include "jubjub.circom";
include "scalarmul_jubjub.circom";

template CardanoKeyOwnership() {
    signal input sk;
    signal input pk_x;
    signal input pk_y;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    component skBits = Num2Bits(254);
    skBits.in <== sk;

    component pkMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        pkMul.e[i] <== skBits.out[i];
    }

    pkMul.out[0] === pk_x;
    pkMul.out[1] === pk_y;
}

component main {public [pk_x, pk_y]} = CardanoKeyOwnership();
