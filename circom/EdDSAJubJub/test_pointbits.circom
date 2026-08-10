/*
 * Test circuit for JubJub point compression/decompression.
 * Round-trip: compress point → bits → decompress → verify same point.
 *
 * The prover must provide x as an additional input for decompression.
 */
pragma circom 2.0.0;

include "pointbits_jubjub.circom";

template TestPointbits() {
    signal input x;
    signal input y;

    // Compress
    component p2b = Point2Bits_Strict_JubJub();
    p2b.in[0] <== x;
    p2b.in[1] <== y;

    // Decompress — prover provides x as input
    component b2p = Bits2Point_Strict_JubJub();
    for (var i = 0; i < 256; i++) {
        b2p.in[i] <== p2b.out[i];
    }
    b2p.x <== x;

    // Verify round-trip
    b2p.out[0] === x;
    b2p.out[1] === y;
}

component main = TestPointbits();
