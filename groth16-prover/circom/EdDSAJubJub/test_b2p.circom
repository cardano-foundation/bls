/*
 * Test circuit for JubJub point decompression only.
 * Decompresses 256-bit encoding → point, verifying curve equation + sign bit.
 *
 * The prover must provide x as an additional input.
 */
pragma circom 2.0.0;

include "pointbits_jubjub.circom";

component main = Bits2Point_Strict_JubJub();
