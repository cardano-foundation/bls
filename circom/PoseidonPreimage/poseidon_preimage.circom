pragma circom 2.0.0;

include "poseidon_bls12_381.circom";

/**
 * Poseidon Hash Pre-image Proof.
 *
 * Proves knowledge of a secret `pre_image` such that
 *     hash_commitment = PoseidonBLS12_381(pre_image, 0)
 *
 * The Poseidon permutation uses BLS12-381 parameters (t=3, alpha=5, RF=8, RP=57)
 * with the second input fixed to 0.
 *
 * Public input:  hash_commitment
 * Private input: pre_image
 */

template PoseidonPreimage() {
    signal input pre_image;
    signal input hash_commitment;

    component hasher = PoseidonBLS12_381();
    hasher.in0 <== pre_image;
    hasher.in1 <== 0;

    hash_commitment === hasher.out;
}

component main {public [hash_commitment]} = PoseidonPreimage();
