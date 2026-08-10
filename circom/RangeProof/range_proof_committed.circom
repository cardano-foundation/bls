pragma circom 2.0.0;

// Committed range proof — prove that value ∈ [0, 2^n) AND
// commitment == Poseidon(value, blinding_factor)
//
// Public input:  commitment
// Private inputs: value, blinding_factor
// Public output: valid (always 1 if constraints are satisfied)
//
// The prover reveals only the commitment. The value and blinding factor
// remain secret. The verifier checks:
// 1. The commitment was correctly formed from the hidden value and blinding factor.
// 2. The hidden value fits within n bits (i.e., is non-negative and less than 2^n).

include "./node_modules/circomlib/circuits/bitify.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";

template RangeProofCommitted(n) {
    signal input commitment;
    signal input value;
    signal input blinding_factor;
    signal output valid;

    // 1. Range proof: value fits in n bits
    component n2b = Num2Bits(n);
    n2b.in <== value;

    // 2. Commitment check: commitment == Poseidon(value, blinding_factor)
    component poseidon = PoseidonBLS12_381();
    poseidon.in0 <== value;
    poseidon.in1 <== blinding_factor;
    poseidon.out === commitment;

    valid <== 1;
}

// Instantiate with n = 32 (32-bit unsigned integer range)
component main {public [commitment]} = RangeProofCommitted(32);
