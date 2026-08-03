pragma circom 2.0.0;

// RangeProof — Nova IVC step circuit (committed), one bit per step.
//
//   b * (1 - b) === 0
//   acc_in === 2 * acc_out + b     (acc_out <-- (acc_in - b) \ 2)
//   idx_out <== idx_in + 1
//   Poseidon(acc_in, blinding_factor) === commitment
//   commitment_out <== commitment          (constant pass-through)
//
// The commitment is bound to the chain value: step 0 has acc_0 = value, so
// commitment = Poseidon(value, blinding_factor), and the chain ending at
// acc_n = 0 proves value < 2^n.  Public inputs ARE the state, in the same
// order as the outputs (n_pub_in == n_pub_out == 3): commitment + acc + idx.

include "../PoseidonPreimage/poseidon_bls12_381.circom";

template RangeCommittedStep() {
    signal input commitment;
    signal input acc_in;
    signal input idx_in;
    signal input blinding_factor;
    signal input b;

    signal output commitment_out;
    signal output acc_out;
    signal output idx_out;

    b * (1 - b) === 0;
    acc_out <-- (acc_in - b) \ 2;
    acc_in === 2 * acc_out + b;
    idx_out <== idx_in + 1;

    component poseidon = PoseidonBLS12_381();
    poseidon.in0 <== acc_in;
    poseidon.in1 <== blinding_factor;
    poseidon.out === commitment;

    commitment_out <== commitment;
}

component main {public [commitment, acc_in, idx_in]} = RangeCommittedStep();
