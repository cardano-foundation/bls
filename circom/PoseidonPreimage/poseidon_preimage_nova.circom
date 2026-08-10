pragma circom 2.0.0;

// PoseidonPreimage — Nova IVC step circuit (hash chain).
//
//   state_out = PoseidonBLS12_381(state_in, chunk)
//
// A chain of N steps hashes N secret chunks.  The public input is exactly
// the state, so the CLI chain rule state_in[i+1] == state_out[i] holds
// (n_pub_in == n_pub_out).

include "poseidon_bls12_381.circom";

template PoseidonPreimageStep() {
    signal input state_in;
    signal input chunk;
    signal output state_out;

    component hasher = PoseidonBLS12_381();
    hasher.in0 <== state_in;
    hasher.in1 <== chunk;
    state_out <== hasher.out;
}

component main {public [state_in]} = PoseidonPreimageStep();
