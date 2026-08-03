pragma circom 2.0.0;

// PoseidonMerkle — Nova IVC step circuit (one Merkle level per step).
//
//   state_out = Poseidon(switch(state_in, sibling, direction))
//
// A chain of `depth` steps walks a leaf commitment up to the root.  The
// leaf commitment itself is hashed off-chain into the initial state, so
// every step is identical.  The public input is exactly the state
// (n_pub_in == n_pub_out == 1).

include "../PoseidonMerkle/poseidon_merkle.circom";

template PoseidonMerkleStep() {
    signal input state_in;
    signal input sibling;
    signal input direction;
    signal output state_out;

    component sw = SelectiveSwitch();
    sw.in0 <== state_in;
    sw.in1 <== sibling;
    sw.s   <== direction;

    component hasher = PoseidonBLS12_381();
    hasher.in0 <== sw.out0;
    hasher.in1 <== sw.out1;
    state_out <== hasher.out;
}

component main {public [state_in]} = PoseidonMerkleStep();
