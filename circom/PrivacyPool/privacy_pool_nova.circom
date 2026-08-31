pragma circom 2.0.0;

// Privacy pool — Nova IVC step circuit (one Merkle level per step).
//
//   state_out = Poseidon(switch(state_in, sibling, direction))
//
// A chain of `depth` steps walks an input note's commitment (computed
// off-chain with NoteCommitment from note.circom) up to the Merkle root.
// The public input is exactly the running state (n_pub_in == n_pub_out == 1),
// matching the nova-slim verifier's expectations.
//
// Validating the last step's state_out against merkle_root, plus the range /
// conservation / nullifier / output-commitment constraints, is handled by a
// thin terminal step in a production pool; here the chain demonstrates the
// Merkle-membership fold whose witness is the dominant cost.

include "../PoseidonPreimage/poseidon_bls12_381.circom";

template PrivacyPoolStep() {
    signal input state_in;       // running Merkle node
    signal input sibling;        // sibling at this level
    signal input direction;      // 1 if sibling is on the left
    signal output state_out;     // hashed node

    // if direction == 1, item is the right child, so the sibling is the
    // left input: hash = Poseidon(sibling, item).
    signal a;
    signal b;
    a <== (sibling - state_in) * direction + state_in;   // a = direction ? sibling : state_in
    b <== (state_in - sibling) * direction + sibling;    // b = direction ? state_in : sibling

    component hasher = PoseidonBLS12_381();
    hasher.in0 <== a;
    hasher.in1 <== b;
    state_out <== hasher.out;
}

component main {public [state_in]} = PrivacyPoolStep();
