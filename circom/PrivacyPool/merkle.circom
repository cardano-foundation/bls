pragma circom 2.0.0;

// Reusable Poseidon Merkle membership over a caller-supplied leaf.
//
// Walks `depth` levels from the leaf to the root, hashing the running value
// with each sibling using PoseidonBLS12_381.  `direction[i] == 1` means the
// sibling is on the left.
//
// Unlike circom/PoseidonMerkle (which hardcodes the leaf as
// Poseidon(nullifier, nonce)), this template lets the caller pass the exact
// leaf — e.g. a note commitment from note.circom.

include "../PoseidonPreimage/poseidon_bls12_381.circom";

template IfThenElse() {
    signal input condition;
    signal input true_value;
    signal input false_value;
    signal output out;

    condition * (1 - condition) === 0;

    signal helper;
    helper <== condition * (true_value - false_value);
    out <== helper + false_value;
}

template SelectiveSwitch() {
    signal input in0;
    signal input in1;
    signal input s;
    signal output out0;
    signal output out1;

    component ifthen0 = IfThenElse();
    ifthen0.condition <== s;
    ifthen0.true_value <== in1;
    ifthen0.false_value <== in0;
    out0 <== ifthen0.out;

    component ifthen1 = IfThenElse();
    ifthen1.condition <== s;
    ifthen1.true_value <== in0;
    ifthen1.false_value <== in1;
    out1 <== ifthen1.out;
}

template PoseidonMerklePath(depth) {
    signal input leaf;                       // caller-supplied leaf commitment
    signal input root;                       // public tree root
    signal input sibling[depth];             // siblings leaf->root
    signal input direction[depth];           // 1 if sibling on the left

    component hashers[depth];
    component switches[depth];

    signal current[depth + 1];
    current[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        switches[i] = SelectiveSwitch();
        switches[i].in0 <== current[i];
        switches[i].in1 <== sibling[i];
        switches[i].s <== direction[i];

        hashers[i] = PoseidonBLS12_381();
        hashers[i].in0 <== switches[i].out0;
        hashers[i].in1 <== switches[i].out1;

        current[i + 1] <== hashers[i].out;
    }

    root === current[depth];
}
