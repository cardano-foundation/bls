pragma circom 2.0.0;

include "../PoseidonPreimage/poseidon_bls12_381.circom";

/**
 * Poseidon-based Merkle membership proof.
 *
 * Verifies that H(nullifier, nonce) is present in a Merkle tree of the
 * given depth, summarized by the public digest.  The path is witnessed by
 * sibling hashes and direction bits (0 = sibling is on the right, 1 = sibling
 * is on the left), ordered from leaf to root.
 */

/*
 * IfThenElse sets `out` to `true_value` if `condition` is 1 and to
 * `false_value` if `condition` is 0.  Enforces that `condition` is binary.
 */
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

/*
 * SelectiveSwitch takes two inputs and produces two outputs.  If `s` is 1,
 * the order is swapped; if `s` is 0, the order is preserved.  Enforces that
 * `s` is binary.
 */
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

/*
 * Verifies that PoseidonBLS12_381(nullifier, nonce) is a leaf of the Merkle
 * tree whose root is `digest`.  The tree has `depth` levels above the leaves.
 *
 * Inputs:
 *   digest: public root of the Merkle tree.
 *   nullifier: private leaf secret.
 *   nonce: private leaf secret.
 *   sibling[depth]: private sibling at each level from leaf to root.
 *   direction[depth]: private direction bit at each level (1 = sibling left).
 */
template PoseidonMerkle(depth) {
    signal input digest;
    signal input nullifier;
    signal input nonce;
    signal input sibling[depth];
    signal input direction[depth];

    // Compute commitment = Poseidon(nullifier, nonce)
    component commitmentHasher = PoseidonBLS12_381();
    commitmentHasher.in0 <== nullifier;
    commitmentHasher.in1 <== nonce;
    signal commitment;
    commitment <== commitmentHasher.out;

    // Walk up the Merkle path
    component hashers[depth];
    component switches[depth];

    signal current[depth + 1];
    current[0] <== commitment;

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

    // Public root must equal the computed root
    digest === current[depth];
}
