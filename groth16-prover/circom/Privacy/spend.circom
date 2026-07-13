include "./mimc.circom";

/*
 * IfThenElse sets `out` to `true_value` if `condition` is 1 and `out` to
 * `false_value` if `condition` is 0.
 *
 * It enforces that `condition` is 0 or 1.
 *
 */
template IfThenElse() {
    signal input condition;
    signal input true_value;
    signal input false_value;
    signal output out;

    // Enforce condition is binary
    condition * (1 - condition) === 0;

    // Helper signal for the quadratic term
    signal helper;
    helper <== condition * (true_value - false_value);

    // out = helper + false_value
    out <== helper + false_value;
}

/*
 * SelectiveSwitch takes two data inputs (`in0`, `in1`) and produces two outputs.
 * If the "select" (`s`) input is 1, then it inverts the order of the inputs
 * in the output. If `s` is 0, then it preserves the order.
 *
 * It enforces that `s` is 0 or 1.
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
 * Verifies the presence of H(`nullifier`, `nonce`) in the tree of depth
 * `depth`, summarized by `digest`.
 * This presence is witnessed by the additional inputs `sibling` and
 * `direction`, which have the following meaning:
 *   sibling[i]: the sibling of the node on the path to this coin
 *               commitment at the i'th level from the bottom.
 *   direction[i]: whether that sibling is on the left.
 *       The "sibling" keys correspond directly to the siblings in the
 *       SparseMerkleTree path.
 *       The "direction" keys the boolean directions from the SparseMerkleTree
 *       path, casted to string-represented integers ("0" or "1").
 */
template Spend(depth) {
    signal input digest;
    signal input nullifier;
    signal input nonce;
    signal input sibling[depth];
    signal input direction[depth];

    // Compute commitment = H(nullifier, nonce)
    component commitmentHasher = Mimc2();
    commitmentHasher.in0 <== nullifier;
    commitmentHasher.in1 <== nonce;
    signal commitment;
    commitment <== commitmentHasher.out;

    // Compute Merkle path
    component hashers[depth];
    component switches[depth];

    signal current[depth + 1];
    current[0] <== commitment;

    for (var i = 0; i < depth; i++) {
        switches[i] = SelectiveSwitch();
        switches[i].in0 <== current[i];
        switches[i].in1 <== sibling[i];
        switches[i].s <== direction[i];

        hashers[i] = Mimc2();
        hashers[i].in0 <== switches[i].out0;
        hashers[i].in1 <== switches[i].out1;

        current[i + 1] <== hashers[i].out;
    }

    // Final check: the computed root must equal the public digest
    digest === current[depth];
}
