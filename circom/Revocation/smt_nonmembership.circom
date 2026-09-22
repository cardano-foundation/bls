pragma circom 2.0.0;

/**
 * Sparse Merkle Tree non-membership proof.
 *
 * Verifies that the leaf at position `leaf_index` is the default empty value (0)
 * in a sparse Merkle tree of the given depth.  The tree uses PoseidonBLS12_381
 * as its compression function, with default leaves computed recursively as
 * default[d] = Poseidon(default[d+1], default[d+1]) and default[depth] = 0.
 *
 * The holder proves non-revocation by showing the path from leaf=0 at their
 * credential's position to the published `root`.
 *
 * Inputs:
 *   root:     public root of the revocation SMT.
 *   leaf_index:  position of the credential in the tree (lower bits of claims_msg).
 *   sibling[depth]: sibling hash at each level from leaf to root.
 *   direction[depth]: direction bit at each level (1 = sibling is on the left).
 */

include "../PoseidonMerkle/poseidon_merkle.circom";
include "../EdDSAJubJub/node_modules/circomlib/circuits/bitify.circom";

template SMTNonMembership(depth) {
    signal input root;
    signal input leaf_index;
    signal input sibling[depth];
    signal input direction[depth];

    // 1. direction bits must be binary
    for (var i = 0; i < depth; i++) {
        direction[i] * (direction[i] - 1) === 0;
    }

    // 2. leaf_index must match the direction bits (little-endian bit decomposition)
    component indexBits = Num2Bits(depth);
    indexBits.in <== leaf_index;
    for (var i = 0; i < depth; i++) {
        indexBits.out[i] === direction[i];
    }

    // 3. Walk up the Merkle path from leaf = 0
    signal current[depth + 1];
    current[0] <== 0;

    component switches[depth];
    component hashers[depth];

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

    // 4. Computed root must equal the published root
    root === current[depth];
}
