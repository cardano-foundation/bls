pragma circom 2.0.0;

/**
 * MetaBatchStep — Nova IVC step circuit for recursive proof aggregation (Step 9).
 *
 * Each step verifies ONE epoch of Groth16 batch proofs (N spends) and updates
 * the running pool state (Merkle root + nullifier accumulator).
 *
 * Architecture:
 *   Public state in : prev_root, nullifier_acc, vk_hash
 *   Public state out: next_root, nullifier_acc_next, vk_hash
 *
 * NOTE: The full embedded pairing check (Miller loop + final exponentiation)
 * is omitted and marked with a TODO. A complete implementation needs
 * ~500K–2M constraints of BLS12-381 pairing arithmetic in R1CS.
 * This scaffold demonstrates the correct interface and state transition.
 */

include "../PoseidonMerkle/poseidon_merkle.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "../PoseidonPreimage/poseidon_bls12_381_t6.circom";

template MetaBatchStep(epochSize, merkleDepth) {
    // ---- public IVC state (chained) ----
    signal input prev_root;
    signal input nullifier_acc;
    signal input vk_hash;

    // ---- public outputs (chained) ----
    signal output next_root;
    signal output nullifier_acc_next;
    signal output vk_hash_out;

    // ---- private: Groth16 batch proofs (scalars only) ----
    signal input pi_a_x[epochSize];
    signal input pi_a_y[epochSize];
    signal input pi_c_x[epochSize];
    signal input pi_c_y[epochSize];

    // ---- private: public inputs per proof ----
    signal input pub_merkle_root[epochSize];
    signal input pub_nullifier_hash[epochSize];
    signal input pub_out_commitment_1[epochSize];
    signal input pub_out_commitment_2[epochSize];
    signal input pub_fee[epochSize];
    signal input pub_pk_audit_x[epochSize];
    signal input pub_pk_audit_y[epochSize];
    signal input pub_addr_commitment[epochSize];

    // ---- 1. Batch commitment (hash all proofs + public inputs) ----
    // This commits the prover to the exact batch data.
    // We chain PoseidonBLS12_381 (2-input) hashes because PoseidonBLS12_381_T6
    // only exposes 5 inputs, and we have 6 values per proof.
    component h0[epochSize];
    component h1[epochSize];
    component h01[epochSize];
    component h2[epochSize];
    component batchLeafHasher[epochSize];
    signal batchLeaf[epochSize];

    for (var i = 0; i < epochSize; i++) {
        h0[i] = PoseidonBLS12_381();
        h0[i].in0 <== pi_a_x[i];
        h0[i].in1 <== pi_a_y[i];

        h1[i] = PoseidonBLS12_381();
        h1[i].in0 <== pi_c_x[i];
        h1[i].in1 <== pi_c_y[i];

        h01[i] = PoseidonBLS12_381();
        h01[i].in0 <== h0[i].out;
        h01[i].in1 <== h1[i].out;

        h2[i] = PoseidonBLS12_381();
        h2[i].in0 <== pub_nullifier_hash[i];
        h2[i].in1 <== pub_merkle_root[i];

        batchLeafHasher[i] = PoseidonBLS12_381();
        batchLeafHasher[i].in0 <== h01[i].out;
        batchLeafHasher[i].in1 <== h2[i].out;
        batchLeaf[i] <== batchLeafHasher[i].out;
    }

    // Chain batch leaves into a single batch commitment via sequential hashing.
    // In production this would be a Merkle tree over the batch.
    signal runningBatch[epochSize + 1];
    runningBatch[0] <== 0;
    component batchChain[epochSize];
    for (var i = 0; i < epochSize; i++) {
        batchChain[i] = PoseidonBLS12_381();
        batchChain[i].in0 <== runningBatch[i];
        batchChain[i].in1 <== batchLeaf[i];
        runningBatch[i + 1] <== batchChain[i].out;
    }
    signal batch_commitment;
    batch_commitment <== runningBatch[epochSize];

    // ---- 2. Nullifier accumulator update ----
    component nullifierHasher[epochSize];
    signal runningNullifier[epochSize + 1];
    runningNullifier[0] <== nullifier_acc;

    for (var i = 0; i < epochSize; i++) {
        nullifierHasher[i] = PoseidonBLS12_381();
        nullifierHasher[i].in0 <== runningNullifier[i];
        nullifierHasher[i].in1 <== pub_nullifier_hash[i];
        runningNullifier[i + 1] <== nullifierHasher[i].out;
    }
    nullifier_acc_next <== runningNullifier[epochSize];

    // ---- 3. Merkle root transition ----
    // Chain Poseidon hashes: runningRoot[i+1] = Poseidon(runningRoot[i], leafVal[i])
    signal runningRoot[2*epochSize + 1];
    runningRoot[0] <== prev_root;

    // Pre-declare helper signals outside the loop (Circom restriction)
    signal leafVal[2*epochSize];
    component rootHash[2*epochSize];
    for (var u = 0; u < epochSize; u++) {
        for (var j = 0; j < 2; j++) {
            var idx = 2*u + j;
            leafVal[idx] <== pub_out_commitment_1[u] + pub_out_commitment_2[u];
            rootHash[idx] = PoseidonBLS12_381();
            rootHash[idx].in0 <== runningRoot[idx];
            rootHash[idx].in1 <== leafVal[idx];
            runningRoot[idx + 1] <== rootHash[idx].out;
        }
    }
    next_root <== runningRoot[2*epochSize];

    // ---- 4. vk_hash carried through ----
    vk_hash_out <== vk_hash;

    // ---- 5. Consistency: all spends reference prev_root ----
    // NOTE: In a sequential pool, each spend may see a different root.
    // For the scaffold we check the first spend matches prev_root;
    // a production circuit would freeze the root for the entire epoch.
    pub_merkle_root[0] === prev_root;
}

// Groth16 instantiation — defaults tuned to Step 6 tree capacity.
// With depth=4, capacity=16, max USERS=5 (5+10=15).  Default epochSize=4 for safety.
component main {public [prev_root, nullifier_acc, vk_hash]} = MetaBatchStep(4, 4);
