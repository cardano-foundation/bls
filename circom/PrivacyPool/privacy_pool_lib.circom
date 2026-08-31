pragma circom 2.0.0;

// Privacy-pool shielded-spend — include-only template (no `component main`).
//
// Extracted from `privacy_pool.circom` so that other circuits (e.g. Step 4
// viewing-key / auditable privacy) can `include` and instantiate the
// `PrivacyPool(depth, nBits)` template directly without a conflicting `main`.

include "note.circom";
include "merkle.circom";
include "bitify.circom";

template PrivacyPool(depth, nBits) {
    // ---- public inputs ----
    signal input merkle_root;
    signal input nullifier_hash;
    signal input out_commitment_1;
    signal input out_commitment_2;
    signal input fee;

    // ---- private inputs ----
    signal input nullifier;
    signal input in_amount;
    signal input in_blinding;
    signal input out_nullifier_1;
    signal input out_amount_1;
    signal input out_blinding_1;
    signal input out_nullifier_2;
    signal input out_amount_2;
    signal input out_blinding_2;
    signal input sibling[depth];
    signal input direction[depth];

    // Input note commitment -> Merkle membership
    component inNote = NoteCommitment();
    inNote.nullifier <== nullifier;
    inNote.amount <== in_amount;
    inNote.blinding <== in_blinding;

    component merkle = PoseidonMerklePath(depth);
    merkle.leaf <== inNote.commitment;
    merkle.root <== merkle_root;
    for (var i = 0; i < depth; i++) {
        merkle.sibling[i] <== sibling[i];
        merkle.direction[i] <== direction[i];
    }

    // Nullifier hash must match the public value
    component nHash = NullifierCommitment();
    nHash.nullifier <== nullifier;
    nHash.nullifier_hash === nullifier_hash;

    // Each output note commits to its own fresh nullifier, amount & blinding.
    component outNote1 = NoteCommitment();
    outNote1.nullifier <== out_nullifier_1;
    outNote1.amount <== out_amount_1;
    outNote1.blinding <== out_blinding_1;
    outNote1.commitment === out_commitment_1;

    component outNote2 = NoteCommitment();
    outNote2.nullifier <== out_nullifier_2;
    outNote2.amount <== out_amount_2;
    outNote2.blinding <== out_blinding_2;
    outNote2.commitment === out_commitment_2;

    // Range-check all amounts to [0, 2^n) via Num2Bits
    component rIn = Num2Bits(nBits);
    rIn.in <== in_amount;

    component rOut1 = Num2Bits(nBits);
    rOut1.in <== out_amount_1;

    component rOut2 = Num2Bits(nBits);
    rOut2.in <== out_amount_2;

    // Value conservation (no inflation / no negative amounts)
    in_amount === out_amount_1 + out_amount_2 + fee;
}
