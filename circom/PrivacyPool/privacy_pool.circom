pragma circom 2.0.0;

// Confidential privacy-pool spend (Step 3 / F5a).
//
// A 1-in / 2-out confidential transaction:
//   - proves the input note's commitment is a leaf of the Merkle tree
//   - reveals a nullifier hash so the pool can mark the note spent
//   - hides all amounts (range-checked to [0, 2^n))
//   - proves value conservation: in == out1 + out2 + fee
//
// Public inputs:  merkle_root, nullifier_hash, out_commitments[2], fee
// Private inputs: nullifier, amounts & blindings, merkle path
//
// Reuses: PoseidonBLS12_381 (PoseidonPreimage), Num2Bits (circomlib bitify).

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
    signal input out_amount_1;
    signal input out_blinding_1;
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

    // Output note commitments must match
    component outNote1 = NoteCommitment();
    outNote1.nullifier <== nullifier;
    outNote1.amount <== out_amount_1;
    outNote1.blinding <== out_blinding_1;
    outNote1.commitment === out_commitment_1;

    component outNote2 = NoteCommitment();
    outNote2.nullifier <== nullifier;
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

component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee]} = PrivacyPool(4, 32);
