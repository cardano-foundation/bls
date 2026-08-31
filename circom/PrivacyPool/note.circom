pragma circom 2.0.0;

// Note commitment & nullifier for a privacy pool.
//
// A note is a confidential value record:
//   commitment    = Poseidon(Poseidon(nullifier, amount), blinding)
//   nullifier_hash = Poseidon(0, nullifier)
//
// The commitment is what sits in the Merkle tree; it binds the amount,
// the nullifier, and a blinding factor.  The nullifier hash is made public
// on spend so the pool can mark the note as spent without revealing the
// nullifier itself.

include "../PoseidonPreimage/poseidon_bls12_381.circom";

// Commitment = Poseidon(Poseidon(nullifier, amount), blinding)
template NoteCommitment() {
    signal input nullifier;      // private secret
    signal input amount;         // private value (range-checked elsewhere)
    signal input blinding;       // private randomness
    signal output commitment;    // leaf placed in the Merkle tree

    component h1 = PoseidonBLS12_381();
    h1.in0 <== nullifier;
    h1.in1 <== amount;

    component h2 = PoseidonBLS12_381();
    h2.in0 <== h1.out;
    h2.in1 <== blinding;

    commitment <== h2.out;
}

// nullifier_hash = Poseidon(0, nullifier)
template NullifierCommitment() {
    signal input nullifier;      // private secret
    signal output nullifier_hash; // public value marking the note spent

    component h = PoseidonBLS12_381();
    h.in0 <== 0;
    h.in1 <== nullifier;

    nullifier_hash <== h.out;
}
