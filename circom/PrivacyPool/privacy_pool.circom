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

include "privacy_pool_lib.circom";

component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee]} = PrivacyPool(4, 32);
