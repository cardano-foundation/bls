pragma circom 2.0.0;

// Blake2b-224 pre-image proof
//
// Public inputs:  blake2b_224_hash[28]  — the 28-byte Cardano key hash
// Private inputs: pre_image[32]          — the 32-byte pre-image (e.g. Ed25519 pubkey)
//
// The circuit proves that Blake2b-224(pre_image) == blake2b_224_hash.
// Cardano uses Blake2b-224 for address and key hashing.

include "blake2b224.circom";

template Blake2b224Preimage() {
    signal input pre_image[32];
    signal input blake2b_224_hash[28];

    component hasher = Blake2b224_bytes(32);
    for (var i = 0; i < 32; i++) {
        hasher.inp_bytes[i] <== pre_image[i];
    }

    for (var i = 0; i < 28; i++) {
        hasher.hash_bytes[i] === blake2b_224_hash[i];
    }
}

component main {public [blake2b_224_hash]} = Blake2b224Preimage();
