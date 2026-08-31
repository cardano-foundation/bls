pragma circom 2.0.0;

// Compliant shielded transfer (Step 4 / F5b) — viewing-key auditor reveal.
//
// Builds directly on Step 3's `PrivacyPool(depth, nBits)` and reuses the Twisted
// ElGamal encryption template (circom/TwistedElGamal/elgamal_encrypt.circom).
//
// A 1-in / 2-out shielded transaction (identity & graph hidden by the pool) in
// which the private input amount is ALSO encrypted to a designated auditor's
// public key (`pk_audit`), producing a Twisted ElGamal ciphertext (E, C):
//
//   E = r * G
//   C = in_amount * H + r * pk_audit
//
// The chain sees only ciphertexts; only the auditor holding the viewing key
// `sk_audit` (such that pk_audit = sk_audit * G) can recover the amount via
//   in_amount * H = C - sk_audit * E
// and a small-discrete-log recovery (the amount is range-checked to [0,2^n)).
//
// Public inputs (11):  merkle_root, nullifier_hash, out_commitment_1,
//   out_commitment_2, fee,  pk_audit(x,y),  E(x,y),  C(x,y).
//
// A policy layer (not enforced here) pins `pk_audit` to the pool's registered
// auditor; the on-chain Aiken gate can whitelist the auditor public key.

include "privacy_pool_lib.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";
include "bitify.circom";

template PrivacyPoolViewable(depth, nBits, scalarBits) {
    // ---- Step 3 shielded-pool public inputs ----
    signal input merkle_root;
    signal input nullifier_hash;
    signal input out_commitment_1;
    signal input out_commitment_2;
    signal input fee;

    // ---- auditor / viewing-key public inputs ----
    signal input pk_audit[2];      // auditor public key (x, y)
    signal output E[2];            // ElGamal ephemeral component (public)
    signal output C[2];            // ElGamal committed ciphertext component (public)

    // ---- Step 3 shielded-pool private inputs ----
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

    // ---- auditor-encryption private input ----
    signal input audit_blinding;   // ephemeral randomness r

    // Reuse the Step 3 PrivacyPool shielded spend verbatim.
    component pool = PrivacyPool(depth, nBits);
    pool.merkle_root <== merkle_root;
    pool.nullifier_hash <== nullifier_hash;
    pool.out_commitment_1 <== out_commitment_1;
    pool.out_commitment_2 <== out_commitment_2;
    pool.fee <== fee;
    pool.nullifier <== nullifier;
    pool.in_amount <== in_amount;
    pool.in_blinding <== in_blinding;
    pool.out_nullifier_1 <== out_nullifier_1;
    pool.out_amount_1 <== out_amount_1;
    pool.out_blinding_1 <== out_blinding_1;
    pool.out_nullifier_2 <== out_nullifier_2;
    pool.out_amount_2 <== out_amount_2;
    pool.out_blinding_2 <== out_blinding_2;
    for (var i = 0; i < depth; i++) {
        pool.sibling[i] <== sibling[i];
        pool.direction[i] <== direction[i];
    }

    // Encrypt the SAME in_amount to the auditor's public key.
    // nBits is reused for the message + random limbs (full scalar in one shot).
    component enc = TwistedElGamalEncrypt(scalarBits);
    enc.message <== in_amount;
    enc.randomness <== audit_blinding;
    enc.pk[0] <== pk_audit[0];
    enc.pk[1] <== pk_audit[1];
    E[0] <== enc.E[0];
    E[1] <== enc.E[1];
    C[0] <== enc.C[0];
    C[1] <== enc.C[1];
}

// scalarBits: number of bits to range-check/scalar-multiply the ElGamal values.
// Using the full BLS12-381 scalar bit width (253) keeps the ephemeral
// randomness strong; the amount itself is still range-checked to [0,2^n) by the
// pool.  Adjust to taste (smaller = fewer constraints, weaker demo randomness).
component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee, pk_audit]} = PrivacyPoolViewable(4, 32, 253);
