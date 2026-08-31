pragma circom 2.0.0;

// Compliant shielded transfer w/ full auditor reveal (Step 5 / F5c) —
// viewing-key decrypt of BOTH the amount AND the recipient address identity.
//
// Builds directly on Step 4's `PrivacyPoolViewable` (itself Step 3's
// `PrivacyPool` + a Twisted ElGamal encryption of the amount to an auditor).
// Step 5 keeps that design and additionally ElGamal-encrypts the recipient's
// address identifier to the SAME auditor public key (`pk_audit`), using the
// SAME ephemeral randomness `r` (a multi-message Twisted ElGamal ciphertext):
//
//   E     = r * G
//   C     = in_amount   * H + r * pk_audit      (amount)
//   C_a0  = addr_limb0  * H + r * pk_audit       (address low  u16 limb)
//   C_a1  = addr_limb1  * H + r * pk_audit       (address high u16 limb)
//   addr_limb0 = recipient_addr & 0xFFFF
//   addr_limb1 = recipient_addr >> 16
//
// The chain sees only ciphertexts.  Only the auditor holding the viewing key
// `sk_audit` (pk_audit = sk_audit * G) recovers the amount and the two address
// limbs via  m*H = C_x - sk_audit*E  and a small discrete-log recovery (each
// limb is < 2^16, the amount < 2^32), then reassembles `recipient_addr`.
//
// The recipient address is bound to the spend via a public commitment
//   addr_commitment = Poseidon(recipient_addr, nullifier)
// so the auditor can verify the recovered address matches the chain.
//
// Public inputs  (13): merkle_root, nullifier_hash, out_commitment_1,
//   out_commitment_2, fee,  pk_audit(x,y),  addr_commitment.
// Public outputs (8):  E[2], C[2], C_a0[2], C_a1[2].
//
// A policy layer (not enforced here) pins `pk_audit` to the pool's registered
// auditor; the on-chain Aiken gate can whitelist the auditor public key.

include "privacy_pool_lib.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "bitify.circom";

template PrivacyPoolViewableAddr(depth, nBits, scalarBits) {
    // ---- Step 3 shielded-pool public inputs ----
    signal input merkle_root;
    signal input nullifier_hash;
    signal input out_commitment_1;
    signal input out_commitment_2;
    signal input fee;

    // ---- auditor / viewing-key public inputs ----
    signal input pk_audit[2];         // auditor public key (x, y)
    signal input addr_commitment;     // Poseidon(recipient_addr, nullifier)

    // ---- public ElGamal ciphertext outputs ----
    signal output E[2];              // shared ephemeral component (public)
    signal output C[2];              // amount ciphertext  (public)
    signal output C_a0[2];           // address low  limb ciphertext (public)
    signal output C_a1[2];           // address high limb ciphertext (public)

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

    // ---- auditor-encryption private inputs ----
    signal input audit_blinding;      // shared ephemeral randomness r
    signal input recipient_addr;      // 32-bit recipient address id (private)

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

    // Split the recipient address into two 16-bit limbs.
    component addrBits = Num2Bits(32);
    addrBits.in <== recipient_addr;
    signal addr_limb0;
    signal addr_limb1;
    var l0 = 0;
    var l1 = 0;
    for (var i = 0; i < 16; i++) {
        l0 += addrBits.out[i] * (1 << i);
        l1 += addrBits.out[i + 16] * (1 << i);
    }
    addr_limb0 <== l0;
    addr_limb1 <== l1;

    // Encrypt the SAME in_amount and the two address limbs to the auditor's
    // public key, sharing the same ephemeral randomness r (audit_blinding).
    component encAmt = TwistedElGamalEncrypt(scalarBits);
    encAmt.message <== in_amount;
    encAmt.randomness <== audit_blinding;
    encAmt.pk[0] <== pk_audit[0];
    encAmt.pk[1] <== pk_audit[1];
    E[0] <== encAmt.E[0];
    E[1] <== encAmt.E[1];
    C[0] <== encAmt.C[0];
    C[1] <== encAmt.C[1];

    // low address limb -> shared ephemeral E (consistency check)
    component encA0 = TwistedElGamalEncrypt(scalarBits);
    encA0.message <== addr_limb0;
    encA0.randomness <== audit_blinding;
    encA0.pk[0] <== pk_audit[0];
    encA0.pk[1] <== pk_audit[1];
    encA0.E[0] === E[0];
    encA0.E[1] === E[1];
    C_a0[0] <== encA0.C[0];
    C_a0[1] <== encA0.C[1];

    // high address limb -> shared ephemeral E (consistency check)
    component encA1 = TwistedElGamalEncrypt(scalarBits);
    encA1.message <== addr_limb1;
    encA1.randomness <== audit_blinding;
    encA1.pk[0] <== pk_audit[0];
    encA1.pk[1] <== pk_audit[1];
    encA1.E[0] === E[0];
    encA1.E[1] === E[1];
    C_a1[0] <== encA1.C[0];
    C_a1[1] <== encA1.C[1];

    // Bind the recipient address to the spend: addr_commitment = Poseidon(addr, nullifier)
    component addrCommit = PoseidonBLS12_381();
    addrCommit.in0 <== recipient_addr;
    addrCommit.in1 <== nullifier;
    addrCommit.out === addr_commitment;
}

// scalarBits: bit width for the ElGamal scalar-multiplies (full BLS12-381 scalar
// width for strong demo randomness).  The amount is range-checked to [0,2^n) by
// the pool and each address limb is range-checked to < 2^16 by the Num2Bits(32)
// split, so the auditor's small-DL recovery always terminates quickly.
component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee, pk_audit, addr_commitment]} = PrivacyPoolViewableAddr(4, 32, 253);
