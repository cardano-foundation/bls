pragma circom 2.0.0;

// Step 10 — Dynamic Multi-Auditor Privacy Pool with Full Reveal.
//
// Extends Step 6's `privacy_pool_viewable_addr.circom` so the holder can
// encrypt the amount and recipient address to ANY auditor currently present
// in an active-set Merkle tree.  The pool no longer hard-codes a single
// `pk_audit`; instead it publishes an `auditor_root` and each spend proves
// that the chosen `pk_audit` is a leaf of that tree.
//
// This gives three new operational properties:
//   1. Multiple concurrent auditors.
//   2. Auditors can join after setup (admin inserts a new leaf → new root).
//   3. Auditors can lose function (admin removes the leaf → new root).
//
// The encryption math is unchanged from Step 5/6:
//   E     = r * G
//   C     = in_amount   * H + r * pk_audit
//   C_a0  = addr_limb0  * H + r * pk_audit
//   C_a1  = addr_limb1  * H + r * pk_audit
//
// Public inputs (14): merkle_root, nullifier_hash, out_commitment_1,
//   out_commitment_2, fee, pk_audit[2], addr_commitment, auditor_root.
// Public outputs (8): E[2], C[2], C_a0[2], C_a1[2].

include "privacy_pool_lib.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "merkle.circom";
include "bitify.circom";

template PrivacyPoolViewableAddrDynamic(depth, nBits, scalarBits, auditorDepth) {
    // ---- Step 3 shielded-pool public inputs ----
    signal input merkle_root;
    signal input nullifier_hash;
    signal input out_commitment_1;
    signal input out_commitment_2;
    signal input fee;

    // ---- auditor / viewing-key public inputs ----
    signal input pk_audit[2];         // chosen auditor public key (x, y)
    signal input addr_commitment;     // Poseidon(recipient_addr, nullifier)
    signal input auditor_root;        // Merkle root of active auditor set

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

    // ---- dynamic-auditor private inputs ----
    signal input auditor_sibling[auditorDepth];
    signal input auditor_direction[auditorDepth];

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

    // Encrypt the SAME in_amount and the two address limbs to the chosen
    // auditor's public key, sharing the same ephemeral randomness r.
    component encAmt = TwistedElGamalEncrypt(scalarBits);
    encAmt.message <== in_amount;
    encAmt.randomness <== audit_blinding;
    encAmt.pk[0] <== pk_audit[0];
    encAmt.pk[1] <== pk_audit[1];
    E[0] <== encAmt.E[0];
    E[1] <== encAmt.E[1];
    C[0] <== encAmt.C[0];
    C[1] <== encAmt.C[1];

    component encA0 = TwistedElGamalEncrypt(scalarBits);
    encA0.message <== addr_limb0;
    encA0.randomness <== audit_blinding;
    encA0.pk[0] <== pk_audit[0];
    encA0.pk[1] <== pk_audit[1];
    encA0.E[0] === E[0];
    encA0.E[1] === E[1];
    C_a0[0] <== encA0.C[0];
    C_a0[1] <== encA0.C[1];

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

    // ---- dynamic auditor membership proof ----
    // The chosen auditor's public key must be a leaf of the active-set tree.
    component auditorLeaf = PoseidonBLS12_381();
    auditorLeaf.in0 <== pk_audit[0];
    auditorLeaf.in1 <== pk_audit[1];

    component auditorPath = PoseidonMerklePath(auditorDepth);
    auditorPath.leaf <== auditorLeaf.out;
    auditorPath.root <== auditor_root;
    for (var i = 0; i < auditorDepth; i++) {
        auditorPath.sibling[i] <== auditor_sibling[i];
        auditorPath.direction[i] <== auditor_direction[i];
    }
}

component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee, pk_audit, addr_commitment, auditor_root]} = PrivacyPoolViewableAddrDynamic(4, 32, 253, 4);
