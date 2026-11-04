pragma circom 2.0.0;

// Step 11 — Private Token Lifecycle inside a Selective-Disclosure Vehicle.
//
// Extends Step 10's dynamic-auditor privacy pool by binding every spend to
// real token commitments.  The pool still hides the sender, amount, and
// transaction graph, but now the circuit additionally proves that the
// Pedersen token commitments in the input/output datums conserve value:
//
//   token_in_value  = token_out1_value + token_out2_value + fee
//
// Each token commitment is a JubJub Pedersen commitment:
//
//   C_token = value * H + blinding * G
//
// The same values are used for the pool notes, so the proof links the
// confidential token layer to the privacy-pool layer.  This is the bridge
// between a CIP-113-style private token (value hidden in the datum) and the
// selective-disclosure pool.
//
// Public inputs (16): merkle_root, nullifier_hash, out_commitment_1,
//   out_commitment_2, fee, pk_audit[2], addr_commitment, auditor_root,
//   token_in_commitment[2], token_out_commitment_1[2], token_out_commitment_2[2].
// Public outputs (8): E[2], C[2], C_a0[2], C_a1[2].

include "privacy_pool_lib.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "merkle.circom";
include "pedersen_commit.circom";
include "bitify.circom";

template PrivacyPoolTokenLifecycle(depth, nBits, scalarBits, auditorDepth) {
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

    // ---- token-layer public inputs ----
    signal input token_in_commitment[2];
    signal input token_out_commitment_1[2];
    signal input token_out_commitment_2[2];

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

    // ---- token-layer private inputs ----
    signal input token_in_value;
    signal input token_in_blinding;
    signal input token_out1_value;
    signal input token_out1_blinding;
    signal input token_out2_value;
    signal input token_out2_blinding;

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

    // Link pool amounts to token values: they must be equal.
    in_amount === token_in_value;
    out_amount_1 === token_out1_value;
    out_amount_2 === token_out2_value;

    // Token conservation: input value is split into outputs + fee.
    token_in_value === token_out1_value + token_out2_value + fee;

    // Prove token commitments open to the claimed values/blindings.
    component tokenIn = PedersenCommit(nBits);
    tokenIn.value <== token_in_value;
    tokenIn.blinding <== token_in_blinding;
    tokenIn.C[0] === token_in_commitment[0];
    tokenIn.C[1] === token_in_commitment[1];

    component tokenOut1 = PedersenCommit(nBits);
    tokenOut1.value <== token_out1_value;
    tokenOut1.blinding <== token_out1_blinding;
    tokenOut1.C[0] === token_out_commitment_1[0];
    tokenOut1.C[1] === token_out_commitment_1[1];

    component tokenOut2 = PedersenCommit(nBits);
    tokenOut2.value <== token_out2_value;
    tokenOut2.blinding <== token_out2_blinding;
    tokenOut2.C[0] === token_out_commitment_2[0];
    tokenOut2.C[1] === token_out_commitment_2[1];

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

component main {public [merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee, pk_audit, addr_commitment, auditor_root, token_in_commitment, token_out_commitment_1, token_out_commitment_2]} = PrivacyPoolTokenLifecycle(4, 32, 253, 4);
