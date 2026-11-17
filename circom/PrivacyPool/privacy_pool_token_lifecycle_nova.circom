pragma circom 2.0.0;

// Step 11 — Privacy-pool token lifecycle with dynamic auditor: NovaSlim step.
//
// Proves, as a single folded Nova step, the full Step 11 statement:
//   * spend of an input privacy-pool note into two output notes,
//   * dynamic-auditor membership of pk_audit in the active-set tree,
//   * Twisted-ElGamal encryption of amount + recipient address to the auditor,
//   * Pedersen conservation of token commitments
//       token_in = token_out1 + token_out2 + fee   (value layer)
//       in_amount = out_amount_1 + out_amount_2 + fee   (pool-note layer)
//
// NovaSlim requires exactly one public input (the IVC state) and one public
// output (the next IVC state).  All per-step public data is therefore committed
// into state_out; the verifier checks state_out against the expected public
// values off-chain / on-chain.  For a singleton demonstration state_in is the 0
// sentinel, matching the Step 10 NovaSlim pattern.

include "privacy_pool_lib.circom";
include "pedersen_commit.circom";
include "merkle.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "bitify.circom";

template PrivacyPoolTokenLifecycleNovaStep(depth, nBits, scalarBits, auditorDepth) {
    // ---- public IVC state ----
    signal input state_in;
    signal output state_out;

    // ---- formerly public inputs, now private instance data ----
    signal input merkle_root;
    signal input nullifier_hash;
    signal input out_commitment_1;
    signal input out_commitment_2;
    signal input fee;
    signal input pk_audit[2];
    signal input addr_commitment;
    signal input auditor_root;
    signal input token_in_commitment[2];
    signal input token_out_commitment_1[2];
    signal input token_out_commitment_2[2];

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
    signal input audit_blinding;
    signal input recipient_addr;
    signal input auditor_sibling[auditorDepth];
    signal input auditor_direction[auditorDepth];
    signal input token_in_value;
    signal input token_in_blinding;
    signal input token_out1_value;
    signal input token_out1_blinding;
    signal input token_out2_value;
    signal input token_out2_blinding;

    // 1. Privacy-pool spend: input note membership, nullifier, output notes,
    //    amount conservation and range checks.
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

    // 2. Recipient address commitment binds the 32-bit address to the nullifier.
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

    component addrCommit = PoseidonBLS12_381();
    addrCommit.in0 <== recipient_addr;
    addrCommit.in1 <== nullifier;
    addrCommit.out === addr_commitment;

    // 3. Dynamic auditor: prove pk_audit is a leaf of the active-set Merkle tree.
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

    // 4. Multi-message Twisted ElGamal to the chosen auditor (shared randomness).
    component encAmt = TwistedElGamalEncrypt(scalarBits);
    encAmt.message <== in_amount;
    encAmt.randomness <== audit_blinding;
    encAmt.pk[0] <== pk_audit[0];
    encAmt.pk[1] <== pk_audit[1];

    signal E[2];
    signal C[2];
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
    signal C_a0[2];
    C_a0[0] <== encA0.C[0];
    C_a0[1] <== encA0.C[1];

    component encA1 = TwistedElGamalEncrypt(scalarBits);
    encA1.message <== addr_limb1;
    encA1.randomness <== audit_blinding;
    encA1.pk[0] <== pk_audit[0];
    encA1.pk[1] <== pk_audit[1];
    encA1.E[0] === E[0];
    encA1.E[1] === E[1];
    signal C_a1[2];
    C_a1[0] <== encA1.C[0];
    C_a1[1] <== encA1.C[1];

    // 5. Token lifecycle: link pool-note amounts to token values, prove the
    //    Pedersen commitments open to those values/blindings, and conserve
    //    token value across the spend (fee is paid inside the token layer).
    in_amount === token_in_value;
    out_amount_1 === token_out1_value;
    out_amount_2 === token_out2_value;
    token_in_value === token_out1_value + token_out2_value + fee;

    component tokenIn = PedersenCommit(scalarBits);
    tokenIn.value <== token_in_value;
    tokenIn.blinding <== token_in_blinding;
    tokenIn.C[0] === token_in_commitment[0];
    tokenIn.C[1] === token_in_commitment[1];

    component tokenOut1 = PedersenCommit(scalarBits);
    tokenOut1.value <== token_out1_value;
    tokenOut1.blinding <== token_out1_blinding;
    tokenOut1.C[0] === token_out_commitment_1[0];
    tokenOut1.C[1] === token_out_commitment_1[1];

    component tokenOut2 = PedersenCommit(scalarBits);
    tokenOut2.value <== token_out2_value;
    tokenOut2.blinding <== token_out2_blinding;
    tokenOut2.C[0] === token_out_commitment_2[0];
    tokenOut2.C[1] === token_out_commitment_2[1];

    // 6. IVC state: commit all per-step public data so the folded proof binds it.
    //    Ordering is fixed and must be reproduced by the witness generator / verifier.
    component h1  = PoseidonBLS12_381(); h1.in0  <== merkle_root;                h1.in1  <== nullifier_hash;
    component h2  = PoseidonBLS12_381(); h2.in0  <== h1.out;                    h2.in1  <== out_commitment_1;
    component h3  = PoseidonBLS12_381(); h3.in0  <== h2.out;                    h3.in1  <== out_commitment_2;
    component h4  = PoseidonBLS12_381(); h4.in0  <== h3.out;                    h4.in1  <== fee;
    component h5  = PoseidonBLS12_381(); h5.in0  <== h4.out;                    h5.in1  <== pk_audit[0];
    component h6  = PoseidonBLS12_381(); h6.in0  <== h5.out;                    h6.in1  <== pk_audit[1];
    component h7  = PoseidonBLS12_381(); h7.in0  <== h6.out;                    h7.in1  <== addr_commitment;
    component h8  = PoseidonBLS12_381(); h8.in0  <== h7.out;                    h8.in1  <== auditor_root;
    component h9  = PoseidonBLS12_381(); h9.in0  <== h8.out;                    h9.in1  <== token_in_commitment[0];
    component h10 = PoseidonBLS12_381(); h10.in0 <== h9.out;                    h10.in1 <== token_in_commitment[1];
    component h11 = PoseidonBLS12_381(); h11.in0 <== h10.out;                   h11.in1 <== token_out_commitment_1[0];
    component h12 = PoseidonBLS12_381(); h12.in0 <== h11.out;                   h12.in1 <== token_out_commitment_1[1];
    component h13 = PoseidonBLS12_381(); h13.in0 <== h12.out;                   h13.in1 <== token_out_commitment_2[0];
    component h14 = PoseidonBLS12_381(); h14.in0 <== h13.out;                   h14.in1 <== token_out_commitment_2[1];
    component h15 = PoseidonBLS12_381(); h15.in0 <== h14.out;                   h15.in1 <== E[0];
    component h16 = PoseidonBLS12_381(); h16.in0 <== h15.out;                   h16.in1 <== E[1];
    component h17 = PoseidonBLS12_381(); h17.in0 <== h16.out;                   h17.in1 <== C[0];
    component h18 = PoseidonBLS12_381(); h18.in0 <== h17.out;                   h18.in1 <== C[1];
    component h19 = PoseidonBLS12_381(); h19.in0 <== h18.out;                   h19.in1 <== C_a0[0];
    component h20 = PoseidonBLS12_381(); h20.in0 <== h19.out;                   h20.in1 <== C_a0[1];
    component h21 = PoseidonBLS12_381(); h21.in0 <== h20.out;                   h21.in1 <== C_a1[0];
    component h22 = PoseidonBLS12_381(); h22.in0 <== h21.out;                   h22.in1 <== C_a1[1];

    // Singleton step: the incoming public state is the 0 sentinel.
    state_in === 0;
    state_out <== h22.out;
}

component main {public [state_in]} = PrivacyPoolTokenLifecycleNovaStep(4, 32, 253, 4);
