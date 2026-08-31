pragma circom 2.0.0;

// Step 5 auditor full reveal — Nova IVC step circuit.
//
// Proves, as a single folded Nova step, a multi-message Twisted ElGamal
// encryption to an auditor's public key using SHARED ephemeral randomness r:
//
//   E     = r * G
//   C     = amount      * H + r * pk_audit     (amount)
//   C_a0  = addr_limb0  * H + r * pk_audit     (address low  u16 limb)
//   C_a1  = addr_limb1  * H + r * pk_audit     (address high u16 limb)
//
// The public IVC state (n_pub_in == n_pub_out == 1, matching the nova-slim
// verifier) is a Poseidon commitment to the shared E and the three C points,
// so the on-chain/IVC attestation binds the exact ciphertexts that the prover
// reveals off-chain.  Only the auditor holding the viewing key `sk_audit`
// (pk_audit = sk_audit * G) can recover the amount and the two address limbs
// via  m*H = C_x - sk_audit*E  followed by small discrete-log recovery, then
// reassemble the recipient address id.  Everyone else sees only the short
// ciphertext commitment.

include "bitify.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";

template AuditViewkeyAddrStep() {
    signal input state_in;         // public IVC state (0 for a singleton step)
    signal input amount;           // private amount (range-checked to u32)
    signal input r;                // private shared ephemeral randomness
    signal input pk_audit[2];      // auditor public key (x, y)
    signal input recipient_addr;   // private 32-bit recipient address id

    signal E[2];                   // shared ElGamal ephemeral component (internal)
    signal C[2];                   // amount ciphertext (internal)
    signal C_a0[2];                // address low  limb ciphertext (internal)
    signal C_a1[2];                // address high limb ciphertext (internal)
    signal output state_out;       // Poseidon commitment to the ciphertexts

    // Range-check the amount to [0, 2^32) via Num2Bits(32).
    component rAmt = Num2Bits(32);
    rAmt.in <== amount;

    // Range-check the recipient address to [0, 2^32) and split into u16 limbs.
    component rAddr = Num2Bits(32);
    rAddr.in <== recipient_addr;
    signal addr_limb0;
    signal addr_limb1;
    var l0 = 0;
    var l1 = 0;
    for (var i = 0; i < 16; i++) {
        l0 += rAddr.out[i] * (1 << i);
        l1 += rAddr.out[i + 16] * (1 << i);
    }
    addr_limb0 <== l0;
    addr_limb1 <== l1;

    // Multi-message Twisted ElGamal to the auditor (shared randomness r).
    component encAmt = TwistedElGamalEncrypt(32);
    encAmt.message <== amount;
    encAmt.randomness <== r;
    encAmt.pk[0] <== pk_audit[0];
    encAmt.pk[1] <== pk_audit[1];
    E[0] <== encAmt.E[0];
    E[1] <== encAmt.E[1];
    C[0] <== encAmt.C[0];
    C[1] <== encAmt.C[1];

    component encA0 = TwistedElGamalEncrypt(32);
    encA0.message <== addr_limb0;
    encA0.randomness <== r;
    encA0.pk[0] <== pk_audit[0];
    encA0.pk[1] <== pk_audit[1];
    encA0.E[0] === E[0];
    encA0.E[1] === E[1];
    C_a0[0] <== encA0.C[0];
    C_a0[1] <== encA0.C[1];

    component encA1 = TwistedElGamalEncrypt(32);
    encA1.message <== addr_limb1;
    encA1.randomness <== r;
    encA1.pk[0] <== pk_audit[0];
    encA1.pk[1] <== pk_audit[1];
    encA1.E[0] === E[0];
    encA1.E[1] === E[1];
    C_a1[0] <== encA1.C[0];
    C_a1[1] <== encA1.C[1];

    // Chain the IVC state: commit the shared E and the three C points.
    component c1 = PoseidonBLS12_381();
    c1.in0 <== E[0];
    c1.in1 <== E[1];

    component c2 = PoseidonBLS12_381();
    c2.in0 <== c1.out;
    c2.in1 <== C[0];

    component c3 = PoseidonBLS12_381();
    c3.in0 <== c2.out;
    c3.in1 <== C[1];

    component c4 = PoseidonBLS12_381();
    c4.in0 <== c3.out;
    c4.in1 <== C_a0[0];

    component c5 = PoseidonBLS12_381();
    c5.in0 <== c4.out;
    c5.in1 <== C_a0[1];

    component c6 = PoseidonBLS12_381();
    c6.in0 <== c5.out;
    c6.in1 <== C_a1[0];

    component c7 = PoseidonBLS12_381();
    c7.in0 <== c6.out;
    c7.in1 <== C_a1[1];

    // For a singleton step the incoming public state is the 0 sentinel.
    state_in === 0;
    state_out <== c7.out;
}

component main {public [state_in]} = AuditViewkeyAddrStep();
