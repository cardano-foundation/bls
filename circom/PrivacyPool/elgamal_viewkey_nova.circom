pragma circom 2.0.0;

// Step 4 auditor viewing-key reveal — Nova IVC step circuit.
//
// Proves, as a single folded Nova step, that a valid Twisted ElGamal
// encryption of a (private) amount to an auditor's public key was computed:
//
//   E = r * G,   C = amount * H + r * pk_audit
//
// The public IVC state (n_pub_in == n_pub_out == 1, matching the nova-slim
// verifier) is a Poseidon commitment to the ciphertext:
//
//   state_out = commit(E.x, E.y, C.x, C.y)
//
// so the on-chain/IVC attestation binds the exact ciphertext that the prover
// reveals off-chain.  Only the designated auditor, holding the viewing key
// `sk_audit` with pk_audit = sk_audit * G, can recover the amount via
//
//   amount * H = C - sk_audit * E
//
// followed by a small discrete-log recovery (amount is u32 range-checked).
// Everyone else sees only the short ciphertext commitment.

include "bitify.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";
include "../TwistedElGamal/elgamal_encrypt.circom";

template AuditViewkeyStep() {
    signal input state_in;         // public IVC state (0 for a singleton step)
    signal input amount;           // private amount (range-checked to u32)
    signal input r;                // private ephemeral randomness (u32 demo)
    signal input pk_audit[2];      // auditor public key (x, y)

    signal E[2];                   // ElGamal ephemeral component (internal)
    signal C[2];                   // ElGamal committed ciphertext component (internal)
    signal output state_out;       // Poseidon commitment to the ciphertext

    // Range-check the amount to [0, 2^32) via Num2Bits(32).
    component rAmt = Num2Bits(32);
    rAmt.in <== amount;

    // Twisted ElGamal encryption of `amount` to the auditor.
    component enc = TwistedElGamalEncrypt(32);
    enc.message <== amount;
    enc.randomness <== r;
    enc.pk[0] <== pk_audit[0];
    enc.pk[1] <== pk_audit[1];
    E[0] <== enc.E[0];
    E[1] <== enc.E[1];
    C[0] <== enc.C[0];
    C[1] <== enc.C[1];

    // Chain the IVC state: commit the ciphertext so the public 1-scalar state
    // binds (E, C).  This is the "reveal handle" the auditor matches to the
    // ciphertext disclosed off-chain.
    component c1 = PoseidonBLS12_381();
    c1.in0 <== E[0];
    c1.in1 <== E[1];

    component c2 = PoseidonBLS12_381();
    c2.in0 <== c1.out;
    c2.in1 <== C[0];

    component c3 = PoseidonBLS12_381();
    c3.in0 <== c2.out;
    c3.in1 <== C[1];

    // For a singleton step the incoming public state is the 0 sentinel.
    // (For chained deployments one would fold in state_in as well.)
    state_in === 0;
    state_out <== c3.out;
}

component main {public [state_in]} = AuditViewkeyStep();
