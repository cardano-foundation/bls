pragma circom 2.0.0;

// Anonymous Airdrop — Nova IVC step circuit (commitment + threshold + one
// MiMC SMT level per step).
//
// Each step enforces the full credential invariant of
// `anonymous_airdrop.circom`:
//   commitment = MiMC2(MiMC2(nullifier, nonce), score)
//   score >= minScore            (32-bit threshold)
//   current_out = MiMC2(switch(current_in, sibling, direction))
// and chains the public values unchanged:
//   digest_out == digest, minScore_out == minScore, nullifier_out == nullifier
//
// A chain of `depth` steps walks the leaf commitment (the app's initial
// state) up to the root.  The app checks current == digest after the fold.
// State (public, 4 + 4 signals): current, digest, minScore, nullifier.
// n_pub_in == n_pub_out == 4.

include "../Privacy/spend.circom";
include "../Privacy/mimc.circom";
include "../Ed25519Verify/node_modules/circomlib/circuits/comparators.circom";
include "../Ed25519Verify/node_modules/circomlib/circuits/bitify.circom";

template AnonymousAirdropStep() {
    signal input current_in;
    signal input digest;
    signal input minScore;
    signal input nullifier;
    signal input nonce;
    signal input score;
    signal input sibling;
    signal input direction;

    signal output current_out;
    signal output digest_out;
    signal output minScore_out;
    signal output nullifier_out;

    // 1. Range proofs: score < 2^32 and minScore < 2^32
    component n2bScore = Num2Bits(32);
    n2bScore.in <== score;
    component n2bMin = Num2Bits(32);
    n2bMin.in <== minScore;

    // 2. Threshold proof: score >= minScore
    component gte = GreaterEqThan(32);
    gte.in[0] <== score;
    gte.in[1] <== minScore;
    gte.out === 1;

    // 3. Commitment = MiMC2(MiMC2(nullifier, nonce), score)
    component hasher0 = Mimc2();
    hasher0.in0 <== nullifier;
    hasher0.in1 <== nonce;
    component hasher1 = Mimc2();
    hasher1.in0 <== hasher0.out;
    hasher1.in1 <== score;

    // 4. One SMT level
    component sw = SelectiveSwitch();
    sw.in0 <== current_in;
    sw.in1 <== sibling;
    sw.s   <== direction;

    component hasher = Mimc2();
    hasher.in0 <== sw.out0;
    hasher.in1 <== sw.out1;

    current_out <== hasher.out;
    digest_out   <== digest;
    minScore_out <== minScore;
    nullifier_out <== nullifier;
}

component main {public [current_in, digest, minScore, nullifier]} = AnonymousAirdropStep();
