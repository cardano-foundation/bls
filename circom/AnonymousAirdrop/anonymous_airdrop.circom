pragma circom 2.0.0;

// Anonymous Airdrop with Reputation Score Threshold
//
// A project wants to airdrop tokens to community members based on their
// reputation score, without revealing who gets what score. Each eligible
// member receives a secret credential (nullifier, nonce, score). The
// project commits all credentials to a Sparse Merkle Tree and publishes
// the root. A member proves:
//
//   1. Their credential exists in the SMT.
//   2. Their score >= minScore (public threshold).
//   3. The nullifier is revealed to prevent double-claims.
//
// Components reused from existing circuits:
//   - Privacy/spend.circom   → SelectiveSwitch, IfThenElse, Mimc2
//   - Privacy/mimc.circom    → Mimc2 hash
//   - circomlib/comparators  → GreaterEqThan
//   - circomlib/bitify       → Num2Bits

include "../Privacy/spend.circom";
include "../Privacy/mimc.circom";
include "../Ed25519Verify/node_modules/circomlib/circuits/comparators.circom";
include "../Ed25519Verify/node_modules/circomlib/circuits/bitify.circom";

template AnonymousAirdrop(depth, n) {
    // ── Public inputs ──────────────────────────────────────────────
    signal input digest;       // SMT root
    signal input minScore;     // Minimum reputation score required
    signal input nullifier;    // Credential ID (revealed to prevent double-claim)

    // ── Private inputs ─────────────────────────────────────────────
    signal input nonce;        // Secret nonce
    signal input score;        // Secret reputation score
    signal input sibling[depth];
    signal input direction[depth];

    // 1. Range proof: score < 2^n
    component n2bScore = Num2Bits(n);
    n2bScore.in <== score;

    // 2. Range proof: minScore < 2^n
    component n2bMin = Num2Bits(n);
    n2bMin.in <== minScore;

    // 3. Threshold proof: score >= minScore
    component gte = GreaterEqThan(n);
    gte.in[0] <== score;
    gte.in[1] <== minScore;
    gte.out === 1;

    // 4. Compute commitment = MiMC(MiMC(nullifier, nonce), score)
    component hasher0 = Mimc2();
    hasher0.in0 <== nullifier;
    hasher0.in1 <== nonce;

    component hasher1 = Mimc2();
    hasher1.in0 <== hasher0.out;
    hasher1.in1 <== score;

    signal commitment;
    commitment <== hasher1.out;

    // 5. SMT membership proof (same structure as Spend(depth))
    component switches[depth];
    component hashers[depth];
    signal current[depth + 1];
    current[0] <== commitment;

    for (var i = 0; i < depth; i++) {
        switches[i] = SelectiveSwitch();
        switches[i].in0 <== current[i];
        switches[i].in1 <== sibling[i];
        switches[i].s   <== direction[i];

        hashers[i] = Mimc2();
        hashers[i].in0 <== switches[i].out0;
        hashers[i].in1 <== switches[i].out1;

        current[i + 1] <== hashers[i].out;
    }

    digest === current[depth];
}
