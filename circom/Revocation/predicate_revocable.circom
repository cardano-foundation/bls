pragma circom 2.0.0;

/**
 * PredicateRevocable — composite selective-disclosure circuit with expiry
 * and Sparse-Merkle-Tree revocation.
 *
 * Extends Predicate with two additional checks:
 *
 *   1. Expiry:  expiry_year >= current_year  (credential has not expired)
 *   2. Revocation:  credential hash is NOT in the revocation SMT
 *
 * The revocation SMT is a sparse Merkle tree maintained by the issuer.
 * Revoked credentials are inserted at position  claims_msg % 2^revocation_depth
 * with leaf value Poseidon(claims_msg, 0).  The holder proves non-membership
 * by showing the path from the default empty leaf (0) at their position to
 * the published revocation_root.
 *
 * Public inputs:
 *   pku, pkv, current_year, country_root, eligible, expiry_year, revocation_root
 *
 * Private inputs:
 *   dob_year, country, Ru, Rv, S, sibling[depth], direction[depth],
 *   revocation_sibling[revocation_depth], revocation_direction[revocation_depth]
 */

include "../Predicate/predicate.circom";
include "./smt_nonmembership.circom";
include "../EdDSAJubJub/node_modules/circomlib/circuits/comparators.circom";
include "../PoseidonPreimage/poseidon_bls12_381.circom";

template PredicateRevocable(depth, revocation_depth) {
    // ---- predicate public inputs ----
    signal input pku;
    signal input pkv;
    signal input current_year;
    signal input country_root;
    signal input eligible;

    // ---- revocation public inputs ----
    signal input expiry_year;
    signal input revocation_root;

    // ---- predicate private inputs ----
    signal input dob_year;
    signal input country;
    signal input Ru;
    signal input Rv;
    signal input S;
    signal input sibling[depth];
    signal input direction[depth];

    // ---- revocation private inputs ----
    signal input revocation_sibling[revocation_depth];
    signal input revocation_direction[revocation_depth];

    // 1. Reuse the Predicate template verbatim
    component predicate = Predicate(depth);
    predicate.pku <== pku;
    predicate.pkv <== pkv;
    predicate.current_year <== current_year;
    predicate.country_root <== country_root;
    predicate.eligible <== eligible;
    predicate.dob_year <== dob_year;
    predicate.country <== country;
    predicate.Ru <== Ru;
    predicate.Rv <== Rv;
    predicate.S <== S;
    for (var i = 0; i < depth; i++) {
        predicate.sibling[i] <== sibling[i];
        predicate.direction[i] <== direction[i];
    }

    // 2. Expiry check: expiry_year >= current_year
    component expiryGte = GreaterEqThan(32);
    expiryGte.in[0] <== expiry_year;
    expiryGte.in[1] <== current_year;
    expiryGte.out === 1;

    // 3. Recompute claims_msg (needed for revocation leaf position)
    component claimsHash = PoseidonBLS12_381();
    claimsHash.in0 <== dob_year;
    claimsHash.in1 <== country;
    signal claims_msg;
    claims_msg <== claimsHash.out;

    // 4. Revocation non-membership: claims_msg is NOT in the revocation SMT
    component smt = SMTNonMembership(revocation_depth);
    smt.root <== revocation_root;
    smt.leaf_index <== claims_msg;
    for (var i = 0; i < revocation_depth; i++) {
        smt.sibling[i] <== revocation_sibling[i];
        smt.direction[i] <== revocation_direction[i];
    }
}

// No component main here — use predicate_revocable_depth2.circom for Groth16
// or predicate_revocable_nova.circom for Nova IVC.
