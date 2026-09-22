pragma circom 2.0.0;

// PredicateRevocable — Nova IVC step circuit.
//
// Each step enforces the full revocable predicate (PredicateRevocable).
// Public state is chained unchanged so n_pub_in == n_pub_out.

include "./predicate_revocable.circom";

template PredicateRevocableStep(depth, revocation_depth) {
    // Public state (chained across steps)
    signal input pku;
    signal input pkv;
    signal input current_year;
    signal input country_root;
    signal input eligible;
    signal input expiry_year;
    signal input revocation_root;

    // Private witness
    signal input dob_year;
    signal input country;
    signal input Ru;
    signal input Rv;
    signal input S;
    signal input sibling[depth];
    signal input direction[depth];
    signal input revocation_sibling[revocation_depth];
    signal input revocation_direction[revocation_depth];

    // Chained state outputs
    signal output pk_u_out;
    signal output pk_v_out;
    signal output current_year_out;
    signal output country_root_out;
    signal output eligible_out;
    signal output expiry_year_out;
    signal output revocation_root_out;

    // Enforce the full revocable predicate
    component pred = PredicateRevocable(depth, revocation_depth);
    pred.pku <== pku;
    pred.pkv <== pkv;
    pred.current_year <== current_year;
    pred.country_root <== country_root;
    pred.eligible <== eligible;
    pred.expiry_year <== expiry_year;
    pred.revocation_root <== revocation_root;
    pred.dob_year <== dob_year;
    pred.country <== country;
    pred.Ru <== Ru;
    pred.Rv <== Rv;
    pred.S <== S;
    for (var i = 0; i < depth; i++) {
        pred.sibling[i] <== sibling[i];
        pred.direction[i] <== direction[i];
    }
    for (var i = 0; i < revocation_depth; i++) {
        pred.revocation_sibling[i] <== revocation_sibling[i];
        pred.revocation_direction[i] <== revocation_direction[i];
    }

    // Chain the state unchanged
    pk_u_out <== pku;
    pk_v_out <== pkv;
    current_year_out <== current_year;
    country_root_out <== country_root;
    eligible_out <== eligible;
    expiry_year_out <== expiry_year;
    revocation_root_out <== revocation_root;
}

component main {public [pku, pkv, current_year, country_root, eligible, expiry_year, revocation_root]} = PredicateRevocableStep(2, 2);
