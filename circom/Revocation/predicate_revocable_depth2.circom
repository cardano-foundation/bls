pragma circom 2.0.0;

// Groth16 instantiation of PredicateRevocable at depth=2, revocation_depth=2.
include "./predicate_revocable.circom";

component main {public [pku, pkv, current_year, country_root, eligible, expiry_year, revocation_root]} = PredicateRevocable(2, 2);
