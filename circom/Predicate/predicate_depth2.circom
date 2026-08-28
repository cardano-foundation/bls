pragma circom 2.0.0;

// Instantiate the Predicate circuit at depth = 2 (approved-countries Merkle tree).
include "./predicate.circom";

component main {public [pku, pkv, current_year, country_root, eligible]} = Predicate(2);
