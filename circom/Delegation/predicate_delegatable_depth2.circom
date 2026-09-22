pragma circom 2.0.0;

// Groth16 instantiation of PredicateDelegatable at depth=2.
include "./predicate_delegatable.circom";

component main {public [pku, pkv, current_year, country_root, eligible, proxy_pku, proxy_pkv, delegation_expiry]} = PredicateDelegatable(2);
