pragma circom 2.0.0;

// PredicateDelegatable — Nova IVC step circuit.
//
// Each step enforces the full delegatable predicate and chains the
// public state unchanged so n_pub_in == n_pub_out.

include "./predicate_delegatable.circom";

template PredicateDelegatableStep(depth) {
    // Public state (chained across steps)
    signal input pku;
    signal input pkv;
    signal input current_year;
    signal input country_root;
    signal input eligible;
    signal input proxy_pku;
    signal input proxy_pkv;
    signal input delegation_expiry;

    // Private witness
    signal input dob_year;
    signal input country;
    signal input Ru;
    signal input Rv;
    signal input S;
    signal input sibling[depth];
    signal input direction[depth];
    signal input holder_sk;
    signal input delegation_sig_ru;
    signal input delegation_sig_rv;
    signal input delegation_sig_s;

    // Chained state outputs
    signal output pk_u_out;
    signal output pk_v_out;
    signal output current_year_out;
    signal output country_root_out;
    signal output eligible_out;
    signal output proxy_pku_out;
    signal output proxy_pkv_out;
    signal output delegation_expiry_out;

    // Enforce the full delegatable predicate
    component pred = PredicateDelegatable(depth);
    pred.pku <== pku;
    pred.pkv <== pkv;
    pred.current_year <== current_year;
    pred.country_root <== country_root;
    pred.eligible <== eligible;
    pred.proxy_pku <== proxy_pku;
    pred.proxy_pkv <== proxy_pkv;
    pred.delegation_expiry <== delegation_expiry;
    pred.dob_year <== dob_year;
    pred.country <== country;
    pred.Ru <== Ru;
    pred.Rv <== Rv;
    pred.S <== S;
    for (var i = 0; i < depth; i++) {
        pred.sibling[i] <== sibling[i];
        pred.direction[i] <== direction[i];
    }
    pred.holder_sk <== holder_sk;
    pred.delegation_sig_ru <== delegation_sig_ru;
    pred.delegation_sig_rv <== delegation_sig_rv;
    pred.delegation_sig_s <== delegation_sig_s;

    // Chain the state unchanged
    pk_u_out <== pku;
    pk_v_out <== pkv;
    current_year_out <== current_year;
    country_root_out <== country_root;
    eligible_out <== eligible;
    proxy_pku_out <== proxy_pku;
    proxy_pkv_out <== proxy_pkv;
    delegation_expiry_out <== delegation_expiry;
}

component main {public [pku, pkv, current_year, country_root, eligible, proxy_pku, proxy_pkv, delegation_expiry]} = PredicateDelegatableStep(2);
