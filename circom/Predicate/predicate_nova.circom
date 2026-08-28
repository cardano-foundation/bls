pragma circom 2.0.0;

// Predicate — Nova IVC step circuit for the composite selective-disclosure
// predicate.
//
// Each step re-proves the FULL credential predicate of `predicate.circom`:
//   claims_msg = Poseidon(dob_year, country)
//   k = PoseidonT6(R, pk, claims_msg) mod l;  [S]·G = R + [k]·pk
//   current_year >= dob_year + 21
//   country ∈ approvedCountries  (full Poseidon Merkle walk of `depth` levels)
//   eligible == 1
//
// This is the "single monolithic step" design: the whole predicate is enforced
// in every step and the public state is chained unchanged:
//   pku_out == pku, pkv_out == pkv, current_year_out == current_year,
//   country_root_out == country_root, eligible_out == eligible
// so n_pub_in == n_pub_out == 5 and the IVC chain rule holds. A fold of N=1
// verifies the predicate exactly once; folding N>1 repetitions is valid but
// redundant for a stateless predicate (kept for composition flexibility).
//
// The private witness (dob_year, country, Ru, Rv, S, sibling[], direction[])
// is hidden by the fold — only the 5 public state scalars are on-chain.

include "./predicate.circom";

template PredicateStep(depth) {
    // Public state (chained across steps)
    signal input pku;
    signal input pkv;
    signal input current_year;
    signal input country_root;
    signal input eligible;

    // Private witness
    signal input dob_year;
    signal input country;
    signal input Ru;
    signal input Rv;
    signal input S;
    signal input sibling[depth];
    signal input direction[depth];

    // Chained state outputs
    signal output pk_u_out;
    signal output pk_v_out;
    signal output current_year_out;
    signal output country_root_out;
    signal output eligible_out;

    // Enforce the full predicate
    component pred = Predicate(depth);
    pred.pku <== pku;
    pred.pkv <== pkv;
    pred.current_year <== current_year;
    pred.country_root <== country_root;
    pred.eligible <== eligible;
    pred.dob_year <== dob_year;
    pred.country <== country;
    pred.Ru <== Ru;
    pred.Rv <== Rv;
    pred.S <== S;
    for (var i = 0; i < depth; i++) {
        pred.sibling[i] <== sibling[i];
        pred.direction[i] <== direction[i];
    }

    // Chain the state unchanged
    pk_u_out <== pku;
    pk_v_out <== pkv;
    current_year_out <== current_year;
    country_root_out <== country_root;
    eligible_out <== eligible;
}

component main {public [pku, pkv, current_year, country_root, eligible]} = PredicateStep(2);
