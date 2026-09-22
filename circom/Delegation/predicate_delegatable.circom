pragma circom 2.0.0;

/**
 * PredicateDelegatable — composite selective-disclosure circuit with
 * anonymous delegation.
 *
 * Extends Predicate so that a holder can delegate proof-generation rights
 * to a proxy.  The proxy generates the ZK proof but cannot forge proofs for
 * other holders or other circuits.
 *
 * The holder signs a delegation message:
 *   delegation_msg = PoseidonT6(proxy_pku, proxy_pkv, delegation_expiry, 0, 0, 0)
 * with their holder_sk (where holder_pk = holder_sk * G).
 *
 * The circuit verifies:
 *   1. Credential predicate (as before)
 *   2. holder_pk = holder_sk * G
 *   3. EdDSA signature on delegation_msg is valid for holder_pk
 *   4. delegation_expiry >= current_year
 *
 * Public inputs:
 *   pku, pkv, current_year, country_root, eligible,
 *   proxy_pku, proxy_pkv, delegation_expiry
 *
 * Private inputs:
 *   dob_year, country, Ru, Rv, S, sibling[depth], direction[depth],
 *   holder_sk, delegation_sig_ru, delegation_sig_rv, delegation_sig_s
 */

include "../Predicate/predicate.circom";
include "../EdDSAJubJub/jubjub.circom";                                     // EscalarMulFixJubJub
include "../EdDSAJubJub/scalarmul_jubjub.circom";                           // EscalarMulAnyJubJub
include "../PoseidonPreimage/poseidon_bls12_381_t6.circom";                 // PoseidonBLS12_381_T6
include "../EdDSAJubJub/node_modules/circomlib/circuits/bitify.circom";      // Num2Bits
include "../EdDSAJubJub/node_modules/circomlib/circuits/comparators.circom"; // GreaterEqThan

template PredicateDelegatable(depth) {
    // ---- predicate public inputs ----
    signal input pku;
    signal input pkv;
    signal input current_year;
    signal input country_root;
    signal input eligible;

    // ---- delegation public inputs ----
    signal input proxy_pku;
    signal input proxy_pkv;
    signal input delegation_expiry;

    // ---- predicate private inputs ----
    signal input dob_year;
    signal input country;
    signal input Ru;
    signal input Rv;
    signal input S;
    signal input sibling[depth];
    signal input direction[depth];

    // ---- delegation private inputs ----
    signal input holder_sk;
    signal input delegation_sig_ru;
    signal input delegation_sig_rv;
    signal input delegation_sig_s;

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

    // 2. Derive holder_pk = holder_sk * G
    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    component holderSkBits = Num2Bits(254);
    holderSkBits.in <== holder_sk;
    component holderPkMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        holderPkMul.e[i] <== holderSkBits.out[i];
    }
    signal holder_pku;
    signal holder_pkv;
    holder_pku <== holderPkMul.out[0];
    holder_pkv <== holderPkMul.out[1];

    // 3. Compute delegation_msg = PoseidonT6(proxy_pku, proxy_pkv, delegation_expiry, 0, 0, 0)
    component delegationMsg = PoseidonBLS12_381_T6();
    delegationMsg.in0 <== proxy_pku;
    delegationMsg.in1 <== proxy_pkv;
    delegationMsg.in2 <== delegation_expiry;
    delegationMsg.in3 <== 0;
    delegationMsg.in4 <== 0;
    delegationMsg.in5 <== 0;
    signal delegation_msg;
    delegation_msg <== delegationMsg.out;

    // 4. Verify delegation signature (standard EdDSA-JubJub)
    component delegationVerify = EdDSAVerifyThirdParty();
    delegationVerify.pku <== holder_pku;
    delegationVerify.pkv <== holder_pkv;
    delegationVerify.msg <== delegation_msg;
    delegationVerify.Ru <== delegation_sig_ru;
    delegationVerify.Rv <== delegation_sig_rv;
    delegationVerify.S <== delegation_sig_s;

    // 5. Delegation expiry check: delegation_expiry >= current_year
    component expiryGte = GreaterEqThan(32);
    expiryGte.in[0] <== delegation_expiry;
    expiryGte.in[1] <== current_year;
    expiryGte.out === 1;
}

// No component main here — use predicate_delegatable_depth2.circom for Groth16
// or predicate_delegatable_nova.circom for Nova IVC.
