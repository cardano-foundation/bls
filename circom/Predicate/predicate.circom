pragma circom 2.0.0;

/**
 * Predicate — composite selective-disclosure circuit.
 *
 * A holder proves they satisfy a predicate over a signed credential without
 * revealing any credential field or identity. Specifically, the holder proves:
 *
 *   issuer_pk owns a valid EdDSA-JubJub signature (R,S) on
 *   claims_msg = Poseidon(dob_year, country)
 *
 * and that the committed credential satisfies:
 *
 *   dob_year + 21 <= current_year        (holder is at least 21 years old)
 *   country ∈ approvedCountries          (country is a leaf of the published Merkle tree)
 *   eligible == 1
 *
 * All field values (dob_year, country) and the signature (R,S) are private
 * inputs. The only public inputs are the issuer public key, the current year,
 * the approved-countries Merkle root, and the eligibility flag.
 *
 * Third-party EdDSA verification: the holder does NOT know the issuer's secret
 * key. They only verify [S]·G = R + [k]·pk with k = PoseidonT6(R, pk, claims_msg) mod l.
 *
 * Reuses validated primitives:
 *   - PoseidonBLS12_381        (`PoseidonPreimage/`)
 *   - PoseidonBLS12_381_T6     (`EdDSAJubJub/poseidon_bls12_381_t6.circom`)
 *   - ModuloL, point muls       (`EdDSAJubJub/eddsa_jubjub.circom`)
 *   - PoseidonMerkle           (`PoseidonMerkle/poseidon_merkle.circom`)
 *   - GreaterEqThan            (circomlib ComparatorFrom01)
 */

// Main-free support files only (eddsa_jubjub.circom bundles a `main`, so it is
// excluded and ModuloL is inlined below).
include "../PoseidonMerkle/poseidon_merkle.circom";                          // PoseidonBLS12_381, SelectiveSwitch, PoseidonMerkle
include "../EdDSAJubJub/jubjub.circom";                                     // JubJubAdd, EscalarMulFixJubJub (+bitify, jubjub_primitives)
include "../EdDSAJubJub/scalarmul_jubjub.circom";                           // EscalarMulAnyJubJub (+bitify, jubjub_primitives)
include "../PoseidonPreimage/poseidon_bls12_381_t6.circom";                 // PoseidonBLS12_381_T6
include "../EdDSAJubJub/node_modules/circomlib/circuits/bitify.circom";      // Num2Bits
include "../EdDSAJubJub/node_modules/circomlib/circuits/comparators.circom"; // GreaterEqThan

/*
 * ModuloL: reduce a BLS12-381 field element mod the JubJub subgroup order l.
 *
 * JubJub over BLS12-381 scalar field: cofactor = 8, so p/l ≈ 8. The quotient
 * q = in/l is in [0, 7], enforced by decomposing q into 3 bits.
 * Copied verbatim from eddsa_jubjub.circom (which cannot be included because
 * it also declares a `component main`).
 */
template ModuloL() {
    signal input in;
    signal output out;

    var L = 6554484396890773809930967563523245729705921265872317281365359162392183254199;
    var L_INV = 36853270128701068303485641906008869780233952125424200970240543035835732912806;

    out <-- in % L;

    signal q;
    q <-- (in - out) * L_INV;

    in === q * L + out;

    signal b0;
    signal b1;
    signal b2;
    b0 <-- q & 1;
    b1 <-- (q >> 1) & 1;
    b2 <-- (q >> 2) & 1;
    q === b0 + 2 * b1 + 4 * b2;
    b0 * (1 - b0) === 0;
    b1 * (1 - b1) === 0;
    b2 * (1 - b2) === 0;
}

/*
 * Third-party EdDSA-JubJub signature verification.
 *
 * Proves: (R, S) is a valid EdDSA-JubJub signature on `msg` for public key
 * (pku, pkv), where the challenge is k = PoseidonT6(R, pk, msg) mod l and the
 * verification equation is [S]·G = R + [k]·pk.
 *
 * The signer's secret key is NOT required — this is standard Schnorr-style
 * verification used when an issuer signs a message for a holder to carry.
 */
template EdDSAVerifyThirdParty() {
    signal input pku;
    signal input pkv;
    signal input msg;
    signal input Ru;
    signal input Rv;
    signal input S;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    // Step 1: k = PoseidonT6(R, pk, msg) mod l
    component challengeHash = PoseidonBLS12_381_T6();
    challengeHash.in0 <== Ru;
    challengeHash.in1 <== Rv;
    challengeHash.in2 <== pku;
    challengeHash.in3 <== pkv;
    challengeHash.in4 <== msg;

    component kModL = ModuloL();
    kModL.in <== challengeHash.out;

    // Step 2: [S]·G (fixed base)
    component sBits = Num2Bits(254);
    sBits.in <== S;
    component sMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        sMul.e[i] <== sBits.out[i];
    }

    // Step 3: [k]·pk (variable base)
    component kBits = Num2Bits(254);
    kBits.in <== kModL.out;
    component kMul = EscalarMulAnyJubJub(254);
    for (var i = 0; i < 254; i++) {
        kMul.e[i] <== kBits.out[i];
    }
    kMul.p[0] <== pku;
    kMul.p[1] <== pkv;

    // Step 4: R + [k]·pk
    component add = JubJubAdd();
    add.x1 <== Ru;
    add.y1 <== Rv;
    add.x2 <== kMul.out[0];
    add.y2 <== kMul.out[1];

    // Step 5: verify [S]·G == R + [k]·pk
    sMul.out[0] === add.xout;
    sMul.out[1] === add.yout;
}

/*
 * Predicate — composite credential predicate proof.
 *
 * Public inputs:
 *   pku, pkv       — issuer public key (JubJub)
 *   current_year   — current year, e.g. 2026
 *   country_root   — Merkle root of the approved-countries set
 *   eligible       — must equal 1
 *
 * Private inputs:
 *   dob_year       — holder's year of birth
 *   country        — holder's country code (leaf of approved set)
 *   Ru, Rv, S      — issuer's EdDSA-JubJub signature on claims_msg
 *   sibling, direction — Merkle membership witness for `country`
 */
template Predicate(depth) {
    signal input pku;
    signal input pkv;
    signal input current_year;
    signal input country_root;
    signal input eligible;

    signal input dob_year;
    signal input country;
    signal input Ru;
    signal input Rv;
    signal input S;
    signal input sibling[depth];
    signal input direction[depth];

    // 1. claims_msg = Poseidon(dob_year, country)
    component claimsHash = PoseidonBLS12_381();
    claimsHash.in0 <== dob_year;
    claimsHash.in1 <== country;
    signal claims_msg;
    claims_msg <== claimsHash.out;

    // 2. Verify issuer's EdDSA-JubJub signature on claims_msg (third party)
    component eddsa = EdDSAVerifyThirdParty();
    eddsa.pku <== pku;
    eddsa.pkv <== pkv;
    eddsa.msg <== claims_msg;
    eddsa.Ru <== Ru;
    eddsa.Rv <== Rv;
    eddsa.S <== S;

    // 3. Age check: current_year >= dob_year + 21 (holder at least 21)
    signal dob_plus_21;
    dob_plus_21 <== dob_year + 21;
    component ageGte = GreaterEqThan(32);
    ageGte.in[0] <== current_year;
    ageGte.in[1] <== dob_plus_21;
    ageGte.out === 1;

    // 4. Range-check country (canonical 32-bit value)
    component countryBits = Num2Bits(32);
    countryBits.in <== country;

    // 5. Country ∈ approvedCountries — Merkle membership with leaf = Poseidon(country, 0)
    component merkle = PoseidonMerkle(depth);
    merkle.digest <== country_root;
    merkle.nullifier <== country;
    merkle.nonce <== 0;
    for (var i = 0; i < depth; i++) {
        merkle.sibling[i] <== sibling[i];
        merkle.direction[i] <== direction[i];
    }

    // 6. eligible must be exactly 1
    eligible === 1;
}
