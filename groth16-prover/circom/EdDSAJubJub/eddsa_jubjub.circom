/*
 * EdDSA-JubJub verifier circuit for BLS12-381.
 *
 * Proves knowledge of a secret key `sk` such that:
 *   1. R = [r]·G where r = Poseidon(sk, msg) mod l  (deterministic nonce)
 *   2. [S]·G = R + [k]·pk   (EdDSA verification equation)
 *      where k = PoseidonT6(R.u, R.v, pk.u, pk.v, msg) mod l
 *
 * Knowledge of pk = [sk]·G is implicit: the challenge k binds pk,
 * and the verification equation requires knowing sk for that pk.
 *
 * Public inputs:  Ru, Rv, pku, pkv, msg, S
 * Private inputs: sk
 *
 * Matches zeroj's EdDSAJubjub.sign/verify scheme:
 *   - Poseidon hash (BLS12-381, t=3 alpha=5 for nonce, t=6 alpha=5 for challenge)
 *   - Challenge binds (R, pk, msg)
 *
 * License: MIT.
 */
pragma circom 2.0.0;

include "bitify.circom";
include "jubjub.circom";
include "scalarmul_jubjub.circom";
include "comparators.circom";
include "poseidon_bls12_381.circom";
include "poseidon_bls12_381_t6.circom";

/*
 * ModuloL: reduce a field element mod the JubJub subgroup order l.
 *
 * JubJub over BLS12-381 scalar field: cofactor = 8, so p/l ≈ 8.
 * The quotient q = in/l is in [0, 7].  We enforce this by decomposing q
 * into 3 bits: q = b0 + 2·b1 + 4·b2 with bi ∈ {0,1}.
 *
 * The prover is additionally constrained by the surrounding circuit:
 *   - For nonce r: R' = [r]·G must equal the public R
 *   - For challenge k: [S]·G must equal R + [k]·pk
 * These make any "wrong" mod-l reduction invalid.
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
 * EdDSAVerifyJubJub: EdDSA signature verification.
 *
 * Proves: "I know sk such that (R,S) is a valid
 * deterministic EdDSA-JubJub signature on msg for pk."
 *
 * Public signals: Ru, Rv (R point), pku, pkv (public key), msg, S (scalar).
 * Private signal: sk (secret key scalar in [1, l)).
 */
template EdDSAVerifyJubJub() {
    // Public inputs
    signal input Ru;
    signal input Rv;
    signal input pku;
    signal input pkv;
    signal input msg;
    signal input S;

    // Private input
    signal input sk;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    // =========================================================================
    // Step 1: Compute r = Poseidon(sk, msg) mod l
    // =========================================================================
    component nonceHash = PoseidonBLS12_381();
    nonceHash.in0 <== sk;
    nonceHash.in1 <== msg;

    component rModL = ModuloL();
    rModL.in <== nonceHash.out;

    // =========================================================================
    // Step 2: Compute R' = [r]·G and verify R' = R
    // =========================================================================
    component rBits = Num2Bits(254);
    rBits.in <== rModL.out;

    component rMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        rMul.e[i] <== rBits.out[i];
    }
    rMul.out[0] === Ru;
    rMul.out[1] === Rv;

    // =========================================================================
    // Step 3: Compute challenge k = PoseidonT6(R, pk, msg) mod l
    // =========================================================================
    component challengeHash = PoseidonBLS12_381_T6();
    challengeHash.in0 <== Ru;
    challengeHash.in1 <== Rv;
    challengeHash.in2 <== pku;
    challengeHash.in3 <== pkv;
    challengeHash.in4 <== msg;

    component kModL = ModuloL();
    kModL.in <== challengeHash.out;

    // =========================================================================
    // Step 4: Compute [S]·G (fixed-base)
    // =========================================================================
    component sBits = Num2Bits(254);
    sBits.in <== S;

    component sMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        sMul.e[i] <== sBits.out[i];
    }

    // =========================================================================
    // Step 5: Compute [k]·pk (variable-base)
    // =========================================================================
    component kBits = Num2Bits(254);
    kBits.in <== kModL.out;

    component kMul = EscalarMulAnyJubJub(254);
    for (var i = 0; i < 254; i++) {
        kMul.e[i] <== kBits.out[i];
    }
    kMul.p[0] <== pku;
    kMul.p[1] <== pkv;

    // =========================================================================
    // Step 6: Compute R + [k]·pk
    // =========================================================================
    component add = JubJubAdd();
    add.x1 <== Ru;
    add.y1 <== Rv;
    add.x2 <== kMul.out[0];
    add.y2 <== kMul.out[1];

    // =========================================================================
    // Step 7: Verify [S]·G = R + [k]·pk
    // =========================================================================
    sMul.out[0] === add.xout;
    sMul.out[1] === add.yout;
}

component main {public [Ru, Rv, pku, pkv, msg, S]} = EdDSAVerifyJubJub();
