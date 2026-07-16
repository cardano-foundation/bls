/*
 * EdDSA-JubJub verifier circuit for BLS12-381.
 *
 * Proves knowledge of a secret key `sk` such that:
 *   1. pk = [sk]·G           (key ownership)
 *   2. R = [r]·G where r = Poseidon(sk, msg) mod l  (deterministic nonce)
 *   3. [S]·G = R + [k]·pk   (EdDSA verification equation)
 *      where k = PoseidonN(R.u, R.v, pk.u, pk.v, msg) mod l
 *
 * Public inputs:  Ru, Rv, pku, pkv, msg, S
 * Private inputs: sk
 *
 * Matches zeroj's EdDSAJubjub.sign/verify scheme:
 *   - Poseidon hash (BLS12-381, t=3, alpha=5)
 *   - Left-fold chaining for 5-input hashN
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

    signal q;
    out <-- in % L;
    q <-- in / L;

    in === q * L + out;

    // q ∈ [0, 7]  (since p < 8L, cofactor = 8)
    // Decompose into 3 bits: q = b0 + 2·b1 + 4·b2
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
 * PoseidonHashN: 5-input Poseidon hash using left-fold chaining.
 *   hashN(a,b,c,d,e) = hash(hash(hash(hash(a,b),c),d),e)
 *
 * Matches zeroj's PoseidonHash.hashN with PoseidonBLS12_381 (t=3, RF=8, RP=57).
 */
template PoseidonHashN5() {
    signal input in0;
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal output out;

    component h1 = PoseidonBLS12_381();
    h1.in0 <== in0;
    h1.in1 <== in1;

    component h2 = PoseidonBLS12_381();
    h2.in0 <== h1.out;
    h2.in1 <== in2;

    component h3 = PoseidonBLS12_381();
    h3.in0 <== h2.out;
    h3.in1 <== in3;

    component h4 = PoseidonBLS12_381();
    h4.in0 <== h3.out;
    h4.in1 <== in4;

    out <== h4.out;
}

/*
 * EdDSAVerifyJubJub: full EdDSA signature verification.
 *
 * Proves: "I know sk such that pk = [sk]·G and (R,S) is a valid
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
    // Step 1: Verify pk = [sk]·G
    // =========================================================================
    component skBits = Num2Bits(254);
    skBits.in <== sk;

    component pkMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        pkMul.e[i] <== skBits.out[i];
    }
    pkMul.out[0] === pku;
    pkMul.out[1] === pkv;

    // =========================================================================
    // Step 2: Compute r = Poseidon(sk, msg) mod l
    // =========================================================================
    component nonceHash = PoseidonBLS12_381();
    nonceHash.in0 <== sk;
    nonceHash.in1 <== msg;

    component rModL = ModuloL();
    rModL.in <== nonceHash.out;

    // =========================================================================
    // Step 3: Compute R' = [r]·G and verify R' = R
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
    // Step 4: Compute challenge k = PoseidonN(R, pk, msg) mod l
    // =========================================================================
    component challengeHash = PoseidonHashN5();
    challengeHash.in0 <== Ru;
    challengeHash.in1 <== Rv;
    challengeHash.in2 <== pku;
    challengeHash.in3 <== pkv;
    challengeHash.in4 <== msg;

    component kModL = ModuloL();
    kModL.in <== challengeHash.out;

    // =========================================================================
    // Step 5: Compute [S]·G (fixed-base)
    // =========================================================================
    component sBits = Num2Bits(254);
    sBits.in <== S;

    component sMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        sMul.e[i] <== sBits.out[i];
    }

    // =========================================================================
    // Step 6: Compute [k]·pk (variable-base)
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
    // Step 7: Compute R + [k]·pk
    // =========================================================================
    component add = JubJubAdd();
    add.x1 <== Ru;
    add.y1 <== Rv;
    add.x2 <== kMul.out[0];
    add.y2 <== kMul.out[1];

    // =========================================================================
    // Step 8: Verify [S]·G = R + [k]·pk
    // =========================================================================
    sMul.out[0] === add.xout;
    sMul.out[1] === add.yout;
}

component main {public [Ru, Rv, pku, pkv, msg, S]} = EdDSAVerifyJubJub();
