/*
 * EC-VRF verification circuit — JubJub over BLS12-381.
 *
 * Implements ECVRF_verify from RFC 9381, adapted to JubJub:
 *   1. H = [Poseidon(msg)]·G            (hash-to-curve, simplified)
 *   2. U = [s]·G  + [neg_c]·pk          (where neg_c = l - c mod l)
 *   3. V = [s]·H  + [neg_c]·Gamma
 *   4. c' = PoseidonChain(pk ‖ H ‖ Gamma ‖ U ‖ V) mod l
 *   5. Assert c' == c
 *
 * Public inputs: pku, pkv (public key), Gamma_u, Gamma_v (VRF output),
 *                msg, c (challenge), s (response scalar)
 *
 * Matches Cardano's BLS12-381 field and JubJub curve.
 * License: MIT.
 */
pragma circom 2.0.0;

include "bitify.circom";
include "jubjub.circom";
include "scalarmul_jubjub.circom";
include "jubjub_primitives.circom";
include "poseidon_bls12_381.circom";

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

template VRFVerify() {
    signal input pku;
    signal input pkv;
    signal input Gamma_u;
    signal input Gamma_v;
    signal input msg;
    signal input c;
    signal input s;

    var BASE8[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];
    var L = 6554484396890773809930967563523245729705921265872317281365359162392183254199;

    // =========================================================================
    // Step 1: H = [Poseidon(msg, 0)]·G   (simplified hash-to-curve)
    // =========================================================================
    component hHash = PoseidonBLS12_381();
    hHash.in0 <== msg;
    hHash.in1 <== 0;

    component hModL = ModuloL();
    hModL.in <== hHash.out;

    component hBits = Num2Bits(254);
    hBits.in <== hModL.out;

    component hMul = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        hMul.e[i] <== hBits.out[i];
    }

    // =========================================================================
    // Step 2: neg_c = L - (c mod L)
    // =========================================================================
    component cModL = ModuloL();
    cModL.in <== c;

    signal neg_c;
    neg_c <== L - cModL.out;

    // =========================================================================
    // Step 3: U = [s]·G + [neg_c]·pk
    // =========================================================================
    component sModL = ModuloL();
    sModL.in <== s;

    component sBits = Num2Bits(254);
    sBits.in <== sModL.out;

    component sMulG = EscalarMulFixJubJub(254, BASE8);
    for (var i = 0; i < 254; i++) {
        sMulG.e[i] <== sBits.out[i];
    }

    component negCBits = Num2Bits(254);
    negCBits.in <== neg_c;

    component cMulPk = EscalarMulAnyJubJub(254);
    for (var i = 0; i < 254; i++) {
        cMulPk.e[i] <== negCBits.out[i];
    }
    cMulPk.p[0] <== pku;
    cMulPk.p[1] <== pkv;

    component uAdd = JubJubAdd();
    uAdd.x1 <== sMulG.out[0];
    uAdd.y1 <== sMulG.out[1];
    uAdd.x2 <== cMulPk.out[0];
    uAdd.y2 <== cMulPk.out[1];

    // =========================================================================
    // Step 4: V = [s]·H + [neg_c]·Gamma
    // =========================================================================
    component cMulGamma = EscalarMulAnyJubJub(254);
    for (var i = 0; i < 254; i++) {
        cMulGamma.e[i] <== negCBits.out[i];
    }
    cMulGamma.p[0] <== Gamma_u;
    cMulGamma.p[1] <== Gamma_v;

    component sMulH = EscalarMulAnyJubJub(254);
    for (var i = 0; i < 254; i++) {
        sMulH.e[i] <== sBits.out[i];
    }
    sMulH.p[0] <== hMul.out[0];
    sMulH.p[1] <== hMul.out[1];

    component vAdd = JubJubAdd();
    vAdd.x1 <== sMulH.out[0];
    vAdd.y1 <== sMulH.out[1];
    vAdd.x2 <== cMulGamma.out[0];
    vAdd.y2 <== cMulGamma.out[1];

    // =========================================================================
    // Step 5: c' = PoseidonChain(pk ‖ H ‖ Gamma ‖ U ‖ V) mod l
    //   Chain Poseidon t=3 hashes (2 inputs each) over 10 field elements.
    //   h1 = Poseidon(pk_x, pk_y)
    //   h2 = Poseidon(h1, H_x)
    //   h3 = Poseidon(h2, H_y)
    //   h4 = Poseidon(h3, Gamma_x)
    //   h5 = Poseidon(h4, Gamma_y)
    //   h6 = Poseidon(h5, U_x)
    //   h7 = Poseidon(h6, U_y)
    //   h8 = Poseidon(h7, V_x)
    //   h9 = Poseidon(h8, V_y)
    // =========================================================================
    component h1 = PoseidonBLS12_381();
    h1.in0 <== pku;
    h1.in1 <== pkv;

    component h2 = PoseidonBLS12_381();
    h2.in0 <== h1.out;
    h2.in1 <== hMul.out[0];

    component h3 = PoseidonBLS12_381();
    h3.in0 <== h2.out;
    h3.in1 <== hMul.out[1];

    component h4 = PoseidonBLS12_381();
    h4.in0 <== h3.out;
    h4.in1 <== Gamma_u;

    component h5 = PoseidonBLS12_381();
    h5.in0 <== h4.out;
    h5.in1 <== Gamma_v;

    component h6 = PoseidonBLS12_381();
    h6.in0 <== h5.out;
    h6.in1 <== uAdd.xout;

    component h7 = PoseidonBLS12_381();
    h7.in0 <== h6.out;
    h7.in1 <== uAdd.yout;

    component h8 = PoseidonBLS12_381();
    h8.in0 <== h7.out;
    h8.in1 <== vAdd.xout;

    component h9 = PoseidonBLS12_381();
    h9.in0 <== h8.out;
    h9.in1 <== vAdd.yout;

    component cPrimeModL = ModuloL();
    cPrimeModL.in <== h9.out;

    // =========================================================================
    // Step 6: Assert c' == c
    // =========================================================================
    cPrimeModL.out === cModL.out;
}

component main {public [pku, pkv, Gamma_u, Gamma_v, msg, c, s]} = VRFVerify();
