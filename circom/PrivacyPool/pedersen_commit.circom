pragma circom 2.0.0;

// Pedersen commitment over JubJub — include-only library.
//
//   C = value * H + blinding * G
//
// G = BASE8 (JubJub generator).  H = 2*G is reused from the TwistedElGamal
// circuits for consistency with the rest of the selective-disclosure stack.
// Both `value` and `blinding` are n-bit scalars; in practice they carry a
// u32 amount and a full-width blinding factor.
//
// This template is intentionally minimal: it proves the commitment opens to
// the supplied value and blinding, nothing more.  Conservation relations
// (e.g. v_in = v_out1 + v_out2 + fee) are enforced by the caller.

include "../EdDSAJubJub/jubjub_primitives.circom";
include "../EdDSAJubJub/escalarmulfix_jubjub.circom";
include "bitify.circom";

template PedersenCommit(nBits) {
    signal input value;       // committed message scalar
    signal input blinding;    // hiding randomness
    signal output C[2];       // JubJub point commitment (x, y)

    // G = BASE8
    var G[2] = [
        28336281903124990867587793011069573392383982287722241916350956173377953689573,
        39385640392217313770878525135509063452020585410343666726093009378539878503883
    ];

    // H = 2*G
    var H[2] = [
        28470720865600895264575250048565445848783776096727055802752773414594395577565,
        22436823168302830732060329876357833227584559018655015131868680653136578255473
    ];

    component vBits = Num2Bits(nBits);
    vBits.in <== value;

    component rBits = Num2Bits(nBits);
    rBits.in <== blinding;

    // value * H
    component vH = EscalarMulFixJubJub(nBits, H);
    for (var i = 0; i < nBits; i++) {
        vH.e[i] <== vBits.out[i];
    }

    // blinding * G
    component rG = EscalarMulFixJubJub(nBits, G);
    for (var i = 0; i < nBits; i++) {
        rG.e[i] <== rBits.out[i];
    }

    // C = vH + rG
    component adder = JubJubAdd();
    adder.x1 <== vH.out[0];
    adder.y1 <== vH.out[1];
    adder.x2 <== rG.out[0];
    adder.y2 <== rG.out[1];

    C[0] <== adder.xout;
    C[1] <== adder.yout;
}
