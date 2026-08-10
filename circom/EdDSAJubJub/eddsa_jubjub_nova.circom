pragma circom 2.0.0;

// EdDSA-JubJub — Nova IVC step circuit (one scalar-mul bit per step).
//
// Each step runs `BitElementMulAnyJubJub`: double the accumulator and
// conditionally add the other point (Montgomery coordinates, [2]), selected
// by the secret bit `sel`.  A chain of 254 steps computes the full scalar
// multiplication [k]·G for the EdDSA verification equation.
//
// State (public, 4 + 4 signals, flattened to scalars): dblIn[2] and addIn[2].
// n_pub_in == n_pub_out == 4.
//
// Compile: circom -l node_modules/circomlib/circuits eddsa_jubjub_nova.circom
// The `jubjub.circom` pre-include (via escalarmulfix_jubjub.circom →
// montgomery.circom from circomlib) must load first so that `Montgomery2Edwards`
// used inside scalarmul_jubjub.circom resolves.

include "jubjub.circom";
include "scalarmul_jubjub.circom";

template JubJubScalarMulStep() {
    signal input dbl_in_0;
    signal input dbl_in_1;
    signal input add_in_0;
    signal input add_in_1;
    signal input sel;

    signal output dbl_out_0;
    signal output dbl_out_1;
    signal output add_out_0;
    signal output add_out_1;

    component step = BitElementMulAnyJubJub();
    step.sel <== sel;
    step.dblIn[0] <== dbl_in_0;
    step.dblIn[1] <== dbl_in_1;
    step.addIn[0] <== add_in_0;
    step.addIn[1] <== add_in_1;

    dbl_out_0 <== step.dblOut[0];
    dbl_out_1 <== step.dblOut[1];
    add_out_0 <== step.addOut[0];
    add_out_1 <== step.addOut[1];
}

component main {public [dbl_in_0, dbl_in_1, add_in_0, add_in_1]} = JubJubScalarMulStep();
