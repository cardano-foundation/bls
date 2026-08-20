/*
 * VRF scalar multiplication step — Nova IVC wrapper.
 *
 * Each step runs one bit of the Montgomery ladder for [scalar]·G on JubJub.
 * A chain of 254 steps computes the full scalar multiplication.
 *
 * Used for VRF response scalar s: chain computes [s]·G which is then
 * combined with other VRF components for on-chain verification.
 *
 * State (public, 4 signals): dbl_in[2] and add_in[2].
 * n_pub_in == n_pub_out == 4.
 *
 * Compile: circom -l node_modules/circomlib/circuits vrf_verify_nova.circom
 */
pragma circom 2.0.0;

include "jubjub.circom";
include "scalarmul_jubjub.circom";

template VRFScalarMulStep() {
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

component main {public [dbl_in_0, dbl_in_1, add_in_0, add_in_1]} = VRFScalarMulStep();
