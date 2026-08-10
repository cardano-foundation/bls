pragma circom 2.0.0;

// Cardano Ed25519 Key Ownership — Nova IVC step circuit (one scalar-mul bit
// per step).
//
// The original `cardano_ed25519_ownership.circom` proves knowledge of a
// 255-bit scalar sk with [sk]·G = PointA on Curve25519 and compress(PointA)
// = A.  Its per-step core is the base-point scalar multiplication, which
// decomposes into 255 `BitElementMulAny` steps (extended coordinates,
// [4][3]): double the accumulator and conditionally add G, selected by the
// secret bit.
//
//   state = (dblIn[4][3], addIn[4][3]);  n_pub_in == n_pub_out == 24.
//
// The point-compression and A-equality checks are final checks performed by
// the application after the fold: verify addOut == PointA (projectively) and
// PointCompress(PointA) == A.  They cannot be folded per-step because the
// accumulator is only the complete public key after all 255 bits.
//
// Compile: circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
//   cardano_ed25519_ownership_nova.circom --r1cs --wasm

include "../Ed25519Verify/scalarmul.circom";

template CardanoEd25519OwnershipStep() {
    signal input dbl_in_0_0; signal input dbl_in_0_1; signal input dbl_in_0_2;
    signal input dbl_in_1_0; signal input dbl_in_1_1; signal input dbl_in_1_2;
    signal input dbl_in_2_0; signal input dbl_in_2_1; signal input dbl_in_2_2;
    signal input dbl_in_3_0; signal input dbl_in_3_1; signal input dbl_in_3_2;
    signal input add_in_0_0; signal input add_in_0_1; signal input add_in_0_2;
    signal input add_in_1_0; signal input add_in_1_1; signal input add_in_1_2;
    signal input add_in_2_0; signal input add_in_2_1; signal input add_in_2_2;
    signal input add_in_3_0; signal input add_in_3_1; signal input add_in_3_2;
    signal input sel;

    signal output dbl_out_0_0; signal output dbl_out_0_1; signal output dbl_out_0_2;
    signal output dbl_out_1_0; signal output dbl_out_1_1; signal output dbl_out_1_2;
    signal output dbl_out_2_0; signal output dbl_out_2_1; signal output dbl_out_2_2;
    signal output dbl_out_3_0; signal output dbl_out_3_1; signal output dbl_out_3_2;
    signal output add_out_0_0; signal output add_out_0_1; signal output add_out_0_2;
    signal output add_out_1_0; signal output add_out_1_1; signal output add_out_1_2;
    signal output add_out_2_0; signal output add_out_2_1; signal output add_out_2_2;
    signal output add_out_3_0; signal output add_out_3_1; signal output add_out_3_2;

    signal dblIn[4][3];
    signal addIn[4][3];

    dblIn[0][0] <== dbl_in_0_0; dblIn[0][1] <== dbl_in_0_1; dblIn[0][2] <== dbl_in_0_2;
    dblIn[1][0] <== dbl_in_1_0; dblIn[1][1] <== dbl_in_1_1; dblIn[1][2] <== dbl_in_1_2;
    dblIn[2][0] <== dbl_in_2_0; dblIn[2][1] <== dbl_in_2_1; dblIn[2][2] <== dbl_in_2_2;
    dblIn[3][0] <== dbl_in_3_0; dblIn[3][1] <== dbl_in_3_1; dblIn[3][2] <== dbl_in_3_2;
    addIn[0][0] <== add_in_0_0; addIn[0][1] <== add_in_0_1; addIn[0][2] <== add_in_0_2;
    addIn[1][0] <== add_in_1_0; addIn[1][1] <== add_in_1_1; addIn[1][2] <== add_in_1_2;
    addIn[2][0] <== add_in_2_0; addIn[2][1] <== add_in_2_1; addIn[2][2] <== add_in_2_2;
    addIn[3][0] <== add_in_3_0; addIn[3][1] <== add_in_3_1; addIn[3][2] <== add_in_3_2;

    component step = BitElementMulAny();
    step.sel <== sel;
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 3; j++) {
            step.dblIn[i][j] <== dblIn[i][j];
            step.addIn[i][j] <== addIn[i][j];
        }
    }

    dbl_out_0_0 <== step.dblOut[0][0]; dbl_out_0_1 <== step.dblOut[0][1]; dbl_out_0_2 <== step.dblOut[0][2];
    dbl_out_1_0 <== step.dblOut[1][0]; dbl_out_1_1 <== step.dblOut[1][1]; dbl_out_1_2 <== step.dblOut[1][2];
    dbl_out_2_0 <== step.dblOut[2][0]; dbl_out_2_1 <== step.dblOut[2][1]; dbl_out_2_2 <== step.dblOut[2][2];
    dbl_out_3_0 <== step.dblOut[3][0]; dbl_out_3_1 <== step.dblOut[3][1]; dbl_out_3_2 <== step.dblOut[3][2];
    add_out_0_0 <== step.addOut[0][0]; add_out_0_1 <== step.addOut[0][1]; add_out_0_2 <== step.addOut[0][2];
    add_out_1_0 <== step.addOut[1][0]; add_out_1_1 <== step.addOut[1][1]; add_out_1_2 <== step.addOut[1][2];
    add_out_2_0 <== step.addOut[2][0]; add_out_2_1 <== step.addOut[2][1]; add_out_2_2 <== step.addOut[2][2];
    add_out_3_0 <== step.addOut[3][0]; add_out_3_1 <== step.addOut[3][1]; add_out_3_2 <== step.addOut[3][2];
}

component main {
    public [
        dbl_in_0_0, dbl_in_0_1, dbl_in_0_2,
        dbl_in_1_0, dbl_in_1_1, dbl_in_1_2,
        dbl_in_2_0, dbl_in_2_1, dbl_in_2_2,
        dbl_in_3_0, dbl_in_3_1, dbl_in_3_2,
        add_in_0_0, add_in_0_1, add_in_0_2,
        add_in_1_0, add_in_1_1, add_in_1_2,
        add_in_2_0, add_in_2_1, add_in_2_2,
        add_in_3_0, add_in_3_1, add_in_3_2
    ]
} = CardanoEd25519OwnershipStep();
