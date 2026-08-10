pragma circom 2.0.0;

include "../Ed25519Verify/scalarmul.circom";

template CardanoKeyOwnershipSMTStep() {
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
} = CardanoKeyOwnershipSMTStep();