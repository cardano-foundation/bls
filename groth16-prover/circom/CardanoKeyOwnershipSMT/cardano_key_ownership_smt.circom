pragma circom 2.0.0;

include "../Ed25519Verify/scalarmul.circom";
include "../Ed25519Verify/pointcompress.circom";
include "../Ed25519Verify/verify.circom";
include "../Privacy/mimc.circom";

template IfThenElse() {
    signal input condition;
    signal input true_value;
    signal input false_value;
    signal output out;

    condition * (1 - condition) === 0;

    signal helper;
    helper <== condition * (true_value - false_value);
    out <== helper + false_value;
}

template SelectiveSwitch() {
    signal input in0;
    signal input in1;
    signal input s;
    signal output out0;
    signal output out1;

    component ifthen0 = IfThenElse();
    ifthen0.condition <== s;
    ifthen0.true_value <== in1;
    ifthen0.false_value <== in0;
    out0 <== ifthen0.out;

    component ifthen1 = IfThenElse();
    ifthen1.condition <== s;
    ifthen1.true_value <== in0;
    ifthen1.false_value <== in1;
    out1 <== ifthen1.out;
}

template CardanoKeyOwnershipSMT(depth) {
    signal input A[256];
    signal input smt_root;
    signal input smt_siblings[depth];
    signal input smt_directions[depth];
    signal input sk[255];
    signal input PointA[4][3];
    signal output out;

    var G[4][3] = [[6836562328990639286768922, 21231440843933962135602345, 10097852978535018773096760],
                   [7737125245533626718119512, 23211375736600880154358579, 30948500982134506872478105],
                   [1, 0, 0],
                   [20943500354259764865654179, 24722277920680796426601402, 31289658119428895172835987]
                  ];

    var i;
    var j;

    component pMul = ScalarMul();
    for(i=0; i<255; i++) {
        pMul.s[i] <== sk[i];
    }
    for(i=0; i<4; i++) {
        for(j=0; j<3; j++) {
            pMul.P[i][j] <== G[i][j];
        }
    }

    component equal = PointEqual();
    for(i=0; i<3; i++) {
        for(j=0; j<3; j++) {
            equal.p[i][j] <== pMul.sP[i][j];
            equal.q[i][j] <== PointA[i][j];
        }
    }

    component compressA = PointCompress();
    for(i=0; i<4; i++) {
        for(j=0; j<3; j++) {
            compressA.P[i][j] <== PointA[i][j];
        }
    }

    for(i=0; i<256; i++) {
        compressA.out[i] === A[i];
    }

    signal leaf;
    component leafHasher = MultiMimc7(6, 91);
    for(i=0; i<3; i++) {
        leafHasher.in[i] <== PointA[0][i];
    }
    for(i=0; i<3; i++) {
        leafHasher.in[i + 3] <== PointA[1][i];
    }
    leafHasher.k <== 0;
    leaf <== leafHasher.out;

    component hashers[depth];
    component switches[depth];
    signal current[depth + 1];
    current[0] <== leaf;

    for(i=0; i<depth; i++) {
        switches[i] = SelectiveSwitch();
        switches[i].in0 <== current[i];
        switches[i].in1 <== smt_siblings[i];
        switches[i].s <== smt_directions[i];

        hashers[i] = Mimc2();
        hashers[i].in0 <== switches[i].out0;
        hashers[i].in1 <== switches[i].out1;

        current[i + 1] <== hashers[i].out;
    }

    smt_root === current[depth];
    out <== equal.out;
}

component main {public [A, smt_root]} = CardanoKeyOwnershipSMT(4);