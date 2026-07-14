pragma circom 2.0.0;

include "poseidon_constants_bls12_381.circom";

/**
 * Poseidon permutation for BLS12-381.
 *
 * Parameters: t=3, alpha=5, RF=8, RP=57.
 * State width = 3.  Input is two field elements; the first state cell is 0.
 *
 * This is a direct Circom port of the Poseidon paper specification,
 * using BLS12-381 round constants and MDS matrix from
 * ZeroJ's PoseidonParamsBLS12_381T3 (Grain LFSR generation).
 */

template PoseidonBLS12_381() {
    signal input in0;
    signal input in1;
    signal output out;

    var N_ROUNDS = 65;
    var T = 3;

    // Initial state: [0, in0, in1]
    signal state[N_ROUNDS + 1][T];

    state[0][0] <== 0;
    state[0][1] <== in0;
    state[0][2] <== in1;

    for (var r = 0; r < N_ROUNDS; r++) {
        // AddRoundConstants
        signal afterAdd[T];
        for (var j = 0; j < T; j++) {
            afterAdd[j] <== state[r][j] + POSEIDON_C[r * T + j];
        }

        // S-box (x^5)
        signal afterSbox[T];
        if (r < 4 || r >= 61) {
            // Full S-box round
            for (var j = 0; j < T; j++) {
                afterSbox[j] <== afterAdd[j] * afterAdd[j] * afterAdd[j] * afterAdd[j] * afterAdd[j];
            }
        } else {
            // Partial S-box round: only first element gets S-box
            afterSbox[0] <== afterAdd[0] * afterAdd[0] * afterAdd[0] * afterAdd[0] * afterAdd[0];
            afterSbox[1] <== afterAdd[1];
            afterSbox[2] <== afterAdd[2];
        }

        // MDS matrix multiplication
        for (var i = 0; i < T; i++) {
            state[r + 1][i] <== POSEIDON_M[i][0] * afterSbox[0] + POSEIDON_M[i][1] * afterSbox[1] + POSEIDON_M[i][2] * afterSbox[2];
        }
    }

    out <== state[N_ROUNDS][0];
}
