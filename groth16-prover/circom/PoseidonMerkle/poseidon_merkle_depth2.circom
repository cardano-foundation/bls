pragma circom 2.0.0;

include "./poseidon_merkle.circom";

component main {public [digest]} = PoseidonMerkle(2);
