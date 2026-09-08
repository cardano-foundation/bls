pragma circom 2.0.0;

include "sha512/sha512.circom";
include "binsum_alt.circom";

template Sha512Smoke() {
    signal input in[1024];
    signal output out[512];

    component s = Sha512(1024);
    for (var i = 0; i < 1024; i++) { s.in[i] <== in[i]; }
    for (var i = 0; i < 512; i++)  { out[i] <== s.out[i]; }
}

component main = Sha512Smoke();