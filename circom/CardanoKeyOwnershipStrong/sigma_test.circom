pragma circom 2.0.0;
include "sha512/sigma.circom";
include "sha512/sigmaplus.circom";
include "binsum_alt.circom";

// Standalone SigmaPlus512 fed a 4-word pattern like the W-expansion sees.
component main = SigmaPlus512();