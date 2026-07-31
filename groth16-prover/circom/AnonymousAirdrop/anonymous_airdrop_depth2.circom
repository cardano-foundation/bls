pragma circom 2.0.0;

// Instantiate AnonymousAirdrop with depth=2 and n=32 (32-bit unsigned scores)
include "./anonymous_airdrop.circom";

component main {public [digest, minScore, nullifier]} = AnonymousAirdrop(2, 32);
