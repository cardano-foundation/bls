pragma circom 2.0.0;

// Limb decomposition with range proofs — enables selective disclosure.
//
// Splits a message into (nLimbs * 16)-bit value into nLimbs u16 limbs.
// Each limb is independently range-constrained to [0, 2^16).
//
// Selective disclosure: a prover can reveal one or a few limbs while
// keeping the others hidden.  Used with the Twisted ElGamal scheme where
// each limb can be encrypted separately, so a single message is split into
// multiple ciphertexts that the verifier can process independently.

include "bitify.circom";

template LimbDecompose(nLimbs) {
    signal input message;              // value to decompose
    signal output limbs[nLimbs];       // u16 limbs
    signal output valid;               // always 1 if constraints hold

    var n = nLimbs * 16;

    component n2b = Num2Bits(n);
    n2b.in <== message;

    // group bits into 16-bit chunks; each limb is a linear constraint.
    // Because Num2Bits already constrains every bit to {0,1}, each limb is
    // automatically range-bounded to [0, 2^16) — no extra range proof needed.
    for (var i = 0; i < nLimbs; i++) {
        var acc = 0;
        for (var j = 0; j < 16; j++) {
            acc += n2b.out[i*16 + j] * (1 << j);
        }
        limbs[i] <== acc;
    }

    valid <== 1;
}

// Instantiate with 8 limbs (128-bit message)
component main = LimbDecompose(8);
