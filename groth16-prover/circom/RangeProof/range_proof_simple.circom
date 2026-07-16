pragma circom 2.0.0;

// Simple range proof — prove that value ∈ [0, 2^n)
//
// Public input:  value
// Public output: valid (always 1 if constraints are satisfied)
//
// The circuit uses Num2Bits(n) to decompose value into n bits.
// Each bit is constrained to {0,1}. If value >= 2^n, the decomposition
// would need more than n bits, causing the final lc1 === in constraint
// inside Num2Bits to fail.

include "./node_modules/circomlib/circuits/bitify.circom";

template RangeProofSimple(n) {
    signal input value;
    signal output valid;

    component n2b = Num2Bits(n);
    n2b.in <== value;

    // Num2Bits constrains each output bit to 0 or 1.
    // If value >= 2^n, the constraint sum(bit[i] * 2^i) === value fails.

    valid <== 1;
}

// Instantiate with n = 32 (32-bit unsigned integer range)
component main {public [value]} = RangeProofSimple(32);
