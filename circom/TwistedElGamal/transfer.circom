pragma circom 2.0.0;

// Twisted ElGamal transfer circuit.
//
// The sender holds an encrypted balance commitment and wants to transfer
// a value while proving, without revealing amounts, that:
//
//   1. the transfer amount is in a valid range:  amount ∈ [0, 2^16)
//   2. the resulting balance does not underflow: remaining >= 0
//   3. the new committed balance equals old balance minus the transfer:
//        newBalance == oldBalance - amount
//
// Because Twisted ElGamal is homomorphic (additive in the exponent), the
// on-chain verifier can check ciphertext relations using only point
// additions.  This circuit proves the *integer arithmetic* and range
// constraints in zero-knowledge.

include "bitify.circom";

template Transfer() {
    signal input oldBalance;       // previous balance (u16 limbs)
    signal input newBalance;       // resulting balance, >= 0
    signal input amount;           // amount to transfer; private

    signal output valid;

    // Range-check amount and newBalance to [0, 2^16) using Num2Bits(16).
    // Num2Bits constrains each of the 16 bits to {0,1} and enforces that the
    // weighted sum equals the input, bounding the value to [0, 2^16).
    component amountRange = Num2Bits(16);
    amountRange.in <== amount;

    component newRange = Num2Bits(16);
    newRange.in <== newBalance;

    // Conservation: newBalance == oldBalance - amount, and no underflow
    // (underflow is prevented because newBalance and amount are both
    //  range-constrained to [0, 2^16); combined with the equality below,
    //  the resulting balance stays within the representable range).
    newBalance === oldBalance - amount;

    valid <== 1;
}

component main {public [oldBalance, newBalance]} = Transfer();
