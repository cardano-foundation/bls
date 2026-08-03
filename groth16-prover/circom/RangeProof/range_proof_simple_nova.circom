pragma circom 2.0.0;

// RangeProof — Nova IVC step circuit (simple), one bit per step.
//
//   b * (1 - b) === 0
//   acc_in === 2 * acc_out + b     (acc_out <-- (acc_in - b) \ 2)
//   idx_out <== idx_in + 1
//
// A chain of n steps starting at acc_0 = value and ending at acc_n = 0
// proves value < 2^n.  The public inputs are exactly the state
// (n_pub_in == n_pub_out == 2: acc + idx).  `idx` is bookkeeping for the
// CLI transcript; the CLI runs exactly n steps and checks acc_n == 0.

template RangeStep() {
    signal input acc_in;
    signal input idx_in;
    signal input b;
    signal output acc_out;
    signal output idx_out;

    b * (1 - b) === 0;
    acc_out <-- (acc_in - b) \ 2;
    acc_in === 2 * acc_out + b;
    idx_out <== idx_in + 1;
}

component main {public [acc_in, idx_in]} = RangeStep();
