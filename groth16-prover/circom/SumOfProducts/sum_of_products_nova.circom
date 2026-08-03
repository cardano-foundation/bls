pragma circom 2.0.0;

// SumOfProducts — Nova IVC step circuit (running sum of products).
//
//   state_out = state_in + a * b
//
// A chain of N steps computes the sum of N pairwise products of secret
// factors.  The public input is exactly the state, so the CLI chain rule
// state_in[i+1] == state_out[i] holds (n_pub_in == n_pub_out).

template SumOfProductsStep() {
    signal input state_in;
    signal input a;
    signal input b;
    signal output state_out;

    state_out <== state_in + a * b;
}

component main {public [state_in]} = SumOfProductsStep();
