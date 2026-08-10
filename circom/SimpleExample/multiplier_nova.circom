pragma circom 2.0.0;

// SimpleExample — Nova IVC step circuit (running product).
//
//   state_out = state_in * x
//
// A chain of N steps proves knowledge of N secret factors whose product
// is the final state.  The public input is exactly the state, so the CLI
// chain rule state_in[i+1] == state_out[i] holds (n_pub_in == n_pub_out).

template MultiplierStep() {
    signal input state_in;
    signal input x;
    signal output state_out;

    state_out <== state_in * x;
}

component main {public [state_in]} = MultiplierStep();
